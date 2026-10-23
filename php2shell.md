Key takeaways
On October 20, 2026, PHP announced that they would release a patch on October 21 at 14:00 UTC for two critical vulnerabilities.

These vulnerabilities are called PHP2Shell because they allow an attacker to achieve remote code execution (RCE).

The details were scheduled to be disclosed on October 22, but information about the vulnerabilities, including their CVE IDs (CVE-2026-109619 and CVE-2026-109618), was leaked early.

CVE-2026-109619 is a use-after-free (UAF) vulnerability in PHP core's upload progress feature.

CVE-2026-109618 is a memory corruption vulnerability triggered by an out-of-memory (OOM) condition.

This blog post provides the full details behind these two vulnerabilities.

Jump to mitigation
Prerequisites for an attack  
The target runs PHP 5 onward with session.upload_progress.enabled = On (the default)

For any endpoint that accepts file uploads (even one that ignores them): PHP's session layer processes the upload progress before userland code runs

Attackers need the build-specific offset between zval_ptr_dtor and zend_call_function (either leaked at runtime or derived from the target's exact PHP binary/distro)

CVE-2026-109619 vulnerability details
There are 5 steps to exploiting the vulnerability:

Access the upload progress feature

Create the free condition

Trigger the free

Heap spray

Trigger the exploit

PHPShell (CVE-2026-109619)Zoom image
Step 1: Access the upload progress feature
PHP has a feature called “upload_progress”, which is available in default builds. This feature provides real-time feedback on how much of a file has been successfully uploaded to the server.

When a user initiates a multipart/form data upload (described in RFC 1867) and includes a POST parameter named “PHP_SESSION_UPLOAD_PROGRESS”, PHP intercepts it before the target script even begins executing.

PHP immediately creates a specific key inside the $_SESSION array (a built-in superglobal associative array used to store and access user data across multiple pages during a single website visit). As the file uploads chunk by chunk, PHP continuously updates this session array with metrics like content_length (total size), bytes_processed, and the names of the files. 

Under the hood, when PHP’s HTTP parser encounters the file field, it triggers the internal FILE_START event. To track the progress efficiently, PHP creates a zval pointer (i.e., a C memory pointer used internally in the PHP’s core) mapped directly to that session array in memory, allowing the C-level engine to rapidly write the incoming byte counts. 

Let’s take a look at the struct “php_session_rfc1867_progress” from php_session.h in the source code of the PHP core:

typedef struct _php_session_rfc1867_progress {
	zval      sid;
	smart_str key;

	zend_long      update_step;
	zend_long      next_update;
	double    next_update_time;
	bool cancel_upload;
	bool apply_trans_sid;
	size_t    content_length;

	zval      data;                 /* the array exported to session data */
	zval      files;                /* data["files"] array */
	zval     *post_bytes_processed; /* data["bytes_processed"] */
	zval     *current_file_bytes_processed;
	zval      current_file;         /* array of currently uploading file */
} php_session_rfc1867_progress;
Copy
It turns out that PHP caches two raw zval * pointers when processing a multipart upload:

zval *post_bytes_processed;

zval *current_file_bytes_processed; 

  So, when the attacker sends a POST request with:

 PHPSESSID cookie/field — It sets the session ID

 PHP_SESSION_UPLOAD_PROGRESS field — It activates the progress tracking

 A file field — It triggers FILE_START, which caches both pointers

When a user sends a POST request that triggers the progress tracking, there are two zval pointers that point into live hash table buckets inside the decoded progress tree.

Step 2: Create the free condition
The attacker pauses the TCP stream for greater than 1 second (the default session.upload_progress.min_freq). This is needed to bypass PHP's rate limiting guard on progress updates.

Step 3: Trigger the free
At this point, before the second update(), the memory looks like this:

progress->post_bytes_processed →  [ bucket in Tree-A ]

progress->current_file_bytes_processed → [ bucket in Tree-A ]

Tree-A is the live decoded session data, stored in $_SESSION under the key "upload_progress_x".

When data resumes, a second FILE_DATA event fires. Because enough time has passed, a second php_session_rfc1867_update() runs, and causes the following flow:

flush() writes Tree-A to disk and resets status

 After flush, sets session_status = none

php_session_initialize() re-reads the session file

Because status is none, PHP treats this as opening a fresh session. It reads the file from disk and deserializes it into a brand new tree — let’s call it Tree-B. Tree-B is a completely new allocation at a different address. It contains the same data as Tree-A, but it's a copy.

php_session_track_init() destroys Tree-A

PHP now has two trees with the same session key:

Tree-A (the old one, still in $_SESSION)

Tree-B (the fresh one, just deserialized)

zend_hash_update() put Tree-B into $_SESSION. The hash table's pDestructor (zval_ptr_dtor) runs on the old value - Tree-A. This frees Tree-A and all its buckets.

Now the pointers are dangling: progress->post_bytes_processed and progress->current_file_bytes_processed they are freed.

Tree-B exists as a new address, but nobody updates the pointers.

So basically, PHP caches raw zval * pointers into a hash table, then destroys and replaces that hash table without updating the cached pointers. This causes UAF, which is the bug behind CVE-2026-109619.

Step 4: Heap spray
Immediately after the free, in the same HTTP POST body as the upload, the attacker places a lot (not one, to ensure saturation) form fields, all named t[]:

--boundary

  Content-Disposition: form-data; name="t[]"

  <288 bytes of forged struct>

  --boundary

  Content-Disposition: form-data; name="t[]"

  <288 bytes of forged struct>

  ... (×149)

PHP's multipart parser (rfc1867.c) processes these as FORMDATA events. Each value becomes a zend_string in $_POST['t'], which is a PHP array. The name t[] tells PHP to append to an array, so all 149 land in $_POST['t'][0] through $_POST['t'][148].

Each tag contains a fake PHP internal function structure with system("<command>") baked in. These allocations are sized to land in the exact same memory slot that was just freed. Then, the allocator might hand the exact same slot of the data that just got freed, and the attacker’s payload can get inside, so the dangling pointer would point to the attacker’s payload.  

Step 5: Trigger the exploit
The attacker sends a second file in the same POST. PHP writes through the dangling pointers into what it thinks is the progress structure:

case MULTIPART_EVENT_FILE_DATA: {
			const multipart_event_file_data *data = event_data;

			if (!Z_TYPE(progress->sid) || !progress->key.s) {
				break;
			}

			Z_LVAL_P(progress->current_file_bytes_processed) = data->offset + data->length;
			Z_LVAL_P(progress->post_bytes_processed) = data->post_bytes_processed;

			php_session_rfc1867_update(progress, false);
		}
Copy
But it's now the attacker's fake function. When PHP's engine touches this corrupted data, it follows the fake pointers and calls the system ("attacker command").

CVE-2026-109618 vulnerability details
In this vulnerability, the problem is that OOM forces PHP to abort execution in unexpected way, so normal cleanup can be bypassed, leaving uninitialized memory vulnerable to malicious overwrite and execution.

The attacker sends a maliciously crafted request designed to rapidly consume memory until it hits PHP's configured memory_limit. This can be achieved through massive file uploads.

Then, when the PHP’s core detects the OOM condition, it must halt execution. Instead of returning through function normally and clearing variables step by step, it uses longjmp() (the underlying C-level mechanism) to instantly unwind the stack and jump directly to the request shutdown mechanism.

Because longjmp() abruptly skips local cleanup and initialization code, certain internal structures are left in a volatile, uninitialized, or dangling state. 

The attacker can take advantage of it, and before the OOM he can manipulate the heap (for example, by using techniques like sending a lot of “t[]” form fields, like we saw earlier).

This fills memory segments with forged C-structures containing malicious execution pointers.

Finally, During the php_request_shutdown phase, PHP systematically goes through active resources to free them. When it encounters the uninitialized memory left behind by the longjmp() interruption, the engine blindly reads the attacker's forged structure. If the engine branches on a function pointer (like a destructor) within that corrupted memory, execution jumps to the attacker's payload, resulting in RCE. 
