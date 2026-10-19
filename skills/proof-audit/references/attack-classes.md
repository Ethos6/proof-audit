# Attack classes

Use these to build hunt units (entry-point group × class). Each class lists what to trace and the control whose absence makes it a finding. Skip classes that cannot apply to the target.

## Access control
- **Missing authentication** — a route, handler or RPC method reachable without the auth middleware its siblings use. Compare route registration lists; look for routes added after the guard, or alternate routers.
- **Broken object authorization (IDOR)** — an ID from the request loads a record without checking the record belongs to the caller or their tenant. Check every lookup by ID, including bulk, export, search and background-job paths.
- **Privilege escalation** — role, permission or `is_admin` fields that a user can set through mass assignment, profile update, invite or sign-up flows.
- **Tenant isolation** — queries, caches, queues, search indexes or file paths keyed without the tenant ID on some path.

## Injection
- **SQL / NoSQL** — string-built queries, raw query APIs, ORM `raw`/`extra`/`$where`, operator injection via JSON objects.
- **Command** — `exec`, `system`, `popen`, `child_process`, `subprocess(shell=True)`, argument injection into git/ffmpeg/tar etc. (`--upload-pack`, leading `-`).
- **Code** — `eval`, `Function`, `vm`, template engines rendering user templates (SSTI), dynamic `import`/`require`, YAML/pickle/Java deserialization of untrusted data.
- **Cross-site scripting** — user data reaching HTML without escaping: `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `|safe`, markdown renderers with HTML enabled, `javascript:` URLs.
- **Header / log injection** — CRLF into headers or redirects; untrusted data into logs read by privileged tooling.

## Files and paths
- **Path traversal** — user input in a filesystem path without normalising and checking it stays inside the base directory (`path.join` alone is not containment).
- **Archive extraction** — zip/tar entries with `..`, absolute paths or symlinks (zip-slip).
- **Upload handling** — user-chosen names or types served from the app origin; uploads stored in executable locations.

## Server-side requests
- **SSRF** — user-supplied URLs fetched by the server without an allowlist; redirects and DNS rebinding around a blocklist; access to cloud metadata (`169.254.169.254`).
- **Open redirect** — user-controlled redirect targets, especially in login flows.

## Authentication and sessions
- Password reset, magic-link and invite tokens: predictability, reuse, no expiry, not bound to the account.
- JWT: `alg: none`, algorithm confusion, unverified signatures, missing audience or expiry checks.
- OAuth/OIDC: missing `state`, unchecked redirect URI, ID token not validated.
- Session fixation; logout not invalidating server-side sessions.
- Timing-unsafe secret comparison where the secret is remotely testable.

## Secrets and cryptography
- Hard-coded live credentials or private keys in source (not test fixtures).
- Weak randomness (`Math.random`, `rand`) for tokens or IDs that guard access.
- Homemade crypto, ECB mode, static IVs, unauthenticated encryption protecting security decisions.

## Web platform
- **CSRF** — state-changing cookie-authenticated endpoints without tokens or SameSite protection.
- **CORS** — reflected origins with credentials allowed.
- **postMessage** — handlers that skip origin checks before acting.
- **Prototype pollution** — deep merge or path-set of user JSON into objects later used for security decisions.

## Resource exhaustion (only with shared impact)
- Unbounded input sizes, regex with catastrophic backtracking on user input, decompression bombs, unbounded pagination — report only when one user can deny service to others.

## Supply chain and CI
- GitHub Actions using `pull_request_target` with checkout of PR code; untrusted input interpolated into `run:` scripts; secrets exposed to forks.
- Install scripts or update mechanisms fetching code without integrity checks.

## LLM and agent features
- Untrusted content (web pages, emails, documents, tool output) reaching a model that can call side-effecting tools without a confirmation step or a deterministic permission check.
- Model output rendered as HTML or executed as code/SQL/shell.
- Retrieval, memory or caches shared across users or tenants.
- The defect is a missing deterministic control, not that the model can be persuaded.

## Memory safety (native code)
- Unchecked lengths into `memcpy`/`strcpy`, integer overflow in size math, use-after-free across callbacks, format strings from input, double fetch from user memory.
