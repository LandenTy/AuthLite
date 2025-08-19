# AuthLite
AuthLite is a lightweight, offline TOTP authenticator written entirely in vanilla HTML, CSS, and JavaScript.
It runs entirely in your browser. Meaning, no backends, no dependencies, and full privacy.

![AuthLite Preview](images/screenshot.png)

Features:
-----------
  - Generates 6-digit TOTP codes
  - Add, Edit, and Delete Accounts
  - All Data Stays in the Browser through localStorage
  - Export / Import encrypted backups (AES-GCM with PBKDF2)
  - Secrets are **never sent** to any server
  - Works offline via ```file:///```
