# TrustVault — Threat Model and Security Testing

## 1. Purpose

This document identifies potential security threats to TrustVault, a Flask-based document-sharing application. It describes possible impacts and tests that should be performed to check the application's access controls and file-handling behavior.

## 2. Assets to Protect

- User accounts and password hashes
- Uploaded documents and their contents
- Document-sharing permissions
- Document integrity hashes
- Audit logs
- Administrator-only functionality
- Application configuration and secret keys

## 3. Potential Threats

### Threat 1: Unauthorized Document Access

**Risk:** A user may attempt to download a document that belongs to another user without permission.

**Potential impact:** Confidential documents could be exposed.

**Mitigation:** Verify authorization on every document download request, including shared-document access.

**Test plan:** Sign in as a different user and attempt to access a document without permission. The application should deny access.

**Result:** Pending verification.

### Threat 2: Unauthorized Administrator Access

**Risk:** A regular user may attempt to access the administrator dashboard or administrator-only actions.

**Potential impact:** Unauthorized access to user records, document metadata, or audit activity.

**Mitigation:** Enforce server-side role checks on every administrator-only route.

**Test plan:** Sign in with a regular account and attempt to open the admin dashboard directly.

**Result:** Pending verification.

### Threat 3: Unsafe File Uploads

**Risk:** A user may upload an unexpected or potentially harmful file.

**Potential impact:** Malicious files may be stored or made available to other users.

**Mitigation:** Validate allowed file types, use safe storage names, enforce size limits, and avoid executing uploaded content.

**Test plan:** Attempt an unsupported file type and an oversized file. Confirm that the application rejects them as intended.

**Result:** Pending verification.

### Threat 4: Unauthorized Document Sharing

**Risk:** A user may attempt to share a document without owning it or without having the necessary permission.

**Potential impact:** Documents could be shared with unauthorized recipients.

**Mitigation:** Verify the current user's permission before creating or revoking a share.

**Test plan:** Attempt to share another user's document and verify that the operation is denied.

**Result:** Pending verification.

### Threat 5: Tampering with Shared Access

**Risk:** A recipient may try to access a document after their share permission has been revoked.

**Potential impact:** Revoked users may retain access to a document.

**Mitigation:** Recheck current sharing permissions whenever a shared document is downloaded.

**Test plan:** Share a document, revoke the recipient's access, and attempt to download it again as that recipient.

**Result:** Pending verification.

### Threat 6: Document Integrity Tampering

**Risk:** A stored document may be modified after its original SHA-256 hash is recorded.

**Potential impact:** Users may receive a modified document without detecting the change.

**Mitigation:** Recalculate the document's SHA-256 hash and compare it with the stored hash during integrity verification.

**Test plan:** Verify an unchanged document, then test a controlled copy with modified contents and confirm that the hash comparison detects the difference.

**Result:** Pending verification.

### Threat 7: Audit Log Tampering or Missing Events

**Risk:** Important user and document actions may not be recorded correctly, or audit records may be modified.

**Potential impact:** Investigations may be unreliable or incomplete.

**Mitigation:** Record important security events consistently and restrict audit-log access to authorized administrators.

**Test plan:** Perform login, upload, download, sharing, and revocation actions. Check whether the expected events appear in the audit log.

**Result:** Pending verification.

### Threat 8: Secret or Database Exposure

**Risk:** Secret keys, database files, or uploaded documents may accidentally be committed to the source repository.

**Potential impact:** Account compromise or disclosure of private information.

**Mitigation:** Use `.gitignore`, keep secrets in environment variables, and review repository contents before submission.

**Test plan:** Inspect tracked files and repository history for accidentally committed secrets or private files. Rotate any exposed credentials.

**Result:** Pending verification.

### Threat 9: Cross-Site Request Forgery (CSRF)

**Risk:** A malicious website may attempt to cause an authenticated user to perform an unwanted action.

**Potential impact:** Unauthorized sharing, revocation, or other state-changing actions.

**Mitigation:** Use CSRF protection for state-changing form submissions and validate requests server-side.

**Test plan:** Review forms and verify that invalid or missing CSRF tokens are rejected where protection is required.

**Result:** Pending verification.

### Threat 10: Weak Session and Configuration Security

**Risk:** Weak secret-key configuration, insecure cookies, or insufficient session handling may expose authenticated sessions.

**Potential impact:** Session compromise or unauthorized account access.

**Mitigation:** Use a strong private secret key, secure cookie settings in production, and appropriate session handling.

**Test plan:** Review the deployment configuration and confirm that secrets are not exposed in source code or responses.

**Result:** Pending verification.
## 4. Known Limitations

- TrustVault is a demonstration project and has not undergone an independent security audit.
- SQLite and local file storage may not provide reliable persistence on an ephemeral hosting filesystem.
- This threat model is a list of potential risks and planned checks, not proof that all threats have been mitigated.
- Production deployment requires further security review, persistent storage, and additional testing.

## 5. Testing Evidence

Record each test only after performing it. Include the test date, account role used (without passwords), steps performed, expected result, actual result, and pass/fail status.

| Test | Status |
|---|---|
| Unauthorized document download | Pending |
| Regular user accessing admin route | Pass |
| Unsupported and oversized uploads | Pending |
| Unauthorized sharing | Pending |
| Download after share revocation | Pending |
| SHA-256 integrity comparison | Pending |
| Audit event verification | Pending |
| Repository secret review | Pending |
| CSRF protection review | Pending |
| Session and deployment configuration review | Pending |

## 6. Conclusion

This threat model identifies important risks for a document-sharing application and provides a plan for validating security controls. Final conclusions should be based on actual test results rather than assumptions.