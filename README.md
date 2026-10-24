# TrustVault — Secure Document Sharing

## Overview

TrustVault is a Flask-based web application designed for document sharing, role-based access control, document integrity verification, and audit logging. It uses SHA-256 hashing to verify whether a document has changed since its hash was recorded.

## Live Demo

https://trustvault-im4o.onrender.com

## Features

- User registration and login
- Role-based access control for administrators
- Document uploads with supported file-type restrictions
- Document sharing between eligible users in the same company
- Shared document downloads
- SHA-256 document integrity verification
- Audit logs for important user and document actions
- Admin dashboard for reviewing users and audit activity
- Document access revocation

## Technology Stack

- Python
- Flask
- Flask-SQLAlchemy
- SQLite
- HTML and CSS
- SHA-256 hashing
- Git and GitHub
- Render deployment

## Run Locally

### Prerequisites

- Python 3.12 or a compatible Python version
- Git

### Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/revathi-104/TrustVault.git
   cd TrustVault
   ```

2. Create and activate a virtual environment:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

   On Windows:

   ```bash
   .venv\Scripts\activate
   ```

3. Install the project dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Configure the required secret key using the application's supported configuration. For deployment, set the `SECRET_KEY` environment variable. Configure `ADMIN_EMAIL` on the server if a designated administrator account is required.

5. Start the application:

   ```bash
   python app.py
   ```

6. Open http://127.0.0.1:5000 in your browser.

## Document Integrity Verification

TrustVault calculates a SHA-256 hash when a document is uploaded. During verification, it recalculates the hash and compares it with the stored value. A matching hash indicates that the file contents match the version originally recorded.

## Deployment

The demonstration application is hosted on Render:

https://trustvault-im4o.onrender.com

## Security and Limitations

- This project is a demonstration application and has not been independently security-audited.
- The current configuration uses SQLite and local file storage.
- Render's free-service filesystem may be ephemeral. Database records and uploaded files may not persist across restarts or redeployments.
- Production use requires persistent database and file storage, plus additional security testing and hardening.
- Do not upload real confidential documents or sensitive personal information to the demo.
- Never commit passwords, secret keys, private databases, or uploaded documents to the repository.

## Testing Status

The following core flows have been manually tested on the deployed application:

- Login and administrator access
- Document upload and download
- SHA-256 integrity verification
- Document sharing and recipient access
- Audit log review

These are manual tests, not a substitute for a comprehensive automated security test suite.

## AI Assistance

AI-assisted development and debugging were used during the project. See `PROMPTS.md` for the prompts and development notes.

## Author

Developed as a fresher hiring challenge project.
