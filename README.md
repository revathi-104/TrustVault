# TrustVault — Secure Document Sharing

## Overview
TrustVault is a Flask-based web application for secure document sharing, role-based access control, and document integrity verification using SHA-256 hashing.

## Features
- User registration and login
- Role-based access control for administrators
- Secure document uploads
- Document sharing between registered users
- Shared document downloads
- SHA-256 document integrity verification
- Audit logs for important user and document actions
- Admin dashboard for reviewing users, documents, and audit activity

## Technology Stack
- Python
- Flask
- Flask-SQLAlchemy
- SQLite
- HTML and CSS
- SHA-256 hashing

## Run Locally
1. Create and activate a Python virtual environment.
2. Install dependencies:
   `pip install flask flask-sqlalchemy flask-login flask-wtf`
3. Start the application:
   `python app.py`
4. Open `http://127.0.0.1:5000` in your browser.

## Security Notes
This project is a demonstration application and has not yet been independently security-audited. Configure production security settings before deploying publicly. Do not commit passwords, secret keys, databases containing personal information, or uploaded documents to a public repository.

## Current Status
Core login, document sharing, document downloading, integrity verification, and admin access-control flows have been manually tested.
