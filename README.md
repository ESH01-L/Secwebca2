# Library Book Record Management System

## Overview
The Library Book Record Management System is a web application designed to help libraries manage their resources effectively. The original version included basic features for logging in, checking out books, and managing the catalog. However, it had several security vulnerabilities that needed to be addressed. This project aims to enhance the system's security while maintaining its core functionalities.

## Key Features
- *CRUD Operations*: Users can create, read, update, and delete book records.
- *User Authentication*: Secure login functionality for both users and administrators.
- *Book Availability Management*: Check and manage the availability of books.
- *Enhanced Security Measures*:
  - Password hashing using bcrypt
  - CSRF protection with tokens
  - Input validation and sanitization
  - Improved session management
  - Integration of Google reCAPTCHA

## Project Objectives
The main goals of this project were to:
- Strengthen user authentication processes.
- Improve input validation and sanitization.
- Protect against common web security threats.
- Enhance overall system resilience and security for users and administrators.

## Security Improvements Implemented
1. *Better Password Hashing*: Replaced MD5 with bcrypt for stronger password protection.
2. *CSRF Protection*: Implemented CSRF tokens to prevent unauthorized actions.
3. *Input Sanitization*: Added measures to clean and validate user input, reducing injection attack risks.
4. *Improved Session Management*: Enhanced handling of user sessions to prevent session hijacking.
5. *reCAPTCHA Integration*: Added reCAPTCHA on the admin login page to block automated attacks.

## Technologies Used
- *Backend*: PHP
- *Database*: MySQL
- *Frontend*: HTML5, CSS3, JavaScript

## Installation Instructions
1. Clone the repository to your local machine.
2. Set up a PHP environment (7.4+ recommended) with MySQL.
3. Import the provided SQL file to create the database schema.
4. Configure database connection settings in config.php.
5. Set up Google reCAPTCHA and update the site key in the relevant files.

## Usage
- Users can register as students, check book availability, manage their accounts, and change passwords.
- Administrators can manage books, authors, categories, and student records while ensuring enhanced security measures are in place.

## Testing
The application has undergone rigorous testing including functional testing of security features and Static Application Security Testing (SAST) to identify potential vulnerabilities.

## Future Improvements
Future enhancements may include:
- Implementing stricter password policies.
- Adding logging for failed login attempts.
- Introducing stricter session timeout policies.
