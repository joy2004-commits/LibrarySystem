# LibrarySystem

# Technologies and Tools Used

-Frontend: HTML, CSS, TailwindCSS (for responsive and modern UI) 
-Backend: PHP (core framework for server-side logic) 
-Database: MySQL (via PDO for secure database interactions) 
-Hashing: bcrypt (password_hash() and password_verify()) 
-Encryption: AES-256-CBC (via OpenSSL for feedback encryption) 
-Environment Management: PHP Dotenv (for secure storage of database credentials and encryption keys) 
-Other Libraries: PDO for database connectivity, OpenSSL for encryption/decryption

# Hashing Implementation

Technology Used: bcrypt

Where it was used: 

User Registration and Login:
-Passwords are hashed using PHP password_hash() function when users register.
-During login, the hashed password is verified using password_verify().

Why it's important:
-Bcrypt includes automatic salting and adaptive work factors to resist brute-force and rainbow table attacks.
-Ensures that even if the database is compromised, actual passwords remain secure.

# Encryption Implementation

Technology Used: AES-256-CBC (via OpenSSL in PHP)

Where it was used:

Feedback Submission Page:
-User feedback is encrypted before storing in the database.
-The feedback can be decrypted only with a secure key stored in an environment variable.

Why it's important:
-Provides confidentiality of sensitive data (feedback content).
-Even if database contents are exposed, the encrypted feedback remains unreadable without the key.

# Screenshots of the System

-Registration Page: Displays a form with fields for full name, email, and password, a password strength indicator (client-side JavaScript), and a "Register" button. Success or error messages (e.g., "Registration successful!" or "Invalid email format") are shown. 

-Login Page: Shows a form with email and password fields, a "Login" button, and a link to the registration page. Error messages (e.g., "Invalid email or password") appear if authentication fails. 

-Dashboard: Displays a welcome message with the users name, forms to add or borrow books, a table listing all books (with edit/delete options), and a table of borrow records. Includes a link to the feedback page and a logout button. 

-Encryption Feature: The feedback page shows a form to submit feedback using AES-256-CBC for maximum security. 

-Error Messages/Validations: Examples include "Password must contain at least one uppercase letter" on the registration page.
