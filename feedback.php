<?php
// feedback.php: User feedback page for Library Management System
// Allows users to submit, decrypt, and delete encrypted feedback
// Implements secure input sanitization, AES-256-CBC encryption, and session management

// Start session with secure settings: 30-minute timeout, HTTP-only cookies, and secure flag for HTTPS
session_start([
    'cookie_lifetime' => 1800, // Expire session after 30 minutes of inactivity
    'cookie_httponly' => true, // Prevent JavaScript access to session cookies (mitigates XSS)
    'cookie_secure' => isset($_SERVER['HTTPS']), // Ensure cookies are sent only over HTTPS when available
]);

// Restrict access to authenticated users
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

require_once 'db_connect.php';

// Generate CSRF token for form security
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Sanitize input to prevent XSS by removing tags, encoding special characters, and trimming whitespace
function sanitizeInput($input) {
    return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
}

// Encrypt message using AES-256-CBC (reversible encryption, unlike hashing)
function encryptMessage($message, $key) {
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc')); // Generate random IV
    $encrypted = openssl_encrypt($message, 'aes-256-cbc', $key, 0, $iv);
    return base64_encode($iv . $encrypted); // Combine IV and encrypted data
}

// Decrypt message using AES-256-CBC
function decryptMessage($encrypted, $key) {
    $data = base64_decode($encrypted);
    $ivLength = openssl_cipher_iv_length('aes-256-cbc');
    $iv = substr($data, 0, $ivLength);
    $encryptedMessage = substr($data, $ivLength);
    return openssl_decrypt($encryptedMessage, 'aes-256-cbc', $key, 0, $iv);
}

// Load encryption key from .env
$encryption_key = hex2bin($_ENV['ENCRYPTION_KEY'] ?? die("Encryption key not set"));

// Validate CSRF token
function validateCsrfToken() {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF token validation failed");
    }
}

// Handle feedback submission
if (isset($_POST['submit_feedback'])) {
    validateCsrfToken();
    $feedback = sanitizeInput($_POST['feedback']);
    if (empty($feedback)) {
        $error = "Feedback is required";
    } else {
        try {
            $encrypted_feedback = encryptMessage($feedback, $encryption_key);
            $stmt = $pdo->prepare("INSERT INTO feedback (user_id, encrypted_feedback) VALUES (?, ?)");
            $stmt->execute([$_SESSION['user_id'], $encrypted_feedback]);
            $success = "Feedback submitted successfully!";
            // Regenerate CSRF token after successful submission
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        } catch (Exception $e) {
            error_log("Feedback submission error: " . $e->getMessage());
            $error = "Failed to submit feedback";
        }
    }
}

// Handle feedback decryption
$decrypted_feedback = null;
if (isset($_POST['decrypt_feedback'])) {
    validateCsrfToken();
    $feedback_id = filter_var($_POST['feedback_id'], FILTER_VALIDATE_INT);
    if ($feedback_id === false) {
        $error = "Invalid feedback ID";
    } else {
        try {
            $stmt = $pdo->prepare("SELECT encrypted_feedback FROM feedback WHERE id = ? AND user_id = ?");
            $stmt->execute([$feedback_id, $_SESSION['user_id']]);
            $feedback = $stmt->fetch();
            if ($feedback) {
                $decrypted_feedback = decryptMessage($feedback['encrypted_feedback'], $encryption_key);
                if ($decrypted_feedback === false) {
                    $error = "Decryption failed";
                }
            } else {
                $error = "Feedback not found or unauthorized";
            }
        } catch (Exception $e) {
            error_log("Decryption error: " . $e->getMessage());
            $error = "Failed to decrypt feedback";
        }
    }
}

// Handle feedback deletion
if (isset($_POST['delete_feedback'])) {
    validateCsrfToken();
    $feedback_id = filter_var($_POST['feedback_id'], FILTER_VALIDATE_INT);
    if ($feedback_id === false) {
        $error = "Invalid feedback ID";
    } else {
        try {
            $stmt = $pdo->prepare("DELETE FROM feedback WHERE id = ? AND user_id = ?");
            $rows = $stmt->execute([$feedback_id, $_SESSION['user_id']]);
            if ($rows) {
                $success = "Feedback deleted successfully!";
                // Regenerate CSRF token after successful deletion
            } else {
                $error = "Feedback not found or unauthorized";
            }
        } catch (PDOException $e) {
            error_log("Feedback deletion error: " . $e->getMessage());
            $error = "Failed to delete feedback";
        }
    }
}

// Fetch user for header
try {
    $stmt = $pdo->prepare("SELECT name FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch();
    if (!$user) {
        die("User not found");
    }
} catch (PDOException $e) {
    error_log("User fetch error: " . $e->getMessage());
    die("An error occurred");
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Feedback - Library Management System</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');

:root {
    --primary-pink: #ec407a;
    --secondary-pink: #f06292;
    --white: #ffffff;
    --white-transparent: rgba(255, 255, 255, 0.95);
    --shadow-pink: rgba(219, 39, 119, 0.15);
    --border-pink: #f8bbd0;
    --error-red: #d32f2f;
    --success-green: #388e3c;
    --text-dark: #2d1b2e;
    --text-link: #c2185b;
    --spacing-xs: 0.5rem;
    --spacing-sm: 0.75rem;
    --spacing-md: 1rem;
    --spacing-lg: 1.5rem;
    --spacing-xl: 2.5rem;
    --font-size-base: 1rem;
    --font-size-sm: 0.875rem;
    --font-size-lg: 1.5rem;
    --font-size-xl: 2rem;
}

body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    margin: 0;
    padding: var(--spacing-lg);
    background: linear-gradient(135deg, #fff0f6 0%, #ffe4e6 100%);
    color: var(--text-dark);
    line-height: 1.6;
}

.container {
    max-width: 1280px;
    margin: 0 auto;
    background: var(--white-transparent);
    padding: var(--spacing-xl);
    border-radius: var(--spacing-lg);
    box-shadow: 0 4px 16px var(--shadow-pink);
    -webkit-backdrop-filter: blur(8px);
    backdrop-filter: blur(8px);
}

h1, h2 {
    color: var(--primary-pink);
    font-weight: 700;
    letter-spacing: -0.025em;
    margin-bottom: var(--spacing-md);
}

h1 {
    font-size: var(--font-size-xl);
}

h2 {
    font-size: var(--font-size-lg);
}

.header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: var(--spacing-xl);
    padding-bottom: var(--spacing-lg);
    border-bottom: 2px solid var(--border-pink);
}

.header span {
    font-weight: 600;
}

.feedback-form {
    display: flex;
    flex-wrap: wrap;
    gap: var(--spacing-lg);
    margin-bottom: var(--spacing-xl);
}

.feedback-form textarea {
    width: 100%;
    min-height: 100px;
    padding: var(--spacing-md);
    border: 2px solid var(--border-pink);
    border-radius: var(--spacing-sm);
    background: rgba(255, 245, 247, 0.8);
    transition: border-color 0.3s ease, box-shadow 0.3s ease;
    font-size: 20px;
    resize: vertical;
}

.feedback-form textarea:focus {
    outline: none;
    border-color: var(--primary-pink);
    box-shadow: 0 0 0 4px rgba(236, 64, 122, 0.15);
}

.feedback-form button, .action-button {
    padding: var(--spacing-sm) var(--spacing-lg);
    background: linear-gradient(135deg, var(--primary-pink) 0%, var(--secondary-pink) 100%);
    color: var(--white);
    border: none;
    border-radius: var(--spacing-sm);
    cursor: pointer;
    font-weight: 600;
    font-size: var(--font-size-base);
    transition: transform 0.3s ease, box-shadow 0.3s ease, background 0.3s ease;
    position: relative;
    overflow: hidden;
}

.feedback-form button:hover, .action-button:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(236, 64, 122, 0.3);
    background: linear-gradient(135deg, var(--secondary-pink) 0%, var(--primary-pink) 100%);
}

.feedback-form button:focus, .action-button:focus {
    outline: 3px solid var(--primary-pink);
    outline-offset: 2px;
}

.delete-button {
    background: linear-gradient(135deg, var(--error-red) 0%, #e57373 100%);
}

.delete-button:hover {
    background: linear-gradient(135deg, #e57373 0%, var(--error-red) 100%);
    box-shadow: 0 4px 12px rgba(211, 47, 47, 0.3);
}

.feedback-form button::after, .action-button::after, .delete-button::after {
    content: '';
    position: absolute;
    top: 50%;
    left: 50%;
    width: 0;
    height: 0;
    background: rgba(255, 255, 255, 0.3);
    border-radius: 50%;
    transform: translate(-50%, -50%);
    transition: width 0.3s ease, height 0.3s ease;
}

.feedback-form button:hover::after, .action-button:hover::after, .delete-button::after {
    width: 100%;
    height: 100%;
}

table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    margin-bottom: var(--spacing-xl);
    border-radius: var(--spacing-md);
    overflow: hidden;
    background: var(--white);
    box-shadow: 0 4px 12px var(--shadow-pink);
}

th, td {
    padding: var(--spacing-md);
    text-align: left;
    border-bottom: 1px solid var(--border-pink);
}

th {
    background: linear-gradient(135deg, var(--secondary-pink) 0%, var(--primary-pink) 100%);
    color: var(--white);
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

td {
    background: var(--white-transparent);
}

tr {
    transition: background 0.3s ease;
}

tr:nth-child(even) {
    background: rgba(252, 228, 236, 0.4);
}

tr:hover {
    background: rgba(244, 143, 177, 0.15);
}

a {
    color: var(--text-link);
    text-decoration: none;
    font-weight: 600;
    transition: color 0.3s ease, transform 0.3s ease;
}

a:hover {
    color: #ad1457;
    text-decoration: underline;
    transform: translateY(-1px);
}

a:focus {
    outline: 3px solid var(--primary-pink);
    outline-offset: 2px;
}

.error {
    color: var(--error-red);
    text-align: center;
    margin-bottom: var(--spacing-lg);
    font-weight: 500;
    background: rgba(211, 47, 47, 0.1);
    padding: var(--spacing-sm);
    border-radius: var(--spacing-sm);
}

.success {
    color: var(--success-green);
    text-align: center;
    margin-bottom: var(--spacing-lg);
    font-weight: 500;
    background: rgba(56, 142, 60, 0.1);
    padding: var(--spacing-sm);
    border-radius: var(--spacing-sm);
}

.feedback-card {
    background: var(--white-transparent);
    padding: var(--spacing-lg);
    border-radius: var(--spacing-md);
    box-shadow: 0 4px 12px var(--shadow-pink);
    margin-bottom: var(--spacing-xl);
    transition: transform 0.3s ease, box-shadow 0.3s ease;
}

.feedback-card:hover {
    transform: translateY(-4px);
    box-shadow: 0 6px 16px rgba(219, 39, 119, 0.2);
}

.feedback-card p {
    margin: 0 0 var(--spacing-lg);
    color: var(--text-dark);
    font-size: 20px; 
}

.security-note {
    display: flex;
    align-items: center;
    gap: var(--spacing-sm);
    color: #6d2e6f;
    font-size: 19px;
    margin-bottom: var(--spacing-lg);
    background: rgba(244, 143, 177, 0.15);
    padding: var(--spacing-md);
    border-radius: var(--spacing-sm);
    font-weight: 500;
}

.decrypted-feedback {
    background: rgba(252, 228, 236, 0.4);
    padding: var(--spacing-lg);
    border-radius: var(--spacing-md);
    margin-top: var(--spacing-xl);
    border-left: 5px solid var(--primary-pink);
    box-shadow: 0 4px 12px var(--shadow-pink);
}

.decrypted-feedback p {
    margin: 0;
    color: var(--text-dark);
    font-size: var(--font-size-base);
}

.back-link {
    display: block;
    margin-bottom: var(--spacing-lg);
    color: var(--text-link);
    font-weight: 600;
    font-size: var(--font-size-base);
    transition: color 0.3s ease, transform 0.3s ease;
}

.back-link:hover {
    color: #ad1457;
    text-decoration: underline;
    transform: translateY(-1px);
}

.action-buttons {
    display: flex;
    gap: var(--spacing-xs);
}

@media (max-width: 768px) {
    .container {
        padding: var(--spacing-lg);
    }
    .feedback-form {
        flex-direction: column;
        gap: var(--spacing-md);
    }
    .feedback-form textarea {
        min-height: 80px;
        font-size: 16px;
    }
    table {
        display: block;
        overflow-x: auto;
        white-space: nowrap;
    }
    th, td {
        padding: var(--spacing-sm);
        font-size: var(--font-size-sm);
    }
    .action-button, .delete-button {
        padding: var(--spacing-xs) var(--spacing-md);
        font-size: var(--font-size-sm);
    }
}
</style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Submit Feedback</h1>
            <div>
                <span>Welcome, <?php echo htmlspecialchars($user['name']); ?>!</span>
                <a href="dashboard.php" class="back-link">Back to Dashboard</a>
            </div>
        </div>

        <div class="feedback-card">
            <p>Share your feedback about the Library Management System.</p>
            <div class="security-note">Your feedback is encrypted using AES-256-CBC for maximum security.</div>

            <?php if (isset($error)): ?>
                <div class="error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            <?php if (isset($success)): ?>
                <div class="success"><?php echo htmlspecialchars($success); ?></div>
            <?php endif; ?>

            <!-- Feedback Submission Form -->
            <form method="POST" class="feedback-form">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <textarea name="feedback" placeholder="Enter your feedback (e.g., suggestions, issues, or comments)" required></textarea>
                <button type="submit" name="submit_feedback">Submit Feedback</button>
            </form>
        </div>

        <!-- Decrypted Feedback -->
        <?php if (isset($decrypted_feedback)): ?>
            <h2>Decrypted Feedback</h2>
            <div class="decrypted-feedback">
                <p><?php echo htmlspecialchars($decrypted_feedback); ?></p>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>