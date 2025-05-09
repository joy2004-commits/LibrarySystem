<?php
// login.php: User login page for Library Management System
// Implements secure authentication with hashed password verification, input sanitization, and session management

// Start session with secure settings: 30-minute timeout, HTTP-only cookies, and secure flag for HTTPS
session_start([
    'cookie_lifetime' => 1800, // Expire session after 30 minutes of inactivity
    'cookie_httponly' => true, // Prevent JavaScript access to session cookies (mitigates XSS)
    'cookie_secure' => isset($_SERVER['HTTPS']), // Ensure cookies are sent only over HTTPS when available
]);

require_once 'db_connect.php';

// Sanitize input to prevent XSS by removing tags, encoding special characters, and trimming whitespace
function sanitizeInput($input) {
    return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
}

if (isset($_POST['login'])) {
    // Sanitize email input to prevent XSS
    $email = sanitizeInput($_POST['email']);
    $password = $_POST['password']; // Password is not sanitized as it's used only for verification

    if (empty($email) || empty($password)) {
        $error = "Email and password are required";
    } else {
        try {
            // Use prepared statement to prevent SQL injection
            $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
            $stmt->execute([$email]);
            $user = $stmt->fetch();

            // Verify password against stored hash using bcrypt
            if ($user && password_verify($password, $user['password_hash'])) {
                // Store user data in session for authentication
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['user_name'] = $user['name'];
                
                // Update last IP address using prepared statement
                $stmt = $pdo->prepare("UPDATE users SET last_ip = ? WHERE id = ?");
                $stmt->execute([$_SERVER['REMOTE_ADDR'], $user['id']]);
                
                header("Location: dashboard.php");
                exit;
            } else {
                $error = "Invalid email or password";
            }
        } catch (PDOException $e) {
            // Log database errors in production
            error_log("Login error: " . $e->getMessage());
            $error = "An error occurred. Please try again.";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>Login - Library Management System</title>
    <style>
        body {
            font-family: 'Arial', sans-serif;
            background: linear-gradient(135deg, #f8c9d4, #f4c8e1);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }

        .login-container {
            background-color: #ffffff;
            padding: 50px;
            border-radius: 16px;
            box-shadow: 0 6px 16px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 500px;
            transition: transform 0.3s ease;
        }

        .login-container:hover {
            transform: scale(1.02);
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.2);
        }

        h2 {
            text-align: center;
            color: #f48fb1;
            font-size: 32px;
            margin-bottom: 30px;
        }

        input[type="text"],
        input[type="email"],
        input[type="password"] {
            width: 100%;
            padding: 18px;
            margin: 14px 0;
            border-radius: 10px;
            border: 2px solid #f48fb1;
            box-sizing: border-box;
            font-size: 18px;
            transition: border 0.3s ease;
        }

        input[type="text"]:focus,
        input[type="email"]:focus,
        input[type="password"]:focus {
            border-color: #ec407a;
            outline: none;
        }

        button[type="submit"] {
            width: 100%;
            padding: 18px;
            background-color: #f48fb1;
            color: white;
            border: none;
            border-radius: 12px;
            font-size: 20px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }

        button[type="submit"]:hover {
            background-color: #ec407a;
        }

        .error-message {
            color: red;
            text-align: center;
            margin-top: 10px;
            font-size: 16px;
        }

        .register-link {
            display: block;
            text-align: center;
            margin-top: 20px;
            font-size: 18px;
        }

        .register-link a {
            color: #f48fb1;
            text-decoration: none;
        }

        .register-link a:hover {
            text-decoration: underline;
        }

        @media (max-width: 600px) {
            .login-container {
                width: 90%;
                padding: 30px;
            }

            h2 {
                font-size: 26px;
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Welcome Back!</h2>
        <?php if (isset($error)): ?>
            <!-- Escape error message to prevent XSS -->
            <div class="error-message"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        <form method="POST">
            <input type="email" name="email" placeholder="Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit" name="login">Login</button>
        </form>
        <div class="register-link">
            Don't have an account? <a href="register.php">Register</a>
        </div>
    </div>
</body>
</html>