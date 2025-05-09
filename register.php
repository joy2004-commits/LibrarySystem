<?php
// register.php: User registration page for Library Management System
// Implements secure password hashing, input sanitization, and password strength validation

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

// Validate password strength to ensure secure passwords
function checkPasswordStrength($password) {
    if (strlen($password) < 8) {
        return ["strength" => "Weak", "message" => "Password must be at least 8 characters"];
    }
    if (!preg_match("/[A-Z]/", $password)) {
        return ["strength" => "Weak", "message" => "Password must contain at least one uppercase letter"];
    }
    if (!preg_match("/[0-9]/", $password)) {
        return ["strength" => "Weak", "message" => "Password must contain at least one number"];
    }
    if (!preg_match("/[!@#$%^&*()_+\-=\[\]{};:'\",.<>?]/", $password)) {
        return ["strength" => "Weak", "message" => "Password must contain at least one special character"];
    }
    return ["strength" => "Strong", "message" => "Password is strong"];
}

if (isset($_POST['register'])) {
    // Sanitize name and email inputs to prevent XSS
    $name = sanitizeInput($_POST['name']);
    $email = sanitizeInput($_POST['email']);
    $password = $_POST['password']; // Password is not sanitized as it's hashed

    if (empty($name) || empty($email) || empty($password)) {
        $error = "All fields are required";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Invalid email format";
    } else {
        $strength = checkPasswordStrength($password);
        if ($strength['strength'] !== "Strong") {
            $error = $strength['message'];
        } else {
            try {
                // Check for existing email using prepared statement to prevent SQL injection
                $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
                $stmt->execute([$email]);
                if ($stmt->fetch()) {
                    $error = "Email already registered";
                } else {
                    // Hash password using bcrypt for secure storage (adaptive hashing with salt)
                    $passwordHash = password_hash($password, PASSWORD_BCRYPT);
                    
                    // Insert user data using prepared statement
                    $stmt = $pdo->prepare("INSERT INTO users (name, email, password_hash, last_ip) VALUES (?, ?, ?, ?)");
                    $stmt->execute([$name, $email, $passwordHash, $_SERVER['REMOTE_ADDR']]);
                    $success = "Registration successful! Please log in.";
                }
            } catch (PDOException $e) {
                // Log database errors in production
                error_log("Registration error: " . $e->getMessage());
                $error = "An error occurred. Please try again.";
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>Register - Library System</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet"/>
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
            max-width: 600px;
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

        input:focus {
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

        .strength-bar {
            height: 8px;
            border-radius: 6px;
            transition: width 0.3s ease, background-color 0.3s ease;
        }
    </style>
    <script>
        // Client-side password strength validation for immediate user feedback
        function checkPasswordStrength() {
            const password = document.getElementById('password').value;
            const bar = document.getElementById('strength-bar');
            const text = document.getElementById('password-strength');

            if (password.length === 0) {
                bar.style.width = '0%';
                bar.className = 'strength-bar';
                text.textContent = '';
                return;
            }

            if (password.length < 8) {
                bar.style.width = '33%';
                bar.className = 'strength-bar bg-red-500';
                text.textContent = 'Weak: At least 8 characters required';
                text.className = 'text-red-500 text-sm mt-1';
            } else if (!/[A-Z]/.test(password)) {
                bar.style.width = '33%';
                bar.className = 'strength-bar bg-red-500';
                text.textContent = 'Weak: Include an uppercase letter';
                text.className = 'text-red-500 text-sm mt-1';
            } else if (!/[0-9]/.test(password)) {
                bar.style.width = '66%';
                bar.className = 'strength-bar bg-yellow-500';
                text.textContent = 'Medium: Include a number';
                text.className = 'text-yellow-500 text-sm mt-1';
            } else if (!/[!@#$%^&*()_+\-=\[\]{};:'\",.<>?]/.test(password)) {
                bar.style.width = '66%';
                bar.className = 'strength-bar bg-yellow-500';
                text.textContent = 'Medium: Include a special character';
                text.className = 'text-yellow-500 text-sm mt-1';
            } else {
                bar.style.width = '100%';
                bar.className = 'strength-bar bg-green-500';
                text.textContent = 'Strong password';
                text.className = 'text-green-500 text-sm mt-1';
            }
        }
    </script>
</head>
<body>
    <div class="login-container">
        <h2><b>Register</b></h2>

        <?php if (isset($error)): ?>
            <!-- Escape error message to prevent XSS -->
            <div class="error-message"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        <?php if (isset($success)): ?>
            <!-- Escape success message to prevent XSS -->
            <div class="text-green-600 text-center mb-4 font-semibold"><?php echo htmlspecialchars($success); ?></div>
        <?php endif; ?>

        <form method="POST">
            <input type="text" name="name" placeholder="Full Name" required />
            <input type="email" name="email" placeholder="Email Address" required />
            <input type="password" name="password" id="password" placeholder="Password" onkeyup="checkPasswordStrength()" required />
            <div class="mt-2 mb-4">
                <div id="strength-bar" class="strength-bar"></div>
                <p id="password-strength"></p>
            </div>
            <button type="submit" name="register">Register</button>
        </form>
        <div class="register-link">
            Already have an account? <a href="login.php">Login</a>
        </div>
    </div>
</body>
</html>