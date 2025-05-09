<?php
// db_connect.php: Centralized MySQL database connection for Library Management System
// Uses PDO with secure configuration to prevent SQL injection and ensure reliable database interactions

// Load environment variables for secure credential management
require_once 'vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

// Retrieve database credentials from .env file
$host = $_ENV['DB_HOST'] ?? 'localhost';
$dbname = $_ENV['DB_NAME'] ?? 'library';
$username = $_ENV['DB_USER'] ?? 'library_user';
$password = $_ENV['DB_PASS'] ?? 'secure_password';

try {
    // Initialize PDO connection with MySQL, using credentials from .env
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    
    // Enable exception-based error handling for robust error management
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Set default fetch mode to associative arrays for consistent data handling
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    
    // Disable emulated prepared statements to ensure true prepared statements, preventing SQL injection
    $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
} catch (PDOException $e) {
    // Log error to file in production to avoid exposing sensitive details
    error_log("Database connection failed: " . $e->getMessage());
    http_response_code(500);
    die("Internal server error. Please try again later.");
}
?>