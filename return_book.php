<?php
session_start([
    'cookie_lifetime' => 1800,
    'cookie_httponly' => true,
    'cookie_secure' => isset($_SERVER['HTTPS']),
]);

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

require_once 'db_connect.php';

if (isset($_GET['id'])) {
    $issue_id = $_GET['id'];
    $return_date = date('Y-m-d');
    
    // Update return_date in issued_books
    $stmt = $pdo->prepare("UPDATE issued_books SET return_date = ? WHERE id = ?");
    $stmt->execute([$return_date, $issue_id]);
    
    // Increment book quantity
    $stmt = $pdo->prepare("UPDATE books SET quantity = quantity + 1 
                           WHERE id = (SELECT book_id FROM issued_books WHERE id = ?)");
    $stmt->execute([$issue_id]);
    
    header("Location: dashboard.php");
    exit();
} else {
    header("Location: dashboard.php");
    exit();
}
