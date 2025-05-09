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

$id = $_GET['id'];
$stmt = $pdo->prepare("SELECT * FROM books WHERE id = ?");
$stmt->execute([$id]);
$book = $stmt->fetch();

if (isset($_POST['update_book'])) {
    $title = $_POST['title'];
    $author = $_POST['author'];
    $isbn = $_POST['isbn'];
    $quantity = $_POST['quantity'];
    
    $stmt = $pdo->prepare("UPDATE books SET title = ?, author = ?, isbn = ?, quantity = ? WHERE id = ?");
    $stmt->execute([$title, $author, $isbn, $quantity, $id]);
    header("Location: dashboard.php");
    exit();
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Edit Book</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <h1>Edit Book</h1>
        <form method="POST" class="book-form">
            <input type="text" name="title" value="<?php echo htmlspecialchars($book['title']); ?>" required>
            <input type="text" name="author" value="<?php echo htmlspecialchars($book['author']); ?>" required>
            <input type="text" name="isbn" value="<?php echo htmlspecialchars($book['isbn']); ?>" required>
            <input type="number" name="quantity" value="<?php echo $book['quantity']; ?>" required>
            <button type="submit" name="update_book">Update Book</button>
        </form>
        <a href="dashboard.php">Back to Dashboard</a>
    </div>
</body>
</html>
