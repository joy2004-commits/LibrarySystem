<?php
// dashboard.php: User dashboard for Library Management System
// Provides book management, borrowing, and a link to the feedback page
// Implements secure input sanitization, prepared statements, and session management

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

// Sanitize input to prevent XSS by removing tags, encoding special characters, and trimming whitespace
function sanitizeInput($input) {
    return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
}

// Generate CSRF token for form security
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Validate CSRF token
function validateCsrfToken() {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF token validation failed");
    }
}

// Handle book addition
if (isset($_POST['add_book'])) {
    validateCsrfToken();
    $title = sanitizeInput($_POST['title']);
    $author = sanitizeInput($_POST['author']);
    $isbn = sanitizeInput($_POST['isbn']);
    $quantity = filter_var($_POST['quantity'], FILTER_VALIDATE_INT);

    if ($quantity === false || $quantity < 0) {
        $error = "Invalid quantity";
    } else {
        try {
            $stmt = $pdo->prepare("INSERT INTO books (title, author, isbn, quantity) VALUES (?, ?, ?, ?)");
            $stmt->execute([$title, $author, $isbn, $quantity]);
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32)); // Regenerate CSRF token
        } catch (PDOException $e) {
            error_log("Book addition error: " . $e->getMessage());
            $error = "Failed to add book";
        }
    }
}

// Handle book borrowing
if (isset($_POST['borrow_book'])) {
    validateCsrfToken();
    $book_id = filter_var($_POST['book_id'], FILTER_VALIDATE_INT);
    $user_id = $_SESSION['user_id'];
    $issue_date = date('Y-m-d');

    if ($book_id === false) {
        $error = "Invalid book selection";
    } else {
        try {
            $stmt = $pdo->prepare("SELECT quantity FROM books WHERE id = ?");
            $stmt->execute([$book_id]);
            $book = $stmt->fetch();

            if ($book && $book['quantity'] > 0) {
                $stmt = $pdo->prepare("INSERT INTO issued_books (book_id, user_id, issue_date) VALUES (?, ?, ?)");
                $stmt->execute([$book_id, $user_id, $issue_date]);
                $stmt = $pdo->prepare("UPDATE books SET quantity = quantity - 1 WHERE id = ?");
                $stmt->execute([$book_id]);
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32)); // Regenerate CSRF token
            } else {
                $error = "Book not available";
            }
        } catch (PDOException $e) {
            error_log("Borrow error: " . $e->getMessage());
            $error = "Failed to borrow book";
        }
    }
}

// Handle book deletion
if (isset($_GET['delete_id'])) {
    $id = filter_var($_GET['delete_id'], FILTER_VALIDATE_INT);
    if ($id !== false) {
        try {
            $stmt = $pdo->prepare("DELETE FROM books WHERE id = ?");
            $stmt->execute([$id]);
            header("Location: dashboard.php");
            exit();
        } catch (PDOException $e) {
            error_log("Delete error: " . $e->getMessage());
            $error = "Failed to delete book";
        }
    }
}

// Fetch user
try {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch();
    if (!$user) {
        die("User not found");
    }
} catch (PDOException $e) {
    error_log("User fetch error: " . $e->getMessage());
    die("An error occurred");
}

// Fetch books
try {
    $books_stmt = $pdo->query("SELECT * FROM books");
    $books_result = $books_stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Books fetch error: " . $e->getMessage());
    die("An error occurred");
}

// Fetch borrow records
try {
    $records_stmt = $pdo->query("SELECT ib.id, b.title AS book_title, u.name AS borrower_name, 
                                 ib.issue_date AS borrow_date, ib.return_date 
                                 FROM issued_books ib 
                                 JOIN books b ON ib.book_id = b.id 
                                 JOIN users u ON ib.user_id = u.id");
    $records_result = $records_stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Borrow records fetch error: " . $e->getMessage());
    die("An error occurred");
}

// Handle logout
if (isset($_POST['logout'])) {
    session_destroy();
    header("Location: login.php");
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard - Library Management System</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <h1>Library Management System</h1>
        <div class="header">
            <!-- Escape user name to prevent XSS -->
            <span>Welcome, <?php echo htmlspecialchars($user['name']); ?>!</span>
            <a href="feedback.php" style="color: #f48fb1; text-decoration: none; margin-left: 20px;">Submit Feedback</a>
            <form method="POST" style="display: inline;">
                <button type="submit" name="logout" style="background-color:rgb(235, 72, 153); color: white; border: none; padding: 10px 20px; font-weight: bold; border-radius: 5px; cursor: pointer;">Sign Out</button>
            </form>
        </div>

        <?php if (isset($error)): ?>
            <!-- Escape error message to prevent XSS -->
            <div style="color: red; text-align: center;"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <!-- Add Book Form -->
        <h2>Add New Book</h2>
        <form method="POST" class="book-form">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <input type="text" name="title" placeholder="Book Title" required>
            <input type="text" name="author" placeholder="Author" required>
            <input type="text" name="isbn" placeholder="ISBN" required>
            <input type="number" name="quantity" placeholder="Quantity" required>
            <button type="submit" name="add_book">Add Book</button>
        </form>

        <!-- Borrow Book Form -->
        <h2>Borrow a Book</h2>
        <form method="POST" class="book-form">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <select name="book_id" required>
                <option value="">Select a Book</option>
                <?php
                try {
                    $stmt = $pdo->query("SELECT id, title FROM books WHERE quantity > 0");
                    while ($book = $stmt->fetch(PDO::FETCH_ASSOC)) {
                        echo "<option value='{$book['id']}'>" . htmlspecialchars($book['title']) . "</option>";
                    }
                } catch (PDOException $e) {
                    error_log("Available books fetch error: " . $e->getMessage());
                    echo "<option value=''>Error loading books</option>";
                }
                ?>
            </select>
            <button type="submit" name="borrow_book">Borrow Book</button>
        </form>

        <!-- All Books Table -->
        <h2>All Books</h2>
        <table>
            <tr>
                <th>Title</th>
                <th>Author</th>
                <th>ISBN</th>
                <th>Quantity</th>
                <th>Actions</th>
            </tr>
            <?php foreach ($books_result as $book): ?>
                <tr>
                    <!-- Escape outputs to prevent XSS -->
                    <td><?php echo htmlspecialchars($book['title']); ?></td>
                    <td><?php echo htmlspecialchars($book['author']); ?></td>
                    <td><?php echo htmlspecialchars($book['isbn']); ?></td>
                    <td><?php echo $book['quantity']; ?></td>
                    <td>
                        <a href="edit_book.php?id=<?php echo $book['id']; ?>">Edit</a>
                        <a href="dashboard.php?delete_id=<?php echo $book['id']; ?>" 
                           onclick="return confirm('Are you sure?')">Delete</a>
                    </td>
                </tr>
            <?php endforeach; ?>
        </table>

        <!-- Borrow and Return Records -->
        <h2>Borrow and Return Records</h2>
        <table>
            <tr>
                <th>Book</th>
                <th>Borrower</th>
                <th>Borrow Date</th>
                <th>Return Date</th>
                <th>Actions</th>
            </tr>
            <?php foreach ($records_result as $record): ?>
                <tr>
                    <!-- Escape outputs to prevent XSS -->
                    <td><?php echo htmlspecialchars($record['book_title']); ?></td>
                    <td><?php echo htmlspecialchars($record['borrower_name']); ?></td>
                    <td><?php echo htmlspecialchars($record['borrow_date']); ?></td>
                    <td><?php echo $record['return_date'] ?: '-'; ?></td>
                    <td>
                        <?php if (!$record['return_date']): ?>
                            <a href="return_book.php?id=<?php echo $record['id']; ?>">Mark Returned</a>
                        <?php else: ?>
                            <span>Returned</span>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
        </table>
    </div>
</body>
</html>