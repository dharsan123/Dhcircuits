<?php
session_start();

// Check if the user is logged in (by checking if 'user_id' exists in the session)
if (!isset($_SESSION['user_id'])) {
    // If not logged in, redirect to the login page
    header("Location: login.php");
    exit;
}

// Optional: Implement session timeout (e.g., log out after 30 minutes of inactivity)
$inactive_limit = 1800; // 30 minutes (in seconds)
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $inactive_limit) {
    session_unset();
    session_destroy();
    header("Location: login.php?timeout=1");
    exit;
}

// Update last activity timestamp
$_SESSION['last_activity'] = time();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to DHCircuits</title>
    <link rel="stylesheet" href="style.css"> <!-- Optional, for styling -->
</head>
<body>
    <div class="main">
        <h1>Welcome to DHCircuits, <?php echo htmlspecialchars($_SESSION['username'], ENT_QUOTES, 'UTF-8'); ?>!</h1>

        <!-- Display button to add user if the user is an admin -->
        <?php if ($_SESSION['role'] === 'admin'): ?>
            <div>
                <a href="adduser.php" class="button">Add User</a>
            </div>
        <?php else: ?>
            <p>You do not have permission to add users.</p>
        <?php endif; ?>

        <div>
            <a href="logout.php" class="button">Logout</a> <!-- Link to log out -->
        </div>
    </div>
</body>
</html>
