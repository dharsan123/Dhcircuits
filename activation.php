<?php
session_start();

// Check if the user is logged in (by checking if 'uid' exists in the session)
if (!isset($_SESSION['uid'])) {
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

// Include the database connection
require_once 'db_connection.php';

// Get the logged-in user's information
$uid = $_SESSION['uid']; // Get the logged-in user's UID

// Get the user's current information from the database
$stmt = $pdo->prepare("SELECT * FROM Users WHERE uid = :uid");
$stmt->execute(['uid' => $uid]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user) {
    echo "User not found!";
    exit;
}

// Check if the user is a new user (NewUser = true and Active = false)
$is_new_user = ($user['NewUser'] == 1 && $user['Active'] == 0);

// Handle form submission to update the user's username and password
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['update_user'])) {
    // Sanitize and validate user inputs to prevent XSS and ensure data integrity
    $new_username = htmlspecialchars(trim($_POST['username']), ENT_QUOTES, 'UTF-8');
    $new_password = htmlspecialchars(trim($_POST['password']), ENT_QUOTES, 'UTF-8');

    // Ensure the new username and password are not empty
    if (empty($new_username) || empty($new_password)) {
        $message = "Username and Password are required fields!";
        $status = 'error';
    } else {
        // Hash the password before storing it in the database
        $hashed_password = password_hash($new_password, PASSWORD_BCRYPT);

        // Check if the new username already exists in the database
        $stmt = $pdo->prepare("SELECT * FROM Users WHERE Username = :username AND uid != :uid");
        $stmt->execute(['username' => $new_username, 'uid' => $uid]);
        if ($stmt->rowCount() > 0) {
            $message = "Username already exists.";
            $status = 'error';
        } else {
            try {
                // Update the user's username and password, and activate the account if it's a new user
                $stmt = $pdo->prepare("
                    UPDATE Users 
                    SET Username = :username, Password = :password, 
                        Active = 1, NewUser = 0 
                    WHERE uid = :uid
                ");
                $stmt->execute([
                    'username' => $new_username,
                    'password' => $hashed_password,
                    'uid' => $uid
                ]);

                // After successful update, display success message and hide the form
                $message = "Your account has been successfully activated and updated!";
                $status = 'success';
            } catch (PDOException $e) {
                $message = "Error: " . $e->getMessage();
                $status = 'error';
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Activate Account - DHCircuits</title>
    <link rel="stylesheet" href="activationstyle.css"> <!-- Optional, for styling -->
</head>
<body>
    <div class="main">
        <h2>Activate Your Account</h2>

        <!-- Display success or error messages -->
        <?php if (isset($message)): ?>
            <p style="color: <?php echo ($status == 'success') ? 'green' : 'red'; ?>;">
                <?php echo $message; ?>
            </p>
        <?php endif; ?>

        <!-- If account is activated, hide the form and show the link -->
        <?php if ($status == 'success'): ?>
            <p>Your account has been activated successfully!</p>
            <a href="welcome.php" class="button">Continue to Welcome Page</a>
        <?php else: ?>
            <!-- Activation Form (only shown if not activated) -->
            <form method="POST" action="activation.php">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" value="<?php echo htmlspecialchars($user['Username'], ENT_QUOTES, 'UTF-8'); ?>" required>

                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>

                <button type="submit" name="update_user">Update Account</button>
            </form>
        <?php endif; ?>

        <div>
            <a href="logout.php" class="button">Logout</a> <!-- Logout link -->
        </div>
    </div>
</body>
</html>
