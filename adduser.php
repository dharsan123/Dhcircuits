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

// Include the database connection
require_once 'db_connection.php';

// Ensure only admin users can access the "Add User" page
if ($_SESSION['role'] !== 'admin') {
    // If not an admin, show a message and restrict access to the page
    echo "<p>You do not have permission to access this page.</p>";
    exit;
}

// Handle form submission to add a new user
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['add_user'])) {
    // Sanitize and validate user inputs to prevent XSS and ensure data integrity
    $new_username = htmlspecialchars(trim($_POST['username']), ENT_QUOTES, 'UTF-8');
    $new_password = htmlspecialchars(trim($_POST['password']), ENT_QUOTES, 'UTF-8');
    $new_fname = htmlspecialchars(trim($_POST['fname']), ENT_QUOTES, 'UTF-8');
    $new_lname = htmlspecialchars(trim($_POST['lname']), ENT_QUOTES, 'UTF-8');
    $new_email = htmlspecialchars(trim($_POST['email']), ENT_QUOTES, 'UTF-8');
    $new_tel = htmlspecialchars(trim($_POST['tel']), ENT_QUOTES, 'UTF-8');
    $new_mobile = htmlspecialchars(trim($_POST['mobile']), ENT_QUOTES, 'UTF-8');
    $new_role = htmlspecialchars(trim($_POST['role']), ENT_QUOTES, 'UTF-8');
    $new_active = 0; // Set Active to 0 for new user (inactive)
    $new_user_flag = 1; // Mark as a new user by default

    // Ensure required fields are not empty
    if (empty($new_username) || empty($new_password) || empty($new_fname) || empty($new_role)) {
        $message = "Username, First Name, and Role are required fields!";
        $status = 'error';
    } else {
        // Validate email format
        if (!empty($new_email) && !filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
            $message = "Invalid email format!";
            $status = 'error';
        } else {
            // Hash the password before storing it in the database
            $hashed_password = password_hash($new_password, PASSWORD_BCRYPT);

            // Check if username already exists
            $stmt = $pdo->prepare("SELECT * FROM Users WHERE Username = :username");
            $stmt->execute(['username' => $new_username]);
            if ($stmt->rowCount() > 0) {
                $message = "Username already exists.";
                $status = 'error';
            } else {
                // Insert new user into the database
                try {
                    $stmt = $pdo->prepare("
                        INSERT INTO Users (Username, Password, Fname, Lname, Active, Created, Email, Tel, Mobile, Role, NewUser)
                        VALUES (:username, :password, :fname, :lname, :active, NOW(), :email, :tel, :mobile, :role, :new_user)
                    ");
                    $stmt->execute([
                        'username' => $new_username,
                        'password' => $hashed_password,
                        'fname' => $new_fname,
                        'lname' => $new_lname,
                        'active' => $new_active,
                        'email' => $new_email,
                        'tel' => $new_tel,
                        'mobile' => $new_mobile,
                        'role' => $new_role,
                        'new_user' => $new_user_flag
                    ]);
                    $message = "User added successfully! The user is inactive until activated.";
                    $status = 'success';
                } catch (PDOException $e) {
                    $message = "Error: " . $e->getMessage();
                    $status = 'error';
                }
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
    <title>Add User - DHCircuits</title>
    <link rel="stylesheet" href="adduserstyle.css"> <!-- Optional, for styling -->
</head>
<body>
    <div class="main">    
        <div>
            <a href="welcome.php" class="button">Back to Welcome Page</a>
        </div>

        <!-- Add User Form (only for admin) -->
        <h2>Add New User</h2>
	<!-- Display success or error messages -->
        <?php if (isset($message)): ?>
            <p style="color: <?php echo ($status == 'success') ? 'green' : 'red'; ?>;">
                <?php echo $message; ?>
            </p>
        <?php endif; ?>
        <form method="POST" action="adduser.php">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required>

            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>

            <label for="fname">First Name:</label>
            <input type="text" id="fname" name="fname" required>

            <label for="lname">Last Name:</label>
            <input type="text" id="lname" name="lname">

            <label for="email">Email:</label>
            <input type="email" id="email" name="email">

            <label for="tel">Telephone:</label>
            <input type="text" id="tel" name="tel">

            <label for="mobile">Mobile:</label>
            <input type="text" id="mobile" name="mobile">

            <label for="role">Role:</label>
            <select id="role" name="role" required>
                <option value="user">User</option>
                <option value="admin">Admin</option>
            </select>

            <button type="submit" name="add_user">Add User</button>
        </form>

        <div>
            <a href="logout.php" class="button">Logout</a> <!-- Link to log out -->
        </div>
    </div>
</body>
</html>
