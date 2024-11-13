<?php
session_start();

// Check if the form is submitted via POST
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $_SESSION['login_error'] = "Invalid CSRF token.";
        header("Location: login.php");
        exit;
    }

    // Sanitize and validate user input to prevent XSS
    $username = htmlspecialchars(trim($_POST['pat_username']), ENT_QUOTES, 'UTF-8');
    $password = htmlspecialchars(trim($_POST['pat_password']), ENT_QUOTES, 'UTF-8');

    // If username or password is empty
    if (empty($username) || empty($password)) {
        $_SESSION['login_error'] = "Username and password are required.";
        header("Location: login.php");
        exit;
    }

    // Include database connection
    require_once 'db_connection.php';

    try {
        // Prepare SQL statement to fetch user data, using a parameterized query (prevents SQL injection)
        $stmt = $pdo->prepare("SELECT UID, Username, Password, Role, NewUser, Active FROM Users WHERE Username = :username");
        $stmt->execute(['username' => $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        // Check if the user exists and password is correct
        if ($user && password_verify($password, $user['Password'])) {
            // Regenerate session ID to prevent session fixation attacks
            session_regenerate_id(true);

            // Set session variables for user information
            $_SESSION['uid'] = $user['UID'];
            $_SESSION['username'] = $user['Username'];
            $_SESSION['role'] = $user['Role']; // Store the user's role

            // Check if the user is a new user or an existing user
            if ($user['NewUser'] == 1 && $user['Active'] == 0) {
                // Redirect new users to the activation page
                header("Location: activation.php");
                exit;
            } else {
                // Redirect existing users to the welcome page
                header("Location: welcome.php");
                exit;
            }

        } else {
            // Invalid login attempt
            $_SESSION['login_error'] = "Invalid username or password.";
            header("Location: login.php");
            exit;
        }
    } catch (PDOException $e) {
        // Database error handling
        $_SESSION['login_error'] = "There was an issue with the login process. Please try again later.";
        header("Location: login.php");
        exit;
    }
} else {
    // Redirect if the form wasn't submitted via POST
    $_SESSION['login_error'] = "Invalid request method.";
    header("Location: login.php");
    exit;
}
