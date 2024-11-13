<?php
session_start();

// Generate a CSRF token if one doesn't exist
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32)); // Secure CSRF token generation
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DHCircuits Login</title>
    <link rel="stylesheet" href="loginstyle.css">
</head>
<body>
    <div class="main">
        <h1>DHCircuits Login</h1>
        <h3>Enter your login credentials</h3>

        <!-- Display login error message if any -->
        <?php
        if (isset($_SESSION['login_error']) && !empty($_SESSION['login_error'])) {
            echo '<p style="color: red;">' . htmlspecialchars($_SESSION['login_error'], ENT_QUOTES, 'UTF-8') . '</p>';
            unset($_SESSION['login_error']); // Clear the error after displaying
        }
        ?>

        <!-- Login Form -->
        <form name="form1" method="POST" action="user_login.php" id="form1">
            <!-- CSRF Token -->
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

            <div id="main_body" class="full-width">
                <!-- Username input -->
                <label for="usernameLogin">Username:</label>
                <input type="text" id="usernameLogin" name="pat_username" placeholder="Enter your Username" required>

                <!-- Password input -->
                <label for="passwordLogin">Password:</label>
                <input type="password" id="passwordLogin" name="pat_password" placeholder="Enter your Password" required>

                <div class="wrap">
                    <button type="submit" name="login_check">Login</button>
                </div>
            </div>
        </form>

        <!-- Go back button -->
        <p><input type="button" value="Go Back" onclick="history.back()"></p>

        <p>Not registered? Please contact us.</p>
    </div>
</body>
</html>
