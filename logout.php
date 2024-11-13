<?php
session_start();

// Destroy the session to log the user out
session_unset();
session_destroy();

// Set a logout success message
$_SESSION['logout_message'] = 'You have successfully logged out.';

// Redirect to the login page
header("Location: login.php");
exit;
?>
