<?php
// db_connection.php

$host = 'homeassistant';
$dbname = 'homeassistant';    
$dbusername = 'homeassistant'; 
$dbpassword = 'Hnkw3bS170690'; 
$charset = 'utf8mb4'; 


// Use TCP/IP connection to MariaDB
$dsn = "mysql:host=$host;port=3306;dbname=$dbname;charset=$charset";  // TCP/IP connection string

// PDO options for error handling and optimized queries
$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,   // Enable exceptions for PDO errors
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, // Fetch associative arrays by default
    PDO::ATTR_EMULATE_PREPARES => false,            // Disable emulation of prepared statements for better security
];

try {
    // Attempt to create a new PDO instance
    $pdo = new PDO($dsn, $dbusername, $dbpassword, $options);

    // Optional: You can log successful connection or just test it
    // echo "Database connected successfully!"; // Comment out for production environment

} catch (PDOException $e) {
    // Log the error message for debugging purposes
    error_log('Connection failed: ' . $e->getMessage());

    // Show a generic error message for the user and stop script execution
    echo 'Database connection failed. Please try again later.';
    die(); // Terminate script execution after error output
}
?>