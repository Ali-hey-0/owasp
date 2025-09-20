<?php
session_start(); // Start the PHP session

// Set cookies
setcookie('user', 'Vorivex', time() + (86400 * 30), "/", '', false, true);
setcookie('email', 'aliheydari1381doc@gmail.com', time() + (86400 * 30), "/", '', false, false);

// Set session variables
$_SESSION['user'] = 'Vorivex';
$_SESSION['email'] = 'aliheydari1381doc@gmail.com';

// Preview cookies and session values
echo "<h3>Cookies:</h3>";
echo "User: " . ($_COOKIE['user'] ?? 'Not set') . "<br>";
echo "Email: " . ($_COOKIE['email'] ?? 'Not set') . "<br>";

echo "<h3>Session:</h3>";
echo "User: " . ($_SESSION['user'] ?? 'Not set') . "<br>";
echo "Email: " . ($_SESSION['email'] ?? 'Not set') . "<br>";
?>