<?php
//Credit to https://www.wikihow.com/Create-a-Secure-Login-Script-in-PHP-and-MySQL for this login handing structure (Hihgly Modified)
include_once 'db-connect.php';
include_once 'functions.php';
 
sec_session_start(); // Our custom secure way of starting a PHP session.
 
if (isset($_POST['username'], $_POST['password'])) {
    $username = $_POST['username'];
    $password = $_POST['password']; // The hashed password.
    $username = preg_replace("/[^a-zA-Z0-9_\-]+/", "", $username); //XSS Security

    $login=login($username, $password, $conn);

    if ($login == "0") {
        // Login success 
        header('Location: ../membersArea.php');
    } else  if ($login == "1") {
        // Login failed 
        header('Location: ../index.php?error=1&username='.$username);
    }else {
        header('Location: ../index.php?error=2&username='.$username);
    }
} else {
    // The correct POST variables were not sent to this page. 
    echo 'Invalid Request';
}

