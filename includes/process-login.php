<?php
include_once 'db-connect.php';
include_once 'functions.php';
 
sec_session_start(); // Our custom secure way of starting a PHP session.
 
if (isset($_POST['username'], $_POST['password'])) {
    $username = $_POST['username'];
    $password = $_POST['password']; // The hashed password.
 
    echo login($username, $password, $conn);

    /*if (login($email, $password, $conn) == true) {
        // Login success 
        header('Location: ../protected_page.php');
    } else {
        // Login failed 
        header('Location: ../index.php?error=1');
    }*/
} else {
    // The correct POST variables were not sent to this page. 
    echo 'Invalid Request';
}