<?php
//Credit to https://www.wikihow.com/Create-a-Secure-Login-Script-in-PHP-and-MySQL for this login handing structure (Hihgly Modified)
include_once 'db-connect.php';
include_once 'functions.php';
 
sec_session_start(); // Our custom secure way of starting a PHP session.
 
if (isset($_POST['username'], $_POST['password'], $_POST['passwordConfirm'])) {

    $username = $_POST['username'];
    $password = $_POST['password']; 
    $passwordConfirm = $_POST['passwordConfirm']; 

    if (register($username, $password, $passwordConfirm, $conn) == 0) {
        // register success 
        header('Location: ../membersArea.php');
    } else  if(register($username, $password, $passwordConfirm, $conn) == 3){
        // register failed 
        header('Location: ../register.php?error=3');
    } else  if(register($username, $password, $passwordConfirm, $conn) == 4){
        // register failed 
        header('Location: ../register.php?error=4');
    }else  if(register($username, $password, $passwordConfirm, $conn) == 5){
        // register failed 
        header('Location: ../registera.php?error=5');
    }

} else {
    // The correct POST variables were not sent to this page. 
    echo 'Invalid Request';
}