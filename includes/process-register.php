<?php
//Credit to https://www.wikihow.com/Create-a-Secure-Login-Script-in-PHP-and-MySQL for this login handing structure (Hihgly Modified)
include_once 'db-connect.php';
include_once 'functions.php';
 
sec_session_start(); // Our custom secure way of starting a PHP session.
 
if (isset($_POST['username'], $_POST['password'], $_POST['passwordConfirm'])) {

    $username = $_POST['username'];
    $password = $_POST['password']; 
    $passwordConfirm = $_POST['passwordConfirm']; 
    $email = $_POST['email'];
    $dob = $_POST['dob']; 

    if (register($username, $password, $passwordConfirm, $email, $dob, $conn) == 0) {
        // register success 
        header('Location: ../membersArea.php');
    } else  if(register($username, $password, $passwordConfirm, $email, $dob, $conn) == 3){
        // register failed 
        header('Location: ../register.php?error=3');
    } else  if(register($username, $password, $passwordConfirm, $email, $dob, $conn) == 4){
        // register failed 
        header('Location: ../register.php?error=4');
    }else  if(register($username, $password, $passwordConfirm, $email, $dob, $conn) == 5){
        // register failed 
        header('Location: ../register.php?error=5');
    }else  if(register($username, $password, $passwordConfirm, $email, $dob, $conn) == 10){
        // register failed 
        header('Location: ../register.php?error=10');
    }else  if(register($username, $password, $passwordConfirm, $email, $dob, $conn) == 11){
        // register failed 
        header('Location: ../register.php?error=11');
    }else  if(register($username, $password, $passwordConfirm, $email, $dob, $conn) == 12){
        // register failed 
        header('Location: ../register.php?error=12');
    }

} else {
    // The correct POST variables were not sent to this page. 
    echo 'Invalid Request';
}