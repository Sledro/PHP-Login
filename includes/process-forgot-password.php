<?php
//Credit to https://www.wikihow.com/Create-a-Secure-Login-Script-in-PHP-and-MySQL for this login handing structure (Hihgly Modified)
include_once 'db-connect.php';
include_once 'functions.php';
 
sec_session_start(); // Our custom secure way of starting a PHP session.
 
if (isset($_POST['username'], $_POST['email'], $_POST['dob'] , $_POST['newPassword'],  $_POST['passwordConfirm'], $_POST['token'])) {

    $token = $_POST['token'];
    $username = $_POST['username'];
    $email = $_POST['email']; 
    $dob = $_POST['dob']; 
    $newPassword = $_POST['newPassword']; 
    $passwordConfirm = $_POST['passwordConfirm']; 

    //echo updatePassword($username, $oldPassword, $newPassword, $passwordConfirm, $conn);
 
    if (updatePassword($username, $email, $dob, $newPassword, $passwordConfirm, $token, $conn) == 0) {
        // register success 
        header('Location: ../forgotPassword.php?error=9');
    } else  if(updatePassword($username, $email, $dob, $newPassword, $passwordConfirm, $token, $conn) == 6){
        // register failed 
        header('Location: ../forgotPassword.php?error=6');
    } else  if(updatePassword($username, $email, $dob, $newPassword, $passwordConfirm, $token, $conn) == 7){
        // register failed 
        header('Location: ../forgotPassword.php?error=7');
    }else  if(updatePassword($username, $email, $dob, $newPassword, $passwordConfirm, $token, $conn) == 8){
        // register failed 
        header('Location: ../forgotPassword.php?error=8');
    }else  if(updatePassword($username, $email, $dob, $newPassword, $passwordConfirm, $token, $conn) == 5){
        // register failed 
        header('Location: ../forgotPassword.php?error=5');
    }else  if(updatePassword($username, $email, $dob, $newPassword, $passwordConfirm, $token, $conn) == 13){
            // register failed 
            header('Location: ../forgotPassword.php?error=13');
    }else  if(updatePassword($username, $email, $dob, $newPassword, $passwordConfirm, $token, $conn) == 14){
        // register failed 
        header('Location: ../forgotPassword.php?error=14');
    }else  if(updatePassword($username, $email, $dob, $newPassword, $passwordConfirm, $token, $conn) == 15){
        // register failed 
        header('Location: ../forgotPassword.php?error=15');
    }else  if(updatePassword($username, $email, $dob, $newPassword, $passwordConfirm, $token, $conn) == 16){
        // register failed 
        header('Location: ../forgotPassword.php?error=16');
    }

} else {
    // The correct POST variables were not sent to this page. 
    echo 'Invalid Request';
}