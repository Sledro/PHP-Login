<?php
//Credit to https://www.wikihow.com/Create-a-Secure-Login-Script-in-PHP-and-MySQL for this login handing structure (Hihgly Modified)
include_once 'db-connect.php';
include_once 'functions.php';
 
sec_session_start(); // Our custom secure way of starting a PHP session.
 
if (isset($_POST['username'], $_POST['oldPassword'], $_POST['newPassword'],  $_POST['passwordConfirm'])) {

    $username = $_POST['username'];
    $oldPassword = $_POST['oldPassword']; 
    $newPassword = $_POST['newPassword']; 
    $passwordConfirm = $_POST['passwordConfirm']; 

 
  if (updatePassword($username, $oldPassword, $newPassword, $passwordConfirm, $conn) == 0) {
        // register success 
        header('Location: ../changePassword.php?error=9');
    } else  if(updatePassword($username, $oldPassword, $newPassword, $passwordConfirm, $conn) == 6){
        // register failed 
        header('Location: ../changePassword.php?error=6');
    } else  if(updatePassword($username, $oldPassword, $newPassword, $passwordConfirm, $conn) == 7){
        // register failed 
        header('Location: ../changePassword.php?error=7');
    }else  if(updatePassword($username, $oldPassword, $newPassword, $passwordConfirm, $conn) == 8){
        // register failed 
        header('Location: ../changePassword.php?error=8');
    }

} else {
    // The correct POST variables were not sent to this page. 
    echo 'Invalid Request';
}