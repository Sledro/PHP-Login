<?php
//Credit to https://www.wikihow.com/Create-a-Secure-Login-Script-in-PHP-and-MySQL for this login handing structure (Hihgly Modified)
include_once 'db-connect.php';
include_once 'functions.php';
 
sec_session_start(); // Our custom secure way of starting a PHP session.
 
if (isset($_POST['username'], $_POST['password'], $_POST['passwordConfirm'])) {

    $username = $_POST['username'];
    $password = $_POST['password']; 
    $passwordConfirm = $_POST['passwordConfirm']; 

    if($password==$passwordConfirm){

        if(isValidUsername($username)==0){

            if(isValidPassword($password)==0){

                if (register($username, $password, $passwordConfirm, $conn) == true) {
                    // register success 
                    header('Location: ../membersArea.php');
                } else {
                    // register failed 
                    header('Location: ../index.php?error=1&username='.$username);
                }

             }else{
            // password failed 
            header('Location: ../index.php?error=5');     
             }
        }else{
            // register failed 
            header('Location: ../index.php?error=3');     
        }
    }else{
        // confirm password failed
        header('Location: ../index.php?error=4');          
    }
} else {
    // The correct POST variables were not sent to this page. 
    echo 'Invalid Request';
}