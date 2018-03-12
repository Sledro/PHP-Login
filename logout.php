<?php

//Credit to https://www.wikihow.com/Create-a-Secure-Login-Script-in-PHP-and-MySQL for how to destroy the session
include_once 'includes/db-connect.php';
include_once './includes/functions.php';
sec_session_start();
 


if(isset($_SESSION['uid'])){
        $uid = preg_replace("/[^0-9]/", "", $_SESSION['uid']); //XSS Security
        logme($uid,time(),"Logout","Success", $exception, "n/a");
        }


// Unset all session values 
$_SESSION = array();
 
// get session parameters 
$params = session_get_cookie_params();
 
// Delete the actual cookie. 
setcookie(session_name(),
        '', time() - 42000, 
        $params["path"], 
        $params["domain"], 
        $params["secure"], 
        $params["httponly"]);
 
// Destroy session 
session_destroy();

header('Location: ./index.php');