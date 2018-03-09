<?php
unlockerCronJob($conn);
//Credit to https://www.wikihow.com/Create-a-Secure-Login-Script-in-PHP-and-MySQL for the secure session function (Slightly Modified)
//I could have jused used session_start() but this function is widely used and adds extra security.
function sec_session_start() {
    define("SECURE", FALSE); 
    $session_name = 'sec_session_id';   // Set a custom session name 
    $secure = SECURE;
    // This stops JavaScript being able to access the session id.
    $httponly = true;
    // Forces sessions to only use cookies.
    if (ini_set('session.use_only_cookies', 1) === FALSE) {
        header("Location: ../error.php?err=Could not initiate a safe session (ini_set)");
        exit();
    }
    // Gets current cookies params.
    $cookieParams = session_get_cookie_params();
    session_set_cookie_params($cookieParams["lifetime"], $cookieParams["path"], $cookieParams["domain"], $secure, $httponly);
    // Sets the session name to the one set above.
    session_name($session_name);
    session_start();            // Start the PHP session 
    session_regenerate_id();    // regenerated the session, delete the old one. 
}

function login($username, $password, $conn) {

    $username = preg_replace("/[^a-zA-Z0-9_\-]+/", "", $username); //XSS Security

    try{
        $stmt = $conn->prepare("SELECT username, password FROM users WHERE username=:username");
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
    }catch(PDOException $exception){ 
        logme($username,time(),"PDOException","SELECT username, password FROM users WHERE username=:username","Error", $exception);
    }
        if ($stmt->rowCount() > 0) {
        
            $hash=$result['password'];
    
            if (password_verify($password, $hash)) {
                                            
                $user_browser = $_SERVER['HTTP_USER_AGENT'];
                $_SESSION['username']=$result['username'];
                $_SESSION['login_string']=hash('sha512', $hash . $user_browser);

                $currTime = time();
                logme($username,time(),"Login","SELECT username, password FROM users WHERE username=:username","Success", "n/a");

                return true;
            } else {
                invlidLoginAttempt($username, $conn);
                return false; //Invalid Password
            }
        } else {
            invlidLoginAttempt($username, $conn);
            return false; //Username not found
        }
}

function invlidLoginAttempt($username, $conn) {

    try{
        $stmt = $conn->prepare("SELECT username FROM login_attempts WHERE username=:username");
        $stmt->bindParam(':username', $username);
        $stmt->execute();
    }catch(PDOException $exception){ 
        logme($username,time(),"PDOException","SELECT username FROM login_attempts WHERE username=:username","Error", $exception, "n/a");
    }
    logme($username,time(),"Login","SELECT username, password FROM users WHERE username=:username","Invalid","n/a");


    if ($stmt->rowCount() > 0) {
        $currtime = time();
        // Increment login attempt counter
        try{
            $stmt = $conn->prepare("UPDATE login_attempts SET attemptNo = attemptNo + 1, time = $currtime WHERE ( username = :username )");
            $stmt->bindParam(':username', $username);
            $stmt->execute();
        }catch(PDOException $exception){ 
            logme($username,time(),"PDOException","UPDATE login_attempts SET attemptNo = attemptNo + 1, time = $currtime WHERE ( username = :username )","Error", $exception, "n/a");
        }
    }else{
        $num=1;
        $currtime = time();
        // prepare sql and bind parameters
        try{
            $stmt = $conn->prepare("INSERT INTO login_attempts (username, time, attemptNo)
            VALUES (:username, :timenow, :attemptNo)");
            $stmt->bindParam(':username', $username);
            $stmt->bindParam(':timenow', $currtime);
            $stmt->bindParam(':attemptNo', $num);
            $stmt->execute();
        }catch(PDOException $exception){ 
            logme($username,time(),"PDOException","INSERT INTO login_attempts (username, time, attemptNo) VALUES (:username, :timenow, :attemptNo)","Error", $exception, "n/a");
        }
    }

}

function checkIfLockedOut($username, $conn) {

    try{
        $stmt = $conn->prepare("SELECT attemptNo FROM login_attempts WHERE username=:username");
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
    }catch(PDOException $exception){ 
        logme($username,time(),"PDOException","SELECT attemptNo FROM login_attempts WHERE username=:username","Error", $exception, "n/a");
    }
    
    if($result['attemptNo'] > 3){
        $true="true";
        return $true;
    }else{
        $false="false";
        return $false;
    }
} 

function unlockerCronJob($conn) {
    try{
        $unclockTime = time()-300;
        $stmt = $conn->prepare("UPDATE login_attempts SET attemptNo = 0 WHERE attemptNo>'3' AND time < $unclockTime");
        $stmt->execute();
    }catch(PDOException $exception){ 
        logme($username,time(),"PDOException","UPDATE login_attempts SET attemptNo = 0 WHERE attemptNo>'3' AND time < $unclockTime","Error", $exception, "n/a");
    }

} 

function isUserLoggedIn($username, $conn) {
    $user_browser = $_SERVER['HTTP_USER_AGENT'];

    try{
        $stmt = $conn->prepare("SELECT password FROM users WHERE username=:username");
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
    }catch(PDOException $exception){ 
        logme($username,time(),"PDOException","SELECT password FROM users WHERE username=:username","Error", $exception, "n/a");
    }
    $login_string=null;
    $login_string=hash('sha512', $result['password'] . $user_browser);


    $login_string_session=null;
    if(isset($_SESSION['login_string']))
        $login_string_session=$_SESSION['login_string'];

    if($login_string==$login_string_session && $username==$_SESSION['username']){
        return "true";
    }else{
        return "false";
    }

} 

function isValidUsername($username) {
    return preg_match("/[^a-zA-Z0-9]+/", $username);
}

function isValidPassword($password) {
    $uppercase = preg_match('@[A-Z]@', $password);
    $lowercase = preg_match('@[a-z]@', $password);
    $number    = preg_match('@[0-9]@', $password);
    
    if(!$uppercase || !$lowercase || !$number || strlen($password) < 8) {
        return 0;
    }else{
        return 1;
    }
}

function isValidDateOfBirth($dob){
    return preg_match("/^(\d{2})-(\d{2})-(\d{4})$/", $dob);
}

//Used to add a a user to the database. Input is sanitized before it gets here.
function register($username, $password, $passwordConfirm, $email, $dob, $conn){
    $error=false;
    if(isValidUsername($username)==1){
        $error=true;
        return "3";
    }
    if($password!=$passwordConfirm){
        $error=true;
        return "4";
    }
    if(isValidPassword($password)==0){
        $error=true;
        return "5";
    }
    if((!filter_var($email, FILTER_VALIDATE_EMAIL))){
        $error=true;
        return "10";
    }
    if(isValidDateOfBirth($dob)==0){
        $error=true;
        return "11";
    }
    
    //Check that username is not already in use, if it is return an error.
    try{
        $stmt = $conn->prepare("SELECT username FROM users WHERE username=:username");
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
    }catch(PDOException $exception){ 
        logme($username,time(),"PDOException","SELECT username FROM users WHERE username=:username","Error", $exception, "n/a");
    }

    if ($stmt->rowCount() > 0) {
        $error=true;
        return "12";
    }

    //If no errors, continue with registration 
    if($error==false){

        $options = ['cost' => 12];
        // prepare sql and bind parameters
        try{
            $stmt = $conn->prepare("INSERT INTO users (username, password, email, dob)
            VALUES (:username, :password, :email, :dob)");
            $stmt->bindParam(':username', $username);
            $stmt->bindParam(':password', password_hash($password, PASSWORD_DEFAULT, $options));
            $stmt->bindParam(':email', encrypt($email));
            $stmt->bindParam(':dob', encrypt($dob));
            $stmt->execute();    
        }catch(PDOException $exception){ 
            logme($username,time(),"INSERT INTO users (username, password, email, dob) VALUES (:username, :password, :email, :dob)","Error", $exception, "n/a");
        }
        return "0";
    }
}

function errorLogging($errorNum){
    $error="";
    if(isset($_GET["error"])){
        if($_GET["error"]=="1"){
            $username = preg_replace("/[^a-zA-Z0-9_\-]+/", "", $_GET['username']); //XSS Security
            $error='<div class="col-lg-12"><div class="alert alert-warning">The username <strong>'.$username.'</strong> & password combination cannot be authenticated at the moment. </strong></div>';
        }
        if($_GET["error"]=="2"){
            $username = preg_replace("/[^a-zA-Z0-9_\-]+/", "", $_GET['username']); //XSS Security
            $error='<div class="col-lg-12"><div class="alert alert-danger"><strong>The username <strong>'.$username.'</strong> has been locked out for too many failed login attempts! Please try again later.. </strong></div>';
        }
        if($_GET["error"]=="3"){
            $error='<div class="col-lg-12"><div class="alert alert-warning"><strong>The username you entered is invalid. Please use alphanumerical charaters only. </strong></div>';
        }
        if($_GET["error"]=="4"){
            $error='<div class="col-lg-12"><div class="alert alert-warning">Your passwords did not match.</div>';
        }
        if($_GET["error"]=="5"){
            $error='<div class="col-lg-12"><div class="alert alert-warning">Your passwords must meet the following criteria: </br></br>           
- Must be a minimum of 8 characters</br> 
-  Must contain at least 1 number</br> 
- Must contain at least one uppercase character</br> 
- Must contain at least one lowercase character</br></div>';
        }
        if($_GET["error"]=="6"){
            $error='<div class="col-lg-12"><div class="alert alert-warning">Your passwords did not match.</div>';
        }
        if($_GET["error"]=="7"){
            $error='<div class="col-lg-12"><div class="alert alert-warning">Your username was not found. Do not edit sessions.</div>';
        }
        if($_GET["error"]=="8"){
            $error='<div class="col-lg-12"><div class="alert alert-warning">You entered an incorrect old password.</div>';
        }
        if($_GET["error"]=="9"){
            $error='<div class="col-lg-12"><div class="alert alert-success">Your password has been updated.</div>';
        }
        if($_GET["error"]=="10"){
            $error='<div class="col-lg-12"><div class="alert alert-warning">You did not eneter a valid email.</div>';
        }
        if($_GET["error"]=="11"){
            $error='<div class="col-lg-12"><div class="alert alert-warning">You need to enter your date of birth in the format DD-MM-YYYY.</div>';
        }
        if($_GET["error"]=="12"){
            $error='<div class="col-lg-12"><div class="alert alert-warning">Sorry, that username is already in use.</div>';
        }
        return $error;
    }
}

function updatePassword($username, $oldPassword, $newPassword, $passwordConfirm, $conn){


    if($newPassword!=$passwordConfirm){
        return "6";
    }

    if(isValidPassword($newPassword)==0){
        return "5";
    }

    $options = ['cost' => 12];

    try{
        $stmt = $conn->prepare("SELECT username, password FROM users WHERE username=:username");
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
    }catch(PDOException $exception){ 
        logme($username,time(),"SELECT username, password FROM users WHERE username=:username","Error", $exception, "n/a");
    }

    if ($stmt->rowCount() > 0) {
    
        $hash=$result['password'];

        if (password_verify($oldPassword, $hash)) {

            // Increment login attempt counter
            try{
                $stmt = $conn->prepare("UPDATE users SET password=:newPassword WHERE username=:username ");
                $stmt->bindParam(':newPassword', password_hash($newPassword, PASSWORD_DEFAULT, $options));
                $stmt->bindParam(':username', $username);
                $stmt->execute();
            }catch(PDOException $exception){ 
                logme($username,time(),"SELECT username, password FROM users WHERE username=:username","Error", $exception, "n/a");
            }

            logme($username,time(),"Password Reset","UPDATE users SET password=:newPassword WHERE username=:username","Success", "n/a");

            return "0";
        }
        logme($username,time(),"Password Reset","UPDATE users SET password=:newPassword WHERE username=:username","Failed", "Old password not correct");
        return "8"; //Old password not correct //////error here, saying incorrect old password even tho its correct
    }else{
        logme($username,time(),"Password Reset","UPDATE users SET password=:newPassword WHERE username=:username","Failed - Username not found", "username not found");
        return "7"; //Usernae not found
    }
}


    function getUser($username, $conn){
        try{
            $username = preg_replace("/[^a-zA-Z0-9_\-]+/", "", $username); //XSS Security
            $stmt = $conn->prepare("SELECT * FROM users WHERE username=:username");
            $stmt->bindParam(':username', $username);
            $stmt->execute();
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
        }catch(PDOException $exception){ 
            logme($username,time(),"SELECT username, password FROM users WHERE username=:username","Error", $exception, "n/a");
        }
        return $result;
    }

//Modified version of encryption and decryption using OpenSLL below
//https://stackoverflow.com/questions/10916284/how-to-encrypt-decrypt-data-in-php


function encrypt($inputString){

    $encryption_key = "LIVERPOOLFC2018!";
    $iv = "LIVERPOOLFC2018!";

    $crypt = base64_encode( openssl_encrypt(
        pkcs7_pad($inputString, 16),    // Input String
        'AES-256-CBC',                  // cipher and mode
        $encryption_key,                // secret key
        0,                              // options (not used)
        $iv                             // initialisation vector
    ) );

    return $crypt;
}

function decrypt($inputString){
    $encryption_key = "LIVERPOOLFC2018!";
    $iv = "LIVERPOOLFC2018!";

    $crypt = openssl_decrypt( 
        base64_decode(pkcs7_pad($inputString, 16)),    // Input String
        'AES-256-CBC',                  // cipher and mode
        $encryption_key,                // secret key
        0,                              // options (not used)
        $iv                             // initialisation vector
    ); 

    return $crypt;
}

function pkcs7_pad($data, $size)
{
    $length = $size - strlen($data) % $size;
    return $data . str_repeat(chr($length), $length);
}

function logme($user,$timestamp,$action,$query,$result,$content){
    $file = fopen("./includes/log.csv", "a");
    $currTime = time();
    $line = encrypt($currTime) .  "," . encrypt($user) .  "," . encrypt($timestamp) .  "," . encrypt($action) .  "," . encrypt($query) .  "," . encrypt($result) . "," . encrypt($content) . PHP_EOL;
    fwrite($file, $line); # $line is an array of string values here
    fclose($file);
}

function readLog(){
    $csvFile = file("./includes/log.csv", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $csv = array_map('str_getcsv', $csvFile);
    return $csv;
}

function generateResetToken($conn, $username){
    $token= bin2hex(openssl_random_pseudo_bytes(16));

    // prepare sql and bind parameters
    try{
        $timestampr=time();
        $stmt = $conn->prepare("UPDATE users SET token = :token, tokenCreatedTimestamp=:timestampr WHERE username=:username");
         $stmt->bindParam(':username', $username);
        $stmt->bindParam(':token', $token);
        $stmt->bindParam(':timestampr', $timestampr);
        $stmt->execute();    
    }catch(PDOException $exception){ 
        logme($username,time(),"INSERT INTO users (token) VALUES (:token)","Error", $exception, "n/a");
    }
}

    function getResetToken($username, $conn){
        try{
            $username = preg_replace("/[^a-zA-Z0-9_\-]+/", "", $username); //XSS Security
            $stmt = $conn->prepare("SELECT * FROM users WHERE username=:username");
            $stmt->bindParam(':username', $username);
            $stmt->execute();
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
        }catch(PDOException $exception){ 
            logme($username,time(),"SELECT * FROM users WHERE username=:username","Error", $exception, "n/a");
        }
        return $result['token'];
    }

?> 