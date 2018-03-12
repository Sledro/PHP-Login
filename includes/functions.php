<?php
/**
 * Functions.php
 *
 * This file contains all of my php functions that are used throught
 * this project. This file in included in many other php files in 
 * also included in this project.
 *
 * @Student #  C00137009
 * @copyright  2018 Daniel Hayden
 * @version    Release: 1.0
 */ 


expireOutdatedTokensCronJob($conn);

/**
 * I could have jused used session_start() but this function is widely used and adds extra security.
 * 
 * @author https://www.wikihow.com/Create-a-Secure-Login-Script-in-PHP-and-MySQL
 */ 
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
    $username_c = encrypt($username);

    try{
        $stmt = $conn->prepare("SELECT * FROM users WHERE username=:username");
        $stmt->bindParam(':username', $username_c);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
    }catch(PDOException $exception){ 
        logme($result['uid'],time(),"PDOException","SELECT * FROM users WHERE username=:username","Error", $exception);
    }


    if ($stmt->rowCount() > 0) {
         if(checkIfLockedOut($result['uid'],$conn)==0){
       
            $hash=$result['password'];
    
            if (password_verify($password, $hash)) {
                                            
                $user_browser = $_SERVER['HTTP_USER_AGENT'];
                $_SESSION['uid']=$result['uid'];
                $_SESSION['login_string']=hash('sha512', $hash . $user_browser);

                $currTime = time();
                logme($result['uid'],time(),"Login","SELECT username, password FROM users WHERE username=:username","Success", "n/a");

                return "0";

            }else{
                logme($result['uid'],time(),"Login","N/A","Error", "Invalid Password", "n/a");
                invlidLoginAttempt($result['uid'], $conn);
                return "1"; //Invalid Password
            }
        } else {
            logme($result['uid'],time(),"Login","N/A","Error", "Locked Out", "n/a");
            invlidLoginAttempt($result['uid'], $conn);
            return "2"; //Locked out
        }
    } else {
        logme($result['uid'],time(),"Login","N/A","Error", "Username not found", "Not found");
        return "1"; //Username not found
    }
}

function invlidLoginAttempt($uid, $conn) {

        // prepare sql and bind parameters
        try{
            $stmt = $conn->prepare("INSERT INTO login_attempts (uid, time) VALUES (:uid, :timenow)");
            $stmt->bindParam(':uid', $uid);
            $stmt->bindParam(':timenow', time());
            $stmt->execute();
        }catch(PDOException $exception){ 
            logme($uid,time(),"PDOException","INSERT INTO login_attempts (uid, time) VALUES (:uid, :timenow)","Error", $exception, "n/a");
        }
}

function checkIfLockedOut($uid, $conn) {
        try{
            $stmt = $conn->prepare("SELECT time FROM login_attempts WHERE uid=:uid ORDER BY time DESC LIMIT 5");
            $stmt->bindParam(':uid', $uid);
            $stmt->execute();
            $result = $stmt->fetchAll();
        }catch(PDOException $exception){ 
            logme($uid,time(),"PDOException","SELECT attemptNo FROM login_attempts WHERE uid=:uid","Error", $exception, "n/a");
        }
     
        if($result[4][0]!=""){
        $answer=$result[0][0]-$result[4][0];
     
        if($answer < 300){
            return 1;
        }else{
            return 0;
        }
    }else{
        return 0;
    }
} 


function isUserLoggedIn($uid, $conn) {
    $user_browser = $_SERVER['HTTP_USER_AGENT'];

    try{
        $stmt = $conn->prepare("SELECT password FROM users WHERE uid=:uid");
        $stmt->bindParam(':uid', $uid);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
    }catch(PDOException $exception){ 
        logme($username,time(),"PDOException","SELECT password FROM users WHERE uid=:uid","Error", $exception, "n/a");
    }
    $login_string=null;
    $login_string=hash('sha512', $result['password'] . $user_browser);


    $login_string_session=null;
    if(isset($_SESSION['login_string']))
        $login_string_session=$_SESSION['login_string'];

    if($login_string==$login_string_session && $uid==$_SESSION['uid']){
        return "true";
    }else{
        return "false";
    }

} 

function isValidUsername($username) {
    return preg_match("/[^a-zA-Z0-9]+/", $username);
}

//Password complexity as per https://technet.microsoft.com/en-us/library/cc786468(v=ws.10).aspx
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
        $stmt->bindParam(':username', decrypt($username));
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
    }catch(PDOException $exception){ 
        logme($result['uid'],time(),"PDOException","SELECT username FROM users WHERE username=:username","Error", $exception, "n/a");
    }

    if ($stmt->rowCount() > 0) {
        $error=true;
        return "12";
    }

    //Check that email is not already in use, if it is return an error.
    try{
        $stmt = $conn->prepare("SELECT username FROM users WHERE email=:email");
        $stmt->bindParam(':username', decrypt($username));
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
    }catch(PDOException $exception){ 
        logme($result[uid],time(),"PDOException","SELECT username FROM users WHERE email=:email","Error", $exception, "n/a");
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
            $stmt->bindParam(':username', encrypt($username));
            $stmt->bindParam(':password', password_hash($password, PASSWORD_DEFAULT, $options));
            $stmt->bindParam(':email', encrypt($email));
            $stmt->bindParam(':dob', encrypt($dob));
            $stmt->execute();    
        }catch(PDOException $exception){ 
            logme($username,time(),"INSERT INTO users (username, password, email, dob)
            VALUES (:username, :password, :email, :dob)","Error", $exception, "n/a");
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
            $error='<div class="col-lg-12"><div class="alert alert-warning">Email entered did not match records.</div>';
        }
        if($_GET["error"]=="9"){
            $error='<div class="col-lg-12"><div class="alert alert-success">Your password has been updated. Click <a href="./index.php">HERE</a> to login. </div>';
        }
        if($_GET["error"]=="10"){
            $error='<div class="col-lg-12"><div class="alert alert-warning">You did not eneter a valid email.</div>';
        }
        if($_GET["error"]=="11"){
            $error='<div class="col-lg-12"><div class="alert alert-warning">You need to enter your date of birth in the format DD-MM-YYYY.</div>';
        }
        if($_GET["error"]=="12"){
            $error='<div class="col-lg-12"><div class="alert alert-warning">Sorry, that username OR email is already in use.</div>';
        }
        if($_GET["error"]=="13"){
            $error='<div class="col-lg-12"><div class="alert alert-warning">Sorry, you entered an invalid token.</div>';
        }
        if($_GET["error"]=="14"){
            $error='<div class="col-lg-12"><div class="alert alert-warning">Sorry, that token has expired, please request a new token.</div>';
        }
        if($_GET["error"]=="15"){
            $error='<div class="col-lg-12"><div class="alert alert-warning">Sorry, the date of birth you entered did not match our records.</div>';
        }
        if($_GET["error"]=="16"){
            $error='<div class="col-lg-12"><div class="alert alert-warning">Sorry, that password contained your username, this is not allowed.</div>';
        }
        return $error;
    }
}

function updatePassword($username, $email, $dob, $newPassword, $passwordConfirm, $token, $conn){


    if($newPassword!=$passwordConfirm){
        return "6";
    }

    if(isValidPassword($newPassword)==0){
        return "5";
    }



    //echo $token;
    $options = ['cost' => 12];

    $result=getUserFromEmail($email,$conn);

    if($result['uid']==""){
        logme("n/a",time(),"Password Reset","n/a","Failed", "Username with that email not found");
        return "8";
    }

    if(getResetToken($result['uid'], $conn)!=$token){
        logme($result['uid'],time(),"Password Reset","n/a","Failed", "Invalid Token entered");
        return "13";
    }

    if(isResetTokenExpired($result['uid'], $conn)==1){
        logme($result['uid'],time(),"Password Reset","n/a","Failed", "Token is expired");
        return "14";
    }

    if ($result) {

        $decryptedRemovePadding = preg_replace('/[\x00-\x1F\x7F-\xFF]/', '', decrypt($result['email']));
        $decryptedRemovePadding2 = preg_replace('/[\x00-\x1F\x7F-\xFF]/', '', decrypt($result['dob']));

        if(checkUsernameNotInPass(decrypt($result['username']),$newPassword,$conn)===true){
            logme($result['uid'],time(),"Password Reset","n/a","Failed", "Username contained in password");
            return "16";
        }

        if ($email==$decryptedRemovePadding) {

            if ($dob==  $decryptedRemovePadding2 ) {
                    // Increment login attempt counter
                    try{
                        $stmt = $conn->prepare("UPDATE users SET password=:newPassword WHERE username=:username");
                        $stmt->bindParam(':newPassword', password_hash($newPassword, PASSWORD_DEFAULT, $options));
                        $stmt->bindParam(':username', $username);
                        $stmt->execute();
                    }catch(PDOException $exception){ 
                        logme($result['uid'],time(),"UPDATE users SET password=:newPassword WHERE username=:username","Error", $exception, "n/a");
                    }

                    try{
                        $stmt = $conn->prepare("UPDATE users SET tokenExpired='1' WHERE username=:username");
                        $stmt->bindParam(':username', $username);
                        $stmt->execute();
                    }catch(PDOException $exception){ 
                        logme($result['uid'],time(),"PDOException","UPDATE users SET tokenExpired='1' WHERE username=:username","Error", $exception, "n/a");
                    }

                    logme($result['uid'],time(),"Password Reset","UPDATE users SET password=:newPassword WHERE username=:username","Success", "n/a");

                    return "0";
                }else{
                    logme($result['uid'],time(),"Password Reset","UPDATE users SET password=:newPassword WHERE username=:username","Failed", "DOB entered did not match records.");
                    return "15"; //DOB entered did not match records
                }
        }
        logme($result['uid'],time(),"Password Reset","UPDATE users SET password=:newPassword WHERE username=:username","Failed", "Email entered did not match records.");
        return "8"; //Email entered did not match records.
    }else{
        logme($result['uid'],time(),"Password Reset","UPDATE users SET password=:newPassword WHERE username=:username","Failed - Username not found", "username not found");
        return "7"; //Usernae not found
    }
}

    function getUser($uid, $conn){
        try{
            $stmt = $conn->prepare("SELECT * FROM users WHERE uid=:uid");
            $stmt->bindParam(':uid', $uid);
            $stmt->execute();
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
        }catch(PDOException $exception){ 
            logme($uid,time(),"SELECT * FROM users WHERE uid=:uid","Error", $exception, "n/a");
        }
        return $result;
    }

    function getUserFromEmail($email, $conn){
        $email_c = encrypt($email);
        try{
            $stmt = $conn->prepare("SELECT * FROM users WHERE email=:email");
            $stmt->bindParam(':email', $email_c);
            $stmt->execute();
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
        }catch(PDOException $exception){ 
            logme($result['uid'],time(),"SELECT * FROM users WHERE uid=:uid","Error", $exception, "n/a");
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
    $decryptedRemovePadding = preg_replace('/[\x00-\x1F\x7F-\xFF]/', '', $crypt);
    return $decryptedRemovePadding;
}

function pkcs7_pad($data, $size)
{
    $length = $size - strlen($data) % $size;
    return $data . str_repeat(chr($length), $length);
}

function logme($uid,$timestamp,$action,$query,$result,$content){
    $file = fopen("log.csv", "a");
    $currTime = time();
    $line = encrypt($currTime) .  "," . encrypt($uid) .  "," . encrypt($timestamp) .  "," . encrypt($action) .  "," . encrypt($query) .  "," . encrypt($result) . "," . encrypt($content) . PHP_EOL;
    fwrite($file, $line); # $line is an array of string values here
    fclose($file);
}

function readLog(){
    $csvFile = file("./includes/log.csv", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $csv = array_map('str_getcsv', $csvFile);
    return $csv;
}

function generateResetToken($conn, $uid){


    $token= bin2hex(openssl_random_pseudo_bytes(16));

    if(getResetToken($uid, $conn)!=""){
        // prepare sql and bind parameters
        try{
            $timestampr=time();
            $stmt = $conn->prepare("UPDATE reset_tokens SET token = :token, tokenExpired='0', tokenCreatedTimestamp=:timestampr WHERE uid=:uid");
            $stmt->bindParam(':uid', $uid);
            $stmt->bindParam(':token', $token);
            $stmt->bindParam(':timestampr', $timestampr);
            $stmt->execute();    
        }catch(PDOException $exception){ 
            logme($uid,time(),"UPDATE users SET token = :token, tokenCreatedTimestamp=:timestampr WHERE username=:username","Error", $exception, "n/a");
        }
    }else{
        $time=time();
        $expired=0;
          // prepare sql and bind parameters
          try{
            $stmt = $conn->prepare("INSERT INTO reset_tokens (uid, token, tokenCreatedTimestamp, tokenExpired)
            VALUES (:uid, :token, :tokenCreatedTimestamp, :tokenExpired)");
            $stmt->bindParam(':token', $token);
            $stmt->bindParam(':tokenCreatedTimestamp', $time);
            $stmt->bindParam(':tokenExpired', $expired);
            $stmt->bindParam(':uid', $uid);
            $stmt->execute();    
        }catch(PDOException $exception){ 
            logme($uid,time(),"INSERT INTO reset_tokens (token, tokenCreatedTimestamp, tokenExpired)
            VALUES (:token, :tokenCreatedTimestamp, :email) WHERE uid=:uid","Error", $exception, "n/a");
        }      
    }
}

    function getResetToken($uid, $conn){
        try{
            $stmt = $conn->prepare("SELECT token FROM reset_tokens WHERE uid=:uid");
            $stmt->bindParam(':uid', $uid);
            $stmt->execute();
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
        }catch(PDOException $exception){ 
            logme($result['uid'],time(),"SELECT token FROM users WHERE username=:username","Error", $exception, "n/a");
        }
        return $result['token'];
    }

    function isResetTokenExpired($uid, $conn){
        try{
            $stmt = $conn->prepare("SELECT tokenExpired FROM reset_tokens WHERE uid=:uid");
            $stmt->bindParam(':uid', $uid);
            $stmt->execute();
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
        }catch(PDOException $exception){ 
            logme($result['uid'],time(),"SELECT tokenExpired FROM reset_tokens WHERE uid=:uid","Error", $exception, "n/a");
        }    
        
        return $result['tokenExpired'];
    }

    function expireOutdatedTokensCronJob($conn){
        try{
            $unclockTime = time()-300;
            $stmt = $conn->prepare("UPDATE reset_tokens SET tokenExpired='1' WHERE tokenCreatedTimestamp < $unclockTime");
            $stmt->execute();
        }catch(PDOException $exception){ 
            logme("N/A",time(),"PDOException","UPDATE users SET tokenExpired = 1 WHERE tokenCreatedTimestamp >= $unclockTime","Error", $exception, "n/a");
        }
    }

    //If over 3 chars
    function checkUsernameNotInPass($username,$pass,$conn){
        if(strlen($username)>3){
            if (stripos($pass, $username)) {
                return true;
            }else{
                return false;
            }
        }else{
            return false;
        }
    }

?> 