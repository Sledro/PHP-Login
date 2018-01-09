<?php
unlockerCronJob($conn);
    //Credit to https://www.wikihow.com/Create-a-Secure-Login-Script-in-PHP-and-MySQL for the secure session function (Slightly Modified)
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

            $stmt = $conn->prepare("SELECT username, password FROM users WHERE username=:username");
            $stmt->bindParam(':username', $username);
            $stmt->execute();
            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($stmt->rowCount() > 0) {
            
                $hash=$result['password'];
        
                if (password_verify($password, $hash)) {
                    $_SESSION['username']=$result['username'];
                    return true;
                } else {
                    invlid_login_attempt($username, $conn);
                    return false; //Invalid Password
                }
            } else {
                invlid_login_attempt($username, $conn);
                return false; //Username not found
            }
    }

    function invlid_login_attempt($username, $conn) {

       
        $stmt = $conn->prepare("SELECT username FROM login_attempts WHERE username=:username");
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        
        if ($stmt->rowCount() > 0) {
            $currtime = time();
            // Increment login attempt counter
            $stmt = $conn->prepare("UPDATE login_attempts SET attemptNo = attemptNo + 1, time = $currtime WHERE ( username = :username )");
            $stmt->bindParam(':username', $username);
            $stmt->execute();
        }else{
            $num=1;
            $currtime = time();
            // prepare sql and bind parameters
            $stmt = $conn->prepare("INSERT INTO login_attempts (username, time, attemptNo)
            VALUES (:username, :timenow, :attemptNo)");
            $stmt->bindParam(':username', $username);
            $stmt->bindParam(':timenow', $currtime);
            $stmt->bindParam(':attemptNo', $num);
            $stmt->execute();
        }
    
    }

    function checkIfLockedOut($username, $conn) {
        $stmt = $conn->prepare("SELECT attemptNo FROM login_attempts WHERE username=:username");
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        if($result['attemptNo'] > 3){
            $true="true";
            return $true;
        }else{
            $false="false";
            return $false;
        }
    } 

    function unlockerCronJob($conn) {
        $unclockTime = time()-300;
        $stmt = $conn->prepare("UPDATE login_attempts SET attemptNo = 0 WHERE attemptNo>'3' AND time < $unclockTime");
        $stmt->execute();

    } 

?> 