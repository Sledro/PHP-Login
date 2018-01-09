<?php

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

        $stmt = $conn->prepare("SELECT username, password FROM users WHERE username=:username");
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        echo $username;
        print_r($result);
        
    }

?> 