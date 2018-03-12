<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
<!-- Latest compiled and minified CSS -->
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
<link rel="stylesheet" href="./assets/css/style.css">
<title>Setup System</title>
</head>
<?php

$host="localhost"; 
$root="root"; 
$root_password=""; 

$db="Project2"; 

if($_SERVER["REQUEST_METHOD"] == "POST"){


        $dbh = new PDO("mysql:host=$host", $root, $root_password);
        $dbh->exec("CREATE DATABASE `$db`;");

        $conn = new PDO("mysql:host=$host;dbname=$db", $root, $root_password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $conn->exec("CREATE TABLE `login_attempts` (
            `field` int(11) NOT NULL,
            `uid` int(255) NOT NULL,
            `time` varchar(30) NOT NULL
          ) ENGINE=InnoDB DEFAULT CHARSET=latin1;");


        $conn->exec("CREATE TABLE `reset_tokens` (
            `uid` int(11) NOT NULL,
            `token` varchar(255) NOT NULL,
            `tokenCreatedTimestamp` varchar(255) NOT NULL,
            `tokenExpired` int(1) NOT NULL
          ) ENGINE=InnoDB DEFAULT CHARSET=latin1;");

        $conn->exec("CREATE TABLE `users` (
            `uid` int(11) NOT NULL,
            `username` varchar(255) NOT NULL,
            `password` char(128) NOT NULL,
            `email` varchar(255) NOT NULL,
            `dob` varchar(255) NOT NULL
          ) ENGINE=InnoDB DEFAULT CHARSET=latin1;");

        $conn->exec("ALTER TABLE `login_attempts`
        ADD PRIMARY KEY (`field`);");

        $conn->exec("ALTER TABLE `reset_tokens`
        ADD PRIMARY KEY (`uid`),
        ADD UNIQUE KEY `uid` (`uid`);");

        $conn->exec("ALTER TABLE `users`
        ADD PRIMARY KEY (`uid`);");

        $conn->exec("ALTER TABLE `login_attempts`
        MODIFY `field` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=30;");     

        $conn->exec("ALTER TABLE `users`
        MODIFY `uid` int(11) NOT NULL AUTO_INCREMENT;
        COMMIT;");    


	    header('Location: ./index.php');
}
?>
<!DOCTYPE html>
<html lang="en-US">
<!--
Credit to https://bootsnipp.com/snippets/featured/login-and-register-tabbed-form#comments for the nice bootstrap theme.
-->
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
<!-- Latest compiled and minified CSS -->
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
<link rel="stylesheet" href="./style.css">
<script src="https://ajax.googleapis.com/ajax/libs/jquery/2.1.1/jquery.min.js"></script>

</head>

<body>

<div class="container">
	<div class="row">
		<div class="col-md-6 col-md-offset-3">
			<div class="panel panel-login">
				<div class="panel-heading">
					<div class="row">
						<div class="col-xs-15">
							<a href="./membersArea.php" id="login-form-link">Database Setup</a>
						</div>
					</div>
					<hr>
				</div>
				<div class="panel-body">
                <form id="login-form" method="post" role="form">
                <div class="col-sm-6 col-sm-offset-3">
					<input type="submit" name="register-submit" id="register-submit" tabindex="4" class="form-control btn btn-register" value="Build DB">
				</div>
                </form>
				</br></br>
			</div>
			</div>
		</div>
	</div>
</div>


</body>
</html>