<?php
include_once 'includes/db-connect.php';
include_once 'includes/functions.php';
 
sec_session_start();

if(isset($_SESSION['username']))
$username = preg_replace("/[^a-zA-Z0-9_\-]+/", "", $_SESSION['username']); //XSS Security

if(isUserLoggedIn($username,$conn)=="false")
header('Location: ./index.php');

$user=getUser($username, $conn);
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
<link rel="stylesheet" href="./assets/css/style.css">
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
							<a href="./membersArea.php" id="login-form-link">Members Area</a>
						</div>
					</div>
					<hr>
				</div>
				<div class="panel-body">
				<nav class="navbar navbar-default">
				<div class="container-fluid">
					<ul class="nav navbar-nav">
					<li class="active"><a href="./membersArea.php">Members Area</a></li>
					<li><a href="./account.php">Account</a></li>
					<li><a href="./changePassword.php">Password Reset</a></li>
					<li><a href="./log.php">Log</a></li>
					<li><a href="./logout.php">Logout</a></li>
					</ul>
				</div>
				</nav>
				Welcome, <b><?php echo htmlentities($username); ?></b></br></br>
                Thanks for logging into the secure Members Area  Welcome to the private members area.
				</br></br>
				</br></br>
			</div>
			</div>
		</div>
	</div>
</div>


</body>
</html>