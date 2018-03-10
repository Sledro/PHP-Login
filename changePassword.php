<?php
include_once 'includes/db-connect.php';
include_once 'includes/functions.php';
 
sec_session_start();

//This cron job unlocks all locked out accounts
unlockerCronJob($conn);

$username=null;
//Note an SSL connection is required to prevent network sniffing
if(isset($_SESSION['username'])){
	$username = preg_replace("/[^a-zA-Z0-9_\-]+/", "", $_SESSION['username']); //XSS Security
	if(!empty($_POST)){
	 generateResetToken($conn, $username);
	}
	 $token = getResetToken($username,$conn);
}
if(isUserLoggedIn($username,$conn)!="true")
	header('Location: ./index.php');

//Error handling
$error=null;
if(isset($_GET["error"])){
	if(!is_numeric($_GET["error"])){
		$error="Dont not edit the URL GET var, thanks.";
	}else{
		$error = errorLogging($_GET["error"]);
	}
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
<link rel="stylesheet" href="./assets/css/style.css">
<title>Login System</title>
</head>

<body>

<div class="container">
	<div class="row">
		<div class="col-md-6 col-md-offset-3">
			<div class="panel panel-login">
				<div class="panel-heading">
					<div class="row">
						<div class="col-xs-12">
							<a href="./register.php" class="active" id="register-form-link">Change Password</a>
						</div>
					</div>
					<hr>
				</div>
				<div class="panel-body">
				<nav class="navbar navbar-default">
				<div class="container-fluid">
					<ul class="nav navbar-nav">
					<li><a  href="./membersArea.php">Members Area</a></li>
					<li ><a href="./account.php">Account</a></li>
					<li class="active"><a href="./changePassword.php">Password Reset</a></li>
					<li><a href="./log.php">Log</a></li>
					<li><a href="./logout.php">Logout</a></li>
					</ul>
				</div>
				</nav>
					<div class="row">
						<div class="col-lg-12">
							<?php echo $error;?>
							<form action="./changePassword.php" method="post" role="form">
							<input type="submit" name="register-submit" id="register-submit" tabindex="4" class="form-control btn btn-register" value="Request New Token"><br/><br/>
							<div class="col-lg-12"><div class="alert alert-success">Reset Token: <?php echo $token;?></div>
							<p>Click the button above to generate a new password reset token. Paste the token received into the box below to reset your password.<strong>
								NOTE:Tokens will expired after 5 minutes from generataion time and are single use.</strong>
							</form>
							<form id="register-form" action="./includes/process-lost-password.php" method="post" role="form">

								<div class="form-group">
									<input type="text" name="token" id="token" tabindex="2" class="form-control" placeholder="Paste reset token here">
								</div>
								<div class="form-group">
								<input type="text" name="email" id="email" required pattern="[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,3}$" title="Please use aplhanumeric charaters only." tabindex="1" class="form-control" placeholder="test@test.com">
								</div>
								<div class="form-group">
									<input type="text" id="dob" required class="form-control" data-format="DD-MM-YYYY" data-template="DD-MMM-YYYY" name="dob" placeholder="DD-MM-YYYY">
								</div>
								<div class="form-group">
									<input type="password" name="newPassword" id="newPassword" tabindex="2" class="form-control" placeholder="New Password">
								</div>
								<div class="form-group">
									<input type="password" name="passwordConfirm" id="passwordConfirm" tabindex="2" class="form-control" placeholder="Confirm New Password">
								</div>
								<input type="hidden" name="username" id="username" tabindex="1" class="form-control" value="<?php echo $username?>">
								<div class="form-group">
									<div class="row">
										<div class="col-sm-6 col-sm-offset-3">
											<input type="submit" name="register-submit" id="register-submit" tabindex="4" class="form-control btn btn-register" value="Update Password">
										</div>
									</div>
								</div>
							</form>
						</div>
					</div>
				</div>
			</div>
		</div>
	</div>
</div>

</body>
</html>