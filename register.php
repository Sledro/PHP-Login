<?php
include_once 'includes/db-connect.php';
include_once 'includes/functions.php';
 
sec_session_start();

//Note an SSL connection is required to prevent network sniffing
if(isset($_SESSION['username']))
	$username = preg_replace("/[^a-zA-Z0-9_\-]+/", "", $_SESSION['username']); //XSS Security

if(isUserLoggedIn($username,$conn)=="true")
	header('Location: ./membersArea.php');

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
						<div class="col-xs-6">
							<a href="./index.php" id="login-form-link">Login</a>
						</div>
						<div class="col-xs-6">
							<a href="./register.php" class="active" id="register-form-link">Register</a>
						</div>
					</div>
					<hr>
				</div>
				<div class="panel-body">
					<div class="row">
						<div class="col-lg-12">
							<?php echo $error;?>
							<form id="register-form" action="./includes/process-register.php" method="post" role="form">
								<div class="form-group">
									<label>Username:</label>
									<input type="text" name="username" id="username" required pattern="[a-zA-Z0-9]+" title="Please use aplhanumeric charaters only." tabindex="1" class="form-control" placeholder="Username" value="">
								</div>
								<div class="form-group">
									<label>Password:</label>
									<input type="password" required name="password" id="password" tabindex="2"  class="form-control" placeholder="Password">
								</div>
								<div class="form-group">
									<label>Confirm Password:</label>
									<input type="password" required name="passwordConfirm" id="passwordConfirm" tabindex="2" class="form-control" placeholder="Confirm Password">
								</div>
								<div class="form-group">
									<label>Email:</label>
									<input type="text" name="email" id="email" required pattern="[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,3}$" title="Please use aplhanumeric charaters only." tabindex="1" class="form-control" placeholder="test@test.com" value="">
								</div>

								<div class="form-group">
									<label>Date of Birth:</label>
									<input type="text" id="date" required class="form-control" data-format="DD-MM-YYYY" data-template="DD-MMM-YYYY" name="dob" placeholder="DD-MM-YYYY">
								</div>
								<div class="form-group">
									<div class="row">
										<div class="col-sm-6 col-sm-offset-3">
											<input type="submit" name="register-submit" id="register-submit" tabindex="4" class="form-control btn btn-register" value="Register Now">
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