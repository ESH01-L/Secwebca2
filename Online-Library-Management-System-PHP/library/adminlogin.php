<?php
session_start();
error_reporting(0);
include('includes/config.php');

if ($_SESSION['alogin'] != '') {
    $_SESSION['alogin'] = '';
}


// Define maximum login attempts and lockout time
define('MAX_LOGIN_ATTEMPTS', 3);
define('LOCKOUT_TIME', 300); // 15 minutes

// Check if the user is locked out
if (isset($_SESSION['login_attempts']) && $_SESSION['login_attempts'] >= MAX_LOGIN_ATTEMPTS) {
    if (time() - $_SESSION['last_login_attempt'] < LOCKOUT_TIME) {
        echo "<script>alert('Too many login attempts. Please try again later.');</script>";
        exit;
    } else {
        // Reset login attempts after lockout time has passed
        $_SESSION['login_attempts'] = 0;
    }
}

// Increment login attempts on each login attempt
if (isset($_POST['login'])) {
    if (!isset($_SESSION['login_attempts'])) {
        $_SESSION['login_attempts'] = 0;
    }
    $_SESSION['login_attempts']++;
    $_SESSION['last_login_attempt'] = time();
}

if (isset($_POST['login'])) {
    // CSRF token validation
    if (!hash_equals($_SESSION['token'], $_POST['token'])) {
        echo "<script>alert('Invalid CSRF token');</script>";
        exit;
    }

    $username = htmlspecialchars($_POST['username']);
    $password = $_POST['password'];

    $sql = "SELECT UserName, Password FROM admin WHERE UserName = :username";
    $query = $dbh->prepare($sql);
    $query->bindParam(':username', $username, PDO::PARAM_STR);
    $query->execute();
    $result = $query->fetch(PDO::FETCH_OBJ);

    if ($result && password_verify($password, $result->Password)) {
        session_regenerate_id(true); // Prevent session fixation
        $_SESSION['alogin'] = $username;
        echo "<script type='text/javascript'> document.location ='admin/dashboard.php'; </script>";
    } else {
        echo "<script>alert('Invalid Details');</script>";
    }
}

// Generate CSRF token
if (empty($_SESSION['token'])) {
    $_SESSION['token'] = bin2hex(random_bytes(32));
}
?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
    <meta name="description" content="" />
    <meta name="author" content="" />
    <title>Online Library Management System</title>
    <!-- BOOTSTRAP CORE STYLE  -->
    <link href="assets/css/bootstrap.css" rel="stylesheet" />
    <!-- FONT AWESOME STYLE  -->
    <link href="assets/css/font-awesome.css" rel="stylesheet" />
    <!-- CUSTOM STYLE  -->
    <link href="assets/css/style.css" rel="stylesheet" />
    <!-- GOOGLE FONT -->
    <link href='http://fonts.googleapis.com/css?family=Open+Sans' rel='stylesheet' type='text/css' />
</head>
<body>
    <!------MENU SECTION START-->
    <?php include('includes/header.php'); ?>
    <!-- MENU SECTION END-->
    <div class="content-wrapper">
        <div class="container">
            <div class="row pad-botm">
                <div class="col-md-12">
                    <h4 class="header-line">ADMIN LOGIN FORM</h4>
                </div>
            </div>
            <!--LOGIN PANEL START-->
            <div class="row">
                <div class="col-md-6 col-sm-6 col-xs-12 col-md-offset-3">
                    <div class="panel panel-info">
                        <div class="panel-heading">
                            LOGIN FORM
                        </div>
                        <div class="panel-body">
                            <form role="form" method="post">
                                <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>" />
                                <div class="form-group">
                                    <label>Enter Username</label>
                                    <input class="form-control" type="text" name="username" autocomplete="off" required />
                                </div>
                                <div class="form-group">
                                    <label>Password</label>
                                    <input class="form-control" type="password" name="password" autocomplete="off" required />
                                </div>
                                <div class="g-recaptcha" data-sitekey="6Lcnn5EqAAAAAPPAlTqjznykTMTrj44vj5ZVxsXM" data-callback="enablesubmitbtn"></div>
                                <script src="https://www.google.com/recaptcha/api.js" async defer></script><br>
                                <input type="submit" id="submit" class="btn btn-info" disabled="disabled" name="login" value="Login"><br><br>
                                <script>
                                    function enablesubmitbtn() {
                                        document.getElementById("submit").disabled = false;
                                    }
                                </script>
                               
                            </form>
                        </div>
                    </div>
                </div>
            </div>
            <!---LOGIN PANEL END-->
        </div>
    </div>
    <!-- CONTENT-WRAPPER SECTION END-->
    <?php include('includes/footer.php'); ?>
    <!-- FOOTER SECTION END-->
    <script src="assets/js/jquery-1.10.2.js"></script>
    <!-- BOOTSTRAP SCRIPTS  -->
    <script src="assets/js/bootstrap.js"></script>
    <!-- CUSTOM SCRIPTS  -->
    <script src="assets/js/custom.js"></script>
</body>
</html>
