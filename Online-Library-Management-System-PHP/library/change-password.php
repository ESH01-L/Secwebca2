<?php
session_start();
include('includes/config.php');
error_reporting(0);

if(strlen($_SESSION['login'])==0) {   
  header('location:index.php');
} else { 
  if(isset($_POST['change'])) {
    // CSRF token validation
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
      $error = "Invalid CSRF token";
    } else {
      $password = $_POST['password'];
      $newpassword = $_POST['newpassword'];
      $confirmpassword = $_POST['confirmpassword'];
      $email = $_SESSION['login'];

      // Check if new password and confirm password match
      if ($newpassword !== $confirmpassword) {
        $error = "New Password and Confirm Password do not match";
      } else {
        // Enforce strong password policy
        if (strlen($newpassword) < 8 || !preg_match("/[A-Z]/", $newpassword) || !preg_match("/[a-z]/", $newpassword) || !preg_match("/[0-9]/", $newpassword) || !preg_match("/[\W]/", $newpassword)) {
          $error = "Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.";
        } else {
          $sql = "SELECT Password FROM tblstudents WHERE EmailId=:email";
          $query = $dbh->prepare($sql);
          $query->bindParam(':email', $email, PDO::PARAM_STR);
          $query->execute();
          $result = $query->fetch(PDO::FETCH_OBJ);

          if ($result && password_verify($password, $result->Password)) {
            $newpasswordHash = password_hash($newpassword, PASSWORD_DEFAULT);
            $con = "UPDATE tblstudents SET Password=:newpassword WHERE EmailId=:email";
            $chngpwd1 = $dbh->prepare($con);
            $chngpwd1->bindParam(':email', $email, PDO::PARAM_STR);
            $chngpwd1->bindParam(':newpassword', $newpasswordHash, PDO::PARAM_STR);
            $chngpwd1->execute();
            $msg = "Your Password successfully changed";
          } else {
            $error = "Your current password is wrong";  
          }
        }
      }
    }
  }

  // Generate CSRF token
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
  <meta name="description" content="" />
  <meta name="author" content="" />
  <title>Online Library Management System | </title>
  <link href="assets/css/bootstrap.css" rel="stylesheet" />
  <link href="assets/css/font-awesome.css" rel="stylesheet" />
  <link href="assets/css/style.css" rel="stylesheet" />
  <link href='http://fonts.googleapis.com/css?family=Open+Sans' rel='stylesheet' type='text/css' />
  <style>
    .errorWrap {
      padding: 10px;
      margin: 0 0 20px 0;
      background: #fff;
      border-left: 4px solid #dd3d36;
      -webkit-box-shadow: 0 1px 1px 0 rgba(0,0,0,.1);
      box-shadow: 0 1px 1px 0 rgba(0,0,0,.1);
    }
    .succWrap {
      padding: 10px;
      margin: 0 0 20px 0;
      background: #fff;
      border-left: 4px solid #5cb85c;
      -webkit-box-shadow: 0 1px 1px 0 rgba(0,0,0,.1);
      box-shadow: 0 1px 1px 0 rgba(0,0,0,.1);
    }
  </style>
</head>
<script type="text/javascript">
function valid() {
  if(document.chngpwd.newpassword.value != document.chngpwd.confirmpassword.value) {
    alert("New Password and Confirm Password Field do not match  !!");
    document.chngpwd.confirmpassword.focus();
    return false;
  }
  return true;
}
</script>

<body>
  <?php include('includes/header.php');?>
  <div class="content-wrapper">
    <div class="container">
      <div class="row pad-botm">
        <div class="col-md-12">
          <h4 class="header-line">User Change Password</h4>
        </div>
      </div>
      <?php if($error){?><div class="errorWrap"><strong>ERROR</strong>:<?php echo htmlentities($error); ?> </div><?php } 
      else if($msg){?><div class="succWrap"><strong>SUCCESS</strong>:<?php echo htmlentities($msg); ?> </div><?php }?>            
      <div class="row">
        <div class="col-md-6 col-sm-6 col-xs-12 col-md-offset-3" >
          <div class="panel panel-info">
            <div class="panel-heading">
              Change Password
            </div>
            <div class="panel-body">
              <form role="form" method="post" onSubmit="return valid();" name="chngpwd">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <div class="form-group">
                  <label>Current Password</label>
                  <input class="form-control" type="password" name="password" autocomplete="off" required  />
                </div>
                <div class="form-group">
                  <label>Enter Password</label>
                  <input class="form-control" type="password" name="newpassword" autocomplete="off" required  />
                </div>
                <div class="form-group">
                  <label>Confirm Password </label>
                  <input class="form-control"  type="password" name="confirmpassword" autocomplete="off" required  />
                </div>
                <button type="submit" name="change" class="btn btn-info">Change </button> 
              </form>
            </div>
          </div>
        </div>
      </div>  
    </div>
  </div>
  <?php include('includes/footer.php');?>
  <script src="assets/js/jquery-1.10.2.js"></script>
  <script src="assets/js/bootstrap.js"></script>
  <script src="assets/js/custom.js"></script>
</body>
</html>
<?php } ?>
