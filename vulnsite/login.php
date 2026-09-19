<?php require_once 'db.php';
$db = get_db();
$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = isset($_POST['username']) ? $_POST['username'] : '';
    $password = isset($_POST['password']) ? $_POST['password'] : '';
    // VULNERABLE: raw concatenation in a POST form (SQLi via username).
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $res = vulnerable_query($db, $sql, $username);
    if ($res) {
        $row = $res->fetchArray(SQLITE3_ASSOC);
        if ($row) {
            // Leaks labeled fields -> feeds success-based SQLi detection on POST.
            $msg = "<div class='record'><p>Welcome back!</p>";
            $msg .= "<p>First name: " . htmlspecialchars($row['first_name']) . "</p>";
            $msg .= "<p>Surname: "    . htmlspecialchars($row['surname']) . "</p>";
            $msg .= "<p>Email: "      . htmlspecialchars($row['email']) . "</p></div>";
        } else {
            $msg = "<p>Invalid credentials.</p>";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>VulnShop - Login</title></head>
<body>
  <h1>Customer login</h1>
  <p><a href="index.php">&larr; Back to home</a></p>

  <form action="login.php" method="POST">
    <label>Username: <input type="text" name="username" value=""></label><br>
    <label>Password: <input type="password" name="password" value=""></label><br>
    <button type="submit" name="Login" value="Login">Login</button>
  </form>

  <?php echo $msg; ?>
</body>
</html>
