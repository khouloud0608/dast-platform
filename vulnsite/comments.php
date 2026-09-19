<?php require_once 'db.php';
$db = get_db();
$id = isset($_GET['id']) ? $_GET['id'] : '1';

// VULNERABLE: raw concatenation. A UNION payload here can leak user rows,
// which the scanner detects via the jump in "First name:"/"Surname:" counts.
$sql = "SELECT author, body FROM comments WHERE product_id = $id";
?>
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>VulnShop - Comments</title></head>
<body>
  <h1>Product comments</h1>
  <p><a href="index.php">&larr; Back to home</a></p>

  <form action="comments.php" method="GET">
    <label>Product ID: <input type="text" name="id" value="<?php echo htmlspecialchars($id); ?>"></label>
    <button type="submit" name="Submit" value="Submit">Show</button>
  </form>

  <?php
  $res = vulnerable_query($db, $sql, $id);
  if ($res) {
      while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
          echo "<div class='record'>";
          foreach ($row as $k => $v) {
              // Generic labeling; UNION-injected user columns will surface as
              // First name:/Surname:/Email: which the scanner counts.
              echo "<p>" . htmlspecialchars(ucfirst($k)) . ": " . htmlspecialchars($v) . "</p>";
          }
          echo "</div>";
      }
  }
  ?>
</body>
</html>
