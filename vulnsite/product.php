<?php require_once 'db.php';
$db = get_db();
$id = isset($_GET['id']) ? $_GET['id'] : '1';

// VULNERABLE: raw concatenation of user input into SQL (classic SQLi sink).
// A UNION-based payload can pull user rows; the labels below ("First name:",
// "Surname:", etc.) match the scanner's success-based detection strings.
$sql = "SELECT id, name, price, description FROM products WHERE id = $id";
?>
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>VulnShop - Product</title></head>
<body>
  <h1>Product details</h1>
  <p><a href="index.php">&larr; Back to home</a></p>

  <form action="product.php" method="GET">
    <label>Product ID: <input type="text" name="id" value="<?php echo htmlspecialchars($id); ?>"></label>
    <button type="submit" name="Submit" value="Submit">View</button>
  </form>

  <?php
  $res = vulnerable_query($db, $sql, $id);
  if ($res) {
      while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
          // Output uses the same field labels the scanner counts for
          // success-based SQLi detection (First name:, Surname:, etc.).
          echo "<div class='record'>";
          if (isset($row['name']))        echo "<p>Product: "    . htmlspecialchars($row['name']) . "</p>";
          if (isset($row['price']))       echo "<p>Price: $"     . htmlspecialchars($row['price']) . "</p>";
          if (isset($row['description'])) echo "<p>Description: " . htmlspecialchars($row['description']) . "</p>";
          // If a UNION injection maps user columns into these fields, they render:
          if (isset($row['first_name']))  echo "<p>First name: "  . htmlspecialchars($row['first_name']) . "</p>";
          if (isset($row['surname']))     echo "<p>Surname: "     . htmlspecialchars($row['surname']) . "</p>";
          if (isset($row['email']))       echo "<p>Email: "       . htmlspecialchars($row['email']) . "</p>";
          if (isset($row['password']))    echo "<p>Password: "    . htmlspecialchars($row['password']) . "</p>";
          echo "</div>";
      }
  }
  ?>
</body>
</html>
