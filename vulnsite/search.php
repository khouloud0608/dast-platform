<?php
$q = isset($_GET['q']) ? $_GET['q'] : '';
?>
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>VulnShop - Search</title></head>
<body>
  <h1>Search products</h1>
  <p><a href="index.php">&larr; Back to home</a></p>

  <form action="search.php" method="GET">
    <label>Search: <input type="text" name="q" value=""></label>
    <button type="submit" name="Submit" value="Submit">Search</button>
  </form>

  <?php
  // VULNERABLE: user input echoed into the page with NO encoding.
  // The scanner's reflected-XSS check confirms the vuln when its payload
  // (e.g. <script>alert(1)</script>) appears verbatim in this output.
  if ($q !== '') {
      echo "<p>You searched for: " . $q . "</p>";
      echo "<p>No products matched '" . $q . "'.</p>";
  }
  ?>
</body>
</html>
