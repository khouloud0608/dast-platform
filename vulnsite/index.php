<?php require_once 'db.php'; ?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>VulnShop - Home</title>
</head>
<body>
  <h1>VulnShop Demo Store</h1>
  <p>A deliberately vulnerable web application for DAST testing.</p>

  <!-- Plain <a href> links so a link-following crawler discovers the whole site -->
  <nav>
    <ul>
      <li><a href="index.php">Home</a></li>
      <li><a href="product.php?id=1">Product 1</a></li>
      <li><a href="product.php?id=2">Product 2</a></li>
      <li><a href="product.php?id=3">Product 3</a></li>
      <li><a href="search.php?q=laptop">Search</a></li>
      <li><a href="comments.php?id=1">Comments</a></li>
      <li><a href="login.php">Login</a></li>
      <li><a href="about.php">About</a></li>
    </ul>
  </nav>

  <h2>Featured products</h2>
  <ul>
    <li><a href="product.php?id=1">Wireless Mouse</a></li>
    <li><a href="product.php?id=2">Mechanical Keyboard</a></li>
    <li><a href="product.php?id=3">USB-C Hub</a></li>
  </ul>
</body>
</html>
