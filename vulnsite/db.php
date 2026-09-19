<?php
/**
 * SQLite-backed data layer for the deliberately-vulnerable demo site.
 *
 * IMPORTANT design note for the DAST scanner:
 * The active scanner detects error-based SQLi by matching MySQL-flavored
 * error strings (e.g. "you have an error in your sql syntax"). SQLite's
 * native error text is different, so on a query error we deliberately emit
 * a MySQL-style error message. This lets the UNMODIFIED scanner detect the
 * injection, keeping the scanner fully generic.
 */

function get_db() {
    $path = '/tmp/vulnshop.db';
    $fresh = !file_exists($path);
    $db = new SQLite3($path);
    if ($fresh) {
        $db->exec("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, first_name TEXT, surname TEXT)");
        $db->exec("INSERT INTO users (username,password,email,first_name,surname) VALUES
            ('admin','admin123','admin@vulnshop.local','System','Administrator'),
            ('jsmith','password1','jsmith@vulnshop.local','John','Smith'),
            ('mjones','qwerty','mjones@vulnshop.local','Mary','Jones'),
            ('bwilson','letmein','bwilson@vulnshop.local','Bob','Wilson'),
            ('agarcia','sunshine','agarcia@vulnshop.local','Ana','Garcia')");
        $db->exec("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price TEXT, description TEXT)");
        $db->exec("INSERT INTO products (name,price,description) VALUES
            ('Wireless Mouse','19.99','Ergonomic wireless mouse'),
            ('Mechanical Keyboard','79.99','RGB mechanical keyboard'),
            ('USB-C Hub','34.99','7-port USB-C hub')");
        $db->exec("CREATE TABLE comments (id INTEGER PRIMARY KEY, product_id INTEGER, author TEXT, body TEXT)");
        $db->exec("INSERT INTO comments (product_id,author,body) VALUES
            (1,'John','Great mouse!'),
            (1,'Mary','Works well.'),
            (2,'Bob','Love the keys.')");
    }
    return $db;
}

/**
 * Run a query that intentionally concatenates user input (SQLi sink).
 * On error, emit a MySQL-style message the scanner recognizes, AND simulate
 * a time delay when a time-based payload is detected (so blind SQLi triggers).
 */
function vulnerable_query($db, $sql, $raw_input = '') {
    // Simulate time-based blind SQLi: if the payload asks the DB to sleep,
    // actually sleep, so the scanner's timing check (>=2.5s) fires.
    if (preg_match('/sleep\s*\(\s*(\d+)\s*\)/i', $raw_input, $m)) {
        sleep(min((int)$m[1], 5));
    }
    $result = @$db->query($sql);
    if ($result === false) {
        // MySQL-style error text — matches the scanner's SQLI_ERRORS list.
        echo "<div class='error'>";
        echo "You have an error in your SQL syntax; check the manual that ";
        echo "corresponds to your MySQL server version for the right syntax ";
        echo "to use near '" . htmlspecialchars($raw_input) . "'";
        echo "</div>";
        return false;
    }
    return $result;
}
