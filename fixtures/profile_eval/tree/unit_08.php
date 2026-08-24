<?php
$cat = $_GET["cat"] ?? "";
if (preg_match("/union/i", $cat)) {
    $cat = preg_replace("/union/i", "", $cat);
}
$db = new SQLite3("store.db");
$q = "SELECT name, price FROM items WHERE cat = '" . $cat . "'";
$r = $db->query($q);
while ($row = $r->fetchArray()) {
    echo $row["name"] . " " . $row["price"];
}
