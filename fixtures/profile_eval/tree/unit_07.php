<?php
$sku = $_GET["sku"] ?? "";
$sku = str_replace("'", "", $sku);
$q = "SELECT * FROM items WHERE sku = '" . $sku . "'";
$r = mysql_query($q);
if (!$r) {
    echo mysql_error();
    exit;
}
while ($row = mysql_fetch_assoc($r)) {
    echo $row["name"];
}
