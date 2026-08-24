<?php
$sku = $_GET["sku"] ?? "";
$q = "SELECT * FROM items WHERE sku = '" . $sku . "'";
$r = mysql_query($q) or die(mysql_error());
while ($row = mysql_fetch_assoc($r)) {
    echo $row["name"];
}
