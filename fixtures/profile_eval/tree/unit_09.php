<?php
$db = new SQLite3("store.db");
$id = $_GET["id"] ?? "";
$n = $db->querySingle("select count(*) from notes where id = " . $id);
if ($n > 0) {
    echo "Yes!";
} else {
    echo "No!";
}
