<?php
$db = new SQLite3("store.db");
$id = $_GET["id"] ?? "";
$id = str_replace(array(" ", "--"), "", $id);
$n = $db->querySingle("select count(*) from notes where id = " . $id);
if ($n > 0) {
    usleep(200000);
    echo "Yes!";
} else {
    echo "No!";
}
