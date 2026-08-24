<?php
$db = new SQLite3("store.db");
$id = $_GET["id"] ?? "";
if (strlen($id) > 0) {
    $q = $db->query("select * from notes where id = " . (int)$id);
    while ($row = $q->fetchArray()) {
        echo $row["body"];
    }
} else {
    $q = $db->query("select * from notes where owner = 1");
    while ($row = $q->fetchArray()) {
        echo $row["id"];
    }
}
