<?php
session_start();
if (!isset($_SESSION["uid"])) {
    $_SESSION["uid"] = 1;
}
$db = new SQLite3("store.db");
$id = $_GET["id"] ?? "";
if (strlen($id) > 0 && ctype_digit($id)) {
    $q = $db->query("select * from notes where id = " . (int)$id);
    while ($row = $q->fetchArray()) {
        echo $row["body"];
    }
} else {
    $uid = (int)$_SESSION["uid"];
    $q = $db->query("select * from notes where owner = " . $uid);
    while ($row = $q->fetchArray()) {
        echo $row["id"];
    }
}
