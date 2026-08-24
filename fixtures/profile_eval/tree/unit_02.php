<?php
$d = $_GET["d"] ?? "";
$d = str_replace(array(";", "&", "|"), "", $d);
if (strpos($d, " ") === 0) {
    $d = ltrim($d);
}
system("/usr/bin/host " . $d);
