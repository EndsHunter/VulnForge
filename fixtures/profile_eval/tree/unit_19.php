<?php
$who = $_GET["w"] ?? "";
$who = str_replace("*", "", $who);
$filter = "(|(uid=" . $who . ")(mail=" . $who . "))";
$sr = ldap_search($ds, "dc=app,dc=tld", $filter, array("ou", "sn", "uid", "mail"));
$info = ldap_get_entries($ds, $sr);
echo $info["count"];
