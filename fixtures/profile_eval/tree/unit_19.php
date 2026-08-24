<?php
$dn = $_GET["h"] ?? "";
$who = $_GET["w"] ?? "";
$filter = "(|(sn=$who*)(givenname=$who*))";
$sr = ldap_search($ds, $dn, $filter, array("ou", "sn", "givenname", "mail"));
$info = ldap_get_entries($ds, $sr);
echo $info["count"];
