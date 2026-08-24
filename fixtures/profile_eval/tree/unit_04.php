<?php
$base = "/var/www/html/store/";
$dest = $base . basename($_FILES["f"]["name"]);
move_uploaded_file($_FILES["f"]["tmp_name"], $dest);
echo $dest;
