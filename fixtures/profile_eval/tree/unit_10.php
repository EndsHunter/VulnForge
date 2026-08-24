<?php
$n = htmlspecialchars($_GET["n"] ?? "", ENT_NOQUOTES);
echo '<input value="' . $n . '">';
