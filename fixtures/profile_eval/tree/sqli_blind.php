<?php
$db = new SQLite3('test.db');

if (strlen($_GET['id']) < 1) {
  echo 'Usage: ?id=1';
} else {
  $count = $db->querySingle('select count(*) from secrets where id = ' . $_GET['id']);

  if ($count > 0) {
    echo 'Yes!';
  } else {
    echo 'No!';
  }
}
