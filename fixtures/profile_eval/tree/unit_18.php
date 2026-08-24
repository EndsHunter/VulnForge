<?php
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $to = $_POST["to"] ?? "";
    $n = $_POST["n"] ?? "0";
    echo "sent " . $n . " to " . $to;
    exit;
}
?>
<html>
<body>
<form method="post">
<input name="to">
<input name="n" value="100">
<button type="submit">ok</button>
</form>
</body>
</html>
