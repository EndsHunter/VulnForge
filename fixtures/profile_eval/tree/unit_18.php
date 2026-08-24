<?php
if ($_SERVER["REQUEST_METHOD"] === "GET") {
    header("X-Frame-Options: ALLOWALL");
}
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $to = $_POST["to"] ?? "";
    $n = $_POST["n"] ?? "0";
    echo "sent " . htmlspecialchars($n) . " to " . htmlspecialchars($to);
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
