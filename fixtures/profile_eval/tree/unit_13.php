<?php
libxml_disable_entity_loader(false);
$raw = file_get_contents("php://input");
if ($raw === "") {
    $raw = $_POST["x"] ?? "<root><c>none</c></root>";
}
$doc = new DOMDocument();
$doc->loadXML($raw, LIBXML_NOENT | LIBXML_DTDLOAD);
$s = simplexml_import_dom($doc);
echo $s->c;
