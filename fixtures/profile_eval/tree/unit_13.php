<?php
libxml_disable_entity_loader(false);
$raw = $_GET["x"] ?? "<root><c>none</c></root>";
$doc = new DOMDocument();
$doc->loadXML($raw, LIBXML_NOENT | LIBXML_DTDLOAD);
$s = simplexml_import_dom($doc);
echo $s->c;
