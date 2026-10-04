<?php
declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';
require_admin();

$xml = file_get_contents('php://input');
$doc = new DOMDocument();

if (($_GET['parser'] ?? '') === 'legacy') {
    // codit-expect: CWE-611 LIBXML_NOENT substitutes external entities from the uploaded document
    $doc->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);
    echo $doc->getElementsByTagName('item')->length;
    exit;
}



// codit-safe: CWE-611 no entity substitution, no DTD loading, no network access
$doc->loadXML($xml, LIBXML_NONET);
echo $doc->getElementsByTagName('item')->length;
