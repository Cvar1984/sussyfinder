<?php
// Unit checks run inside PHP for test/unit.js (and per PHP version by
// test/run.js): structural signals for each snippet in $SUSSY_CASES, the
// listing of the fixture directory $SUSSY_FIXTURE, and ml-model.json
// validation. Set by the prelude (test/lib.js phpJob): $SUSSY_MAIN,
// $SUSSY_CASES, $SUSSY_FIXTURE, $SUSSY_MODELS. Must stay PHP 4.3-safe.
define('SUSSY_LIB', true);
include $SUSSY_MAIN;

$cases = array();
foreach (explode("\0", file_get_contents($SUSSY_CASES)) as $src) {
    $t = getFileTokens($src);
    $cases[] = array_values(array_unique(array_merge(compareTokens($tokenNeedles, tokenTextSet($t)), findStructuralSignals($t, $src, $tokenNeedles))));
}

$GLOBALS['phpWarnings'] = array();
$listing = getSortedByPattern($SUSSY_FIXTURE, $pattern);
$names = array();
foreach ($listing['file_readable'] as $file) {
    $names[] = rawurlencode(basename($file));
}
$outsideWarned = false;
foreach ($GLOBALS['phpWarnings'] as $warning) {
    if (strpos($warning, 'outside the scanned directory') !== false) {
        $outsideWarned = true;
    }
}

// mlModelJson(): which model files main.php accepts (true) or refuses (false)
$models = array();
foreach ($SUSSY_MODELS as $file) {
    $models[] = mlModelJson($file) !== 'null';
}

echo json_encode(array('php' => PHP_VERSION, 'cases' => $cases, 'listing' => $names, 'outside_warned' => $outsideWarned, 'models' => $models));
