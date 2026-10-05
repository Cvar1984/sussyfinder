<?php
// Feature extraction job for test/run.js and test/train-ml.js: runs main.php's
// real scanner over $SUSSY_DIRS and appends one JSON row per file to
// $SUSSY_STATE/rows. Set by the prelude that includes this file (test/lib.js
// phpJob): $SUSSY_MAIN, $SUSSY_STATE, $SUSSY_DIRS, $SUSSY_SKIP, and
// optionally $SUSSY_RELATIVE ('1': row paths relative to the scanned dir).
//
// Must stay PHP 4.3-safe: test/run.js runs it on every PHTest version.
// PHP itself can crash on a file (4.3.0's tokenizer segfaults on some modern
// code), so finished paths go to $SUSSY_STATE/done and the current one to
// $SUSSY_STATE/progress; the runner adds a crashing path to $SUSSY_SKIP and
// reruns, which resumes where it stopped.
define('SUSSY_LIB', true);
include $SUSSY_MAIN;

$skip = array();
foreach (array($SUSSY_SKIP, $SUSSY_STATE . '/done') as $list) {
    if (file_exists($list)) {
        foreach (explode("\0", file_get_contents($list)) as $file) {
            $skip[$file] = 1;
        }
    }
}
$rows = fopen($SUSSY_STATE . '/rows', 'a');
$done = fopen($SUSSY_STATE . '/done', 'a');
foreach ($SUSSY_DIRS as $dir) {
    $listing = getSortedByPattern($dir, $pattern);
    $seen = array();
    foreach ($listing['file_readable'] as $file) {
        if (isset($skip[$file])) {
            continue;
        }
        $fh = fopen($SUSSY_STATE . '/progress', 'w');
        fwrite($fh, $file);
        fclose($fh);
        foreach (scanReadablePaths(array($file), array(), array(), $tokenNeedles, $seen) as $row) {
            if (!empty($SUSSY_RELATIVE)) {
                $row['path'] = substr($file, strlen(rtrim($dir, '/')) + 1);
            }
            fwrite($rows, jsonEncode($row) . "\n");
        }
        fwrite($done, $file . "\0");
        fflush($rows);
        fflush($done);
    }
}
echo jsonEncode(array('php' => PHP_VERSION, 'weights' => $tokenNeedles, 'roles' => $tokenRoles));
