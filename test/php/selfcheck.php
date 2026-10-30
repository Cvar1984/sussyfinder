<?php
// Unit checks run inside PHP for `test/run unit` (and per PHP version by
// `test/run matrix`; test/lib/selfcheck.js writes the inputs and judges the
// output): structural signals for each snippet in $SUSSY_CASES, the
// listing of the fixture directory $SUSSY_FIXTURE, and ml-model.json
// validation. Set by the prelude (test/lib/php.js phpJob): $SUSSY_MAIN,
// $SUSSY_CASES, $SUSSY_FIXTURE, $SUSSY_MODELS, $SUSSY_CHECKSUM_FIXTURE. Must stay PHP
// 4.3-safe.
define('SUSSY_LIB', true);
// The download cache in a fresh temporary folder (/work is read-only in containers)
$cacheDir = (function_exists('sys_get_temp_dir') ? sys_get_temp_dir() : '/tmp') . '/sussy-cache-' . getmypid();
define('CACHE_DIR', $cacheDir);
// Vendor checksums read local stand-ins for their downloads
define('_CHECKSUMS_URL_', $SUSSY_CHECKSUM_FIXTURE . '/checksums.txt');
define('_WP_CORE_CHECKSUMS_URL_', $SUSSY_CHECKSUM_FIXTURE . '/manifests/core-{version}-{locale}.json');
define('_WP_PLUGIN_CHECKSUMS_URL_', $SUSSY_CHECKSUM_FIXTURE . '/manifests/plugin-{slug}-{version}.json');
include $SUSSY_MAIN;

$cases = array();
foreach (explode("\0", file_get_contents($SUSSY_CASES)) as $src) {
    $cases[] = matchTokens($src, $tokenNeedles);
}

$GLOBALS['phpWarnings'] = array();
$listing = listFiles($SUSSY_FIXTURE, $pattern, '', 0);
$names = array();
foreach ($listing['file_readable'] as $file) {
    $names[] = rawurlencode(basename($file));
}
// Paged listing: a file per page, followed to the end, lists what one page
// does, each file once; a made-up "after" only skips names, never leaves the
// directory; a file gone before it is read stays in the results
$paged = array();
$after = '';
$pages = 0;
do {
    $page = listFiles($SUSSY_FIXTURE, $pattern, $after, 1);
    $paged = array_merge($paged, $page['file_readable'], $page['file_not_readable']);
    $after = $page['next'];
} while ($after !== null && ++$pages < 100);
$full = array_merge($listing['file_readable'], $listing['file_not_readable']);
sort($paged);
sort($full);
$inside = true;
foreach (array('..', '../..', '%2Fetc', '%2E%2E%2F%2E%2E', 'out', 'out/etc', 'sub/../..', 'zzz') as $cursor) {
    $page = listFiles($SUSSY_FIXTURE, $pattern, $cursor, 1);
    foreach (array_merge($page['file_readable'], $page['file_not_readable']) as $file) {
        $inside = $inside && strpos($file, realpath($SUSSY_FIXTURE) . '/') === 0;
    }
}
$seen = array();
$gone = scanReadablePaths(array($SUSSY_FIXTURE . '/missing.php'), array(), array(), $tokenNeedles, $seen);
$limits = array();
foreach (array(0, 2, 10, 100) as $limit) {
    ini_set('max_execution_time', $limit);
    $limits[] = listSeconds();
}
$paging = array('equal' => $paged === $full && count($full) > 1, 'pages' => $pages + 1, 'inside' => $inside,
    'gone' => count($gone) == 1 && $gone[0]['gone'] === true && $gone[0]['is_unreadable'] === true, 'seconds' => $limits);

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

// Per-unit ML segmentation (mlFeatureUnits()): a file with top-level functions
// and classes yields the whole-file vector first, then one vector per unit, so
// a shell injected into a big legitimate file is scored on its own function
// instead of diluted. Locked per PHP version so every build segments alike.
$unitProbes = array();
$probes = array(
    // inline code only: just the whole-file vector, no sub-units
    "<?php echo \$_GET['x']; system(\$_POST['c']); \$a = base64_decode(\$_REQUEST['d']); eval(\$a);",
    // two functions and a class around a main body: whole + 3 units
    "<?php\n"
        . "function alpha(\$a, \$b) { \$r = \$a + \$b; \$r = \$r * 2; \$r = str_repeat('x', \$r); return strrev(\$r); }\n"
        . "class Beta { function gamma(\$n) { \$s = 0; for (\$i = 0; \$i < \$n; \$i++) { \$s += \$i; } return \$s; } }\n"
        . "\$z = alpha(1, 2); \$y = strlen(\$z); echo \$y . \$z;\n",
);
foreach ($probes as $probe) {
    $sig = codeTokens(getFileTokens($probe));
    $sig = $sig['sig'];
    $maxLine = maxLineLength($probe);
    $entropy = shannonEntropy($probe);
    $units = mlFeatureUnits($sig, $maxLine, $entropy);
    $unitProbes[] = array('count' => count($units), 'firstIsWhole' => $units[0] === mlFeatures($sig, $maxLine, $entropy));
}

// Vendor checksums (checksumVerified()) on $SUSSY_CHECKSUM_FIXTURE: a WordPress
// install (de_DE) with a plugin and a vendor library, its manifests local files
$cs = $SUSSY_CHECKSUM_FIXTURE . '/site';
$vendorMd5 = md5_file($cs . '/vendor/acme/lib/src/A.php');
$checksums = array(
    'json' => functionAvailable('json_decode'),
    'root' => checksumRoot($cs . '/wp-content/plugins/demo/inc/x.php', 'wp-includes/version.php'),
    'verified' => array(
        checksumVerified($cs . '/wp-login.php', md5_file($cs . '/wp-login.php')),
        checksumVerified($cs . '/wp-login.php', md5('changed')),
        checksumVerified($cs . '/wp-content/plugins/demo/inc/x.php', md5_file($cs . '/wp-content/plugins/demo/inc/x.php')),
        checksumVerified($cs . '/vendor/acme/lib/src/A.php', $vendorMd5),
        checksumVerified($SUSSY_CHECKSUM_FIXTURE . '/elsewhere/A.php', $vendorMd5),
        checksumVerified($cs . '/vendor/acme/lib/xsrc/A.php', $vendorMd5),
    ),
);

// The download cache: kept downloads and 404s come back, fetchText() answers
// from it without the network (example.invalid can't resolve), clearing empties it
cacheStore('https://example.invalid/list.txt', "abc\n");
cacheStore('https://example.invalid/missing.json', null);
$cache = array(
    cacheLoad('https://example.invalid/list.txt'),
    cacheLoad('https://example.invalid/missing.json'),
    cacheLoad('https://example.invalid/never.txt'),
    fetchText('https://example.invalid/list.txt'),
    fetchText('https://example.invalid/missing.json', true),
    cacheClear(),
    cacheLoad('https://example.invalid/list.txt'),
);
@rmdir($cacheDir);
// The temp folder is found, and a cache folder other users can write to (one
// another hosting account could have planted) is refused
$openDir = $cacheDir . '-open';
@mkdir($openDir);
@chmod($openDir, 0777);
$cache[] = is_string(tempDir()) && is_writable(tempDir());
$cache[] = cacheDirIsOwn($openDir);
@rmdir($openDir);

echo jsonEncode(array('php' => PHP_VERSION, 'cases' => $cases, 'listing' => $names, 'outside_warned' => $outsideWarned, 'models' => $models, 'units' => $unitProbes, 'checksums' => $checksums, 'cache' => $cache, 'paging' => $paging));
