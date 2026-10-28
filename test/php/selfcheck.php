<?php
// Unit checks run inside PHP for `test/run unit` (and per PHP version by
// `test/run matrix`; test/lib/selfcheck.js writes the inputs and judges the
// output): structural signals for each snippet in $SUSSY_CASES, the
// listing of the fixture directory $SUSSY_FIXTURE, and ml-model.json
// validation. Set by the prelude (test/lib/php.js phpJob): $SUSSY_MAIN,
// $SUSSY_CASES, $SUSSY_FIXTURE, $SUSSY_MODELS, $SUSSY_CHECKSUM_FIXTURE. Must stay PHP
// 4.3-safe.
define('SUSSY_LIB', true);
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

echo jsonEncode(array('php' => PHP_VERSION, 'cases' => $cases, 'listing' => $names, 'outside_warned' => $outsideWarned, 'models' => $models, 'units' => $unitProbes, 'checksums' => $checksums));
