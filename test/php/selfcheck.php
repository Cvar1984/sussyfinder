<?php
// Unit checks run inside PHP for `test/run unit` (and per PHP version by
// `test/run matrix`; test/lib/selfcheck.js writes the inputs and judges the
// output): structural signals for each snippet in $SUSSY_CASES, the
// listing of the fixture directory $SUSSY_FIXTURE, and ml-model.json
// validation. Set by the prelude (test/lib/php.js phpJob): $SUSSY_MAIN,
// $SUSSY_CASES, $SUSSY_FIXTURE, $SUSSY_MODELS, $SUSSY_CHECKSUM_FIXTURE. Must stay PHP
// 4.3-safe.
define('SUSSY_LIB', true);
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
// install (de_DE) with a plugin and a vendor library. The manifests are seeded
// in the APIs' own formats (escaped slashes, an md5 list, upper case), so
// nothing here touches the network.
$cs = $SUSSY_CHECKSUM_FIXTURE . '/site';
$coreMd5 = md5_file($cs . '/wp-login.php');
$pluginMd5 = md5_file($cs . '/wp-content/plugins/demo/inc/x.php');
$vendorMd5 = md5_file($cs . '/vendor/acme/lib/src/A.php');
$manifests = &checksumManifests();
$manifests['wp-core:6.6.2:de_DE'] = parseWordPressCoreChecksums('{"checksums":{"wp-login.php":"' . strtoupper($coreMd5) . '","wp-admin\\/about.php":"' . str_repeat('0', 32) . '"}}');
$manifests['wp-plugin:demo:1.2'] = parseWordPressPluginChecksums('{"plugin":"demo","version":"1.2","source":"https:\\/\\/x\\/","files":{"inc\\/x.php":{"md5":["' . str_repeat('f', 32) . '","' . $pluginMd5 . '"],"sha256":["a","b"]},"demo.php":{"md5":"' . str_repeat('e', 32) . '","sha256":"c"}}}');
$manifests['list:' . _CHECKSUMS_URL_] = parseChecksumList($vendorMd5 . " acme src/A.php\nnot a checksum line\n");
$checksums = array(
    'install' => wordpressInstall($cs . '/wp-content/plugins/demo/inc/x.php'),
    'core' => $manifests['wp-core:6.6.2:de_DE'],
    'plugin' => $manifests['wp-plugin:demo:1.2'],
    'header' => array(pluginHeaderVersion(file_get_contents($cs . '/wp-content/plugins/demo/demo.php')), pluginHeaderVersion("<?php\n// Version: 9\n")),
    'verified' => array(
        checksumVerified($cs . '/wp-login.php', $coreMd5),                     // core file
        checksumVerified($cs . '/wp-login.php', md5('changed')),               // core file, modified
        checksumVerified($cs . '/wp-content/plugins/demo/inc/x.php', $pluginMd5), // plugin file
        checksumVerified($cs . '/vendor/acme/lib/src/A.php', $vendorMd5),      // release file in place
        checksumVerified($SUSSY_CHECKSUM_FIXTURE . '/elsewhere/A.php', $vendorMd5), // same bytes, wrong place
        checksumVerified($cs . '/vendor/acme/lib/xsrc/A.php', $vendorMd5),     // suffix not at a directory
    ),
);

echo jsonEncode(array('php' => PHP_VERSION, 'cases' => $cases, 'listing' => $names, 'outside_warned' => $outsideWarned, 'models' => $models, 'units' => $unitProbes, 'checksums' => $checksums));
