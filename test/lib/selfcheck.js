// The PHP-side unit checks, run by `test/run unit` on the local php and by
// `test/run matrix` on every PHP version: test/php/selfcheck.php runs main.php's
// detectors on small snippets, lists a fixture directory, and validates
// model files; this module writes those inputs and judges the output.
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { ROOT, MODEL, PHP_JOBS } = require('./paths');
const { phpJob, jobJson } = require('./php');
const { md5 } = require('./util');

const JOB = path.join(PHP_JOBS, 'selfcheck.php');

// --- Structural detector cases: snippet => signals that must / must not appear ---
const CASES = [
    ["<?php $_GET['a']($_GET['b']);", ['@input_call', '@dyn_call'], []],
    ["<?php $f = 'ba'.'se64_decode';", ['base64_decode', '@concat_name'], []],
    ['<?php $f = "\\x73ystem";', ['system', '@concat_name'], []],
    ["<?php 'system'('id');", ['system', '@concat_name', '@dyn_call'], []],
    ["<?php \\system('id');", ['system'], []],
    // A needle name counts only as a call to the global function
    ["<?php namespace Drupal\\Tests\\system\\Functional; use Magento\\Framework\\Exec; class System {}", [], ['system', 'exec']],
    ["<?php $a = new Exec(); Exec::run(); $b instanceof System; Foo\\system('x');", [], ['system', 'exec']],
    ["<?php @system($_GET['c']);", ['system'], []],
    // An execution function named as a string, reached by a callback
    ["<?php array_map('ass'.'ert', $_POST['c']);", ['assert', '@callback_exec'], []],
    // PHP 4's long request arrays are request input like $_POST
    ["<?php system($HTTP_POST_VARS['c']); move_uploaded_file($HTTP_POST_FILES['f']['tmp_name'], 'x');",
        ['system', '$http_post_vars', '$http_post_files'], []],
    // assert() of a string or request value runs it as PHP; a bare assert($expr)
    // test assertion does not
    ["<?php assert(\"ev\".\"al\");", ['assert', '@assert_exec'], []],
    ["<?php assert($_POST['c']);", ['assert', '@assert_exec'], []],
    ["<?php assert($count === 3);", ['assert'], ['@assert_exec']],
    // new COM(...)/new DOTNET(...): Windows command execution
    ["<?php $o = new COM('WScript.Shell'); $o->Run($_GET['c']);", ['@com_exec'], []],
    ["<?php $x = new \\DOTNET('a', 'b');", ['@com_exec'], []],
    // a plain class named Com* must NOT trip @com_exec
    ["<?php $x = new Comment($a);", [], ['@com_exec']],
    ["<?php filter_var($_GET['x'], FILTER_CALLBACK, array('options' => 'shell_exec'));", ['shell_exec', '@callback_exec'], []],
    ["<?php $m = array('name' => 'system', 'run' => 'exec');", [], ['@callback_exec']],
    // Execution via include: a stream wrapper, a request superglobal, XSLT into PHP
    ["<?php include('php://input');", ['@wrapper_include'], []],
    ["<?php include $_GET['f'];", ['@input_include'], []],
    ["<?php require_once $_REQUEST['p'] . '.php';", ['@input_include'], []],
    ["<?php include $_SERVER['DOCUMENT_ROOT'] . '/inc.php'; require 'config.php';", [], ['@input_include', '@wrapper_include']],
    ['<?php echo `id`;', ['`'], []],
    ["<?php preg_replace('/x/e', $_POST['c'], 'x');", ['@preg_e'], []],
    ["<?php \\preg_replace('/x/e', $_POST['c'], 'x');", ['@preg_e'], []], // one token on PHP 8, three before
    ["<?php preg_replace('#x#i', 'y', 'x'); function_exists('exec');", [], ['@preg_e', 'exec', '@concat_name']],
    ['<?php $q = "SELECT `{$t}`"; $s = "$a eval";', [], ['`', 'eval']],
    ["<?php $this->exec('x'); A::system(); new $cls(); $o->$m();", [], ['exec', 'system', '@dyn_call']],
    ['<?php __halt_compiler();' + 'A'.repeat(2000), ['@halt_payload'], []],
    ["<?php $x = '" + 'A'.repeat(6000) + "';", ['@long_line'], []],
    ["<?if(1)shell_exec($_GET['c']);", ['shell_exec'], []], // short open tag, whatever this host's short_open_tag
    ['<%@ Page Language="C#" %><% Response.Write(Request.Form["c"]); %>', ['@foreign_code'], []],
    ['<%@ LANGUAGE = VBScript.Encode %><%#@~^XAAAAA==encoded%>', ['@foreign_code'], []],
    ['#!/usr/bin/perl\nuse CGI;\nprint `id`;', ['@foreign_code'], []],
    ['#!/usr/bin/env perl\nprint "Content-type: text/html\\n\\n";', ['@foreign_code'], []],
    ['<html><% if (x) { %>tpl<% } %></html><?php echo 1; ?>', [], ['@foreign_code']],
    ['<% if user %><p>Hello</p><% end %>', [], ['@foreign_code']], // an ERB/EJS template is not ASP
];

// --- Listing fixture: the names getSortedByPattern must return (rawurlencoded) ---
// It also holds what must NOT be listed or must not hang the scan: a FIFO
// named .php, a "root -> /" symlink (not followed, but warned about), and
// non-PHP names.
const LISTING_WANT = ['.user.ini', 'a.php', 'caf%E9.php', 'deep.php', 'it%27s%20%22odd%22.php', 'linked.php', 'shell.php.', 'x.php.jpg'].sort();
// Expected mlFeatureUnits() unit counts for selfcheck.php's probes, in order.
const UNIT_PROBES = [1, 4];
function buildFixture(work) {
    const fixture = path.join(work, 'fixture');
    fs.mkdirSync(path.join(fixture, 'sub'), { recursive: true });
    fs.mkdirSync(path.join(work, 'outside'), { recursive: true });
    const body = '<?php $f = "ba"."se64_decode"; `id`;';
    ['a.php', 'x.php.jpg', 'shell.php.', '.user.ini', 'notes.txt', 'jquery.shape.js', 'it\'s "odd".php', 'sub/deep.php', '../outside/target.php']
        .forEach(n => fs.writeFileSync(path.join(fixture, n), body));
    fs.writeFileSync(Buffer.from(path.join(fixture, 'caf') + '\xe9.php', 'latin1'), body); // not valid UTF-8
    execFileSync('mkfifo', [path.join(fixture, 'fifo.php')]);
    fs.symlinkSync('/', path.join(fixture, 'out'));
    fs.symlinkSync('../outside/target.php', path.join(fixture, 'linked.php'));
    return fixture;
}

// --- Vendor checksums fixture (checksumVerified()): a WordPress install
// (de_DE) with a plugin and a vendor library, and local stand-ins for the
// manifests in the APIs' own formats (escaped slashes, upper case, an md5
// list). Only an en_US core manifest exists, so the locale falls back. ---
const CORE = '<?php // core file\n', PLUGIN = '<?php // plugin file\n', VENDOR = '<?php // vendor file\n';
function buildChecksumFixture(work) {
    const dir = path.join(work, 'checksums');
    const files = {
        'site/wp-includes/version.php': "<?php\n$wp_version = '6.6.2';\n$wp_local_package = 'de_DE';\n",
        'site/wp-login.php': CORE,
        'site/wp-content/plugins/demo/demo.php': '<?php\n/**\n * Plugin Name: Demo\n * Version: 1.2 */\n',
        'site/wp-content/plugins/demo/inc/x.php': PLUGIN,
        'site/vendor/acme/lib/src/A.php': VENDOR,
        'site/vendor/acme/lib/xsrc/A.php': VENDOR,
        'elsewhere/A.php': VENDOR,
        'manifests/core-6.6.2-en_US.json': '{"checksums":{"wp-login.php":"' + md5(CORE).toUpperCase() + '","wp-admin\\/about.php":"' + '0'.repeat(32) + '"}}',
        'manifests/plugin-demo-1.2.json': '{"plugin":"demo","version":"1.2","files":{"inc\\/x.php":{"md5":["' + 'f'.repeat(32) + '","' + md5(PLUGIN) +
            '"],"sha256":["a","b"]},"demo.php":{"md5":"' + 'e'.repeat(32) + '","sha256":"c"}}}',
        'checksums.txt': md5(VENDOR) + ' acme src/A.php\nnot a checksum line\n',
    };
    Object.entries(files).forEach(([name, text]) => {
        fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
        fs.writeFileSync(path.join(dir, name), text);
    });
    return dir;
}
// selfcheck.php's probes, in order: core file, the same modified, plugin file,
// release file in place, the same bytes elsewhere, a suffix not at a directory.
// Without json_decode() (PHP < 5.2) only checksums.txt can verify.
const checksumWant = json => [json ? 'WordPress 6.6.2 core' : false, false, json ? 'WordPress.org plugin demo 1.2' : false, 'acme release file src/A.php', false, false];

// --- Model files main.php must accept (true) or refuse (false) ---
function buildModels(work) {
    const good = fs.readFileSync(MODEL, 'utf8').trim();
    const files = {
        'shipped.json': [good, true],
        'other-version.json': [good.replace(/"features":\d+/, '"features":999'), false],
        'injection.json': [good.replace('"weights":"', '"weights":"</script><script>alert(1)</script>'), false],
        'truncated.json': [good.slice(0, 200), false],
        'not-json.json': ['404: Not Found', false],
    };
    const dir = path.join(work, 'models');
    fs.mkdirSync(dir, { recursive: true });
    Object.entries(files).forEach(([name, [text]]) => fs.writeFileSync(path.join(dir, name), text));
    return { names: Object.keys(files), want: Object.values(files).map(([, ok]) => ok), paths: Object.keys(files).map(n => path.join(dir, n)) };
}

/**
 * Write everything selfcheck.php reads into `work`: cases, fixture, model
 * files. Returns the expected model results and vars(mainPhp, phpWork): the
 * prelude variables, given where PHP sees main.php and `work` (the same path
 * locally, a mount point in a container).
 */
function prepare(work) {
    fs.writeFileSync(path.join(work, 'cases.txt'), CASES.map(c => c[0]).join('\0'));
    buildFixture(work);
    buildChecksumFixture(work);
    const models = buildModels(work);
    return {
        models,
        vars: (mainPhp, phpWork = work) => ((inPhp) => ({
            SUSSY_MAIN: mainPhp, SUSSY_CASES: inPhp(path.join(work, 'cases.txt')),
            SUSSY_FIXTURE: inPhp(path.join(work, 'fixture')), SUSSY_MODELS: models.paths.map(inPhp),
            SUSSY_CHECKSUM_FIXTURE: inPhp(path.join(work, 'checksums')),
        }))(p => path.join(phpWork, path.relative(work, p))),
    };
}

/** Compare selfcheck.php's output with what's expected; returns failures as text */
function check(out, models) {
    const failures = [];
    CASES.forEach(([src, want, reject], i) => {
        const got = out.cases[i] || [];
        const bad = want.filter(x => !got.includes(x)).map(x => 'missing ' + x).concat(reject.filter(x => got.includes(x)).map(x => 'unexpected ' + x));
        if (bad.length) failures.push(`detector: ${JSON.stringify(src.slice(0, 50))}: ${bad.join(', ')}  got [${got}]`);
    });
    const listed = (out.listing || []).slice().sort();
    if (JSON.stringify(listed) !== JSON.stringify(LISTING_WANT)) failures.push(`listing: got [${listed.join(', ')}]`);
    if (out.outside_warned !== true) failures.push('listing: no warning for the symlink leading outside');
    models.want.forEach((ok, i) => { if ((out.models || [])[i] !== ok) failures.push(`ml-model.json check: ${models.names[i]} should be ${ok ? 'accepted' : 'refused'}`); });
    // mlFeatureUnits() segmentation, in selfcheck.php's probe order: inline-only
    // code is one vector (the whole file), functions+class around a main body
    // is four (whole + alpha + Beta + main). The first is always the whole file.
    UNIT_PROBES.forEach((want, i) => {
        const got = (out.units || [])[i];
        if (!got || got.count !== want || got.firstIsWhole !== true) {
            failures.push(`mlFeatureUnits probe ${i}: want ${want} units (whole-file first), got ${JSON.stringify(got)}`);
        }
    });
    // Vendor checksums: install detection, manifests, matching
    const cs = out.checksums || {};
    if (!/\/site$/.test(cs.root || '')) failures.push(`checksumRoot: want .../site, got ${JSON.stringify(cs.root)}`);
    const want = checksumWant(cs.json === true);
    if (JSON.stringify(cs.verified) !== JSON.stringify(want)) failures.push(`checksumVerified: want ${JSON.stringify(want)}, got ${JSON.stringify(cs.verified)}`);
    // Download cache: stored text, a kept 404 (null), not cached (false), the
    // same two through fetchText(), 2 files cleared, then gone
    const cacheWant = ['abc\n', null, false, 'abc\n', false, 2, false];
    if (JSON.stringify(out.cache) !== JSON.stringify(cacheWant)) failures.push(`download cache: want ${JSON.stringify(cacheWant)}, got ${JSON.stringify(out.cache)}`);
    return failures;
}

/**
 * Run the checks with a PHP: `php(jobFile)` resolves to its stdout, `repo`
 * and `phpWork` are where that PHP sees the repository and `work`, and
 * the job file is written to `work` as `name`.php. Resolves to
 * { php, failures, summary }.
 */
const prepared = new Map(); // work dir => prepare() result: every PHP version reads the same inputs
async function run({ work, php, repo, phpWork = work, name = 'selfcheck' }) {
    if (!prepared.has(work)) prepared.set(work, prepare(work));
    const prep = prepared.get(work);
    const inPhp = p => path.join(phpWork, path.relative(work, p));
    const job = phpJob(path.join(work, name + '.php'), path.join(repo, path.relative(ROOT, JOB)), prep.vars(path.join(repo, 'main.php'), phpWork));
    try {
        const out = jobJson(await php(inPhp(job)));
        return { php: out.php, failures: check(out, prep.models), summary: `${CASES.length} detector cases, listing, ${prep.models.names.length} model files, ${UNIT_PROBES.length} unit probes, ${checksumWant(true).length} checksum probes, download cache` };
    } catch (e) {
        return { php: '?', failures: ['the PHP self-check produced no JSON: ' + e.message.split('\n')[0]] };
    }
}

module.exports = { CASES, LISTING_WANT, prepare, check, run };
