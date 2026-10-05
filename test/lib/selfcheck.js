// The PHP-side unit checks, run by `test/run unit` on the local php and by
// `test/run matrix` on every PHP version: test/php/selfcheck.php runs main.php's
// detectors on small snippets, lists a fixture directory, and validates
// model files; this module writes those inputs and judges the output.
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { ROOT, MODEL, PHP_JOBS } = require('./paths');
const { phpJob, jobJson } = require('./php');

const JOB = path.join(PHP_JOBS, 'selfcheck.php');

// --- Structural detector cases: snippet => signals that must / must not appear ---
const CASES = [
    ["<?php $_GET['a']($_GET['b']);", ['@input_call', '@dyn_call'], []],
    ["<?php $f = 'ba'.'se64_decode';", ['base64_decode', '@concat_name'], []],
    ['<?php $f = "\\x73ystem";', ['system', '@concat_name'], []],
    ["<?php 'system'('id');", ['system', '@concat_name', '@dyn_call'], []],
    ["<?php \\system('id');", ['system'], []],
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
    const models = buildModels(work);
    return {
        models,
        vars: (mainPhp, phpWork = work) => ((inPhp) => ({
            SUSSY_MAIN: mainPhp, SUSSY_CASES: inPhp(path.join(work, 'cases.txt')),
            SUSSY_FIXTURE: inPhp(path.join(work, 'fixture')), SUSSY_MODELS: models.paths.map(inPhp),
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
        return { php: out.php, failures: check(out, prep.models), summary: `${CASES.length} detector cases, listing, ${prep.models.names.length} model files` };
    } catch (e) {
        return { php: '?', failures: ['the PHP self-check produced no JSON: ' + e.message.split('\n')[0]] };
    }
}

module.exports = { CASES, LISTING_WANT, prepare, check, run };
