// Unit tests: fast, no sample corpora, no Docker.
//
// In PHP (test/php/selfcheck.php, also run per PHP version by test/run.js):
// the structural detectors on small snippets, which names the directory
// listing returns, and which ml-model.json files main.php accepts.
// In JS: labels, feature decoding, the trainer's pieces (folds, caps,
// training, quantization) and their agreement with main.php's mlScore(),
// and the corpus list in .gitmodules.
//
// Usage: node test/unit.js
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const lib = require('./lib');

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
    const good = fs.readFileSync(path.join(lib.ROOT, 'ml-model.json'), 'utf8').trim();
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
function prepareSelfcheck(work) {
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
function checkSelfcheck(out, models) {
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

// --- JS unit tests ---
function jsTests() {
    const ml = require('./ml');
    const tests = [];
    const test = (name, fn) => tests.push([name, fn]);
    const assert = (ok, msg) => { if (!ok) throw new Error(msg); };

    test('isRunnable: PHP, or another server language, but not plain text', () => {
        assert(lib.isRunnable({ has_php: true, matched_tokens: [] }), 'PHP file');
        assert(lib.isRunnable({ has_php: false, matched_tokens: ['@foreign_code'] }), 'ASP file');
        assert(!lib.isRunnable({ has_php: false, matched_tokens: [] }), 'robots.txt');
    });

    test('decodeBits matches the bitmap, upper- and lowercase', () => {
        const hex = 'a3' + '0'.repeat(508) + 'f1';
        const want = []; for (let i = 0; i < hex.length; i++) for (let b = 0; b < 4; b++) if (parseInt(hex[i], 16) & (1 << b)) want.push(i * 4 + b);
        assert(JSON.stringify([...ml.decodeBits(hex)]) === JSON.stringify(want), 'lowercase');
        assert(JSON.stringify([...ml.decodeBits(hex.toUpperCase())]) === JSON.stringify(want), 'uppercase');
    });

    test("quantized model: trainer's scorer equals main.php's mlScore()", () => {
        const ctx = lib.loadScoring({ weights: {} });
        const w = Float64Array.from({ length: 2048 }, (_, i) => Math.sin(i * 12.9898) * 1.5);
        const model = ml.quantize({ w, b: 0.3 });
        const score = ml.scorer(model);
        for (let t = 0; t < 50; t++) {
            let hex = ''; for (let i = 0; i < 512; i++) hex += ((i * 7 + t * 13) % 16).toString(16);
            const a = score(ml.decodeBits(hex)), b = ctx.mlScore(hex, model);
            assert(Math.abs(a - b) < 1e-12, `sample ${t}: ${a} vs ${b}`);
        }
    });

    const fakeSamples = () => {
        const s = [];
        for (let i = 0; i < 60; i++) s.push({ label: 1, md5: lib.sha1('s' + i), group: 'shell:' + (i % 20), corpus: 'shells', bits: Uint16Array.of(i % 7, 100) });
        for (let i = 0; i < 300; i++) s.push({ label: 0, md5: lib.sha1('b' + i), group: 'family:f' + (i % 9), corpus: 'c' + (i % 12), family: 'f' + (i % 9), bits: Uint16Array.of(200 + i % 5, 300) });
        return s;
    };
    const foldsOf = s => Object.fromEntries(s.map(d => [d.md5, d.fold]));

    test('folds keep groups whole and ignore listing order', () => {
        const a = fakeSamples(), b = fakeSamples().reverse();
        ml.assignFolds(a, 5); ml.assignFolds(b, 5);
        const sorted = x => JSON.stringify(Object.entries(foldsOf(x)).sort());
        assert(sorted(a) === sorted(b), 'listing order changed the folds');
        for (const [, members] of lib.groupBy(a, d => d.group)) assert(new Set(members.map(d => d.fold)).size === 1, 'a group was split');
        assert(new Set(a.map(d => d.fold)).size === 5, 'not every fold used');
    });

    test('benign cap picks the same files whatever the order', () => {
        const pick = s => ml.capPerCorpus(s.filter(d => !d.label), 10).map(d => d.md5).sort().join();
        const a = fakeSamples();
        assert(pick(a) === pick(a.slice().reverse()), 'order changed the cap');
        assert(ml.capPerCorpus(a.filter(d => !d.label), 10).length === 12 * 10, 'cap per corpus');
    });

    test('training separates a separable set; workers give identical weights', async () => {
        const s = fakeSamples(), packed = ml.pack(s), idx = s.map(d => d.idx);
        const opts = { buckets: 2048, epochs: 60, l2: 0.001 };
        const local = ml.train(packed, idx, opts);
        const [worker] = await ml.trainParallel(packed, [idx], opts);
        assert(local.w.every((x, i) => x === worker.w[i]) && local.b === worker.b, 'worker weights differ');
        const score = ml.scorer(ml.quantize(local));
        assert(s.every(d => (score(d.bits) >= 0.5) === (d.label === 1)), 'not separated');
    });

    test('.gitmodules: samples labelled by folder, benchmark set present', () => {
        const corpora = lib.loadCorpora();
        assert(corpora.some(c => c.label === 'shell') && corpora.some(c => c.label === 'benign'), 'both labels');
        assert(corpora.every(c => c.commit), 'every sample pinned');
        const bench = corpora.filter(c => c.benchmark);
        assert(bench.some(c => c.label === 'shell') && bench.some(c => c.label === 'benign'), 'benchmark set has both labels');
    });

    test('scoring block constants', () => {
        const ctx = lib.loadScoring({ weights: {} });
        ['Z_THRESHOLD', 'ANOMALY_SCORE', 'CRITICAL_SCORE', 'ML_THRESHOLD', 'ML_FLOOR'].forEach(n => assert(typeof lib.constant(ctx, n) === 'number', n));
    });
    return tests;
}

async function main() {
    let failed = 0;
    const work = fs.mkdtempSync(path.join(os.tmpdir(), 'sussy-unit-'));
    try {
        const prep = prepareSelfcheck(work);
        const job = lib.phpJob(path.join(work, 'selfcheck-job.php'), path.join(__dirname, 'php', 'selfcheck.php'), prep.vars(lib.MAIN));
        const raw = execFileSync('php', ['-d', 'error_log=' + path.join(work, 'php-errors.log'), job]).toString();
        const out = JSON.parse(raw.slice(raw.indexOf('{')));
        const failures = checkSelfcheck(out, prep.models);
        failures.forEach(f => console.log('FAIL ' + f));
        console.log(`${failures.length ? 'FAIL' : 'PASS'} PHP ${out.php}: ${CASES.length} detector cases, listing, ${prep.models.names.length} model files`);
        failed += failures.length;
    } finally {
        fs.rmSync(work, { recursive: true, force: true });
    }
    for (const [name, fn] of jsTests()) {
        try { await fn(); console.log('PASS ' + name); } catch (e) { failed++; console.log(`FAIL ${name}: ${e.message}`); }
    }
    console.log(failed ? `${failed} failed` : 'all passed');
    process.exit(failed ? 1 : 0);
}

module.exports = { CASES, LISTING_WANT, prepareSelfcheck, checkSelfcheck };
if (require.main === module) main();
