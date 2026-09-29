// Unified test runner: detector self-checks + detection benchmark, on the local
// PHP or on every PHTest version (plus a page/AJAX smoke test there).
//
// For each PHP it runs main.php's real feature extraction (via the SUSSY_LIB
// include) over test/webshells (malicious) mixed with test/WordPress +
// test/laravel (benign), then scores the rows with main.php's real client-side
// scoring block and prints detection/false-positive rates.
//
// Usage:
//   node test/run.js                         local `php` only
//   node test/run.js --php all               every version in PHTest/versions.list (docker)
//   node test/run.js --php 4.3.11,8.5.6      just those versions
//   extra: --list (misses/false positives), --tokens (per-token counts), --threshold 3.5
//
// Exits 1 if a self-check fails, a supported version (4.3+) can't extract
// features, or its page/AJAX smoke test fails. A file that crashes PHP itself
// is skipped and reported, not failed. Containers mount the repo
// READ-ONLY so a blacklist hit can never delete corpus files.
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');

const root = path.join(__dirname, '..');
const args = process.argv.slice(2);
const opt = name => { const i = args.indexOf(name); return i === -1 ? null : args[i + 1]; };
const threshold = parseFloat(opt('--threshold') || '3.5');
const web = fs.readFileSync(path.join(root, 'main.php'), 'utf8');
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'sussy-test-'));
fs.chmodSync(work, 0o755); // Apache in the containers runs as www-data
const containers = [];
process.on('exit', () => {
    containers.forEach(c => { try { execFileSync('docker', ['rm', '-f', c], { stdio: 'ignore' }); } catch (e) { } });
    fs.rmSync(work, { recursive: true, force: true });
});
process.on('SIGINT', () => process.exit(130));
const sleep = ms => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

// --- Structural detector self-checks: snippet => signals that must / must not appear ---
const cases = [
    ["<?php $_GET['a']($_GET['b']);", ['@input_call', '@dyn_call'], []],
    ["<?php $f = 'ba'.'se64_decode';", ['base64_decode', '@concat_name'], []],
    ['<?php $f = "\\x73ystem";', ['system', '@concat_name'], []],
    ["<?php 'system'('id');", ['system', '@concat_name', '@dyn_call'], []],
    ["<?php \\system('id');", ['system'], []],
    ["<?php echo `id`;", ['`'], []],
    ["<?php preg_replace('/x/e', $_POST['c'], 'x');", ['@preg_e'], []],
    ["<?php preg_replace('#x#i', 'y', 'x'); function_exists('exec');", [], ['@preg_e', 'exec', '@concat_name']],
    ['<?php $q = "SELECT `{$t}`"; $s = "$a eval";', [], ['`', 'eval']],
    ["<?php $this->exec('x'); A::system(); new $cls(); $o->$m();", [], ['exec', 'system', '@dyn_call']],
    ["<?php __halt_compiler();" + 'A'.repeat(2000), ['@halt_payload'], []],
    ["<?php $x = '" + 'A'.repeat(6000) + "';", ['@long_line'], []],
    ["<?if(1)shell_exec($_GET['c']);", ['shell_exec'], []], // short open tag, whatever this host's short_open_tag
];
fs.writeFileSync(path.join(work, 'cases.txt'), cases.map(c => c[0]).join('\0'));

// --- Listing fixture: which names getSortedByPattern must return (rawurlencoded) ---
// Also holds what must NOT be listed or must not hang the scan: a FIFO named
// .php, a "root -> /" symlink (not followed, but warned about), non-PHP names.
const fixture = path.join(work, 'fixture');
fs.mkdirSync(path.join(fixture, 'sub'), { recursive: true });
fs.mkdirSync(path.join(work, 'outside'));
const shellBody = '<?php $f = "ba"."se64_decode"; `id`;';
['a.php', 'x.php.jpg', 'shell.php.', '.user.ini', 'notes.txt', 'jquery.shape.js', 'it\'s "odd".php', 'sub/deep.php', '../outside/target.php']
    .forEach(n => fs.writeFileSync(path.join(fixture, n), shellBody));
fs.writeFileSync(Buffer.from(path.join(fixture, 'caf') + '\xe9.php', 'latin1'), shellBody); // not valid UTF-8
execFileSync('mkfifo', [path.join(fixture, 'fifo.php')]);
fs.symlinkSync('/', path.join(fixture, 'out'));
fs.symlinkSync('../outside/target.php', path.join(fixture, 'linked.php'));
const listingWant = ['.user.ini', 'a.php', 'caf%E9.php', 'deep.php', 'it%27s%20%22odd%22.php', 'linked.php', 'shell.php.', 'x.php.jpg'].sort();

// Extraction script run by each PHP. Must stay PHP 4.3-safe (no -r in PHP 4 CGI,
// so it's a file; json_encode comes from main.php's fallback on old PHP).
// PHP itself can crash on a file (4.3.0's tokenizer segfaults on some modern
// code), so rows are appended to <state>/rows as they're produced, finished
// paths to <state>/done, and the current path to <state>/progress. After a
// crash the runner adds that path to skip.txt and reruns, which resumes where
// it stopped (the UI isolates such files the same way, one by one).
const phpString = s => "'" + s.replace(/\\/g, '\\\\').replace(/'/g, "\\'") + "'";
const extractScript = (repo, dir, state) => `<?php
define('SUSSY_LIB', true);
include ${phpString(repo + '/main.php')};
$cases = array();
foreach (explode("\\0", file_get_contents(${phpString(dir + '/cases.txt')})) as $src) {
    $t = getFileTokens($src);
    $cases[] = array_values(array_unique(array_merge(compareTokens($tokenNeedles, tokenTextSet($t)), findStructuralSignals($t, $src, $tokenNeedles))));
}
$skip = array_flip(explode("\\0", file_get_contents(${phpString(dir + '/skip.txt')})));
if (file_exists(${phpString(state + '/done')})) {
    foreach (explode("\\0", file_get_contents(${phpString(state + '/done')})) as $file) {
        $skip[$file] = 1;
    }
}
$rows = fopen(${phpString(state + '/rows')}, 'a');
$done = fopen(${phpString(state + '/done')}, 'a');
foreach (array('test/webshells', 'test/WordPress', 'test/laravel') as $corpus) {
    $r = getSortedByPattern(${phpString(repo + '/')} . $corpus, $pattern);
    $seen = array();
    $new = array();
    foreach ($r['file_readable'] as $file) {
        if (isset($skip[$file])) {
            continue;
        }
        $fh = fopen(${phpString(state + '/progress')}, 'w');
        fwrite($fh, $file);
        fclose($fh);
        foreach (scanReadablePaths(array($file), array(), array(), $tokenNeedles, $seen, $new) as $row) {
            fwrite($rows, json_encode($row) . "\\n");
        }
        fwrite($done, $file . "\\0");
        fflush($rows);
        fflush($done);
    }
}
$GLOBALS['phpWarnings'] = array();
$listing = getSortedByPattern(${phpString(dir + '/fixture')}, $pattern);
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
echo json_encode(array('php' => PHP_VERSION, 'weights' => $tokenNeedles, 'cases' => $cases, 'listing' => $names, 'outside_warned' => $outsideWarned));
`;

// --- Targets: local php, or PHTest containers ---
const versionOk = v => { const [a, b] = v.split('.').map(Number); return a > 4 || (a === 4 && b >= 3); };
let targets;
const phpOpt = opt('--php');
if (!phpOpt) {
    const state = path.join(work, 'state');
    fs.mkdirSync(state);
    fs.writeFileSync(path.join(work, 'extract.php'), extractScript(root, work, state));
    targets = [{
        name: 'local', supported: true, repo: root,
        // error_log into the temp dir: a php.ini with error_log=./error_log would litter the repo
        runPhp: () => execFileSync('php', ['-d', 'error_log=' + path.join(work, 'php-errors.log'), path.join(work, 'extract.php')], { maxBuffer: 1 << 28 }),
        read: file => { try { return fs.readFileSync(path.join(state, file), 'utf8'); } catch (e) { return ''; } },
    }];
} else {
    const known = fs.readFileSync(path.join(root, 'PHTest/versions.list'), 'utf8').split('\n')
        .filter(l => l.trim() && !l.startsWith('#')).map(l => { const [v, type] = l.split('|'); return { v, type }; });
    const want = phpOpt === 'all' ? known : phpOpt.split(',').map(v => known.find(k => k.v === v) || { v, type: null });
    fs.writeFileSync(path.join(work, 'extract.php'), extractScript('/var/www/html', '/work', '/tmp'));
    targets = want.map(({ v, type }, i) => {
        const legacy = type === 'legacy';
        const name = 'sf-test-' + v;
        return {
            name: 'PHP ' + v, v, type, supported: versionOk(v), repo: '/var/www/html', port: 18100 + i,
            container: name, legacy,
            runPhp: () => execFileSync('docker', ['exec', name].concat(legacy ? ['php-cgi', '-q'] : ['php'], ['/work/extract.php']), { maxBuffer: 1 << 28, stdio: ['ignore', 'pipe', 'ignore'] }),
            read: file => { try { return execFileSync('docker', ['exec', name, 'cat', '/tmp/' + file], { maxBuffer: 1 << 28, stdio: ['ignore', 'pipe', 'ignore'] }).toString(); } catch (e) { return ''; } },
        };
    });
}

// --- Web smoke test (containers only): page, inline JS, scan + process over HTTP ---
function webCheck(t) {
    const url = `http://127.0.0.1:${t.port}/main.php`;
    const curl = (extra, csrfHeader = true) => {
        const args = ['-s', '-m', '120'].concat(csrfHeader ? ['-H', 'X-Sussy-Request: 1'] : [], extra, [url]);
        try { return execFileSync('curl', args, { maxBuffer: 1 << 26 }).toString(); } catch (e) { return ''; }
    };
    const json = s => { try { return JSON.parse(s); } catch (e) { return null; } };
    const page = curl([], false);
    const js = [...page.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]).join('\n;\n');
    let jsOk = page.includes('</html>');
    try { new vm.Script(js); } catch (e) { jsOk = false; }
    const scan = json(curl(['--data', 'ajax_action=scan', '--data', 'dir=/var/www/html/test/webshells/php']));
    // Must return (the FIFO can't hang it) and list the fixture's 8 names
    const fixtureScan = json(curl(['--data', 'ajax_action=scan', '--data', 'dir=/work/fixture']));
    // Without the CSRF header every action is refused
    const noHeader = json(curl(['--data', 'ajax_action=scan', '--data', 'dir=/work/fixture'], false));
    // Paths are rawurlencoded on the wire, then form-encoded; the Latin-1 name must round-trip
    const micro = '/var/www/html/test/webshells/php/micro.php';
    const microMd5 = require('crypto').createHash('md5').update(fs.readFileSync(path.join(root, 'test/webshells/php/micro.php'))).digest('hex');
    const latin1 = '%2Fwork%2Ffixture%2Fcaf%E9.php';
    const wire = p => encodeURIComponent(encodeURIComponent(p));
    const paths = [wire(micro), wire('/work/fixture/it\'s "odd".php'), encodeURIComponent(latin1)].join('%00');
    const proc = json(curl(['--data', 'ajax_action=process', '--data', 'paths=' + paths,
        '--data', 'seen_hashes=' + encodeURIComponent(microMd5 + ':' + encodeURIComponent('/earlier/micro.php'))]));
    const feats = proc && proc.features || [];
    const procOk = feats.length === 3 && decodeURIComponent(feats[0].duplicate_of) === '/earlier/micro.php' &&
        feats[1].matched_tokens.includes('@concat_name') && feats[2].path === latin1;
    const fixtureOk = !!fixtureScan && fixtureScan.total === listingWant.length;
    const csrfOk = !!noHeader && noHeader.error === 'forbidden';
    const ok = jsOk && !!scan && scan.total > 0 && fixtureOk && procOk && csrfOk;
    return {
        ok, text: `page ${jsOk ? 'OK' : 'BROKEN'}, scan ${scan ? scan.total + ' files' : 'FAIL'}, fixture scan ${fixtureOk ? 'OK' : 'FAIL'}, ` +
            `process ${procOk ? 'OK' : 'FAIL'}, CSRF check ${csrfOk ? 'OK' : 'FAIL'}` + (proc ? ` (${proc.warnings.length} warnings)` : ''),
    };
}

// --- Run ---
let failed = 0;
const results = [];
targets.forEach(t => {
    if (t.container) {
        const ini = t.legacy ? '/usr/local/lib/php.ini' : '/usr/local/etc/php/php.ini';
        const image = t.legacy ? 'phtest-php:' + t.v : `php:${t.v}-apache`;
        try {
            execFileSync('docker', ['rm', '-f', t.container], { stdio: 'ignore' });
            execFileSync('docker', ['run', '-d', '--rm', '--name', t.container, '-p', t.port + ':80',
                '-v', root + ':/var/www/html:ro', '-v', work + ':/work:ro',
                '-v', path.join(root, 'PHTest/conf', t.v, 'php.ini') + ':' + ini + ':ro', image], { stdio: 'ignore' });
            containers.push(t.container);
        } catch (e) {
            console.log(`\n== ${t.name}: container failed to start (image ${image} built?)`);
            if (t.supported) failed++;
            return;
        }
        for (let i = 0; i < 40; i++) {
            try { execFileSync('curl', ['-s', '-o', '/dev/null', `http://127.0.0.1:${t.port}/`]); break; } catch (e) { sleep(250); }
        }
    }

    // Extract features; if PHP dies on a file, skip that file and resume
    let out = null;
    const crashed = [];
    while (!out) {
        fs.writeFileSync(path.join(work, 'skip.txt'), crashed.join('\0'));
        try {
            const raw = t.runPhp().toString();
            out = JSON.parse(raw.slice(raw.indexOf('{')));
        } catch (e) {
            const last = t.read('progress');
            if (!last || crashed.includes(last)) break; // no progress: a real failure, not a per-file crash
            crashed.push(last);
        }
    }
    if (out) {
        const byPath = new Map(); // a crash between writing a row and marking it done can repeat a row
        t.read('rows').split('\n').filter(Boolean).forEach(l => { const row = JSON.parse(l); byPath.set(row.path, row); });
        out.features = [...byPath.values()];
    }
    const r = { t, out, crashed };
    results.push(r);
    console.log(`\n== ${t.name}${out ? ' (' + out.php + ')' : ''}`);
    crashed.forEach(f => console.log(`PHP crashed on     ${f.slice(t.repo.length + 1)} (skipped; the UI isolates such files the same way)`));
    if (!out) {
        console.log(t.supported ? 'FAIL: feature extraction produced no JSON' : 'feature extraction failed (expected: below the PHP 4.3 floor)');
        if (t.supported) failed++;
        if (t.container) { const w = webCheck(t); r.web = w; console.log('web                ' + w.text); if (t.supported && !w.ok) failed++; }
        return;
    }

    // Self-checks
    let casesFailed = 0;
    cases.forEach(([src, want, reject], i) => {
        const got = out.cases[i] || [];
        const bad = want.filter(x => !got.includes(x)).map(x => 'missing ' + x).concat(reject.filter(x => got.includes(x)).map(x => 'unexpected ' + x));
        if (bad.length) { casesFailed++; console.log('  FAIL ' + src.slice(0, 60) + ': ' + bad.join(', ') + '  got [' + got + ']'); }
    });
    console.log(`self-checks        ${cases.length - casesFailed}/${cases.length} passed`);
    if (casesFailed && t.supported) failed++;
    r.casesFailed = casesFailed;

    // Listing checks on the fixture
    const listed = (out.listing || []).slice().sort();
    r.listingOk = JSON.stringify(listed) === JSON.stringify(listingWant) && out.outside_warned === true;
    console.log('listing checks     ' + (r.listingOk ? 'OK' : `FAIL: got [${listed.join(', ')}]` + (out.outside_warned ? '' : ', no warning for the outside symlink')));
    if (!r.listingOk && t.supported) failed++;

    // Benchmark: main.php's client-side scoring block, run as-is
    const start = web.indexOf('// --- Client-side threat scoring');
    const end = web.indexOf('// --- End client-side threat scoring ---');
    const ctx = vm.createContext({ tokenWeights: out.weights });
    vm.runInContext(web.slice(start, end), ctx);
    // The corpora were copied at different times (webshells keep 2024 mtimes), so
    // timestamps would "detect" them for free; score on content only.
    out.features.forEach(d => { d.mtime = 0; d.ctime = 0; d.rel = d.path.slice(t.repo.length + 1); });
    const rows = ctx.analyzeData(out.features, threshold);
    const isMal = d => d.rel.startsWith('test/webshells/');
    const mal = rows.filter(isMal), ben = rows.filter(d => !isMal(d));
    const report = (label, hit) => {
        const tp = mal.filter(hit).length, fp = ben.filter(hit).length;
        const pct = (a, b) => (100 * a / Math.max(1, b)).toFixed(1) + '%';
        console.log(`${label.padEnd(18)} detected ${tp}/${mal.length} (${pct(tp, mal.length)})   false positives ${fp}/${ben.length} (${pct(fp, ben.length)})`);
        return [tp, fp];
    };
    r.anomaly = report('anomaly', d => d.isAnomaly);
    report('score >= 8', d => d.threatScore >= 8);
    report('score >= 15', d => d.threatScore >= 15);
    report('  zSusp only', d => d.zScores.susp > threshold && d.threatScore < 8);
    report('  zEntropy only', d => d.zScores.entropy > threshold && d.threatScore < 8);
    report('  residual only', d => d.residual > 5 && d.threatScore < 8);
    r.rows = rows;
    r.isMal = isMal;

    if (t.container) { const w = webCheck(t); r.web = w; console.log('web                ' + w.text); if (t.supported && !w.ok) failed++; }
});

// --- Cross-version comparison against the newest version that produced features ---
const withRows = results.filter(r => r.rows);
const ref = withRows[withRows.length - 1];
if (withRows.length > 1) {
    const sig = d => d.matched_tokens.slice().sort().join(',');
    const refMap = new Map(ref.rows.map(d => [d.rel, sig(d)]));
    console.log(`\n== Summary (matches compared with ${ref.t.name})`);
    console.log('PHP        self-checks  listing  anomaly detected / FP      web  files matching differently');
    results.forEach(r => {
        const diff = r.rows ? r.rows.filter(d => refMap.get(d.rel) !== sig(d)) : [];
        r.diff = diff;
        console.log((r.t.v || r.t.name).padEnd(10) + ' ' +
            (r.rows ? `${cases.length - r.casesFailed}/${cases.length}` : '-').padEnd(12) + ' ' +
            (r.rows ? (r.listingOk ? 'OK' : 'FAIL') : '-').padEnd(8) + ' ' +
            (r.anomaly ? `${r.anomaly[0]} / ${r.anomaly[1]}` : (r.t.supported ? 'FAIL' : 'n/a (below 4.3)')).padEnd(26) + ' ' +
            (r.web ? (r.web.ok ? 'OK' : 'FAIL') : '-').padEnd(4) + ' ' +
            (r.rows ? diff.length : '-') + (r.crashed.length ? `  (PHP crashed on ${r.crashed.length} file(s), skipped)` : ''));
    });
}

// --- Detail listings, for the reference (newest) run ---
if (ref && args.includes('--tokens')) {
    const count = {};
    ref.rows.forEach(d => d.matched_tokens.forEach(x => {
        count[x] = count[x] || [0, 0];
        count[x][ref.isMal(d) ? 0 : 1]++;
    }));
    console.log(`\n${ref.t.name}: token                  webshells  benign  weight`);
    Object.keys(count).sort((a, b) => count[b][1] - count[a][1]).forEach(x => {
        console.log(x.padEnd(28) + String(count[x][0]).padStart(10) + String(count[x][1]).padStart(8) + String(ref.out.weights[x]).padStart(8));
    });
}
if (ref && args.includes('--list')) {
    console.log(`\n${ref.t.name} MISSED:`);
    ref.rows.filter(d => ref.isMal(d) && !d.isAnomaly).forEach(d => console.log('  ' + d.rel + '  [' + d.matched_tokens.join(', ') + ']'));
    console.log(`\n${ref.t.name} FALSE POSITIVES:`);
    ref.rows.filter(d => !ref.isMal(d) && d.isAnomaly).forEach(d => console.log('  ' + d.rel + '  score=' + d.threatScore + '  [' + d.matched_tokens.join(', ') + ']'));
    results.filter(r => r.diff && r.diff.length).forEach(r => {
        const refRows = new Map(ref.rows.map(d => [d.rel, d]));
        console.log(`\n${r.t.name} matches differently from ${ref.t.name}:`);
        r.diff.forEach(d => {
            const o = refRows.get(d.rel);
            const mine = new Set(d.matched_tokens), theirs = new Set(o ? o.matched_tokens : []);
            const only = [...mine].filter(x => !theirs.has(x)), missing = [...theirs].filter(x => !mine.has(x));
            console.log('  ' + d.rel + (only.length ? '  +[' + only.join(', ') + ']' : '') + (missing.length ? '  -[' + missing.join(', ') + ']' : ''));
        });
    });
}
process.exit(failed ? 1 : 0);
