// Benchmark and per-PHP-version test runner, on the local PHP or on every
// test/PHTest version (plus a page/AJAX smoke test there).
//
// For each PHP it runs test/unit.js's PHP unit checks, then main.php's real
// feature extraction over the benchmark samples (the .gitmodules entries
// with benchmark = true: webshells mixed with legitimate code), scores the
// rows with main.php's real client-side scoring block and prints detection
// and false-positive rates.
//
// Exits 1 if a unit check fails, a supported version (4.3+) can't extract
// features, or its page/AJAX smoke test fails. A file that crashes PHP itself
// is skipped and reported, not failed. Containers mount the repo READ-ONLY so
// a blacklist hit can never delete sample files.
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');
const lib = require('./lib');
const unit = require('./unit');

const args = lib.cli({
    php: { type: 'string', arg: 'all|5.6,8.5.6', help: 'run in Docker instead of the local php: "all" (test/PHTest/versions.list) or versions (any official php:<v>-apache tag)' },
    profile: { type: 'string', arg: 'default,hardened,minimal', help: 'php.ini environment(s) for --php, each version runs under each (default: default)' },
    list: { type: 'boolean', help: 'missed webshells, false positives, per-version differences' },
    tokens: { type: 'boolean', help: 'how often each token appears in webshells vs. benign files' },
    threshold: { type: 'string', arg: 'z', help: "Z-score threshold (default: main.php's Z_THRESHOLD)" },
    'no-ml': { type: 'boolean', help: 'rules only' },
    dump: { type: 'string', arg: 'file', help: 'write every scored row (zScores, threatScore, mal, ...) as JSON' },
}, 'Usage: node test/run.js [options]');

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'sussy-test-'));
fs.chmodSync(work, 0o755); // Apache in the containers runs as www-data
const containers = [];
process.on('exit', () => {
    containers.forEach(c => { try { execFileSync('docker', ['rm', '-f', c], { stdio: 'ignore' }); } catch (e) { } });
    fs.rmSync(work, { recursive: true, force: true });
});
process.on('SIGINT', () => process.exit(130));
const sleep = ms => new Promise(r => setTimeout(r, ms));
const PHTEST = path.join(lib.ROOT, 'test', 'PHTest');

const bench = lib.loadCorpora().filter(c => c.benchmark);
const missing = bench.filter(c => !lib.isCheckedOut(c));
if (missing.length) {
    console.error(`benchmark samples not checked out: git submodule update --init ${missing.map(c => c.path).join(' ')}`);
    process.exit(1);
}
const shellPrefixes = bench.filter(c => c.label === 'shell').map(c => c.path + '/');
const inShellCorpus = d => shellPrefixes.some(p => d.rel.startsWith(p));
const isMal = d => inShellCorpus(d) && lib.isRunnable(d);
const selfcheck = unit.prepareSelfcheck(work);

// --- Targets: local php, or test/PHTest containers ---
// Each has the paths PHP sees: repo (main.php and samples), work (this temp dir), state (extraction state).
function localTarget() {
    const state = path.join(work, 'state');
    fs.mkdirSync(state);
    const php = file => lib.execAsync('php', ['-d', 'error_log=' + path.join(work, 'php-errors.log'), file]); // not ./error_log in the repo
    return {
        name: 'local', supported: true, repo: lib.ROOT, work, state,
        php, read: file => { try { return fs.readFileSync(path.join(state, file), 'utf8'); } catch (e) { return ''; } },
    };
}
// php.ini environments for --php, layered over each version's own php.ini (conf.d):
// how the scanner copes with typical shared hosting, and with functions missing
// that its compatibility layer has to provide itself.
const PROFILES = {
    default: { about: "the image's own php.ini", ini: '' },
    hardened: {
        about: 'shared-hosting style: no exec family, no cURL, no remote fopen',
        ini: 'disable_functions = exec,shell_exec,system,passthru,proc_open,popen,pcntl_exec,curl_init,curl_exec,curl_multi_exec,fsockopen,pfsockopen\nallow_url_fopen = Off\n',
    },
    minimal: {
        about: 'json_encode and cURL missing (as on PHP < 5.2 or a stripped build)',
        ini: 'disable_functions = json_encode,curl_init,curl_exec,curl_setopt,curl_error\n',
    },
};

function containerTargets(spec, profileSpec) {
    const known = fs.readFileSync(path.join(PHTEST, 'versions.list'), 'utf8').split('\n')
        .filter(l => l.trim() && !l.startsWith('#')).map(l => { const [v, type] = l.split('|'); return { v, type }; });
    const want = spec === 'all' ? known : spec.split(',').map(v => known.find(k => k.v === v) || { v, type: 'official' });
    const profiles = (profileSpec || 'default').split(',');
    profiles.filter(p => !PROFILES[p]).forEach(p => { console.error(`unknown profile ${p} (have: ${Object.keys(PROFILES).join(', ')})`); process.exit(2); });
    const supported = v => { const [a, b] = v.split('.').map(Number); return a > 4 || (a === 4 && b >= 3); };
    const targets = [];
    for (const { v, type } of want) for (const profile of profiles) {
        const legacy = type === 'legacy';
        if (profile !== 'default' && legacy) continue; // profiles go into the official images' conf.d
        const container = `sf-test-${v}-${profile}`;
        const exec = (cmd, opts = {}) => lib.execAsync('docker', ['exec', container].concat(cmd), Object.assign({ stdio: ['ignore', 'pipe', 'ignore'] }, opts));
        targets.push({
            name: `PHP ${v}` + (profile === 'default' ? '' : ` (${profile})`), v, profile, legacy, supported: supported(v), container, port: 18100 + targets.length,
            repo: '/var/www/html', work: '/work', state: '/tmp',
            php: file => exec((legacy ? ['php-cgi', '-q'] : ['php']).concat(file)),
            read: file => { try { return execFileSync('docker', ['exec', container, 'cat', '/tmp/' + file], { maxBuffer: lib.MAX_BUFFER, stdio: ['ignore', 'pipe', 'ignore'] }).toString(); } catch (e) { return ''; } },
        });
    }
    return targets;
}

async function startContainer(t) {
    const image = t.legacy ? 'phtest-php:' + t.v : `php:${t.v}-apache`;
    const mounts = ['-v', lib.ROOT + ':/var/www/html:ro', '-v', work + ':/work:ro'];
    const conf = path.join(PHTEST, 'conf', t.v, 'php.ini');
    if (fs.existsSync(conf)) mounts.push('-v', conf + ':' + (t.legacy ? '/usr/local/lib/php.ini' : '/usr/local/etc/php/php.ini') + ':ro');
    if (!t.legacy) {
        const profileIni = path.join(work, `profile-${t.profile}.ini`);
        fs.writeFileSync(profileIni, `; test/run.js profile "${t.profile}": ${PROFILES[t.profile].about}\n` + PROFILES[t.profile].ini);
        mounts.push('-v', profileIni + ':/usr/local/etc/php/conf.d/zz-sussy-profile.ini:ro');
    }
    try {
        execFileSync('docker', ['rm', '-f', t.container], { stdio: 'ignore' });
        execFileSync('docker', ['run', '-d', '--rm', '--name', t.container, '-p', t.port + ':80'].concat(mounts, [image]), { stdio: 'ignore' });
        containers.push(t.container);
    } catch (e) {
        return `container failed to start (image ${image} built or pulled?)`;
    }
    for (let i = 0; i < 40; i++) {
        try { execFileSync('curl', ['-s', '-o', '/dev/null', `http://127.0.0.1:${t.port}/`]); break; } catch (e) { await sleep(250); }
    }
    return null;
}

// --- Steps per target ---
const inTarget = (t, hostPath) => path.join(t.work, path.relative(work, hostPath));

async function runUnitChecks(t) {
    const job = lib.phpJob(path.join(work, `selfcheck-${t.container || 'local'}.php`), path.join(t.repo, 'test/php/selfcheck.php'),
        selfcheck.vars(path.join(t.repo, 'main.php'), t.work));
    try {
        const raw = String(await t.php(inTarget(t, job)));
        return unit.checkSelfcheck(JSON.parse(raw.slice(raw.indexOf('{'))), selfcheck.models);
    } catch (e) {
        return ['unit checks produced no JSON'];
    }
}

async function extractBenchmark(t) {
    const job = lib.phpJob(path.join(work, `extract-${t.container || 'local'}.php`), path.join(t.repo, 'test/php/extract.php'), {
        SUSSY_MAIN: path.join(t.repo, 'main.php'), SUSSY_STATE: t.state,
        SUSSY_DIRS: bench.map(c => path.join(t.repo, path.relative(lib.ROOT, c.dir))), SUSSY_SKIP: inTarget(t, path.join(work, 'skip.txt')),
    });
    const { summary, crashed } = await lib.runResumable({ run: () => t.php(inTarget(t, job)), read: t.read, skipFile: path.join(work, 'skip.txt') });
    const rows = summary ? lib.contentOnly(lib.parseRows(t.read('rows'))) : [];
    rows.forEach(d => { d.rel = d.path.slice(t.repo.length + 1); });
    return { summary, crashed, rows };
}

function benchmark(summary, rows) {
    const ctx = lib.loadScoring({ weights: summary.weights, roles: summary.roles, model: args['no-ml'] ? null : lib.readModel() });
    const threshold = args.threshold ? parseFloat(args.threshold) : lib.constant(ctx, 'Z_THRESHOLD');
    const anomalyScore = lib.constant(ctx, 'ANOMALY_SCORE'), criticalScore = lib.constant(ctx, 'CRITICAL_SCORE');
    const scored = ctx.analyzeData(rows, threshold);
    const notCode = scored.filter(d => inShellCorpus(d) && !lib.isRunnable(d));
    const mal = scored.filter(isMal), ben = scored.filter(d => !inShellCorpus(d));
    if (notCode.length) console.log(`not counted        ${notCode.length} shell-corpus file(s) with no server code: ${notCode.map(d => d.rel.split('/').pop()).join(', ')}`);
    const line = (label, hit) => {
        const r = lib.rates(mal, ben, hit);
        console.log(`${label.padEnd(18)} detected ${r.tp}/${r.nMal} (${lib.pct(r.tp, r.nMal)})   false positives ${r.fp}/${r.nBen} (${lib.pct(r.fp, r.nBen)})`);
        return r;
    };
    const anomaly = line('anomaly', d => d.isAnomaly);
    line(`score >= ${anomalyScore}`, d => d.threatScore >= anomalyScore);
    line(`score >= ${criticalScore}`, d => d.threatScore >= criticalScore);
    line('  zSusp only', d => d.zScores.susp > threshold && d.threatScore < anomalyScore);
    line('  zEntropy only', d => d.zScores.entropy > threshold && d.threatScore < anomalyScore);
    line('  residual only', d => d.residual > 5 && d.threatScore < anomalyScore);
    // In-sample: the shipped model was trained on these files (test/train-ml.js has the cross-validated numbers)
    line('  ml only*', d => d.mlOnly);
    console.log('  * trained on these samples; node test/train-ml.js for held-out rates');
    if (args.dump) fs.writeFileSync(args.dump, JSON.stringify(scored.map(d => Object.assign({ mal: isMal(d) }, d))));
    return { scored, anomaly, weights: summary.weights };
}

// --- Web smoke test (containers only): page, inline JS, scan + process over HTTP ---
function webCheck(t) {
    const url = `http://127.0.0.1:${t.port}/main.php`;
    const curl = (extra, csrfHeader = true) => {
        const a = ['-s', '-m', '120'].concat(csrfHeader ? ['-H', 'X-Sussy-Request: 1'] : [], extra, [url]);
        try { return execFileSync('curl', a, { maxBuffer: 1 << 26 }).toString(); } catch (e) { return ''; }
    };
    const json = s => { try { return JSON.parse(s); } catch (e) { return null; } };
    const shells = path.join(t.repo, lib.corpus('blackarch-webshells').path, 'php');
    const page = curl([], false);
    const js = [...page.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]).join('\n;\n');
    let jsOk = page.includes('</html>');
    try { new vm.Script(js); } catch (e) { jsOk = false; }
    const scan = json(curl(['--data', 'ajax_action=scan', '--data', 'dir=' + shells]));
    // Must return (the FIFO can't hang it) and list the fixture's names
    const fixtureScan = json(curl(['--data', 'ajax_action=scan', '--data', 'dir=/work/fixture']));
    // Without the CSRF header every action is refused
    const noHeader = json(curl(['--data', 'ajax_action=scan', '--data', 'dir=/work/fixture'], false));
    // Paths are rawurlencoded on the wire, then form-encoded; the Latin-1 name must round-trip
    const micro = shells + '/micro.php';
    const microMd5 = require('crypto').createHash('md5').update(fs.readFileSync(path.join(lib.ROOT, path.relative(t.repo, micro)))).digest('hex');
    const latin1 = '%2Fwork%2Ffixture%2Fcaf%E9.php';
    const wire = p => encodeURIComponent(encodeURIComponent(p));
    // comma-separated (%2C); a path that doesn't exist must come back as a warning, not vanish
    const paths = [wire(micro), wire('/work/fixture/it\'s "odd".php'), encodeURIComponent(latin1), wire('/work/fixture/missing.php')].join('%2C');
    const proc = json(curl(['--data', 'ajax_action=process', '--data', 'paths=' + paths]));
    const feats = proc && proc.features || [];
    const procOk = feats.length === 3 && feats[0].md5 === microMd5 &&
        feats[1].matched_tokens.includes('@concat_name') && feats[2].path === latin1 &&
        proc.warnings.some(w => w.indexOf('Skipped /work/fixture/missing.php') === 0);
    const fixtureOk = !!fixtureScan && fixtureScan.total === unit.LISTING_WANT.length;
    const csrfOk = !!noHeader && noHeader.error === 'forbidden';
    return {
        ok: jsOk && !!scan && scan.total > 0 && fixtureOk && procOk && csrfOk,
        text: `page ${jsOk ? 'OK' : 'BROKEN'}, scan ${scan ? scan.total + ' files' : 'FAIL'}, fixture scan ${fixtureOk ? 'OK' : 'FAIL'}, ` +
            `process ${procOk ? 'OK' : 'FAIL'}, CSRF check ${csrfOk ? 'OK' : 'FAIL'}` + (proc ? ` (${proc.warnings.length} warnings)` : ''),
    };
}

/** All steps for one PHP; returns its result record (ok === false fails the run) */
async function runTarget(t) {
    const r = { t, ok: true };
    const fail = () => { if (t.supported) r.ok = false; };
    if (t.container) {
        const err = await startContainer(t);
        if (err) { console.log(`\n== ${t.name}: ${err}`); fail(); return r; }
    }
    r.unitFailures = await runUnitChecks(t);
    const ex = await extractBenchmark(t);
    r.crashed = ex.crashed;
    console.log(`\n== ${t.name}${ex.summary ? ' (' + ex.summary.php + ')' : ''}`);
    ex.crashed.forEach(f => console.log(`PHP crashed on     ${f.slice(t.repo.length + 1)} (skipped; the UI isolates such files the same way)`));
    r.unitFailures.forEach(f => console.log('  FAIL ' + f));
    console.log(`unit checks        ${r.unitFailures.length ? r.unitFailures.length + ' FAILED' : 'OK'}`);
    if (r.unitFailures.length) fail();
    if (ex.summary) {
        Object.assign(r, benchmark(ex.summary, ex.rows));
    } else {
        console.log(t.supported ? 'FAIL: feature extraction produced no JSON' : 'feature extraction failed (expected: below the PHP 4.3 floor)');
        fail();
    }
    if (t.container) {
        r.web = webCheck(t);
        console.log('web                ' + r.web.text);
        if (!r.web.ok) fail();
    }
    return r;
}

// --- Reports across targets ---
const signature = d => d.matched_tokens.slice().sort().join(',');
function printSummary(results, ref) {
    const refByRel = new Map(ref.scored.map(d => [d.rel, d]));
    results.forEach(r => { r.diff = r.scored ? r.scored.filter(d => signature(refByRel.get(d.rel) || { matched_tokens: [] }) !== signature(d)) : []; });
    if (results.length < 2) return refByRel;
    console.log(`\n== Summary (matches compared with ${ref.t.name})`);
    console.log('PHP                    unit checks  anomaly detected / FP      web  files matching differently');
    results.forEach(r => console.log((r.t.v ? r.t.v + (r.t.profile !== 'default' ? ' ' + r.t.profile : '') : r.t.name).padEnd(22) + ' ' +
        (r.unitFailures ? (r.unitFailures.length ? r.unitFailures.length + ' FAILED' : 'OK') : '-').padEnd(12) + ' ' +
        (r.anomaly ? `${r.anomaly.tp} / ${r.anomaly.fp}` : (r.t.supported ? 'FAIL' : 'n/a (below 4.3)')).padEnd(26) + ' ' +
        (r.web ? (r.web.ok ? 'OK' : 'FAIL') : '-').padEnd(4) + ' ' +
        (r.scored ? r.diff.length : '-') + (r.crashed && r.crashed.length ? `  (PHP crashed on ${r.crashed.length} file(s), skipped)` : '')));
    return refByRel;
}
function printTokens(ref) {
    const count = {};
    ref.scored.forEach(d => d.matched_tokens.forEach(x => { (count[x] = count[x] || [0, 0])[isMal(d) ? 0 : 1]++; }));
    console.log(`\n${ref.t.name}: token                  webshells  benign  weight`);
    Object.keys(count).sort((a, b) => count[b][1] - count[a][1]).forEach(x =>
        console.log(x.padEnd(28) + String(count[x][0]).padStart(10) + String(count[x][1]).padStart(8) + String(ref.weights[x]).padStart(8)));
}
function printLists(results, ref, refByRel) {
    console.log(`\n${ref.t.name} MISSED:`);
    ref.scored.filter(d => isMal(d) && !d.isAnomaly).forEach(d => console.log('  ' + d.rel + '  [' + d.matched_tokens.join(', ') + ']'));
    console.log(`\n${ref.t.name} FALSE POSITIVES:`);
    ref.scored.filter(d => !inShellCorpus(d) && d.isAnomaly).forEach(d => console.log('  ' + d.rel + '  score=' + d.threatScore + '  [' + d.matched_tokens.join(', ') + ']'));
    results.filter(r => r !== ref && r.diff && r.diff.length).forEach(r => {
        console.log(`\n${r.t.name} matches differently from ${ref.t.name}:`);
        r.diff.forEach(d => {
            const mine = new Set(d.matched_tokens), theirs = new Set((refByRel.get(d.rel) || { matched_tokens: [] }).matched_tokens);
            const only = [...mine].filter(x => !theirs.has(x)), gone = [...theirs].filter(x => !mine.has(x));
            console.log('  ' + d.rel + (only.length ? '  +[' + only.join(', ') + ']' : '') + (gone.length ? '  -[' + gone.join(', ') + ']' : ''));
        });
    });
}

(async () => {
    const targets = args.php ? containerTargets(args.php, args.profile) : [localTarget()];
    const results = [];
    for (const t of targets) results.push(await runTarget(t));
    const withRows = results.filter(r => r.scored);
    const ref = withRows[withRows.length - 1]; // the newest PHP that produced rows
    if (ref) {
        const refByRel = printSummary(results, ref);
        if (args.tokens) printTokens(ref);
        if (args.list) printLists(results, ref, refByRel);
    }
    process.exit(results.every(r => r.ok) ? 0 : 1);
})().catch(e => { console.error(e); process.exit(1); });
