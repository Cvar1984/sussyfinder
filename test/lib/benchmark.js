// The detection benchmark, shared by `test/run bench` (local php) and
// `test/run matrix` (Docker): for each target PHP, the PHP self-check, then
// main.php's real feature extraction over the benchmark samples (.gitmodules
// entries with benchmark = true: webshells mixed with legitimate code),
// scored by main.php's real client-side scoring block; detection and
// false-positive rates per target, and across targets which files match
// differently from the newest PHP.
//
// A target fails when its self-check fails, a supported PHP (4.3+) can't
// extract features, or (containers) its web check fails. A file that crashes
// PHP itself is skipped and reported, not failed.
const fs = require('fs');
const path = require('path');
const { ROOT, PHP_JOBS } = require('./paths');
const { phpJob, runResumable, parseRows } = require('./php');
const { benchmarkSet, isRunnable, contentOnly } = require('./corpora');
const { loadScoring, constant, readModel } = require('./scanner');
const { rates, pct } = require('./util');
const selfcheck = require('./selfcheck');
const { startContainer } = require('./targets');
const { webCheck } = require('./webcheck');

// Options both commands take
const OPTIONS = {
    list: { type: 'boolean', help: 'missed webshells, false positives, per-version differences' },
    tokens: { type: 'boolean', help: 'how often each token appears in webshells vs. benign files' },
    threshold: { type: 'string', arg: 'z', help: "Z-score threshold (default: main.php's Z_THRESHOLD)" },
    'no-ml': { type: 'boolean', help: 'rules only' },
    dump: { type: 'string', arg: 'file', help: 'write every scored row (zScores, threatScore, mal, ...) as JSON' },
};

/** Runs the benchmark on `targets` (lib/targets.js) with `args` (OPTIONS); resolves to the exit code */
async function runBenchmark(targets, args, work) {
    const bench = benchmarkSet();
    const shellPrefixes = bench.filter(c => c.label === 'shell').map(c => c.path + '/');
    const inShellCorpus = d => shellPrefixes.some(p => d.rel.startsWith(p));
    const isMal = d => inShellCorpus(d) && isRunnable(d);
    const inTarget = (t, hostPath) => path.join(t.work, path.relative(work, hostPath));

    async function runUnitChecks(t) {
        const r = await selfcheck.run({ work, php: t.php, repo: t.repo, phpWork: t.work, name: 'selfcheck-' + (t.container || 'local') });
        return r.failures;
    }

    async function extractBenchmark(t) {
        const job = phpJob(path.join(work, `extract-${t.container || 'local'}.php`), path.join(t.repo, path.relative(ROOT, path.join(PHP_JOBS, 'extract.php'))), {
            SUSSY_MAIN: path.join(t.repo, 'main.php'), SUSSY_STATE: t.state,
            SUSSY_DIRS: bench.map(c => path.join(t.repo, path.relative(ROOT, c.dir))), SUSSY_SKIP: inTarget(t, path.join(work, 'skip.txt')),
        });
        const { summary, crashed } = await runResumable({ run: () => t.php(inTarget(t, job)), read: t.read, skipFile: path.join(work, 'skip.txt') });
        const rows = summary ? contentOnly(parseRows(t.read('rows'))) : [];
        rows.forEach(d => { d.rel = d.path.slice(t.repo.length + 1); });
        return { summary, crashed, rows };
    }

    function benchmark(summary, rows) {
        const ctx = loadScoring({ weights: summary.weights, roles: summary.roles, model: args['no-ml'] ? null : readModel() });
        const threshold = args.threshold ? parseFloat(args.threshold) : constant(ctx, 'Z_THRESHOLD');
        const anomalyScore = constant(ctx, 'ANOMALY_SCORE'), criticalScore = constant(ctx, 'CRITICAL_SCORE');
        const scored = ctx.analyzeData(rows, threshold);
        const notCode = scored.filter(d => inShellCorpus(d) && !isRunnable(d));
        const mal = scored.filter(isMal), ben = scored.filter(d => !inShellCorpus(d));
        if (notCode.length) console.log(`not counted        ${notCode.length} shell-corpus file(s) with no server code: ${notCode.map(d => d.rel.split('/').pop()).join(', ')}`);
        const line = (label, hit) => {
            const r = rates(mal, ben, hit);
            console.log(`${label.padEnd(18)} detected ${r.tp}/${r.nMal} (${pct(r.tp, r.nMal)})   false positives ${r.fp}/${r.nBen} (${pct(r.fp, r.nBen)})`);
            return r;
        };
        const anomaly = line('anomaly', d => d.isAnomaly);
        line(`score >= ${anomalyScore}`, d => d.threatScore >= anomalyScore);
        line(`score >= ${criticalScore}`, d => d.threatScore >= criticalScore);
        line('  zSusp only', d => d.zScores.susp > threshold && d.threatScore < anomalyScore);
        line('  zEntropy only', d => d.zScores.entropy > threshold && d.threatScore < anomalyScore);
        line('  residual only', d => d.residual > 5 && d.threatScore < anomalyScore);
        // In-sample: the shipped model was trained on these files (test/run train has the cross-validated numbers)
        line('  ml only*', d => d.mlOnly);
        console.log('  * trained on these samples; test/run train for held-out rates');
        if (args.dump) fs.writeFileSync(args.dump, JSON.stringify(scored.map(d => Object.assign({ mal: isMal(d) }, d))));
        return { scored, anomaly, weights: summary.weights };
    }

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

    const results = [];
    for (const t of targets) results.push(await runTarget(t));
    const withRows = results.filter(r => r.scored);
    const ref = withRows[withRows.length - 1]; // the newest PHP that produced rows
    if (ref) {
        const refByRel = printSummary(results, ref);
        if (args.tokens) printTokens(ref);
        if (args.list) printLists(results, ref, refByRel);
    }
    return results.every(r => r.ok) ? 0 : 1;
}

module.exports = { OPTIONS, runBenchmark };
