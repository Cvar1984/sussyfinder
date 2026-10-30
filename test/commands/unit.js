// `test/run unit`: fast tests with no samples or Docker.
//  - In PHP (lib/selfcheck.js, test/php/selfcheck.php): main.php's detectors on
//    small snippets, the names its directory listing returns, and which
//    ml-model.json files it accepts.
//  - In JS: labels, feature decoding, the trainer's pieces (folds, caps,
//    training, quantization) and their agreement with main.php's mlScore(),
//    the scoring block's threshold handling, and the corpus list.
const { execAsync } = require('../lib/php');
const { ROOT } = require('../lib/paths');
const { isRunnable, loadCorpora } = require('../lib/corpora');
const { loadScoring, constant } = require('../lib/scanner');
const { sha1, groupBy } = require('../lib/util');
const { tempDir } = require('../lib/cleanup');
const ml = require('../lib/ml');
const selfcheck = require('../lib/selfcheck');
const path = require('path');

// --- JS unit tests ---
function jsTests() {
    const tests = [];
    const test = (name, fn) => tests.push([name, fn]);
    const assert = (ok, msg) => { if (!ok) throw new Error(msg); };

    test('isRunnable: PHP, or another server language, but not plain text', () => {
        assert(isRunnable({ has_php: true, matched_tokens: [] }), 'PHP file');
        assert(isRunnable({ has_php: false, matched_tokens: ['@foreign_code'] }), 'ASP file');
        assert(!isRunnable({ has_php: false, matched_tokens: [] }), 'robots.txt');
    });

    test('decodeBits matches the bitmap, upper- and lowercase', () => {
        const hex = 'a3' + '0'.repeat(508) + 'f1';
        const want = []; for (let i = 0; i < hex.length; i++) for (let b = 0; b < 4; b++) if (parseInt(hex[i], 16) & (1 << b)) want.push(i * 4 + b);
        assert(JSON.stringify([...ml.decodeBits(hex)]) === JSON.stringify(want), 'lowercase');
        assert(JSON.stringify([...ml.decodeBits(hex.toUpperCase())]) === JSON.stringify(want), 'uppercase');
    });

    test("quantized model: trainer's scorer equals main.php's mlScore()", () => {
        const ctx = loadScoring({ weights: {} });
        const w = Float64Array.from({ length: 2048 }, (_, i) => Math.sin(i * 12.9898) * 1.5);
        const model = ml.quantize({ w, b: 0.3 });
        const score = ml.scorer(model);
        for (let t = 0; t < 50; t++) {
            let hex = ''; for (let i = 0; i < 512; i++) hex += ((i * 7 + t * 13) % 16).toString(16);
            const a = score(ml.decodeBits(hex)), b = ctx.mlScore(hex, model);
            assert(Math.abs(a - b) < 1e-12, `sample ${t}: ${a} vs ${b}`);
        }
    });

    test("trainer's scorerUnits equals main.php's mlScoreUnits() (per-unit max)", () => {
        const w = Float64Array.from({ length: 2048 }, (_, i) => Math.sin(i * 12.9898) * 1.5);
        const model = ml.quantize({ w, b: 0.3 });
        const ctx = loadScoring({ weights: {}, model });
        const floor = constant(ctx, 'ML_UNIT_FLOOR');
        const mlScoreUnits = constant(ctx, 'mlScoreUnits');
        const score = ml.scorerUnits(model, floor);
        const hexOf = seed => { let h = ''; for (let i = 0; i < 512; i++) h += ((i * 7 + seed * 13) % 16).toString(16); return h; };
        for (let t = 0; t < 30; t++) {
            const whole = hexOf(t);
            const units = t % 4 === 0 ? [] : [hexOf(t + 100), hexOf(t + 200), hexOf(t + 300)];
            const d = { ml_features: whole, ml_units: units.length ? units : null };
            const a = score({ bits: ml.decodeBits(whole), unitBits: units.map(ml.decodeBits) });
            const b = mlScoreUnits(d);
            assert(Math.abs(a - b) < 1e-12, `sample ${t}: ${a} vs ${b}`);
        }
    });

    const fakeSamples = () => {
        const s = [];
        for (let i = 0; i < 60; i++) s.push({ label: 1, md5: sha1('s' + i), group: 'shell:' + (i % 20), corpus: 'shells', bits: Uint16Array.of(i % 7, 100) });
        for (let i = 0; i < 300; i++) s.push({ label: 0, md5: sha1('b' + i), group: 'family:f' + (i % 9), corpus: 'c' + (i % 12), family: 'f' + (i % 9), bits: Uint16Array.of(200 + i % 5, 300) });
        return s;
    };
    const foldsOf = s => Object.fromEntries(s.map(d => [d.md5, d.fold]));

    test('folds keep groups whole and ignore listing order', () => {
        const a = fakeSamples(), b = fakeSamples().reverse();
        ml.assignFolds(a, 5); ml.assignFolds(b, 5);
        const sorted = x => JSON.stringify(Object.entries(foldsOf(x)).sort());
        assert(sorted(a) === sorted(b), 'listing order changed the folds');
        for (const [, members] of groupBy(a, d => d.group)) assert(new Set(members.map(d => d.fold)).size === 1, 'a group was split');
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
        const corpora = loadCorpora();
        assert(corpora.some(c => c.label === 'shell') && corpora.some(c => c.label === 'benign'), 'both labels');
        assert(corpora.every(c => c.commit), 'every sample pinned');
        const bench = corpora.filter(c => c.benchmark);
        assert(bench.some(c => c.label === 'shell') && bench.some(c => c.label === 'benign'), 'benchmark set has both labels');
    });

    test('re-flagging at a new Z-threshold equals a full rescore', () => {
        const ctx = loadScoring();
        const rows = Array.from({ length: 60 }, (_, i) => ({
            path: '/x/' + i + '.php', size: 100 + i * 37 % 900, mtime: 1e9 + (i % 7) * 86400 * (i % 5 ? 1 : 400),
            ctime: 1e9 + (i % 7) * 86400, owner: i % 19 ? 1 : 2, entropy: 4 + (i % 9) / 3, total_tokens: 20 + i,
            matched_tokens: i % 4 ? ['substr'] : ['eval', '$_get'], mlScore: null, is_htaccess: false,
            is_unreadable: i === 5, is_blacklisted: false, duplicate_of: false, md5: 'm' + i,
        }));
        const strip = list => JSON.stringify(list.map(d => [d.isAnomaly, d.mlOnly, d.threatScore]));
        for (const t of [0.5, 2, 3.5, 8]) {
            assert(strip(ctx.flagAnomalies(ctx.analyzeData(rows, 3.5), t)) === strip(ctx.analyzeData(rows, t)), 'threshold ' + t);
        }
        assert(new Set(ctx.analyzeData(rows, 0.5).map(d => d.isAnomaly)).size === 2, 'the sample has anomalies and normal rows');
        // The page keeps only the scored rows and rescores those (an MHR hit, the end of a scan)
        const fields = list => JSON.stringify(list.map(d => [d.isAnomaly, d.mlOnly, d.threatScore, d.ruleScore, d.zScores, d.rareOwner, d.entropy]));
        assert(fields(ctx.analyzeData(ctx.analyzeData(rows, 2), 2)) === fields(ctx.analyzeData(rows, 2)), 'rescoring scored rows changes them');
    });

    test('withMlScore: the ML score worked out once, the bitmaps dropped, the same threat score', () => {
        const w = Float64Array.from({ length: 2048 }, (_, i) => Math.sin(i * 12.9898) * 1.5);
        const ctx = loadScoring({ model: ml.quantize({ w, b: 0.3 }) });
        let hex = ''; for (let i = 0; i < 512; i++) hex += ((i * 5 + 3) % 16).toString(16);
        const raw = { path: 'a.php', size: 900, mtime: 1e9, ctime: 1e9, owner: 1, entropy: 5, total_tokens: 80, matched_tokens: ['eval'],
            ml_features: hex, ml_units: [hex.split('').reverse().join('')], is_htaccess: false, is_unreadable: false, is_blacklisted: false, duplicate_of: false, md5: 'x' };
        const r = ctx.withMlScore(raw);
        assert(!('ml_features' in r) && !('ml_units' in r) && raw.ml_features === hex, 'bitmaps dropped from the copy only');
        assert(r.mlScore === ctx.mlScoreUnits(raw) && r.mlScore !== null, 'mlScore ' + r.mlScore);
        assert(ctx.withMlScore(Object.assign({}, raw, { is_htaccess: true })).mlScore === null, '.htaccess has no ML score');
        assert(ctx.analyzeData([r], 3.5)[0].mlPoints === ctx.mlPoints(r.mlScore), 'ML points from mlScore');
    });

    test('markDuplicates: the newest copy is the original (then the first path), whatever the order', () => {
        const ctx = loadScoring({ weights: {} });
        const rows = () => [
            { path: 'b/x.php', md5: 'A', mtime: 200 }, { path: 'a/x.php', md5: 'A', mtime: 200 }, { path: 'c/x.php', md5: 'A', mtime: 100 },
            { path: 'd/y.php', md5: 'B', mtime: 50 }, { path: 'e/y.php', md5: 'B', mtime: 90 },
            { path: 'f/z.php', md5: 'C', mtime: 10 }, { path: 'gone.php', md5: 'N/A', mtime: 0, is_unreadable: true },
        ];
        const want = JSON.stringify({ 'b/x.php': 'a/x.php', 'a/x.php': false, 'c/x.php': 'a/x.php', 'd/y.php': 'e/y.php', 'e/y.php': false, 'f/z.php': false, 'gone.php': false });
        for (let seed = 0; seed < 20; seed++) {
            const list = rows().sort((a, b) => ((a.path.charCodeAt(0) * (seed + 3)) % 7) - ((b.path.charCodeAt(0) * (seed + 3)) % 7));
            ctx.markDuplicates(list);
            const got = JSON.stringify(Object.fromEntries(list.sort((a, b) => rows().findIndex(r => r.path === a.path) - rows().findIndex(r => r.path === b.path)).map(d => [d.path, d.duplicate_of])));
            assert(got === want, `order ${seed}: ${got}`);
        }
    });

    test('scoring block constants', () => {
        const ctx = loadScoring({ weights: {} });
        ['Z_THRESHOLD', 'ANOMALY_SCORE', 'CRITICAL_SCORE', 'ML_THRESHOLD', 'ML_FLOOR', 'ML_CRITICAL'].forEach(n => assert(typeof constant(ctx, n) === 'number', n));
    });
    test('ML points: 0 at the floor, the anomaly bar at ML_THRESHOLD, critical at ML_CRITICAL, rising', () => {
        const ctx = loadScoring({ weights: {} });
        const c = n => constant(ctx, n);
        assert(ctx.mlPoints(c('ML_FLOOR')) === 0 && ctx.mlPoints(null) === 0, 'floor');
        assert(ctx.mlPoints(c('ML_THRESHOLD')) === c('ANOMALY_SCORE'), 'threshold');
        assert(ctx.mlPoints(c('ML_CRITICAL')) === c('CRITICAL_SCORE'), 'critical');
        for (let m = 0; m < 1; m += 0.01) assert(ctx.mlPoints(m + 0.01) >= ctx.mlPoints(m), 'monotonic at ' + m.toFixed(2));
    });
    test('a verified release file scores below VERIFIED_MAX and isn\'t flagged, unless the blacklist or MHR names it', () => {
        const ctx = loadScoring();
        const file = (path, extra) => Object.assign({ path, matched_tokens: ['eval', 'base64_decode', '$_post'], total_tokens: 400, size: 9000,
            mtime: 1e9, ctime: 1e9, owner: 1, entropy: 6, md5: 'x', mlScore: null, is_blacklisted: false, is_htaccess: false, duplicate_of: false }, extra);
        const verified = { verified: 'acme release file a.php' };
        const rows = ctx.analyzeData([file('plain.php', {}), file('verified.php', verified),
            file('verified-more.php', Object.assign({}, verified, { matched_tokens: ['eval', 'system', 'base64_decode', '$_post', '$_get'] })),
            file('verified-blacklisted.php', Object.assign({ is_blacklisted: true }, verified)),
            file('verified-mhr.php', Object.assign({ mhr_hit: true }, verified))], constant(ctx, 'Z_THRESHOLD'));
        const flagged = rows.map(d => d.isAnomaly);
        assert(JSON.stringify(flagged) === '[true,false,false,true,true]', 'isAnomaly per row: ' + JSON.stringify(flagged));
        assert(rows[1].contentScore >= constant(ctx, 'CRITICAL_SCORE') && rows[1].threatScore < constant(ctx, 'VERIFIED_MAX'),
            `content ${rows[1].contentScore} held to ${rows[1].threatScore}`);
        assert(rows[2].threatScore > rows[1].threatScore, 'verified files stay in order');
        assert(rows[3].threatScore === 100 && rows[4].threatScore === 100, 'the blacklist and MHR still win');
    });
    return tests;
}

module.exports = {
    name: 'unit',
    summary: 'unit tests in PHP and JS: detectors, listing, model checks, ML pieces (seconds)',
    about: `
Runs main.php's PHP-side checks with the local php (detector snippets, the
listing fixture, model file validation), then the JS unit tests. Needs no
samples and no Docker.`,
    options: {},
    async run() {
        let failed = 0;
        const work = tempDir('unit');
        const php = file => execAsync('php', ['-d', 'error_log=' + path.join(work, 'php-errors.log'), file]);
        const r = await selfcheck.run({ work, php, repo: ROOT });
        r.failures.forEach(f => console.log('FAIL ' + f));
        console.log(`${r.failures.length ? 'FAIL' : 'PASS'} PHP ${r.php}: ${r.summary || 'self-check'}`);
        failed += r.failures.length;
        for (const [name, fn] of jsTests()) {
            try { await fn(); console.log('PASS ' + name); } catch (e) { failed++; console.log(`FAIL ${name}: ${e.message}`); }
        }
        console.log(failed ? `${failed} failed` : 'all passed');
        return failed ? 1 : 0;
    },
};
