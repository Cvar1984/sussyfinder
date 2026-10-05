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
            matched_tokens: i % 4 ? ['substr'] : ['eval', '$_get'], ml_features: null, is_htaccess: false,
            is_unreadable: i === 5, is_blacklisted: false, duplicate_of: false, md5: 'm' + i,
        }));
        const strip = list => JSON.stringify(list.map(d => [d.isAnomaly, d.mlOnly, d.threatScore]));
        for (const t of [0.5, 2, 3.5, 8]) {
            assert(strip(ctx.flagAnomalies(ctx.analyzeData(rows, 3.5), t)) === strip(ctx.analyzeData(rows, t)), 'threshold ' + t);
        }
        assert(new Set(ctx.analyzeData(rows, 0.5).map(d => d.isAnomaly)).size === 2, 'the sample has anomalies and normal rows');
    });

    test('scoring block constants', () => {
        const ctx = loadScoring({ weights: {} });
        ['Z_THRESHOLD', 'ANOMALY_SCORE', 'CRITICAL_SCORE', 'ML_THRESHOLD', 'ML_FLOOR'].forEach(n => assert(typeof constant(ctx, n) === 'number', n));
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
