// The ML pipeline as plain functions, used by test/train-ml.js (the CLI) and
// tested by test/unit.js: feature extraction with a per-corpus cache, sample
// building (labels, de-duplication), shell clustering, stable folds and caps,
// logistic-regression training on packed features (in worker threads), int8
// quantization and the scorer that mirrors main.php's mlScore().
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const lib = require('./lib');

const EXTRACT_PHP = path.join(__dirname, 'php', 'extract.php');
const CACHE_DIR = path.join(__dirname, 'corpora', '.rows');

// --- Features ---

/**
 * Cache key: main.php's extractor and test/php/extract.php. Not the checkout
 * path, so a clone elsewhere reuses the same cache.
 */
const featureKey = () => lib.sha1(lib.extractorSource() + fs.readFileSync(EXTRACT_PHP, 'utf8')).slice(0, 12);
const cacheFile = (c, key) => path.join(CACHE_DIR, `${c.name}-${(c.commit || 'local').slice(0, 10)}-${key}.jsonl`);

/**
 * Run main.php's extractor over `dir`, writing one JSON row per file (paths
 * relative to `dir`) to `outFile`. A file PHP crashes on is skipped and
 * reported. Rows stream to disk, so corpus size isn't limited by memory.
 */
async function extractTo(dir, outFile) {
    const state = fs.mkdtempSync(path.join(os.tmpdir(), 'sussy-ml-'));
    try {
        const job = lib.phpJob(path.join(state, 'job.php'), EXTRACT_PHP, {
            SUSSY_MAIN: lib.MAIN, SUSSY_STATE: state, SUSSY_DIRS: [dir], SUSSY_SKIP: path.join(state, 'skip'), SUSSY_RELATIVE: '1',
        });
        const read = name => { try { return fs.readFileSync(path.join(state, name), 'utf8'); } catch (e) { return ''; } };
        const { summary, crashed } = await lib.runResumable({ run: () => lib.execAsync('php', [job]), read, skipFile: path.join(state, 'skip') });
        if (!summary) throw new Error('feature extraction failed for ' + dir);
        crashed.forEach(f => process.stderr.write(`PHP crashed on ${f}, skipped\n`));
        fs.copyFileSync(path.join(state, 'rows'), outFile + '.tmp');
        fs.renameSync(outFile + '.tmp', outFile);
    } finally {
        fs.rmSync(state, { recursive: true, force: true });
    }
    return outFile;
}

/**
 * A corpus's rows from the cache (one file per corpus commit and feature
 * key), extracting them on a miss; this corpus's files under any other key
 * are removed. Resolves to the cache path.
 */
async function extractCorpus(c, key) {
    const cache = cacheFile(c, key);
    if (fs.existsSync(cache)) return cache;
    fs.mkdirSync(CACHE_DIR, { recursive: true });
    await extractTo(c.dir, cache);
    const stale = new RegExp(`^${c.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}-([0-9a-f]{10}|local)-[0-9a-f]{12}\\.jsonl$`);
    fs.readdirSync(CACHE_DIR).filter(f => stale.test(f) && path.join(CACHE_DIR, f) !== cache).forEach(f => fs.rmSync(path.join(CACHE_DIR, f)));
    return cache;
}

// Hex digit -> value by char code (parseInt per digit is several times slower)
const NIBBLE = new Uint8Array(128);
'0123456789abcdef'.split('').forEach((ch, i) => { NIBBLE[ch.charCodeAt(0)] = i; NIBBLE[ch.toUpperCase().charCodeAt(0)] = i; });
const scratch = new Uint16Array(1 << 16);
/** Set-bit indices of an ml_features hex bitmap */
function decodeBits(hex) {
    let n = 0;
    for (let i = 0, k = 0; i < hex.length; i++, k += 4) {
        const v = NIBBLE[hex.charCodeAt(i) & 127];
        if (v & 1) scratch[n++] = k;
        if (v & 2) scratch[n++] = k + 1;
        if (v & 4) scratch[n++] = k + 2;
        if (v & 8) scratch[n++] = k + 3;
    }
    return scratch.slice(0, n);
}

// --- Samples ---

/**
 * Labelled, de-duplicated samples from the cached rows of each corpus.
 * Each corpus is rule-scored on its own (as a scan of it would be). Dropped:
 * .htaccess files, shell-collection files that can't run (lib.isRunnable),
 * and exact copies (by MD5); a file that also ships in a benign project is
 * benign. Keeps `hex` for the first `keepHex` samples (scorer parity checks).
 */
function buildSamples(corpora, ctx, { keepHex = 500 } = {}) {
    const all = [];
    const dropped = { htaccess: 0, notCode: 0, conflicts: 0 };
    for (const c of corpora) {
        const raw = lib.contentOnly(lib.parseRows(fs.readFileSync(c.cache, 'utf8')));
        const scored = ctx.analyzeData(raw, lib.constant(ctx, 'Z_THRESHOLD'));
        raw.forEach((d, i) => {
            if (!d.ml_features) return;
            if (d.is_htaccess) { dropped.htaccess++; return; }
            if (c.label === 'shell' && !lib.isRunnable(d)) { dropped.notCode++; return; }
            all.push({
                id: c.name + '/' + d.path, corpus: c.name, family: c.family, label: c.label === 'shell' ? 1 : 0, md5: d.md5,
                foreign: !d.has_php, bits: decodeBits(d.ml_features), hex: all.length < keepHex ? d.ml_features : null,
                ruleAnomaly: scored[i].isAnomaly && !scored[i].mlOnly, ruleScore: scored[i].ruleScore,
            });
        });
    }
    const benignMd5 = new Set(all.filter(d => !d.label).map(d => d.md5));
    const unique = new Map();
    for (const d of all) {
        if (d.label && benignMd5.has(d.md5)) { dropped.conflicts++; continue; }
        const k = d.label + d.md5;
        if (unique.has(k)) unique.get(k).copies++;
        else { d.copies = 1; unique.set(k, d); }
    }
    return { samples: [...unique.values()], files: all.length, dropped };
}

const popcnt = x => { x -= (x >>> 1) & 0x55555555; x = (x & 0x33333333) + ((x >>> 2) & 0x33333333); return (((x + (x >>> 4)) & 0x0F0F0F0F) * 0x01010101) >>> 24; };
/**
 * Group near-identical shells (feature-set Jaccard >= `similar`), so a variant
 * of a training shell can't count as a held-out catch; benign samples are
 * grouped by family. Sets d.group; a cluster is named by its smallest MD5,
 * which doesn't depend on listing order.
 */
function assignGroups(samples, buckets, similar) {
    const mal = samples.filter(d => d.label);
    const words = buckets / 32;
    const sets = mal.map(d => { const s = new Uint32Array(words); d.bits.forEach(b => { s[b >>> 5] |= 1 << (b & 31); }); return s; });
    const parent = mal.map((_, i) => i);
    const find = i => { while (parent[i] !== i) i = parent[i] = parent[parent[i]]; return i; };
    const order = mal.map((_, i) => i).sort((a, b) => mal[a].bits.length - mal[b].bits.length);
    for (let x = 0; x < order.length; x++) {
        const a = order[x];
        for (let y = x + 1; y < order.length; y++) {
            const b = order[y];
            if (mal[a].bits.length < similar * mal[b].bits.length) break; // Jaccard <= |A|/|B|
            let inter = 0;
            for (let w = 0; w < words; w++) inter += popcnt(sets[a][w] & sets[b][w]);
            if (inter / (mal[a].bits.length + mal[b].bits.length - inter) >= similar) parent[find(a)] = find(b);
        }
    }
    const name = new Map();
    mal.forEach((d, i) => { const r = find(i); if (!name.has(r) || d.md5 < name.get(r)) name.set(r, d.md5); });
    mal.forEach((d, i) => { d.group = 'shell:' + name.get(find(i)); });
    samples.filter(d => !d.label).forEach(d => { d.group = 'family:' + d.family; });
}

/**
 * Cross-validation folds: whole groups, greedily balanced by size, largest
 * first, ties broken by a hash of the group name. The same groups always land
 * in the same folds, whatever order the corpora are listed in.
 */
function assignFolds(samples, folds) {
    for (const label of [1, 0]) {
        const groups = [...lib.groupBy(samples.filter(d => d.label === label), d => d.group)]
            .map(([key, members]) => ({ members, tie: lib.sha1(key) }))
            .sort((a, b) => b.members.length - a.members.length || (a.tie < b.tie ? -1 : 1));
        const sizes = new Array(folds).fill(0);
        for (const g of groups) {
            const f = sizes.indexOf(Math.min(...sizes));
            sizes[f] += g.members.length;
            g.members.forEach(d => { d.fold = f; });
        }
    }
}

/**
 * At most `cap` benign training samples per corpus, so huge projects don't
 * drown the rest: the ones with the smallest hash of their MD5 (stable).
 */
function capPerCorpus(benign, cap) {
    const out = [];
    for (const list of lib.groupBy(benign, d => d.corpus).values()) {
        out.push(...list.map(d => ({ d, h: lib.sha1(d.md5) })).sort((a, b) => (a.h < b.h ? -1 : 1)).slice(0, cap).map(x => x.d));
    }
    return out;
}

// --- Training ---

/**
 * All samples' feature bits in one shared array (offsets per sample) with
 * their labels: training walks contiguous memory, and worker threads share it.
 * Sets d.idx on each sample.
 */
function pack(samples) {
    const total = samples.reduce((n, d) => n + d.bits.length, 0);
    const bits = new Uint16Array(new SharedArrayBuffer(total * 2));
    const offsets = new Uint32Array(new SharedArrayBuffer((samples.length + 1) * 4));
    const labels = new Uint8Array(new SharedArrayBuffer(samples.length));
    let o = 0;
    samples.forEach((d, i) => { d.idx = i; offsets[i] = o; bits.set(d.bits, o); o += d.bits.length; labels[i] = d.label; });
    offsets[samples.length] = o;
    return { bits, offsets, labels };
}

/**
 * Logistic regression on binary features, full-batch Adam, class-balanced
 * loss, L2 on the weights. `indices` picks (and orders) the training samples.
 */
function train({ bits, offsets, labels }, indices, { buckets, epochs, l2, lr = 0.05 }) {
    const w = new Float64Array(buckets), m = new Float64Array(buckets), v = new Float64Array(buckets), g = new Float64Array(buckets);
    let b = 0, mb = 0, vb = 0;
    const n = indices.length;
    let pos = 0;
    for (let i = 0; i < n; i++) pos += labels[indices[i]];
    const cw = [n / (2 * (n - pos)), n / (2 * pos)];
    const b1 = 0.9, b2 = 0.999, eps = 1e-8;
    for (let e = 1; e <= epochs; e++) {
        g.fill(0);
        let gb = 0;
        for (let i = 0; i < n; i++) {
            const r = indices[i], lo = offsets[r], hi = offsets[r + 1], y = labels[r];
            let z = b;
            for (let k = lo; k < hi; k++) z += w[bits[k]];
            const err = (1 / (1 + Math.exp(-z)) - y) * cw[y] / n;
            gb += err;
            for (let k = lo; k < hi; k++) g[bits[k]] += err;
        }
        const c1 = 1 - Math.pow(b1, e), c2 = 1 - Math.pow(b2, e);
        for (let k = 0; k < buckets; k++) {
            const gk = g[k] + l2 * w[k];
            m[k] = b1 * m[k] + (1 - b1) * gk;
            v[k] = b2 * v[k] + (1 - b2) * gk * gk;
            w[k] -= lr * (m[k] / c1) / (Math.sqrt(v[k] / c2) + eps);
        }
        mb = b1 * mb + (1 - b1) * gb;
        vb = b2 * vb + (1 - b2) * gb * gb;
        b -= lr * (mb / c1) / (Math.sqrt(vb / c2) + eps);
    }
    return { w, b };
}

/** Train one model per index list, each in its own worker thread, all at once */
function trainParallel(packed, indexLists, opts) {
    return Promise.all(indexLists.map(indices => new Promise((resolve, reject) => {
        const shared = new Int32Array(new SharedArrayBuffer(indices.length * 4));
        shared.set(indices);
        const worker = new Worker(__filename, { workerData: { packed, indices: shared, opts } });
        worker.once('message', resolve);
        worker.once('error', reject);
        worker.once('exit', code => { if (code) reject(new Error('training worker exited with ' + code)); });
    })));
}
if (!isMainThread && workerData && workerData.packed) {
    const model = train(workerData.packed, workerData.indices, workerData.opts);
    parentPort.postMessage(model, [model.w.buffer]);
}

/** int8 weights as hex (two's complement) plus scale and bias: what ml-model.json holds */
function quantize(model) {
    let max = 0;
    for (const x of model.w) max = Math.max(max, Math.abs(x));
    const scale = max / 127 || 1;
    let hex = '';
    for (const x of model.w) hex += ((Math.round(x / scale) + 256) % 256).toString(16).padStart(2, '0');
    return { scale: +scale.toPrecision(6), bias: +model.b.toPrecision(6), weights: hex };
}

/** main.php's mlScore() arithmetic on decoded bits (test/unit.js checks they agree) */
function scorer(model) {
    const w = new Int8Array(model.weights.length / 2);
    for (let i = 0; i < w.length; i++) w[i] = parseInt(model.weights.substr(i * 2, 2), 16);
    return bits => { let s = 0; for (let k = 0; k < bits.length; k++) s += w[bits[k]]; return 1 / (1 + Math.exp(-(model.bias + s * model.scale))); };
}

module.exports = {
    CACHE_DIR, featureKey, extractTo, extractCorpus, decodeBits, buildSamples, assignGroups, assignFolds, capPerCorpus,
    pack, train, trainParallel, quantize, scorer,
};
