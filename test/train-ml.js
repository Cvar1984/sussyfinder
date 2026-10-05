// Trains the client-side ML model (logistic regression over main.php's hashed
// token features, see mlFeatures()) on the corpora in test/corpora.json,
// reports cross-validated detection/false-positive rates, and with --write
// stores the int8-quantized weights in ml-model.json, which main.php downloads.
//
// Usage:
//   node test/fetch-corpora.js            download the corpora first (once)
//   node test/train-ml.js                 cross-validate only
//   node test/train-ml.js --write         cross-validate, then train on everything and write ml-model.json
//   extra: --folds 5, --l2 0.001, --epochs 400, --cap 2000 (benign training files
//          per corpus), --similar 0.8, --by-family, --list,
//          --check DIR (repeatable: how many files in DIR, assumed benign, get flagged)
//
// What keeps the numbers honest:
// - Files are de-duplicated by MD5; a file that also ships in a benign
//   project isn't counted as a shell.
// - Shells whose feature sets are near-identical (Jaccard >= --similar) are
//   one cluster and share a fold, so a variant of a training shell can't
//   count as a held-out detection.
// - Benign corpora of the same family (e.g. every WordPress version) share a
//   fold, so false positives are always measured on projects the model never saw.
// The benchmark in test/run.js scores the shipped model on files it was trained
// on, so its ML line is optimistic; these numbers are the ones to quote.
const { execFile, execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');

const root = path.join(__dirname, '..');
const args = process.argv.slice(2);
const opt = (name, def) => { const i = args.indexOf(name); return i === -1 ? def : args[i + 1]; };
const folds = parseInt(opt('--folds', '5'), 10);
const l2 = parseFloat(opt('--l2', '0.001'));
const epochs = parseInt(opt('--epochs', '400'), 10);
const cap = parseInt(opt('--cap', '2000'), 10);
const similar = parseFloat(opt('--similar', '0.8'));
const mainPath = path.join(root, 'main.php');
const web = fs.readFileSync(mainPath, 'utf8');
const buckets = parseInt(web.match(/define\('ML_BUCKETS', (\d+)\)/)[1], 10);
const featureVersion = parseInt(web.match(/define\('ML_FEATURE_VERSION', (\d+)\)/)[1], 10);
const t0 = Date.now();
const log = msg => process.stderr.write(`[${((Date.now() - t0) / 1000).toFixed(0)}s] ${msg}\n`);

let seed = 1984;
const rand = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
const shuffle = a => { for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(rand() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; };

// --- main.php's scoring block: rule-based anomaly flags, and its ML scorer ---
const start = web.indexOf('// --- Client-side threat scoring');
const end = web.indexOf('// --- End client-side threat scoring ---');
const weightsJson = execFileSync('php', ['-r', "define('SUSSY_LIB', true); include " + JSON.stringify(mainPath) + "; echo json_encode($tokenNeedles);"]).toString();
const ctx = vm.createContext({ tokenWeights: JSON.parse(weightsJson) });
vm.runInContext(web.slice(start, end), ctx);
const threshold = vm.runInContext('ML_THRESHOLD', ctx);

// --- Feature extraction, cached per corpus and per feature-code version ---
// The cache key covers everything in main.php that shapes a row, so editing
// the extractor (or the needles) re-extracts instead of reusing stale rows.
const featureCode = web.slice(0, web.indexOf('// test/run.js includes this file'));
const featureHash = crypto.createHash('sha1').update(featureCode).digest('hex').slice(0, 12);
const cacheDir = path.join(__dirname, 'corpora', '.rows');
fs.mkdirSync(cacheDir, { recursive: true });
const extractScript = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sussy-ml-')), 'extract.php');
fs.writeFileSync(extractScript, `<?php
define('SUSSY_LIB', true);
include ${JSON.stringify(mainPath)};
$base = rtrim($argv[1], '/') . '/';
$r = getSortedByPattern($argv[1], $pattern);
$seen = array();
$new = array();
foreach ($r['file_readable'] as $file) {
    foreach (scanReadablePaths(array($file), array(), array(), $tokenNeedles, $seen, $new) as $row) {
        $content = file_get_contents($file);
        // Server code in another language (ASP, JSP, CGI) in a PHP-named file
        $row['no_php'] = !preg_match('/<\\?(php|=|\\s)/i', $content);
        $row['foreign'] = (bool) preg_match('/<%|Response\\.Write|CreateObject|Runtime\\.getRuntime|^#!.*perl|\\buse CGI\\b/im', $content);
        $row['path'] = substr($file, strlen($base));
        echo json_encode($row), "\\n";
    }
}
`);
const run = (cmd, a) => new Promise((resolve, reject) => execFile(cmd, a, { maxBuffer: 1 << 30 }, (e, out) => e ? reject(e) : resolve(out)));

function corpusDir(c) {
    return c.path ? path.join(root, c.path) : path.join(__dirname, 'corpora', c.name, c.subdir || '');
}
async function extract(c) {
    const cache = path.join(cacheDir, `${c.name}-${(c.commit || 'local').slice(0, 10)}-${featureHash}.jsonl`);
    if (!fs.existsSync(cache)) {
        const out = await run('php', [extractScript, corpusDir(c)]);
        fs.writeFileSync(cache + '.tmp', out);
        fs.renameSync(cache + '.tmp', cache);
    }
    return cache;
}

// Lean row kept in memory: feature bits plus what the reports need
function toBits(hex) {
    const bits = [];
    for (let i = 0; i < hex.length; i++) {
        const nibble = parseInt(hex[i], 16);
        for (let b = 0; b < 4; b++) if (nibble & (1 << b)) bits.push(i * 4 + b);
    }
    return Uint16Array.from(bits);
}

(async () => {
    const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, 'corpora.json'), 'utf8'));
    const corpora = manifest.corpora.filter(c => fs.existsSync(corpusDir(c)));
    const missing = manifest.corpora.length - corpora.length;
    if (missing) log(`${missing} corpora not downloaded (node test/fetch-corpora.js), skipping them`);
    const exclude = fs.readFileSync(path.join(__dirname, 'ml-exclude.txt'), 'utf8').split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));

    let next = 0, done = 0;
    await Promise.all(Array.from({ length: Math.max(1, os.cpus().length) }, async () => {
        while (next < corpora.length) {
            const c = corpora[next++];
            c.cache = await extract(c);
            if (++done % 10 === 0 || done === corpora.length) log(`features ${done}/${corpora.length} corpora`);
        }
    }));

    const all = [];
    const dropped = { htaccess: 0, notShell: 0, excluded: 0 };
    for (const c of corpora) {
        const raw = fs.readFileSync(c.cache, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
        raw.forEach(d => { d.mtime = 0; d.ctime = 0; });
        // Rule-based verdicts as if this corpus were scanned on its own
        const res = ctx.analyzeData(raw, 3.5);
        raw.forEach((d, i) => {
            const id = c.name + '/' + d.path;
            if (!d.ml_features) return;
            if (d.is_htaccess) { dropped.htaccess++; return; }
            if (exclude.some(x => id.includes(x))) { dropped.excluded++; return; }
            // A shell-collection file with no PHP and no other server code
            // (a README page, robots.txt) can't run as a webshell
            if (c.label === 'shell' && d.no_php && !d.foreign) { dropped.notShell++; return; }
            all.push({
                id, corpus: c.name, family: c.family, label: c.label === 'shell' ? 1 : 0, md5: d.md5,
                foreign: d.no_php && d.foreign, bits: toBits(d.ml_features), hex: all.length < 500 ? d.ml_features : null,
                ruleAnomaly: res[i].isAnomaly && !res[i].mlOnly, ruleScore: res[i].ruleScore,
            });
        });
    }

    // De-duplicate by MD5; a file that ships in a benign project is benign
    const benignMd5 = new Set(all.filter(d => !d.label).map(d => d.md5));
    const byMd5 = new Map();
    let conflicts = 0;
    for (const d of all) {
        if (d.label && benignMd5.has(d.md5)) { conflicts++; continue; }
        const k = d.label + d.md5;
        if (byMd5.has(k)) { byMd5.get(k).copies++; continue; }
        d.copies = 1;
        byMd5.set(k, d);
    }
    const rows = [...byMd5.values()];
    const mal = rows.filter(d => d.label), ben = rows.filter(d => !d.label);
    log(`${all.length} files -> ${mal.length} unique shells, ${ben.length} unique benign ` +
        `(dropped: ${dropped.htaccess} .htaccess, ${dropped.notShell} non-code files in shell collections, ` +
        `${dropped.excluded} excluded, ${conflicts} shell-collection files also found in benign projects)`);

    // --- Shell clusters: union-find over near-identical feature sets ---
    const words = buckets / 32;
    const popcnt = x => { x -= (x >>> 1) & 0x55555555; x = (x & 0x33333333) + ((x >>> 2) & 0x33333333); return (((x + (x >>> 4)) & 0x0F0F0F0F) * 0x01010101) >>> 24; };
    mal.forEach(d => { d.set = new Uint32Array(words); d.bits.forEach(b => { d.set[b >>> 5] |= 1 << (b & 31); }); });
    const parent = mal.map((_, i) => i);
    const find = i => { while (parent[i] !== i) i = parent[i] = parent[parent[i]]; return i; };
    const order = mal.map((_, i) => i).sort((a, b) => mal[a].bits.length - mal[b].bits.length);
    for (let x = 0; x < order.length; x++) {
        const A = mal[order[x]];
        for (let y = x + 1; y < order.length; y++) {
            const B = mal[order[y]];
            if (A.bits.length < similar * B.bits.length) break; // Jaccard <= |A|/|B|
            let inter = 0;
            for (let w = 0; w < words; w++) inter += popcnt(A.set[w] & B.set[w]);
            if (inter / (A.bits.length + B.bits.length - inter) >= similar) parent[find(order[x])] = find(order[y]);
        }
    }
    mal.forEach((d, i) => { d.group = 'shell:' + find(i); delete d.set; });
    ben.forEach(d => { d.group = 'family:' + d.family; });
    const clusters = new Set(mal.map(d => d.group)).size;
    log(`${clusters} shell clusters (Jaccard >= ${similar}), ${new Set(ben.map(d => d.family)).size} benign families`);

    // --- Folds: whole clusters/families, greedily balanced by size ---
    [mal, ben].forEach(set => {
        const groups = new Map();
        set.forEach(d => { if (!groups.has(d.group)) groups.set(d.group, []); groups.get(d.group).push(d); });
        const sizes = new Array(folds).fill(0);
        shuffle([...groups.values()]).sort((a, b) => b.length - a.length).forEach(g => {
            const f = sizes.indexOf(Math.min(...sizes));
            sizes[f] += g.length;
            g.forEach(d => { d.fold = f; });
        });
    });

    // Benign training rows: at most --cap per corpus, so huge projects don't drown the rest
    const capped = [];
    const perCorpus = new Map();
    ben.forEach(d => { if (!perCorpus.has(d.corpus)) perCorpus.set(d.corpus, []); perCorpus.get(d.corpus).push(d); });
    perCorpus.forEach(list => capped.push(...shuffle(list.slice()).slice(0, cap)));

    // --- Logistic regression on binary features, Adam, class-balanced loss ---
    function train(set) {
        const w = new Float64Array(buckets), m = new Float64Array(buckets), v = new Float64Array(buckets), g = new Float64Array(buckets);
        let b = 0, mb = 0, vb = 0;
        const pos = set.filter(d => d.label).length, neg = set.length - pos;
        const cw = [set.length / (2 * neg), set.length / (2 * pos)];
        const lr = 0.05, b1 = 0.9, b2 = 0.999, eps = 1e-8;
        for (let e = 1; e <= epochs; e++) {
            g.fill(0);
            let gb = 0;
            for (const d of set) {
                const bits = d.bits;
                let z = b;
                for (let k = 0; k < bits.length; k++) z += w[bits[k]];
                const err = (1 / (1 + Math.exp(-z)) - d.label) * cw[d.label] / set.length;
                gb += err;
                for (let k = 0; k < bits.length; k++) g[bits[k]] += err;
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

    // int8 weights as hex (two's complement), plus scale and bias: what ml-model.json holds
    function quantize(model) {
        let max = 0;
        for (const x of model.w) max = Math.max(max, Math.abs(x));
        const scale = max / 127 || 1;
        let hex = '';
        for (const x of model.w) hex += ((Math.round(x / scale) + 256) % 256).toString(16).padStart(2, '0');
        return { scale: +scale.toPrecision(6), bias: +model.b.toPrecision(6), weights: hex };
    }
    // Same arithmetic as main.php's mlScore(), on pre-decoded bits
    function scorer(model) {
        const w = new Int8Array(model.weights.length / 2);
        for (let i = 0; i < w.length; i++) w[i] = parseInt(model.weights.substr(i * 2, 2), 16);
        return d => { let s = 0; for (let k = 0; k < d.bits.length; k++) s += w[d.bits[k]]; return 1 / (1 + Math.exp(-(model.bias + s * model.scale))); };
    }

    for (let f = 0; f < folds; f++) {
        const model = quantize(train(mal.filter(d => d.fold !== f).concat(capped.filter(d => d.fold !== f))));
        const score = scorer(model);
        rows.filter(d => d.fold === f).forEach(d => { d.cvScore = score(d); });
        log(`fold ${f + 1}/${folds}`);
        if (f === 0) rows.filter(d => d.hex).forEach(d => { // the shortcut must match main.php exactly
            if (Math.abs(score(d) - ctx.mlScore(d.hex, model)) > 1e-9) throw new Error('scorer mismatch on ' + d.id);
        });
    }

    // --- Report ---
    const pct = (a, b) => (100 * a / Math.max(1, b)).toFixed(1) + '%';
    const clustersHit = hit => new Set(mal.filter(hit).map(d => d.group)).size;
    const report = (label, hit) => {
        const tp = mal.filter(hit).length, fp = ben.filter(hit).length;
        console.log(`${label.padEnd(26)} shells ${String(tp).padStart(5)}/${mal.length} (${pct(tp, mal.length).padStart(6)})  ` +
            `clusters ${String(clustersHit(hit)).padStart(4)}/${clusters}   false positives ${String(fp).padStart(5)}/${ben.length} (${pct(fp, ben.length)})`);
    };
    console.log(`\n${folds}-fold cross-validation, held-out scores: ${mal.length} unique shells in ${clusters} clusters, ` +
        `${ben.length} unique benign files in ${new Set(ben.map(d => d.family)).size} families (whole families held out)`);
    console.log(`${buckets} buckets, l2 ${l2}, ${epochs} epochs, benign cap ${cap}/corpus, ${((Date.now() - t0) / 1000).toFixed(0)}s\n`);
    report('rules only (anomaly)', d => d.ruleAnomaly);
    [0.5, 0.7, 0.8, 0.9, 0.95, 0.98].forEach(t => report(`ml >= ${t}${t === threshold ? ' (shipped)' : ''}`, d => d.cvScore >= t));
    report(`rules or ml >= ${threshold}`, d => d.ruleAnomaly || d.cvScore >= threshold);
    report(`  ml only (>= ${threshold})`, d => !d.ruleAnomaly && d.cvScore >= threshold);
    // How main.php combines them: ML points added to the rule score (mlPoints())
    const floor = vm.runInContext('ML_FLOOR', ctx);
    const combined = (d, f) => d.ruleScore + ctx.mlPoints(d.cvScore, f);
    console.log(`\nThreat score with ML points (ML_FLOOR sweep, shipped ${floor}):`);
    [0.5, 0.6, 0.7, 0.8].forEach(f => {
        report(`  anomaly, floor ${f}${f === floor ? ' *' : ''}`, d => d.ruleAnomaly || combined(d, f) >= 8);
        report(`  score >= 15, floor ${f}`, d => combined(d, f) >= 15);
    });
    const isPhp = d => !d.foreign;
    const phpShells = mal.filter(isPhp).length;
    console.log(`\nPHP files only (ASP/JSP/CGI in PHP-named files left out):`);
    [['rules only', d => isPhp(d) && d.ruleAnomaly], [`rules or ml >= ${threshold}`, d => isPhp(d) && (d.ruleAnomaly || d.cvScore >= threshold)]].forEach(([label, hit]) => {
        const tp = mal.filter(hit).length;
        console.log(`  ${label.padEnd(24)} shells ${tp}/${phpShells} (${pct(tp, phpShells)})`);
    });

    if (args.includes('--by-family')) {
        console.log('\nFalse positives per benign family (held out):  rules   ml>=' + threshold);
        const fam = new Map();
        ben.forEach(d => { if (!fam.has(d.family)) fam.set(d.family, []); fam.get(d.family).push(d); });
        [...fam.entries()].sort((a, b) => b[1].filter(d => d.cvScore >= threshold).length / b[1].length - a[1].filter(d => d.cvScore >= threshold).length / a[1].length)
            .forEach(([name, list]) => {
                const r = list.filter(d => d.ruleAnomaly).length, m = list.filter(d => d.cvScore >= threshold).length;
                console.log(`  ${name.padEnd(16)} ${String(list.length).padStart(6)} files  ${pct(r, list.length).padStart(6)}  ${pct(m, list.length).padStart(6)}`);
            });
    }
    if (args.includes('--list')) {
        console.log('\nHELD-OUT MISSES (rules and ml):');
        mal.filter(d => !d.ruleAnomaly && d.cvScore < threshold).forEach(d => console.log(`  ${d.id}  ml=${d.cvScore.toFixed(3)}`));
        console.log('\nML FALSE POSITIVES:');
        ben.filter(d => d.cvScore >= threshold).forEach(d => console.log(`  ${d.id}  ml=${d.cvScore.toFixed(3)}${d.ruleAnomaly ? '  (rules flag it too)' : ''}`));
    }

    const finalModel = (args.includes('--write') || args.includes('--check')) ? quantize(train(mal.concat(capped))) : null;

    // --- --check DIR: score files the model never saw (e.g. another framework) ---
    const checkDirs = args.map((a, i) => a === '--check' ? args[i + 1] : null).filter(Boolean);
    for (const dir of checkDirs) {
        const out = await run('php', [extractScript, path.resolve(dir)]);
        const set = out.split('\n').filter(Boolean).map(l => JSON.parse(l)).filter(d => d.ml_features && !d.is_htaccess);
        const res = ctx.analyzeData(set, 3.5);
        const rule = res.filter(d => d.isAnomaly && !d.mlOnly).length;
        const flagged = set.filter(d => ctx.mlScore(d.ml_features, finalModel) >= threshold);
        console.log(`\n--check ${dir}: ${set.length} files   rules flag ${rule} (${pct(rule, set.length)})   ml >= ${threshold} flags ${flagged.length} (${pct(flagged.length, set.length)})`);
        if (args.includes('--list')) flagged.forEach(d => console.log(`  ${d.path}  ml=${ctx.mlScore(d.ml_features, finalModel).toFixed(3)}`));
    }

    if (args.includes('--write')) {
        // Key order matters: main.php checks the file against a fixed pattern
        const file = { features: featureVersion, buckets, scale: finalModel.scale, bias: finalModel.bias, weights: finalModel.weights };
        fs.writeFileSync(path.join(root, 'ml-model.json'), JSON.stringify(file) + '\n');
        console.log(`\nwrote ml-model.json (feature version ${featureVersion}, ${buckets} int8 weights, trained on ${mal.length} shells + ${capped.length} benign files)`);
    }
})().catch(e => { console.error(e); process.exit(1); });
