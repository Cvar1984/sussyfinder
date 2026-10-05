// Trains the client-side ML model (logistic regression over main.php's hashed
// token features, see mlFeatures()) on test/webshells vs test/WordPress +
// test/laravel, reports grouped k-fold cross-validated detection/false-positive
// rates, and with --write stores the int8-quantized weights in main.php.
//
// Usage:
//   node test/train-ml.js                 cross-validate only
//   node test/train-ml.js --write         cross-validate, then train on everything and update main.php
//   extra: --rows rows.json (reuse a `node test/run.js --dump` file), --folds 5,
//          --l2 0.001, --epochs 400, --list (held-out misses/false positives),
//          --check DIR (repeatable: how many files in DIR, assumed benign, get flagged)
//
// Byte-identical files share a fold, so a copy of a training shell can't
// count as a held-out detection. The CV numbers are the honest ones; the
// benchmark in test/run.js scores the shipped model on the data it was
// trained on, so its ML line is optimistic.
const { execFileSync } = require('child_process');
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
const mainPath = path.join(root, 'main.php');
const web = fs.readFileSync(mainPath, 'utf8');
const buckets = parseInt(web.match(/define\('ML_BUCKETS', (\d+)\)/)[1], 10);

// --- Rows: from --rows, or extracted now by test/run.js ---
let rowsFile = opt('--rows', null);
if (!rowsFile) {
    rowsFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sussy-ml-')), 'rows.json');
    execFileSync('node', [path.join(__dirname, 'run.js'), '--dump', rowsFile], { stdio: ['ignore', 'ignore', 'inherit'] });
}
const rows = JSON.parse(fs.readFileSync(rowsFile, 'utf8')).filter(d => d.ml_features && !d.is_htaccess);
rows.forEach(d => {
    d.rel = d.path.slice(d.path.indexOf('test/'));
    d.label = d.rel.startsWith('test/webshells/') ? 1 : 0;
    d.mtime = 0;
    d.ctime = 0;
    d.bits = [];
    for (let i = 0; i < d.ml_features.length; i++) {
        const nibble = parseInt(d.ml_features[i], 16);
        for (let b = 0; b < 4; b++) if (nibble & (1 << b)) d.bits.push(i * 4 + b);
    }
});

// --- main.php's scoring block: rule-based anomaly flags, and its ML scorer ---
const start = web.indexOf('// --- Client-side threat scoring');
const end = web.indexOf('// --- End client-side threat scoring ---');
const weightsJson = execFileSync('php', ['-r', "define('SUSSY_LIB', true); include " + JSON.stringify(mainPath) + "; echo json_encode($tokenNeedles);"]).toString();
const ctx = vm.createContext({ tokenWeights: JSON.parse(weightsJson) });
vm.runInContext(web.slice(start, end), ctx);
const analyzed = ctx.analyzeData(rows, 3.5);
rows.forEach((d, i) => { d.ruleAnomaly = analyzed[i].isAnomaly && !analyzed[i].mlOnly; });

// --- Logistic regression on binary features, Adam, class-balanced loss ---
function train(set) {
    const w = new Float64Array(buckets), m = new Float64Array(buckets), v = new Float64Array(buckets);
    let b = 0, mb = 0, vb = 0;
    const pos = set.filter(d => d.label).length, neg = set.length - pos;
    const cw = [set.length / (2 * neg), set.length / (2 * pos)];
    const lr = 0.05, b1 = 0.9, b2 = 0.999, eps = 1e-8;
    const g = new Float64Array(buckets);
    for (let e = 1; e <= epochs; e++) {
        g.fill(0);
        let gb = 0;
        for (const d of set) {
            let z = b;
            for (const k of d.bits) z += w[k];
            const err = (1 / (1 + Math.exp(-z)) - d.label) * cw[d.label] / set.length;
            gb += err;
            for (const k of d.bits) g[k] += err;
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

// int8 weights as hex (two's complement), plus scale and bias: what main.php ships
function quantize(model) {
    let max = 0;
    for (const x of model.w) max = Math.max(max, Math.abs(x));
    const scale = max / 127 || 1;
    let hex = '';
    for (const x of model.w) hex += ((Math.round(x / scale) + 256) % 256).toString(16).padStart(2, '0');
    return { scale: +scale.toPrecision(6), bias: +model.b.toPrecision(6), weights: hex };
}

// --- Grouped, stratified folds (seeded shuffle) ---
let seed = 1984;
const rand = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
const groups = new Map();
rows.forEach(d => { if (!groups.has(d.md5)) groups.set(d.md5, []); groups.get(d.md5).push(d); });
[0, 1].forEach(label => {
    const gs = [...groups.values()].filter(g => g[0].label === label);
    for (let i = gs.length - 1; i > 0; i--) { const j = Math.floor(rand() * (i + 1)); [gs[i], gs[j]] = [gs[j], gs[i]]; }
    gs.forEach((g, i) => g.forEach(d => { d.fold = i % folds; }));
});
for (let f = 0; f < folds; f++) {
    const model = quantize(train(rows.filter(d => d.fold !== f)));
    rows.filter(d => d.fold === f).forEach(d => { d.cvScore = ctx.mlScore(d.ml_features, model); });
    process.stderr.write(`fold ${f + 1}/${folds}\r`);
}

const threshold = vm.runInContext('ML_THRESHOLD', ctx);
const mal = rows.filter(d => d.label), ben = rows.filter(d => !d.label);
const pct = (a, b) => (100 * a / Math.max(1, b)).toFixed(1) + '%';
const report = (label, hit) => {
    const tp = mal.filter(hit).length, fp = ben.filter(hit).length;
    console.log(`${label.padEnd(26)} detected ${tp}/${mal.length} (${pct(tp, mal.length)})   false positives ${fp}/${ben.length} (${pct(fp, ben.length)})`);
};
console.log(`${folds}-fold cross-validation (held-out scores), ${buckets} buckets, l2 ${l2}, ${epochs} epochs`);
report('rules only (anomaly)', d => d.ruleAnomaly);
[0.5, 0.7, 0.8, 0.9, 0.95, 0.98].forEach(t => report(`ml >= ${t}${t === threshold ? ' (shipped)' : ''}`, d => d.cvScore >= t));
report(`rules or ml >= ${threshold}`, d => d.ruleAnomaly || d.cvScore >= threshold);
report(`  ml only (>= ${threshold})`, d => !d.ruleAnomaly && d.cvScore >= threshold);

if (args.includes('--list')) {
    console.log('\nHELD-OUT MISSES (rules and ml):');
    mal.filter(d => !d.ruleAnomaly && d.cvScore < threshold).forEach(d => console.log(`  ${d.rel}  ml=${d.cvScore.toFixed(3)}`));
    console.log('\nCAUGHT BY ML ONLY:');
    mal.filter(d => !d.ruleAnomaly && d.cvScore >= threshold).forEach(d => console.log(`  ${d.rel}  ml=${d.cvScore.toFixed(3)}`));
    console.log('\nML FALSE POSITIVES:');
    ben.filter(d => d.cvScore >= threshold).forEach(d => console.log(`  ${d.rel}  ml=${d.cvScore.toFixed(3)}${d.ruleAnomaly ? '  (rules flag it too)' : ''}`));
}

// --- --check DIR: score files the model never saw (e.g. another framework) ---
// Everything in DIR is treated as benign; prints what each detector flags.
const checkDirs = args.map((a, i) => a === '--check' ? args[i + 1] : null).filter(Boolean);
if (checkDirs.length) {
    const model = quantize(train(rows));
    const script = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sussy-ml-')), 'extract.php');
    fs.writeFileSync(script, `<?php
define('SUSSY_LIB', true);
include ${JSON.stringify(mainPath)};
$r = getSortedByPattern($argv[1], $pattern);
$seen = array();
$new = array();
foreach ($r['file_readable'] as $file) {
    foreach (scanReadablePaths(array($file), array(), array(), $tokenNeedles, $seen, $new) as $row) {
        echo json_encode($row), "\n";
    }
}
`);
    checkDirs.forEach(dir => {
        const out = execFileSync('php', [script, path.resolve(dir)], { maxBuffer: 1 << 30 }).toString();
        const set = out.split('\n').filter(Boolean).map(l => JSON.parse(l)).filter(d => d.ml_features && !d.is_htaccess);
        const res = ctx.analyzeData(set, 3.5);
        const rule = res.filter(d => d.isAnomaly && !d.mlOnly).length;
        const flagged = res.filter(d => mlScore(d) >= threshold);
        console.log(`\n--check ${dir}: ${set.length} files   rules flag ${rule} (${pct(rule, set.length)})   ml >= ${threshold} flags ${flagged.length} (${pct(flagged.length, set.length)})`);
        if (args.includes('--list')) flagged.forEach(d => console.log(`  ${d.path}  ml=${mlScore(d).toFixed(3)}`));
        function mlScore(d) { return ctx.mlScore(d.ml_features, model); }
    });
}

if (args.includes('--write')) {
    const model = quantize(train(rows));
    const line = 'const ML_MODEL = ' + JSON.stringify(model) + ';';
    const updated = web.replace(/const ML_MODEL = .*;/, () => line);
    if (updated === web && !web.includes(line)) throw new Error('ML_MODEL line not found in main.php');
    fs.writeFileSync(mainPath, updated);
    console.log(`\nwrote ML_MODEL (${model.weights.length / 2} int8 weights) to main.php`);
}
