// Trains the client-side ML model (logistic regression over main.php's hashed
// token features, see mlFeatures()) on the sample submodules under
// test/corpora/, reports cross-validated detection/false-positive rates, and
// with --write stores the int8-quantized weights in ml-model.json, which
// main.php downloads. The pipeline itself is in test/ml.js.
//
// Fetch the samples first: git submodule update --init test/corpora/
//
// What keeps the numbers honest:
// - Files are de-duplicated by MD5; a file that also ships in a benign
//   project isn't counted as a shell.
// - Near-identical shells (feature-set Jaccard >= --similar) are one cluster
//   and share a fold, so a variant of a training shell can't count as a
//   held-out detection.
// - Benign corpora of the same family (e.g. every WordPress release) share a
//   fold, so false positives are always measured on projects the model never saw.
// - Folds and the benign cap are chosen by hashes, not a random stream, so
//   adding or reordering corpora only moves the samples that changed.
// test/run.js scores the shipped model on files it was trained on, so its ML
// line is optimistic; these numbers are the ones to quote.
const fs = require('fs');
const os = require('os');
const path = require('path');
const lib = require('./lib');
const ml = require('./ml');

const args = lib.cli({
    folds: { type: 'string', default: '5', help: 'cross-validation folds' },
    l2: { type: 'string', default: '0.001', help: 'L2 penalty on the weights' },
    epochs: { type: 'string', default: '400', help: 'full-batch Adam epochs' },
    cap: { type: 'string', default: '2000', help: 'benign training files per corpus' },
    similar: { type: 'string', default: '0.8', help: 'Jaccard at which shells are one cluster' },
    'by-family': { type: 'boolean', help: 'false positives per benign family' },
    list: { type: 'boolean', help: 'held-out misses and false positives' },
    check: { type: 'string', multiple: true, arg: 'dir', help: 'how many files in a trusted dir get flagged (repeatable)' },
    write: { type: 'boolean', help: 'train on everything and write ml-model.json' },
}, 'Usage: node test/train-ml.js [options]');
const opts = {
    folds: parseInt(args.folds, 10), l2: parseFloat(args.l2), epochs: parseInt(args.epochs, 10),
    cap: parseInt(args.cap, 10), similar: parseFloat(args.similar),
};
const t0 = Date.now();
const log = msg => process.stderr.write(`[${((Date.now() - t0) / 1000).toFixed(0)}s] ${msg}\n`);
const src = fs.readFileSync(lib.MAIN, 'utf8');
const define = name => parseInt(src.match(new RegExp(`define\\('${name}', (\\d+)\\)`))[1], 10);
const buckets = define('ML_BUCKETS'), featureVersion = define('ML_FEATURE_VERSION');

async function extractAll(corpora) {
    const key = ml.featureKey();
    let next = 0, done = 0;
    await Promise.all(Array.from({ length: os.cpus().length }, async () => {
        while (next < corpora.length) {
            const c = corpora[next++];
            c.cache = await ml.extractCorpus(c, key);
            if (++done % 20 === 0 || done === corpora.length) log(`features ${done}/${corpora.length} corpora`);
        }
    }));
}

function printReport(mal, ben, clusters, ctx) {
    const threshold = lib.constant(ctx, 'ML_THRESHOLD'), floor = lib.constant(ctx, 'ML_FLOOR');
    const anomalyScore = lib.constant(ctx, 'ANOMALY_SCORE'), criticalScore = lib.constant(ctx, 'CRITICAL_SCORE');
    const line = (label, hit) => {
        const r = lib.rates(mal, ben, hit), hitClusters = new Set(mal.filter(hit).map(d => d.group)).size;
        console.log(`${label.padEnd(26)} shells ${String(r.tp).padStart(5)}/${r.nMal} (${lib.pct(r.tp, r.nMal).padStart(6)})  ` +
            `clusters ${String(hitClusters).padStart(4)}/${clusters}   false positives ${String(r.fp).padStart(5)}/${r.nBen} (${lib.pct(r.fp, r.nBen)})`);
    };
    console.log(`\n${opts.folds}-fold cross-validation, held-out scores: ${mal.length} unique shells in ${clusters} clusters, ` +
        `${ben.length} unique benign files in ${new Set(ben.map(d => d.family)).size} families (whole families held out)`);
    console.log(`${buckets} buckets, l2 ${opts.l2}, ${opts.epochs} epochs, benign cap ${opts.cap}/corpus, ${((Date.now() - t0) / 1000).toFixed(0)}s\n`);
    line('rules only (anomaly)', d => d.ruleAnomaly);
    [0.5, 0.7, 0.8, 0.9, 0.95, 0.98].forEach(t => line(`ml >= ${t}${t === threshold ? ' (shipped)' : ''}`, d => d.cvScore >= t));
    line(`rules or ml >= ${threshold}`, d => d.ruleAnomaly || d.cvScore >= threshold);
    line(`  ml only (>= ${threshold})`, d => !d.ruleAnomaly && d.cvScore >= threshold);
    // How main.php combines them: ML points added to the rule score (mlPoints())
    console.log(`\nThreat score with ML points (ML_FLOOR sweep, shipped ${floor}):`);
    [0.5, 0.6, 0.7, 0.8].forEach(f => {
        const combined = d => d.ruleScore + ctx.mlPoints(d.cvScore, f);
        line(`  anomaly, floor ${f}${f === floor ? ' *' : ''}`, d => d.ruleAnomaly || combined(d) >= anomalyScore);
        line(`  score >= ${criticalScore}, floor ${f}`, d => combined(d) >= criticalScore);
    });
    const php = mal.filter(d => !d.foreign);
    console.log(`\nPHP files only (ASP/JSP/CGI in PHP-named files left out):`);
    [['rules only', d => d.ruleAnomaly], [`rules or ml >= ${threshold}`, d => d.ruleAnomaly || d.cvScore >= threshold]].forEach(([label, hit]) => {
        const tp = php.filter(hit).length;
        console.log(`  ${label.padEnd(24)} shells ${tp}/${php.length} (${lib.pct(tp, php.length)})`);
    });
    if (args['by-family']) {
        console.log(`\nFalse positives per benign family (held out):  rules   ml>=${threshold}`);
        [...lib.groupBy(ben, d => d.family)]
            .map(([name, list]) => ({ name, n: list.length, rules: list.filter(d => d.ruleAnomaly).length, ml: list.filter(d => d.cvScore >= threshold).length }))
            .sort((a, b) => b.ml / b.n - a.ml / a.n)
            .forEach(f => console.log(`  ${f.name.padEnd(16)} ${String(f.n).padStart(6)} files  ${lib.pct(f.rules, f.n).padStart(6)}  ${lib.pct(f.ml, f.n).padStart(6)}`));
    }
    if (args.list) {
        console.log('\nHELD-OUT MISSES (rules and ml):');
        mal.filter(d => !d.ruleAnomaly && d.cvScore < threshold).forEach(d => console.log(`  ${d.id}  ml=${d.cvScore.toFixed(3)}`));
        console.log('\nML FALSE POSITIVES:');
        ben.filter(d => d.cvScore >= threshold).forEach(d => console.log(`  ${d.id}  ml=${d.cvScore.toFixed(3)}${d.ruleAnomaly ? '  (rules flag it too)' : ''}`));
    }
}

/** --check DIR: score a directory the model never saw (all assumed benign) */
async function checkDir(dir, model, ctx) {
    const tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sussy-check-')), 'rows.jsonl');
    const rows = lib.contentOnly(lib.parseRows(fs.readFileSync(await ml.extractTo(path.resolve(dir), tmp), 'utf8')))
        .filter(d => d.ml_features && !d.is_htaccess);
    fs.rmSync(path.dirname(tmp), { recursive: true, force: true });
    const scored = ctx.analyzeData(rows, lib.constant(ctx, 'Z_THRESHOLD'));
    const score = ml.scorer(model), threshold = lib.constant(ctx, 'ML_THRESHOLD');
    const rules = scored.filter(d => d.isAnomaly && !d.mlOnly).length;
    const flagged = rows.map(d => ({ d, s: score(ml.decodeBits(d.ml_features)) })).filter(x => x.s >= threshold);
    console.log(`\n--check ${dir}: ${rows.length} files   rules flag ${rules} (${lib.pct(rules, rows.length)})   ml >= ${threshold} flags ${flagged.length} (${lib.pct(flagged.length, rows.length)})`);
    if (args.list) flagged.forEach(x => console.log(`  ${x.d.path}  ml=${x.s.toFixed(3)}`));
}

(async () => {
    const listed = lib.loadCorpora();
    const corpora = listed.filter(lib.isCheckedOut);
    if (corpora.length < listed.length) log(`${listed.length - corpora.length} sample submodules not checked out (git submodule update --init test/corpora/), skipping them`);
    await extractAll(corpora);

    const ctx = lib.loadScoring({ weights: lib.tokenWeights() });
    const { samples, files, dropped } = ml.buildSamples(corpora, ctx);
    const mal = samples.filter(d => d.label), ben = samples.filter(d => !d.label);
    log(`${files} files -> ${mal.length} unique shells, ${ben.length} unique benign (dropped: ${dropped.htaccess} .htaccess, ` +
        `${dropped.notCode} non-code files in shell collections, ${dropped.conflicts} shell-collection files also found in benign projects)`);
    ml.assignGroups(samples, buckets, opts.similar);
    ml.assignFolds(samples, opts.folds);
    const clusters = new Set(mal.map(d => d.group)).size;
    log(`${clusters} shell clusters (Jaccard >= ${opts.similar}), ${new Set(ben.map(d => d.family)).size} benign families`);

    // One training set per fold (everything outside it), plus the final model on everything
    const packed = ml.pack(samples);
    const pool = mal.concat(ml.capPerCorpus(ben, opts.cap));
    const sets = Array.from({ length: opts.folds }, (_, f) => pool.filter(d => d.fold !== f).map(d => d.idx));
    const wantFinal = args.write || args.check;
    if (wantFinal) sets.push(pool.map(d => d.idx));
    log(`training ${sets.length} models in parallel`);
    const models = (await ml.trainParallel(packed, sets, { buckets, epochs: opts.epochs, l2: opts.l2 })).map(ml.quantize);
    models.slice(0, opts.folds).forEach((model, f) => {
        const score = ml.scorer(model);
        samples.filter(d => d.fold === f).forEach(d => { d.cvScore = score(d.bits); });
    });
    // The fast scorer must agree with main.php's mlScore() exactly
    samples.filter(d => d.hex).forEach(d => {
        if (Math.abs(ml.scorer(models[0])(d.bits) - ctx.mlScore(d.hex, models[0])) > 1e-9) throw new Error('scorer mismatch on ' + d.id);
    });
    printReport(mal, ben, clusters, ctx);

    const finalModel = wantFinal ? models[models.length - 1] : null;
    for (const dir of args.check || []) await checkDir(dir, finalModel, ctx);
    if (args.write) {
        // Key order matters: main.php checks the file against a fixed pattern
        const file = { features: featureVersion, buckets, scale: finalModel.scale, bias: finalModel.bias, weights: finalModel.weights };
        fs.writeFileSync(path.join(lib.ROOT, 'ml-model.json'), JSON.stringify(file) + '\n');
        console.log(`\nwrote ml-model.json (feature version ${featureVersion}, ${buckets} int8 weights, trained on ${pool.length} files)`);
    }
})().catch(e => { console.error(e); process.exit(1); });
