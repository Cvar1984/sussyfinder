// `test/run checksums`: builds checksums.txt, the release-file part of
// main.php's vendor checksums (checksumVerified()). A file byte-identical to
// one of these, at a path ending in the same place in its release, is shown
// as verified and never flagged.
//
// Only release files the scanner comes near flagging are listed (flagged, or
// a threat score of at least --min-score), which keeps the list small enough
// to download per scan; every other release file isn't flagged anyway.
// Never listed: an MD5 that also occurs in a webshell corpus or in
// blacklist.txt, so a shell kit bundling a release file stays flagged.
const fs = require('fs');
const path = require('path');
const { ROOT } = require('../lib/paths');
const { parseRows } = require('../lib/php');
const { loadCorpora, isCheckedOut, contentOnly } = require('../lib/corpora');
const { loadScoring, constant, readModel } = require('../lib/scanner');
const ml = require('../lib/ml');

const OUT = path.join(ROOT, 'checksums.txt');

async function build(minScore) {
    const corpora = loadCorpora().filter(isCheckedOut);
    const ctx = loadScoring({ model: readModel() });
    const z = constant(ctx, 'Z_THRESHOLD');
    const key = ml.featureKey();
    const shellMd5 = new Set(fs.readFileSync(path.join(ROOT, 'blacklist.txt'), 'utf8').split('\n').map(l => l.trim().toLowerCase()).filter(Boolean));
    const listed = new Map(); // "md5 path" => line
    let benign = 0;
    for (const c of corpora) {
        const rows = contentOnly(parseRows(fs.readFileSync(await ml.extractCorpus(c, key), 'utf8')));
        if (c.label === 'shell') {
            rows.forEach(r => shellMd5.add(r.md5));
            continue;
        }
        benign += rows.length;
        ctx.analyzeData(rows.map(ctx.withMlScore), z).forEach(d => {
            if (!/^[0-9a-f]{32}$/.test(d.md5) || /\s/.test(c.family) || /[\r\n]/.test(d.path)) return;
            if (d.isAnomaly || d.threatScore >= minScore) listed.set(d.md5 + ' ' + d.path, `${d.md5} ${c.family} ${d.path}`);
        });
    }
    const lines = [...listed.values()].filter(l => !shellMd5.has(l.slice(0, 32))).sort();
    return { lines, dropped: listed.size - lines.length, benign, corpora: corpora.filter(c => c.label !== 'shell').length };
}

module.exports = {
    name: 'checksums',
    summary: 'build checksums.txt (release files main.php shows as verified); --write saves it',
    about: `
Scores every file of the checked-out benign corpora (the releases under
test/corpora/noise/) with the shipped rules and model, and lists the ones that
are flagged or score at least --min-score as "<md5> <family> <path in the
release>". main.php downloads the list and shows a file as verified when its
MD5 matches and its path ends with the listed one. An MD5 found in a webshell
corpus or blacklist.txt is never listed.

Rerun with --write after retraining the model or changing the rules, since
which release files come near the anomaly bar depends on both.`,
    options: {
        'min-score': { type: 'string', default: '4', help: 'also list release files scoring at least this' },
        write: { type: 'boolean', help: 'write checksums.txt' },
    },
    examples: ['test/run checksums', 'test/run checksums --write'],
    async run(args) {
        const minScore = parseFloat(args['min-score']);
        const { lines, dropped, benign, corpora } = await build(minScore);
        const families = new Map();
        lines.forEach(l => { const f = l.split(' ')[1]; families.set(f, (families.get(f) || 0) + 1); });
        const bytes = lines.reduce((n, l) => n + l.length + 1, 0);
        console.log(`${lines.length} release files listed (flagged or score >= ${minScore}) of ${benign} in ${corpora} corpora, ` +
            `${families.size} families, ${(bytes / 1048576).toFixed(2)} MB; ${dropped} left out because the MD5 is also a shell or blacklisted`);
        console.log('most listed: ' + [...families].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([f, n]) => `${f} ${n}`).join(', '));
        if (args.write) {
            fs.writeFileSync(OUT, lines.join('\n') + '\n');
            console.log('wrote checksums.txt');
        }
        return 0;
    },
};
