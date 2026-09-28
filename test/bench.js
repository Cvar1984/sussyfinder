// Detection benchmark: runs main.php's real PHP feature extraction and its
// real client-side scoring (the "Client-side threat scoring" block, pulled
// out of main.php at runtime) over test/webshells (malicious) mixed with
// test/WordPress + test/laravel (benign), then prints detection/FP rates.
// Also fails if a structural-detector self-check fails.
//
// Usage: node test/bench.js [--list] [--tokens] [--threshold 3.5]
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.join(__dirname, '..');
const args = process.argv.slice(2);
const list = args.includes('--list');
const thIdx = args.indexOf('--threshold');
const threshold = thIdx === -1 ? 3.5 : parseFloat(args[thIdx + 1]);
const malDir = path.join(root, 'test/webshells');
const dirs = [malDir, path.join(root, 'test/WordPress'), path.join(root, 'test/laravel')];

const web = fs.readFileSync(path.join(root, 'main.php'), 'utf8');

// --- Structural detector self-check: snippet => signals that must / must not appear ---
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
];
const check = `define('SUSSY_LIB', true); include 'main.php';
$out = array();
foreach (json_decode(file_get_contents('php://stdin')) as $src) {
    $t = getFileTokens($src);
    $out[] = array_merge(compareTokens($tokenNeedles, tokenTextSet($t)), findStructuralSignals($t, $src, $tokenNeedles));
}
echo json_encode($out);`;
const got = JSON.parse(execFileSync('php', ['-r', check], { cwd: root, input: JSON.stringify(cases.map(c => c[0])) }).toString());
let failed = 0;
cases.forEach(([src, want, reject], i) => {
    const bad = want.filter(t => !got[i].includes(t)).map(t => 'missing ' + t)
        .concat(reject.filter(t => got[i].includes(t)).map(t => 'unexpected ' + t));
    if (bad.length) { failed++; console.log('FAIL ' + src.slice(0, 60) + ': ' + bad.join(', ') + '  got [' + got[i] + ']'); }
});

// --- PHP features ---
const php = `define('SUSSY_LIB', true); include 'main.php';
$out = array();
foreach (array_slice($argv, 1) as $dir) {
    $r = getSortedByPattern($dir, $pattern);
    $seen = array(); $new = array();
    $out = array_merge($out, scanReadablePaths($r['file_readable'], array(), array(), $tokenNeedles, $seen, $new));
}
echo json_encode(array('weights' => $tokenNeedles, 'features' => $out));`;
const out = JSON.parse(execFileSync('php', ['-r', php, '--', ...dirs], { cwd: root, maxBuffer: 1 << 28 }).toString());

// --- JS scoring, straight from main.php ---
const start = web.indexOf('// --- Client-side threat scoring');
const end = web.indexOf('// --- End client-side threat scoring ---');
const ctx = vm.createContext({ tokenWeights: out.weights });
vm.runInContext(web.slice(start, end), ctx);
// The corpora were copied at different times (webshells keep 2024 mtimes), so
// timestamps would "detect" them for free; score on content only.
out.features.forEach(d => { d.mtime = 0; d.ctime = 0; });
const rows = ctx.analyzeData(out.features, threshold);

const isMal = d => d.path.startsWith(malDir + '/');
const report = (label, hit) => {
    const mal = rows.filter(isMal), ben = rows.filter(d => !isMal(d));
    const tp = mal.filter(hit).length, fp = ben.filter(hit).length;
    const pct = (a, b) => (100 * a / Math.max(1, b)).toFixed(1) + '%';
    console.log(`${label.padEnd(18)} detected ${tp}/${mal.length} (${pct(tp, mal.length)})   false positives ${fp}/${ben.length} (${pct(fp, ben.length)})`);
};
report('anomaly', d => d.isAnomaly);
report('score >= 8', d => d.threatScore >= 8);
report('score >= 15', d => d.threatScore >= 15);
report('  zSusp only', d => d.zScores.susp > threshold && d.threatScore < 8);
report('  zEntropy only', d => d.zScores.entropy > threshold && d.threatScore < 8);
report('  residual only', d => d.residual > 5 && d.threatScore < 8);

if (args.includes('--tokens')) {
    const count = {};
    rows.forEach(d => d.matched_tokens.forEach(t => {
        count[t] = count[t] || [0, 0];
        count[t][isMal(d) ? 0 : 1]++;
    }));
    console.log('\ntoken                        webshells  benign  weight');
    Object.keys(count).sort((a, b) => count[b][1] - count[a][1]).forEach(t => {
        console.log(t.padEnd(28) + String(count[t][0]).padStart(10) + String(count[t][1]).padStart(8) + String(out.weights[t]).padStart(8));
    });
}

if (list) {
    const rel = p => path.relative(root, p);
    console.log('\nMISSED:');
    rows.filter(d => isMal(d) && !d.isAnomaly).forEach(d => console.log('  ' + rel(d.path) + '  [' + d.matched_tokens.join(', ') + ']'));
    console.log('\nFALSE POSITIVES:');
    rows.filter(d => !isMal(d) && d.isAnomaly).forEach(d => console.log('  ' + rel(d.path) + '  score=' + d.threatScore + '  [' + d.matched_tokens.join(', ') + ']'));
}
process.exit(failed ? 1 : 0);
