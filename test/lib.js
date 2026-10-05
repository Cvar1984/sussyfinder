// Shared helpers for test/unit.js, test/run.js, test/ui.js and test/train-ml.js:
// command-line parsing, PHP jobs (test/php/*.php) with crash-resume, main.php's
// client-side scoring block in a vm context, the sample corpora listed in
// .gitmodules, and how a sample is labelled.
const { execFile, execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const util = require('util');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');
const MAIN = path.join(ROOT, 'main.php');
const SCORING_START = '// --- Client-side threat scoring';
const SCORING_END = '// --- End client-side threat scoring ---';
const LIB_END = '// The test scripts include this file'; // end of the PHP main.php shares with the tests
const MAX_BUFFER = 1 << 28;

// --- Command line ---

/**
 * Parse process.argv strictly: an unknown or misspelt option is an error,
 * not silently ignored. `options` uses util.parseArgs' format plus a `help`
 * text per option, which also builds the usage message.
 */
function cli(options, usage) {
    try {
        return util.parseArgs({ options, strict: true, allowPositionals: false }).values;
    } catch (e) {
        const lines = Object.entries(options).map(([name, o]) =>
            `  --${name}${o.type === 'string' ? ' <' + (o.arg || 'value') + '>' : ''}`.padEnd(28) + (o.help || ''));
        console.error(`${e.message}\n\n${usage}\n\nOptions:\n${lines.join('\n')}`);
        process.exit(2);
    }
}

// --- PHP jobs ---

// A PHP single-quoted string literal (safe for any path, PHP 4.3+)
const phpString = s => "'" + String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'") + "'";
const phpValue = v => Array.isArray(v) ? 'array(' + v.map(phpValue).join(', ') + ')' : phpString(v);

/**
 * Write a prelude that sets `vars` as PHP globals and includes `script`.
 * Paths are as PHP will see them (inside a container they differ from the
 * host's). PHP 4 CGI has no -r, so jobs are always files. Returns its path.
 */
function phpJob(file, script, vars) {
    const sets = Object.entries(vars).map(([k, v]) => `$${k} = ${phpValue(v)};`);
    fs.writeFileSync(file, `<?php\n${sets.join('\n')}\ninclude ${phpString(script)};\n`);
    return file;
}

/**
 * Run an extraction job until it finishes, skipping any file PHP itself
 * crashes on: on failure, the path in the job's progress file goes to the
 * skip list and the job reruns (it resumes from its done list).
 * `run()` resolves to the job's stdout; `read(name)` reads a state file.
 * Resolves to { summary, crashed }, summary null when PHP failed outright.
 */
async function runResumable({ run, read, skipFile }) {
    const crashed = [];
    for (;;) {
        fs.writeFileSync(skipFile, crashed.join('\0'));
        try {
            const out = String(await run());
            return { summary: JSON.parse(out.slice(out.indexOf('{'))), crashed };
        } catch (e) {
            const last = read('progress');
            if (!last || crashed.includes(last)) return { summary: null, crashed };
            crashed.push(last);
        }
    }
}

const execAsync = (cmd, args, opts = {}) => new Promise((resolve, reject) =>
    execFile(cmd, args, Object.assign({ maxBuffer: MAX_BUFFER }, opts), (e, out) => e ? reject(e) : resolve(out)));

/** Rows of an extraction state file; a crash between a row and its "done" mark can repeat a row. */
function parseRows(jsonl) {
    const byPath = new Map();
    for (const line of jsonl.split('\n')) if (line) { const row = JSON.parse(line); byPath.set(row.path, row); }
    return [...byPath.values()];
}

/** main.php's detection policy from the local php: { weights: $tokenNeedles, roles: $tokenRoles } */
let policy = null;
function tokenPolicy() {
    if (!policy) {
        const php = `define('SUSSY_LIB', true); include ${phpString(MAIN)}; echo jsonEncode(array('weights' => $tokenNeedles, 'roles' => $tokenRoles));`;
        policy = JSON.parse(execFileSync('php', ['-r', php]).toString());
    }
    return policy;
}

// --- main.php's client-side scoring ---

const mainSource = () => fs.readFileSync(MAIN, 'utf8');

/** A slice of main.php between two markers; throws if they moved */
function between(src, start, end) {
    const a = src.indexOf(start), b = src.indexOf(end, a);
    if (a < 0 || b < 0) throw new Error(`main.php markers not found: "${start}" .. "${end}"`);
    return src.slice(a, b);
}

/**
 * main.php's scoring block (calculateThreatScore, analyzeData, mlScore, ...),
 * run as-is in a vm context with the page's globals. `weights` and `roles`
 * default to the local php's policy; `model` null scores rules only.
 */
function loadScoring({ weights, roles, model = null } = {}) {
    const ctx = vm.createContext({ tokenWeights: weights || tokenPolicy().weights, tokenRoles: roles || tokenPolicy().roles, ML_MODEL: model });
    vm.runInContext(between(mainSource(), SCORING_START, SCORING_END), ctx);
    return ctx;
}
/** A top-level const of the scoring block, e.g. Z_THRESHOLD, ML_THRESHOLD */
const constant = (ctx, name) => vm.runInContext(name, ctx);

const readModel = () => JSON.parse(fs.readFileSync(path.join(ROOT, 'ml-model.json'), 'utf8'));

/** Everything in main.php that shapes an extracted row (for cache keys) */
const extractorSource = () => between(mainSource(), '<?php', LIB_END);

// --- Sample corpora ---

/**
 * The sample submodules: test/corpora/positive/* (webshells) and
 * test/corpora/noise/* (legitimate code). Extra .gitmodules keys, which git
 * ignores: "family" (corpora held out together in cross-validation),
 * "subdir" (the part of the repository holding samples) and "benchmark"
 * (part of test/run.js's quick benchmark set).
 */
function loadCorpora() {
    const subs = new Map();
    const cfg = execFileSync('git', ['config', '-f', path.join(ROOT, '.gitmodules'), '--get-regexp', '^submodule\\.'], { encoding: 'utf8' });
    for (const line of cfg.split('\n').filter(Boolean)) {
        const sp = line.indexOf(' '), key = line.slice(0, sp), dot = key.lastIndexOf('.');
        const name = key.slice('submodule.'.length, dot);
        if (!subs.has(name)) subs.set(name, {});
        subs.get(name)[key.slice(dot + 1)] = line.slice(sp + 1);
    }
    const pinned = new Map(execFileSync('git', ['ls-files', '-s'], { cwd: ROOT, encoding: 'utf8', maxBuffer: MAX_BUFFER })
        .split('\n').filter(l => l.startsWith('160000')).map(l => [l.split('\t')[1], l.split(' ')[1]]));
    const corpora = [];
    for (const s of subs.values()) {
        const m = /^test\/corpora\/(positive|noise)\/([^/]+)$/.exec(s.path);
        if (!m) continue;
        corpora.push({
            name: m[2], path: s.path, label: m[1] === 'positive' ? 'shell' : 'benign',
            family: s.family || m[2], dir: path.join(ROOT, s.path, s.subdir || ''),
            commit: pinned.get(s.path), benchmark: s.benchmark === 'true',
        });
    }
    return corpora;
}
/** An uninitialized submodule is an empty directory */
const isCheckedOut = c => fs.existsSync(c.dir) && fs.readdirSync(c.dir).length > 0;
const corpus = (name, list = loadCorpora()) => {
    const c = list.find(x => x.name === name);
    if (!c) throw new Error('no sample corpus named ' + name);
    return c;
};

// --- Labels and rates ---

/**
 * Whether a file can run as server code: it holds PHP, or main.php's
 * @foreign_code saw ASP/JSP/CGI. A shell-collection file that can't (a saved
 * 404 page, a robots.txt) is a labelling error, not a shell.
 */
const isRunnable = row => !!row.has_php || (row.matched_tokens || []).includes('@foreign_code');

/** Timestamps say when a corpus was copied, not anything about the file: score on content only */
const contentOnly = rows => { rows.forEach(d => { d.mtime = 0; d.ctime = 0; }); return rows; };

const pct = (a, b) => (100 * a / Math.max(1, b)).toFixed(1) + '%';
/** True/false positives of predicate `hit` over shells `mal` and benign `ben` */
const rates = (mal, ben, hit) => ({ tp: mal.filter(hit).length, fp: ben.filter(hit).length, nMal: mal.length, nBen: ben.length });

const sha1 = s => crypto.createHash('sha1').update(s).digest('hex');
const groupBy = (list, key) => {
    const m = new Map();
    for (const x of list) { const k = key(x); if (!m.has(k)) m.set(k, []); m.get(k).push(x); }
    return m;
};

module.exports = {
    ROOT, MAIN, MAX_BUFFER, cli, phpString, phpJob, runResumable, execAsync, parseRows, tokenPolicy,
    loadScoring, constant, readModel, extractorSource, loadCorpora, isCheckedOut, corpus,
    isRunnable, contentOnly, pct, rates, sha1, groupBy,
};
