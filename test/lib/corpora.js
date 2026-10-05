// The sample corpora: git submodules under test/corpora/positive/ (webshells)
// and test/corpora/noise/ (legitimate code), and how a sample is labelled.
//
// Extra .gitmodules keys, which git ignores: "family" (corpora held out
// together in cross-validation), "subdir" (the part of the repository holding
// samples) and "benchmark" (part of the quick benchmark set).
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { ROOT, MAX_BUFFER } = require('./paths');

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

/** The benchmark set (benchmark = true); throws naming the fetch command when some aren't checked out */
function benchmarkSet() {
    const bench = loadCorpora().filter(c => c.benchmark);
    const missing = bench.filter(c => !isCheckedOut(c));
    if (missing.length) throw new Error('benchmark samples not checked out; run: test/run setup');
    return bench;
}

/**
 * Whether a file can run as server code: it holds PHP, or main.php's
 * @foreign_code saw ASP/JSP/CGI. A shell-collection file that can't (a saved
 * 404 page, a robots.txt) is a labelling error, not a shell.
 */
const isRunnable = row => !!row.has_php || (row.matched_tokens || []).includes('@foreign_code');

/** Timestamps say when a corpus was copied, not anything about the file: score on content only */
const contentOnly = rows => { rows.forEach(d => { d.mtime = 0; d.ctime = 0; }); return rows; };

module.exports = { loadCorpora, isCheckedOut, corpus, benchmarkSet, isRunnable, contentOnly };
