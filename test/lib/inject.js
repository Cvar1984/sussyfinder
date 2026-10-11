// The injected-shell test: each shell inserted into a legitimate file, the
// way backdoors usually arrive (test/php/inject.php builds the file in memory
// and runs main.php's real analysis on it; nothing is written or executed).
// Shared by the benchmark (bench, matrix) and training (train).
const fs = require('fs');
const path = require('path');
const { ROOT, PHP_JOBS } = require('./paths');
const { phpJob, runResumable, parseRows } = require('./php');
const { sha1 } = require('./util');

const JOB = path.join(PHP_JOBS, 'inject.php');

/** Whether a legitimate file makes a realistic host: PHP, a few KB (an index.php, a plugin file, a template) */
const isHost = row => !!row.has_php && !row.is_htaccess && row.size >= 1024 && row.size <= 40 * 1024;

/**
 * One host per shell, chosen by hashes so the same shell always lands in the
 * same file whatever order the lists come in. Each item has a stable `key`;
 * returns [{ shell, host }].
 */
function pairUp(shells, hosts) {
    const ordered = hosts.slice().sort((a, b) => (sha1(a.key) < sha1(b.key) ? -1 : 1));
    if (!ordered.length) return [];
    return shells.map(shell => ({ shell, host: ordered[parseInt(sha1('inject:' + shell.key).slice(0, 8), 16) % ordered.length] }));
}

/**
 * Run inject.php over `pairs` ([{ shellPath, hostPath, id }], paths as PHP
 * sees them) with `php(jobFile)`; `read(name)` reads a file of `state`, the
 * job's state dir as PHP sees it, and `work`/`phpWork` are the host-side temp
 * dir and where PHP sees it. Resolves to the rows (path = id), skipping any
 * pair PHP itself crashes on.
 */
async function runInjection({ pairs, php, read, state, work, phpWork = work, repo = ROOT, name = 'inject' }) {
    const inPhp = p => path.join(phpWork, path.relative(work, p));
    const pairsFile = path.join(work, name + '-pairs.tsv');
    fs.writeFileSync(pairsFile, pairs.map(p => [p.shellPath, p.hostPath, p.id].join('\t')).join('\n'));
    const skipFile = path.join(work, name + '-skip.txt');
    const job = phpJob(path.join(work, name + '.php'), path.join(repo, path.relative(ROOT, JOB)), {
        SUSSY_MAIN: path.join(repo, 'main.php'), SUSSY_STATE: state, SUSSY_PAIRS: inPhp(pairsFile), SUSSY_SKIP: inPhp(skipFile),
    });
    const { summary, crashed } = await runResumable({ run: () => php(inPhp(job)), read, skipFile });
    if (!summary) throw new Error('the injection job failed');
    return { rows: parseRows(read('rows')), crashed };
}

module.exports = { isHost, pairUp, runInjection };
