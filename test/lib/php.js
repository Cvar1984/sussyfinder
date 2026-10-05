// Running PHP jobs (test/php/*.php): a generated prelude sets the job's
// variables, and extraction jobs resume past files that crash PHP itself.
const { execFile } = require('child_process');
const fs = require('fs');
const { MAX_BUFFER } = require('./paths');

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

/** The JSON object a job prints last (anything before it is PHP noise) */
const jobJson = out => { out = String(out); return JSON.parse(out.slice(out.indexOf('{'))); };

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
            return { summary: jobJson(await run()), crashed };
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

module.exports = { phpString, phpJob, jobJson, runResumable, execAsync, parseRows };
