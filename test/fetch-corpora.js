// Downloads the corpora listed in test/corpora.json into test/corpora/<name>
// (git-ignored), each as a shallow checkout of one commit, for
// test/train-ml.js. Entries without a pinned "commit" are resolved from
// "ref" (or the default branch) and the commit is written back to the
// manifest, so later fetches get exactly the same files.
//
// Usage:
//   node test/fetch-corpora.js               fetch what's missing
//   node test/fetch-corpora.js --only a,b    just those corpora
//   node test/fetch-corpora.js --jobs 4      parallel downloads (default 4)
//
// The shell corpora are real webshells. They are only read and tokenized,
// never executed, but keep test/corpora/ out of any web root.
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const manifestPath = path.join(__dirname, 'corpora.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const args = process.argv.slice(2);
const opt = (name, def) => { const i = args.indexOf(name); return i === -1 ? def : args[i + 1]; };
const only = opt('--only', null) ? opt('--only').split(',') : null;
const jobs = parseInt(opt('--jobs', '4'), 10);
const base = path.join(__dirname, 'corpora');

const git = (cwd, gitArgs) => new Promise((resolve, reject) => {
    execFile('git', gitArgs, { cwd, maxBuffer: 1 << 26, timeout: 30 * 60 * 1000 }, (err, stdout, stderr) =>
        err ? reject(new Error(stderr.trim() || err.message)) : resolve(stdout.trim()));
});

async function fetchOne(c) {
    const dir = path.join(base, c.name);
    const stamp = path.join(dir, '.commit');
    if (c.commit && fs.existsSync(stamp) && fs.readFileSync(stamp, 'utf8').trim() === c.commit) return 'present';
    fs.rmSync(dir, { recursive: true, force: true });
    fs.mkdirSync(dir, { recursive: true });
    const url = 'https://github.com/' + c.repo + '.git';
    let want = c.commit;
    if (!want) {
        const ref = c.ref ? 'refs/tags/' + c.ref : 'HEAD';
        const refs = new Map((await git(dir, ['ls-remote', url, ref, ref + '^{}'])).split('\n').filter(Boolean).map(l => l.split('\t').reverse()));
        want = refs.get(ref + '^{}') || refs.get(ref); // a peeled tag (^{}) points at the commit
        if (!want) throw new Error('ref not found: ' + ref);
    }
    await git(dir, ['init', '-q']);
    for (let attempt = 0; ; attempt++) {
        try {
            await git(dir, ['fetch', '-q', '--depth', '1', url, want]);
            break;
        } catch (e) {
            if (attempt >= 3) throw e;
            await new Promise(r => setTimeout(r, 2000 << attempt));
        }
    }
    await git(dir, ['checkout', '-q', 'FETCH_HEAD']);
    fs.rmSync(path.join(dir, '.git'), { recursive: true, force: true });
    fs.writeFileSync(stamp, want + '\n');
    c.commit = want;
    return 'fetched ' + want.slice(0, 10);
}

(async () => {
    const todo = manifest.corpora.filter(c => c.repo && (!only || only.includes(c.name)));
    let next = 0, failed = 0;
    const worker = async () => {
        while (next < todo.length) {
            const c = todo[next++];
            try {
                console.log(`${c.name.padEnd(36)} ${await fetchOne(c)}`);
            } catch (e) {
                failed++;
                console.log(`${c.name.padEnd(36)} FAILED: ${e.message.split('\n')[0]}`);
            }
            fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 1) + '\n');
        }
    };
    await Promise.all(Array.from({ length: jobs }, worker));
    process.exit(failed ? 1 : 0);
})();
