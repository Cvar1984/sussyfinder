// `test/run bench`: the detection benchmark on the local php (lib/benchmark.js).
const { OPTIONS, runBenchmark } = require('../lib/benchmark');
const { localTarget } = require('../lib/targets');
const { tempDir } = require('../lib/cleanup');

module.exports = {
    name: 'bench',
    summary: 'detection benchmark on the local php: PHP self-check, then detection and false-positive rates',
    about: `
Runs the PHP self-check, then main.php's real feature extraction and its real
client-side scoring over the benchmark samples (benchmark = true in
.gitmodules: blackarch-webshells mixed with wordpress-7.2-alpha and
laravel-skeleton), and prints detection and false-positive rates.

Timestamps are zeroed (the corpora were copied at different times), so the
ctime/mtime and owner signals aren't measured. Webshell-corpus files with no
server code at all (a saved 404 page, a robots.txt) aren't counted as missed
shells; the run names them. The "ml only" line scores the shipped model on
files it was trained on, so it is optimistic: test/run train has held-out
rates. Fails if a self-check fails.`,
    options: OPTIONS,
    examples: ['test/run bench --list', 'test/run bench --tokens --no-ml'],
    run(args) {
        const work = tempDir('bench');
        return runBenchmark([localTarget(work)], args, work);
    },
};
