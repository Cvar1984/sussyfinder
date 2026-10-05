// `test/run matrix`: the benchmark plus a page/AJAX check on many PHP
// versions and php.ini profiles, in Docker (lib/benchmark.js, lib/targets.js).
const fs = require('fs');
const { OPTIONS, runBenchmark } = require('../lib/benchmark');
const { DEFAULT_VERSIONS, PROFILES, dockerTargets } = require('../lib/targets');
const { tempDir } = require('../lib/cleanup');

module.exports = {
    name: 'matrix',
    summary: 'benchmark + page/AJAX check on every PHP version and php.ini profile (Docker)',
    about: `
For each PHP version under each php.ini profile, starts a php:<version>-apache
container (or a PHTest legacy build) with the repository mounted read-only,
then runs what bench does there, plus a web check: the page and its inline
JS, scan, process (paths round-trip byte for byte, a missing file comes back
as a warning) and the CSRF check. Ends with a table of all of them and lists
files that match differently than on the newest PHP.

Profiles:
${Object.entries(PROFILES).map(([name, p]) => `  ${name.padEnd(9)} ${p.about}`).join('\n')}`,
    options: Object.assign({
        php: { type: 'string', arg: 'versions', help: `"all" (test/PHTest/versions.list) or a list of php:<v>-apache tags (default: ${DEFAULT_VERSIONS})` },
        profile: { type: 'string', arg: 'names', help: `php.ini profiles, each version runs under each (default: all: ${Object.keys(PROFILES).join(',')})` },
    }, OPTIONS),
    examples: ['test/run matrix', 'test/run matrix --php 7.4,8.5 --profile default', 'test/run matrix --php all --list'],
    run(args) {
        const work = tempDir('matrix');
        fs.chmodSync(work, 0o755); // Apache in the containers runs as www-data
        const targets = dockerTargets(args.php || DEFAULT_VERSIONS, args.profile || Object.keys(PROFILES).join(','), work);
        return runBenchmark(targets, args, work);
    },
};
