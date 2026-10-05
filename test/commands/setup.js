// `test/run setup`: fetch what the other commands need: the sample submodules
// and, for the matrix, PHTest and the official PHP images.
const { spawnSync } = require('child_process');
const path = require('path');
const { ROOT, PHTEST } = require('../lib/paths');
const { loadCorpora } = require('../lib/corpora');
const { DEFAULT_VERSIONS } = require('../lib/targets');

/** Run a command with its output shown; returns whether it succeeded */
function sh(cmd, args) {
    console.log('$ ' + [cmd].concat(args).join(' '));
    return spawnSync(cmd, args, { cwd: ROOT, stdio: 'inherit' }).status === 0;
}

module.exports = {
    name: 'setup',
    summary: 'fetch the samples (benchmark set, or --all), PHTest and the Docker images',
    about: `
Initialises the sample submodules the other commands read. Without options it
fetches the benchmark set (enough for unit, bench, ui and matrix); --all
fetches every sample corpus, which train uses (over 10 GB). The samples are
real, working webshells: keep the checkout out of any web root.`,
    options: {
        all: { type: 'boolean', help: 'every sample corpus, for train (over 10 GB)' },
        phtest: { type: 'boolean', help: 'the PHTest submodule (legacy PHP builds for matrix --php all)' },
        docker: { type: 'boolean', help: `pull the php:<v>-apache images matrix uses (${DEFAULT_VERSIONS})` },
    },
    examples: ['test/run setup', 'test/run setup --docker', 'test/run setup --all'],
    run(args) {
        const corpora = loadCorpora().filter(c => args.all || c.benchmark);
        let ok = sh('git', ['submodule', 'update', '--init'].concat(corpora.map(c => c.path)));
        if (args.phtest) ok = sh('git', ['submodule', 'update', '--init', path.relative(ROOT, PHTEST)]) && ok;
        if (args.docker) {
            for (const v of DEFAULT_VERSIONS.split(',')) ok = sh('docker', ['pull', '-q', `php:${v}-apache`]) && ok;
        }
        console.log(ok ? 'setup done' : 'setup FAILED (see above)');
        return ok ? 0 : 1;
    },
};
