// `test/run all`: the everyday check before a commit, every suite in one go.
module.exports = {
    name: 'all',
    summary: 'unit, bench and ui in one go (+ matrix with --matrix); a table of results at the end',
    about: `
Runs unit, then bench, then ui, each with its default options, and ends with
one line per suite. With --matrix it also runs matrix (Docker, every default
PHP version and profile). Exits 1 if any suite fails.`,
    options: {
        matrix: { type: 'boolean', help: 'also run the Docker matrix' },
        'require-browser': { type: 'boolean', help: 'ui fails instead of skipping when no browser is found' },
    },
    examples: ['test/run all', 'test/run all --matrix'],
    async run(args) {
        const { find, parse } = require('../lib/cli');
        const suites = ['unit', 'bench', 'ui'].concat(args.matrix ? ['matrix'] : []);
        const results = [];
        for (const name of suites) {
            const cmd = find(name);
            const argv = name === 'ui' && args['require-browser'] ? ['--require-browser'] : [];
            console.log(`\n######## test/run ${name} ${argv.join(' ')}`.trimEnd() + '\n');
            const t0 = Date.now();
            let code;
            try { code = await cmd.run(parse(cmd, argv)); } catch (e) { console.error(e.stack || e.message); code = 1; }
            results.push({ name, ok: code === 0, s: ((Date.now() - t0) / 1000).toFixed(0) });
        }
        console.log('\n######## summary\n');
        results.forEach(r => console.log(`  ${r.name.padEnd(8)} ${r.ok ? 'PASS' : 'FAIL'}  ${r.s}s`));
        return results.every(r => r.ok) ? 0 : 1;
    },
};
