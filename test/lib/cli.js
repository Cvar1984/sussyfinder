// test/run's command line: the index of commands, strict option parsing
// (a misspelt option is an error, not ignored), per-command help, and
// cleanup when a command ends or is interrupted.
const util = require('util');
const cleanup = require('./cleanup');

const LAYOUT = `Layout (test/README.md has the details):
  test/run          this entry point
  test/commands/    one file per command
  test/lib/         what the commands share (PHP jobs, main.php, samples, Docker, ML, browser)
  test/php/         the PHP-side jobs, PHP 4.3-safe
  test/corpora/     sample submodules: positive/ webshells, noise/ legitimate code
  test/PHTest/      Docker builds of legacy PHP versions (submodule)`;

const commands = () => require('../commands');

function printIndex() {
    const list = commands();
    const width = Math.max(...list.map(c => c.name.length));
    console.log('SussyFinder tests, benchmark and ML training\n');
    console.log('Usage: test/run <command> [options]\n');
    console.log('Commands:');
    list.forEach(c => console.log(`  ${c.name.padEnd(width)}  ${c.summary}`));
    console.log(`\ntest/run <command> --help shows a command's options.\n`);
    console.log(LAYOUT);
}

function printUsage(cmd) {
    const opts = Object.entries(cmd.options || {}).map(([name, o]) =>
        `  --${name}${o.type === 'string' ? ' <' + (o.arg || 'value') + '>' : ''}`.padEnd(34) + (o.help || '') +
        (o.default !== undefined ? ` (default: ${o.default})` : ''));
    console.log(`Usage: test/run ${cmd.name}${opts.length ? ' [options]' : ''}\n`);
    console.log(cmd.about.trim() + '\n');
    if (opts.length) console.log('Options:\n' + opts.join('\n') + '\n');
    if (cmd.examples) console.log('Examples:\n' + cmd.examples.map(e => '  ' + e).join('\n'));
}

/** Parse argv for `cmd`; throws with a message on an unknown or malformed option */
function parse(cmd, argv) {
    const options = Object.assign({ help: { type: 'boolean', short: 'h' } }, cmd.options || {});
    return util.parseArgs({ args: argv, options, strict: true, allowPositionals: false }).values;
}

const find = name => commands().find(c => c.name === name);

async function main(argv) {
    const [name, ...rest] = argv;
    if (!name || ['help', '-h', '--help'].includes(name)) {
        printIndex();
        return 0;
    }
    const cmd = find(name);
    if (!cmd) {
        console.error(`unknown command: ${name}\n`);
        printIndex();
        return 2;
    }
    let args;
    try {
        args = parse(cmd, rest);
    } catch (e) {
        console.error(e.message + '\n');
        printUsage(cmd);
        return 2;
    }
    if (args.help) {
        printUsage(cmd);
        return 0;
    }
    // Ctrl+C, kill, or output piped into something that stopped reading (| head)
    const stop = code => cleanup.run().then(() => process.exit(code));
    process.on('SIGINT', () => stop(130));
    process.on('SIGTERM', () => stop(143));
    process.stdout.on('error', e => { if (e.code === 'EPIPE') stop(0); });
    try {
        return await cmd.run(args);
    } catch (e) {
        console.error(e.stack || e.message);
        return 1;
    } finally {
        await cleanup.run();
    }
}

module.exports = { main, parse, find };
