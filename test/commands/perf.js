// `test/run perf`: how fast a scan goes through the real page and how much
// browser memory its results hold, for comparing changes to the scan flow.
//
// Like `test/run ui`, it scans a sandbox copy with the whitelist and blacklist
// off, so nothing is ever deleted: whole benign releases from
// test/corpora/noise/ are copied until there are --files files.
const fs = require('fs');
const path = require('path');
const { MAIN } = require('../lib/paths');
const { loadCorpora, isCheckedOut } = require('../lib/corpora');
const { tempDir } = require('../lib/cleanup');
const { sleep } = require('../lib/util');
const { findChrome, spawnManaged, openPage } = require('../lib/browser');
const { phpString } = require('../lib/php');

function countFiles(dir) {
    let n = 0;
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) n += e.isDirectory() ? countFiles(path.join(dir, e.name)) : e.isFile() ? 1 : 0;
    return n;
}

/** Copy benign releases into data/ until it holds at least `want` files */
function buildData(data, want) {
    let n = 0;
    for (const c of loadCorpora().filter(c => c.label === 'benign' && isCheckedOut(c)).sort((a, b) => a.name < b.name ? -1 : 1)) {
        if (n >= want) break;
        fs.cpSync(c.dir, path.join(data, c.name), { recursive: true, filter: src => !src.includes(path.sep + '.git') });
        n = countFiles(data);
    }
    return n;
}

module.exports = {
    name: 'perf',
    summary: 'scan timing and browser memory through the real page (minutes)',
    about: `
Copies whole benign releases into a sandbox until it holds --files files,
serves a copy of the page (lists off, nothing deleted) with php -S and several
workers, and scans it in headless Chrome. Reports the time to the first
listed row, the total scan time, the JS heap after a garbage collection and
the number of DOM elements. --define sets main.php settings in the copy, e.g.
--define MAX_PARALLEL=1. --latency adds a round trip to every request, as a
remote host would.`,
    options: {
        files: { type: 'string', default: '20000', help: 'files in the sandbox' },
        latency: { type: 'string', default: '0', help: 'added latency per request, in ms' },
        main: { type: 'string', help: 'scan with this main.php instead of the repo\'s (e.g. an older version)' },
        define: { type: 'string', multiple: true, help: 'NAME=value setting for the page copy' },
        workers: { type: 'string', default: '4', help: 'php -S workers' },
    },
    examples: ['test/run perf --files 50000 --latency 100', 'test/run perf --define MAX_PARALLEL=1'],
    async run(args) {
        const chrome = findChrome();
        if (!chrome) { console.log('SKIP: no Chrome/Chromium found'); return 0; }
        const box = tempDir('perf');
        const data = path.join(box, 'data');
        fs.mkdirSync(path.join(box, 'www'), { recursive: true });
        const files = buildData(data, parseInt(args.files, 10));
        const defines = { _WHITELIST_: 'false', _BLACKLIST_: 'false', _CHECKSUMS_: 'false', _MHR_: 'false', _ML_MODEL_URL_: phpString(path.join(path.dirname(MAIN), 'ml-model.json')) };
        (args.define || []).forEach(d => { const eq = d.indexOf('='); defines[d.slice(0, eq)] = d.slice(eq + 1); });
        const page = fs.readFileSync(args.main || MAIN, 'utf8');
        fs.writeFileSync(path.join(box, 'www', 'main.php'), '<?php ' + Object.entries(defines).map(([k, v]) => `define('${k}', ${v});`).join(' ') + page.slice('<?php'.length));

        const port = 19000 + Math.floor(Math.random() * 1000);
        process.env.PHP_CLI_SERVER_WORKERS = args.workers;
        spawnManaged('php', ['-d', 'error_log=' + path.join(box, 'php-errors.log'), '-S', '127.0.0.1:' + port, '-t', path.join(box, 'www')]);
        const { send, js, errors } = await openPage({ chrome, url: `http://127.0.0.1:${port}/main.php`, profileDir: path.join(box, 'chrome'), viewport: { width: 1400, height: 1000 }, dpr: 1, port: port + 1000 });
        const latency = parseFloat(args.latency);
        if (latency > 0) {
            await send('Network.enable');
            await send('Network.emulateNetworkConditions', { offline: false, latency, downloadThroughput: -1, uploadThroughput: -1 });
        }

        console.log(`${files} files in the sandbox, latency ${latency} ms, ${args.workers} php workers` + (args.define ? ', ' + args.define.join(' ') : ''));
        const t0 = Date.now();
        await js(`document.querySelector('input[name="dir"]').value = ${JSON.stringify(data)}; startChunkedScan(); true`);
        let first = null;
        const rows = () => js('document.querySelectorAll("#result tr[data-path]").length');
        for (;;) {
            if (first === null && await rows() > 0) first = Date.now() - t0;
            if (await js('analyzedData.length > 0 && document.getElementById("ajaxProgress").style.display === "none"')) break;
            if (Date.now() - t0 > 3600e3) throw new Error('scan did not finish in an hour');
            await sleep(100);
        }
        const total = Date.now() - t0;
        await sleep(500);
        await send('HeapProfiler.enable');
        await send('HeapProfiler.collectGarbage');
        const heap = await send('Runtime.getHeapUsage');
        const scanned = await js('analyzedData.length');
        const dom = await js('document.getElementsByTagName("*").length');
        console.log(`first row ${(first / 1000).toFixed(1)} s, scan ${(total / 1000).toFixed(1)} s, ` +
            `${scanned} rows, ${await rows()} in the table, heap ${(heap.usedSize / 1048576).toFixed(1)} MB ` +
            `(${Math.round(heap.usedSize / scanned)} B per row), ${dom} DOM elements`);
        if (errors.length) console.log('page errors: ' + errors.join(' | ').slice(0, 300));
        return errors.length ? 1 : 0;
    },
};
