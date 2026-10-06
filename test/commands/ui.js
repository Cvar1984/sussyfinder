// `test/run ui`: the page's interactive parts in headless Chrome, with real
// mouse and keyboard events: charts, selection, hover linking, filters, the
// threshold control, zoom, HiDPI sizing, and file-name escaping.
//
// It builds a sandbox in a temp dir: a copy of main.php with the whitelist and
// blacklist off (so nothing is ever deleted), copies of the benchmark webshells
// and of WordPress's wp-includes with distinct dates, and a file named
// a');alert(1);('.php. Then it serves it with `php -S` and scans it.
const fs = require('fs');
const path = require('path');
const { MAIN } = require('../lib/paths');
const { loadCorpora, corpus } = require('../lib/corpora');
const { tempDir } = require('../lib/cleanup');
const { sleep } = require('../lib/util');
const { findChrome, spawnManaged, openPage } = require('../lib/browser');

const VIEWPORT = { width: 1400, height: 1000 }, DPR = 2;
let DATA;
// The open page's helpers, set by run()
let send, js, waitFor, mouse, click, pressEscape, setViewport, dialogs, errors;

let fails = 0;
const check = (name, ok, info = '') => { console.log((ok ? 'PASS ' : 'FAIL ') + name + (info ? '  (' + info + ')' : '')); if (!ok) fails++; };
/** Scroll chart i into view; resolves to its on-screen rectangle */
const focusChart = async i => {
    await js(`_charts[${i}].canvas.scrollIntoView({block: "center"}); true`); await sleep(200);
    return js(`(() => { const r = _charts[${i}].canvas.getBoundingClientRect(); return { x: r.left, y: r.top, w: r.width, h: r.height }; })()`);
};
const selectionSize = () => js('_chartSelection ? _chartSelection.size : 0');
const tableRows = () => js('document.querySelectorAll("#result tr[data-path]").length');

function buildSandbox(box) {
    fs.mkdirSync(path.join(box, 'www'));
    let page = fs.readFileSync(MAIN, 'utf8');
    // No hash lists (the sandbox may be offline), set the way main.php's settings are overridden
    if (!page.startsWith('<?php')) throw new Error('main.php no longer starts with <?php');
    page = "<?php define('_WHITELIST_', false); define('_BLACKLIST_', false);" + page.slice('<?php'.length);
    fs.writeFileSync(path.join(box, 'www', 'main.php'), page);
    const corpora = loadCorpora();
    fs.cpSync(path.join(corpus('blackarch-webshells', corpora).dir, 'php'), path.join(DATA, 'shells'), { recursive: true });
    const wp = path.join(corpus('wordpress-7.2-alpha', corpora).dir, 'wp-includes');
    fs.mkdirSync(path.join(DATA, 'wp'));
    fs.readdirSync(wp).filter(f => f.endsWith('.php')).forEach(f => fs.copyFileSync(path.join(wp, f), path.join(DATA, 'wp', f)));
    const xss = path.join(DATA, "a');alert(1);('.php");
    fs.writeFileSync(xss, '<?php eval($_GET[1]);');
    // distinct dates so the timeline has several buckets
    const stamp = (dir, date) => fs.readdirSync(dir).forEach(f => fs.utimesSync(path.join(dir, f), date, date));
    stamp(path.join(DATA, 'shells'), new Date('2024-03-01T10:00:00Z'));
    stamp(path.join(DATA, 'wp'), new Date('2025-06-15T12:00:00Z'));
    fs.utimesSync(xss, new Date('2026-01-10T09:00:00Z'), new Date('2026-01-10T09:00:00Z'));
}

// --- Scenarios ---
async function testScanAndCharts() {
    await js(`document.querySelector('input[name="dir"]').value = ${JSON.stringify(DATA)}; startChunkedScan(); true`);
    check('scan finished', await waitFor('analyzedData.length > 0 && document.getElementById("ajaxProgress").style.display === "none"'), await js('analyzedData.length') + ' files');
    await js('toggleCharts(); true'); await sleep(300);
    check('4 charts built', await js('_charts.length') === 4);
    check(`canvases sized at device pixel ratio ${DPR} (sharp)`, await js(`_charts.every(c => c.canvas.width === Math.round(c.canvas.clientWidth * ${DPR}))`),
        await js('_charts[0].canvas.width + "px backing for " + _charts[0].canvas.clientWidth + "px CSS"'));
    const docListeners = async () => { const doc = await send('Runtime.evaluate', { expression: 'document' }); return (await send('DOMDebugger.getEventListeners', { objectId: doc.result.objectId })).listeners.length; };
    const before = await docListeners();
    for (let i = 0; i < 5; i++) await js('renderCharts(analyzedData); true');
    check('no document listener leak across 5 rebuilds', await docListeners() === before, before + ' listeners');
}

async function testBrushSelection(total) {
    const r = await focusChart(0); // brush the high-rule-score band of the Threat Matrix
    await mouse('mousePressed', r.x + 72, r.y + 31); await mouse('mouseMoved', r.x + r.w - 31, r.y + 120); await mouse('mouseReleased', r.x + r.w - 31, r.y + 120);
    await sleep(300);
    const sel = await selectionSize(), rows = await tableRows();
    check('drag-select on Threat Matrix selects files', sel > 0 && sel < total, sel + ' of ' + total);
    check('table shows only the selection', rows === sel, rows + ' rows');
    check('selection bar visible', await js('document.getElementById("chartSelectionBar").style.display === "block"'));
    check('selected files are the high scorers', await js('analyzedData.filter(d => _chartSelection.has(d.path)).every(d => d.threatScore > 0)'));
    check('Threat Matrix colours every dot by its file\'s verdict', await js(`_charts[0].marks.every(m =>
        m.color === (isCritical(m.d) ? '#ff4444' : m.d.isAnomaly ? '#ffaa00' : '#5a6b7a'))`), await js('_charts[0].marks.length') + ' dots');
    check('Threat Matrix puts files over the rule bar above the files under it', await js(`(() => {
        const m = _charts[0].marks, over = m.filter(p => p.d.ruleScore >= ANOMALY_SCORE), under = m.filter(p => p.d.ruleScore < ANOMALY_SCORE);
        return over.length > 0 && under.length > 0 && Math.max(...over.map(p => p.y)) < Math.min(...under.map(p => p.y));
    })()`));
    await pressEscape();
    check('Escape clears selection', await js('_chartSelection === null') && await tableRows() === total);
}

async function testTimeline() {
    const r = await focusChart(1);
    const bars = await js('_charts[1].marks.filter(m => m.bucket.files.length).sort((a, b) => b.bucket.files.length - a.bucket.files.length).slice(0, 2).map(m => ({ x: (m.x0 + m.x1) / 2, n: m.bucket.files.length }))');
    await click(r.x + bars[0].x, r.y + r.h - 60);
    check('click on timeline bar selects its files', await selectionSize() === bars[0].n, bars[0].n + ' files');
    if (bars[1]) {
        await click(r.x + bars[1].x, r.y + r.h - 60, 2); // Ctrl
        check('Ctrl+click adds to the selection', await selectionSize() === bars[0].n + bars[1].n);
    }
    await pressEscape();
}

async function testHoverLinking() {
    const r = await focusChart(3);
    const dot = await js('(() => { const m = _charts[3].marks[_charts[3].marks.length - 1]; return { x: m.x, y: m.y, path: m.d.path }; })()');
    await mouse('mouseMoved', r.x + dot.x, r.y + dot.y); await sleep(150);
    const p = JSON.stringify(dot.path);
    check('hovering a dot links its table row', await js(`_chartHover === ${p} && !!_rowByPath.get(${p}) && _rowByPath.get(${p}).classList.contains('row-linked')`));
    check('tooltip shown for the hovered dot', await js('document.getElementById("chart-tooltip").style.display === "block"'));
    await js('document.querySelector("#result tr[data-path]").scrollIntoView({block: "center"}); true'); await sleep(150);
    const row = await js('(() => { const tr = document.querySelector("#result tr[data-path]"); const r = tr.getBoundingClientRect(); return { x: r.left + 20, y: r.top + 5, path: tr.getAttribute("data-path") }; })()');
    await mouse('mouseMoved', row.x, row.y); await sleep(150);
    check('hovering a table row sets the chart hover', await js(`_chartHover === ${JSON.stringify(row.path)}`));
    check('hovered file is ringed in the entropy chart', await js(`_charts[3].marks.some(m => m.d.path === ${JSON.stringify(row.path)})`));
}

async function testFilters() {
    await js('document.getElementById("severityFilter").value = "critical"; applySeverityFilter(); true'); await sleep(300);
    const visible = await js('analyzedData.filter(d => !d.is_unreadable && d.size !== null && d.mtime !== null && shouldShowFile(d)).length');
    check('timeline coloured bars count what the table shows', await js('_charts[1].marks.reduce((s, m) => s + m.shown, 0)') === visible, visible + ' visible');
    check('top-scores chart only lists files passing the filter', await js('_charts[2].marks.every(m => passesTableFilters(m.d))'));
    await js('clearFilters(); true'); await sleep(200);
    await js('document.getElementById("zThreshold").value = "1.5"; applyThreshold(); true'); await sleep(300);
    check('threshold control re-flags like a full rescore',
        await js('JSON.stringify(analyzedData.map(d => d.isAnomaly)) === JSON.stringify(analyzeData(rawFileData, 1.5).map(d => d.isAnomaly))'),
        await js('analyzedData.filter(d => d.isAnomaly).length') + ' anomalies at 1.5');
    await js('document.getElementById("zThreshold").value = String(Z_THRESHOLD); applyThreshold(); true'); await sleep(300);
}

async function testZoomAndResize() {
    const r = await focusChart(0);
    const inView = await js('_charts[0].marks.length');
    for (let i = 0; i < 12; i++) await send('Input.dispatchMouseEvent', { type: 'mouseWheel', x: r.x + 80, y: r.y + r.h - 50, deltaX: 0, deltaY: -100 });
    await sleep(200);
    check('wheel zoom on Threat Matrix', await js('_charts[0].marks.length') < inView, inView + ' -> ' + await js('_charts[0].marks.length') + ' dots in view');
    await setViewport(800); await sleep(500);
    check('charts resize with the window', await js(`_charts.every(c => c.canvas.width === Math.round(c.canvas.clientWidth * ${DPR}) && c.w === c.canvas.clientWidth)`), await js('_charts[0].canvas.clientWidth + "px"'));
}

async function testHostileFileName() {
    await js(`(() => { document.getElementById('searchInput').value = 'alert'; applySearch(); return true; })()`); await sleep(200);
    const link = await js(`(() => { const el = document.querySelector('#result .file-link'); if (!el) return null; el.scrollIntoView({block: 'center'}); const r = el.getBoundingClientRect(); return { x: r.left + 5, y: r.top + 5, text: el.textContent }; })()`);
    if (link) await click(link.x, link.y);
    check("clicking the file named a');alert(1);('.php runs no script", !!link && dialogs() === 0, link ? link.text.split('/').pop() : 'row not found');
}

/** PNGs of the page's parts, for looking at a change: charts.png, matrix.png, table.png */
async function screenshots(dir) {
    fs.mkdirSync(dir, { recursive: true });
    const shot = async (file, selector) => {
        await js(`document.querySelector(${JSON.stringify(selector)}).scrollIntoView({block: "start"}); true`); await sleep(400);
        const r = await js(`(() => { const r = document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect(); return { x: r.left + scrollX, y: r.top + scrollY, width: r.width, height: Math.min(r.height, 4000) }; })()`);
        const png = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: Object.assign({ scale: 1 }, r) });
        fs.writeFileSync(path.join(dir, file), Buffer.from(png.data, 'base64'));
        console.log('saved ' + path.join(dir, file));
    };
    await shot('charts.png', '#chartsGrid');
    await shot('matrix.png', '#chartsGrid .chart-box');
    await shot('table.png', '#result');
}

module.exports = {
    name: 'ui',
    summary: 'the page in headless Chrome: charts, selection, hover, filters, escaping (~30 s)',
    about: `
Scans a sandbox copy of the benchmark webshells and some WordPress files
(whitelist and blacklist off, so nothing is deleted) through the real page,
served by php -S, and drives it with real mouse and keyboard events.

Needs php and Chrome or Chromium: on PATH (google-chrome, chromium) or named
by CHROME_BIN. Without a browser it prints SKIP and passes, unless
--require-browser.`,
    options: {
        'require-browser': { type: 'boolean', help: 'fail instead of skipping when no browser is found' },
        screenshot: { type: 'string', arg: 'dir', help: 'save PNGs of the results table and the charts after the scan' },
    },
    examples: ['CHROME_BIN=/usr/bin/chromium test/run ui'],
    async run(args) {
        const chrome = findChrome();
        if (!chrome) {
            console.log('SKIP: no Chrome/Chromium found (put it on PATH or set CHROME_BIN)');
            return args['require-browser'] ? 1 : 0;
        }
        fails = 0;
        const box = tempDir('ui');
        DATA = path.join(box, 'data');
        buildSandbox(box);
        const port = 18000 + Math.floor(Math.random() * 1000);
        spawnManaged('php', ['-d', 'error_log=' + path.join(box, 'php-errors.log'), '-S', '127.0.0.1:' + port, '-t', path.join(box, 'www')]);
        const page = await openPage({ chrome, url: `http://127.0.0.1:${port}/main.php`, profileDir: path.join(box, 'chrome'), viewport: VIEWPORT, dpr: DPR, port: port + 1000 });
        ({ send, js, waitFor, mouse, click, pressEscape, setViewport, dialogs, errors } = page);

        await testScanAndCharts();
        if (args.screenshot) await screenshots(args.screenshot);
        await testBrushSelection(await tableRows());
        await testTimeline();
        await testHoverLinking();
        await testFilters();
        await testZoomAndResize();
        await testHostileFileName();
        check('no JavaScript errors on the page', errors.length === 0, errors.join(' | ').slice(0, 300));
        console.log(fails ? fails + ' FAILED' : 'all passed');
        return fails ? 1 : 0;
    },
};
