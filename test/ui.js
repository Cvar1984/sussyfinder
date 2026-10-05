// Browser test for the page's interactive parts (charts, selection, hover
// linking, file-name escaping), driven in headless Chrome over the DevTools
// protocol with real mouse and keyboard events.
//
// It builds a sandbox in a temp dir: a copy of main.php with the whitelist and
// blacklist off (so nothing is ever deleted), copies of the benchmark webshells
// and of WordPress's wp-includes with distinct dates, and a file named
// a');alert(1);('.php. Then it serves it with `php -S` and scans it.
//
// Usage: node test/ui.js     (needs php and Chrome/Chromium: on PATH as
//        google-chrome or chromium, or set CHROME_BIN; exits 0 with SKIP
//        when there is none, or fails instead with --require-browser)
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const lib = require('./lib');

const args = lib.cli({
    'require-browser': { type: 'boolean', help: 'fail instead of skipping when no browser is found' },
}, 'Usage: node test/ui.js [options]');
const VIEWPORT = { width: 1400, height: 1000 }, DPR = 2;
const box = fs.mkdtempSync(path.join(os.tmpdir(), 'sussy-ui-'));
const DATA = path.join(box, 'data');
const PORT = 18000 + Math.floor(Math.random() * 1000), CDP = PORT + 1000;
const URL = `http://127.0.0.1:${PORT}/main.php`;
const children = [];
// Chrome keeps writing its profile until it has exited, so wait for that before removing the sandbox
async function finish(code) {
    children.forEach(c => c.kill());
    await Promise.all(children.map(c => c.exitCode !== null || c.signalCode ? null : new Promise(r => c.once('exit', r))));
    fs.rmSync(box, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    process.exit(code);
}
process.on('SIGINT', () => finish(130));

/** Chrome from CHROME_BIN or PATH; as root it only starts with --no-sandbox */
function findChrome() {
    const bin = process.env.CHROME_BIN || ['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser'].find(b => {
        try { execFileSync('which', [b], { stdio: 'ignore' }); return true; } catch (e) { return false; }
    });
    return bin && { bin, flags: process.getuid && process.getuid() === 0 ? ['--no-sandbox'] : [] };
}

function buildSandbox() {
    fs.mkdirSync(path.join(box, 'www'));
    let page = fs.readFileSync(lib.MAIN, 'utf8');
    for (const name of ['_WHITELIST_', '_BLACKLIST_']) {
        const on = `define('${name}', true);`;
        if (!page.includes(on)) throw new Error(`main.php no longer has ${on}: can't switch it off for the test`);
        page = page.replace(on, `define('${name}', false);`);
    }
    fs.writeFileSync(path.join(box, 'www', 'main.php'), page);
    const corpora = lib.loadCorpora();
    fs.cpSync(path.join(lib.corpus('blackarch-webshells', corpora).dir, 'php'), path.join(DATA, 'shells'), { recursive: true });
    const wp = path.join(lib.corpus('wordpress-7.2-alpha', corpora).dir, 'wp-includes');
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

// --- DevTools protocol plumbing ---
const sleep = ms => new Promise(r => setTimeout(r, ms));
let ws, seq = 0; const pending = new Map(); const errors = []; let dialogs = 0;
const send = (method, params = {}) => new Promise((res, rej) => { const id = ++seq; pending.set(id, { res, rej }); ws.send(JSON.stringify({ id, method, params })); });
const js = async expr => {
    const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true });
    if (r.exceptionDetails) throw new Error(expr + ' -> ' + JSON.stringify(r.exceptionDetails).slice(0, 300));
    return r.result.value;
};
const waitFor = async (expr, ms = 60000) => { const t = Date.now(); while (Date.now() - t < ms) { if (await js(expr)) return true; await sleep(200); } return false; };
const mouse = (type, x, y, extra = {}) => send('Input.dispatchMouseEvent', Object.assign({ type, x, y, button: 'left', clickCount: 1 }, extra));
const click = async (x, y, modifiers = 0) => { await mouse('mousePressed', x, y, { modifiers }); await mouse('mouseReleased', x, y, { modifiers }); await sleep(300); };
const pressEscape = async () => { await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 }); await sleep(200); };
const setViewport = width => send('Emulation.setDeviceMetricsOverride', { width, height: VIEWPORT.height, deviceScaleFactor: DPR, mobile: false });
/** Scroll chart i into view; resolves to its on-screen rectangle */
const focusChart = async i => {
    await js(`_charts[${i}].canvas.scrollIntoView({block: "center"}); true`); await sleep(200);
    return js(`(() => { const r = _charts[${i}].canvas.getBoundingClientRect(); return { x: r.left, y: r.top, w: r.width, h: r.height }; })()`);
};
const selectionSize = () => js('_chartSelection ? _chartSelection.size : 0');
const tableRows = () => js('document.querySelectorAll("#result tr[data-path]").length');
let fails = 0;
const check = (name, ok, info = '') => { console.log((ok ? 'PASS ' : 'FAIL ') + name + (info ? '  (' + info + ')' : '')); if (!ok) fails++; };

async function connect(chrome) {
    children.push(spawn(chrome.bin, chrome.flags.concat(['--headless=new', '--remote-debugging-port=' + CDP, '--user-data-dir=' + path.join(box, 'chrome'),
        '--force-device-scale-factor=' + DPR, `--window-size=${VIEWPORT.width},${VIEWPORT.height}`, 'about:blank']), { stdio: 'ignore' }));
    let target;
    for (let i = 0; i < 100 && !target; i++) { try { target = await (await fetch(`http://127.0.0.1:${CDP}/json/new?` + URL, { method: 'PUT' })).json(); } catch (e) { await sleep(200); } }
    if (!target) throw new Error(`${chrome.bin} did not start (see --no-sandbox, CHROME_BIN)`);
    ws = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise(r => ws.onopen = r);
    ws.onmessage = m => {
        const d = JSON.parse(m.data);
        if (d.id && pending.has(d.id)) { const p = pending.get(d.id); pending.delete(d.id); d.error ? p.rej(new Error(JSON.stringify(d.error))) : p.res(d.result); }
        if (d.method === 'Runtime.exceptionThrown') errors.push(d.params.exceptionDetails.exception ? d.params.exceptionDetails.exception.description : d.params.exceptionDetails.text);
        if (d.method === 'Page.javascriptDialogOpening') { dialogs++; send('Page.handleJavaScriptDialog', { accept: true }); }
    };
    await send('Runtime.enable'); await send('Page.enable');
    await setViewport(VIEWPORT.width);
    await send('Page.navigate', { url: URL }); await waitFor('document.readyState === "complete"');
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
    const r = await focusChart(0); // brush the high-score half of the Threat Matrix
    await mouse('mousePressed', r.x + 72, r.y + 31); await mouse('mouseMoved', r.x + r.w - 31, r.y + 120); await mouse('mouseReleased', r.x + r.w - 31, r.y + 120);
    await sleep(300);
    const sel = await selectionSize(), rows = await tableRows();
    check('drag-select on Threat Matrix selects files', sel > 0 && sel < total, sel + ' of ' + total);
    check('table shows only the selection', rows === sel, rows + ' rows');
    check('selection bar visible', await js('document.getElementById("chartSelectionBar").style.display === "block"'));
    check('selected files are the high scorers', await js('analyzedData.filter(d => _chartSelection.has(d.path)).every(d => d.threatScore > 0)'));
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
    check("clicking the file named a');alert(1);('.php runs no script", !!link && dialogs === 0, link ? link.text.split('/').pop() : 'row not found');
}

(async () => {
    const chrome = findChrome();
    if (!chrome) {
        console.log('SKIP: no Chrome/Chromium found (put it on PATH or set CHROME_BIN)');
        return finish(args['require-browser'] ? 1 : 0);
    }
    buildSandbox();
    children.push(spawn('php', ['-d', 'error_log=' + path.join(box, 'php-errors.log'), '-S', '127.0.0.1:' + PORT, '-t', path.join(box, 'www')], { stdio: 'ignore' }));
    await connect(chrome);
    await testScanAndCharts();
    await testBrushSelection(await tableRows());
    await testTimeline();
    await testHoverLinking();
    await testFilters();
    await testZoomAndResize();
    await testHostileFileName();
    check('no JavaScript errors on the page', errors.length === 0, errors.join(' | ').slice(0, 300));
    console.log(fails ? fails + ' FAILED' : 'all passed');
    await finish(fails ? 1 : 0);
})().catch(e => { console.log('ERROR', e.message); finish(1); });
