// Browser test for the page's interactive parts (charts, selection, hover
// linking, file-name escaping), driven in headless Chrome over the DevTools
// protocol with real mouse and keyboard events.
//
// It builds a sandbox in a temp dir: a copy of main.php with the whitelist and
// blacklist off (so nothing is ever deleted), copies of test/corpora/positive/blackarch-webshells/php and
// test/corpora/noise/wordpress-7.2-alpha/wp-includes with distinct dates, and a file named
// a');alert(1);('.php. Then it serves it with `php -S` and scans it.
//
// Usage: node test/ui.js        (needs php and google-chrome or chromium)
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const root = path.join(__dirname, '..');
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

fs.mkdirSync(path.join(box, 'www'));
fs.writeFileSync(path.join(box, 'www', 'main.php'), fs.readFileSync(path.join(root, 'main.php'), 'utf8')
    .replace("define('_WHITELIST_', true);", "define('_WHITELIST_', false);")
    .replace("define('_BLACKLIST_', true);", "define('_BLACKLIST_', false);"));
fs.cpSync(path.join(root, 'test/corpora/positive/blackarch-webshells/php'), path.join(DATA, 'shells'), { recursive: true });
fs.mkdirSync(path.join(DATA, 'wp'));
fs.readdirSync(path.join(root, 'test/corpora/noise/wordpress-7.2-alpha/wp-includes')).filter(f => f.endsWith('.php'))
    .forEach(f => fs.copyFileSync(path.join(root, 'test/corpora/noise/wordpress-7.2-alpha/wp-includes', f), path.join(DATA, 'wp', f)));
const xss = path.join(DATA, "a');alert(1);('.php");
fs.writeFileSync(xss, '<?php eval($_GET[1]);');
// distinct dates so the timeline has several buckets
const stamp = (dir, date) => fs.readdirSync(dir).forEach(f => fs.utimesSync(path.join(dir, f), date, date));
stamp(path.join(DATA, 'shells'), new Date('2024-03-01T10:00:00Z'));
stamp(path.join(DATA, 'wp'), new Date('2025-06-15T12:00:00Z'));
fs.utimesSync(xss, new Date('2026-01-10T09:00:00Z'), new Date('2026-01-10T09:00:00Z'));

const chromeBin = ['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser'].find(b => {
    try { execFileSync('which', [b], { stdio: 'ignore' }); return true; } catch (e) { return false; }
});
if (!chromeBin) { console.log('SKIP: no google-chrome or chromium found'); process.exit(0); }
children.push(spawn('php', ['-d', 'error_log=' + path.join(box, 'php-errors.log'), '-S', '127.0.0.1:' + PORT, '-t', path.join(box, 'www')], { stdio: 'ignore' }));

const sleep = ms => new Promise(r => setTimeout(r, ms));
let ws, seq = 0; const pending = new Map(); const errors = []; let dialogs = 0;
const send = (method, params = {}) => new Promise((res, rej) => { const id = ++seq; pending.set(id, { res, rej }); ws.send(JSON.stringify({ id, method, params })); });
const js = async expr => { const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true }); if (r.exceptionDetails) throw new Error(expr + ' -> ' + JSON.stringify(r.exceptionDetails).slice(0, 300)); return r.result.value; };
const mouse = (type, x, y, extra = {}) => send('Input.dispatchMouseEvent', Object.assign({ type, x, y, button: 'left', clickCount: 1 }, extra));
let fails = 0; const check = (name, ok, info = '') => { console.log((ok ? 'PASS ' : 'FAIL ') + name + (info ? '  (' + info + ')' : '')); if (!ok) fails++; };
const waitFor = async (expr, ms = 60000) => { const t = Date.now(); while (Date.now() - t < ms) { if (await js(expr)) return true; await sleep(200); } return false; };

(async () => {
  children.push(spawn(chromeBin, ['--headless=new', '--remote-debugging-port=' + CDP, '--user-data-dir=' + path.join(box, 'chrome'), '--force-device-scale-factor=2', '--window-size=1400,1000', 'about:blank'], { stdio: 'ignore' }));
  let target; for (let i = 0; i < 100 && !target; i++) { try { target = await (await fetch(`http://127.0.0.1:${CDP}/json/new?` + URL, { method: 'PUT' })).json(); } catch (e) { await sleep(200); } }
  ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise(r => ws.onopen = r);
  ws.onmessage = m => { const d = JSON.parse(m.data); if (d.id && pending.has(d.id)) { const p = pending.get(d.id); pending.delete(d.id); d.error ? p.rej(new Error(JSON.stringify(d.error))) : p.res(d.result); }
    if (d.method === 'Runtime.exceptionThrown') errors.push(d.params.exceptionDetails.exception ? d.params.exceptionDetails.exception.description : d.params.exceptionDetails.text);
    if (d.method === 'Page.javascriptDialogOpening') { dialogs++; send('Page.handleJavaScriptDialog', { accept: true }); } };
  await send('Runtime.enable'); await send('Page.enable');
  await send('Emulation.setDeviceMetricsOverride', { width: 1400, height: 1000, deviceScaleFactor: 2, mobile: false });
  await send('Page.navigate', { url: URL }); await waitFor('document.readyState === "complete"');

  // scan
  await js(`document.querySelector('input[name="dir"]').value = ${JSON.stringify(DATA)}; startChunkedScan(); true`);
  check('scan finished', await waitFor('analyzedData.length > 0 && document.getElementById("ajaxProgress").style.display === "none"'), await js('analyzedData.length') + ' files');
  const total = await js('document.querySelectorAll("#result tr[data-path]").length');

  // open charts
  await js('toggleCharts(); true'); await sleep(300);
  check('4 charts built', await js('_charts.length') === 4);
  const dpr = await js('_charts.map(c => c.canvas.width === Math.round(c.canvas.clientWidth * 2)).every(Boolean)');
  check('canvases sized at device pixel ratio 2 (sharp)', dpr, await js('_charts[0].canvas.width + "px backing for " + _charts[0].canvas.clientWidth + "px CSS"'));
  const docListeners = async () => { const doc = await send('Runtime.evaluate', { expression: 'document' }); const l = await send('DOMDebugger.getEventListeners', { objectId: doc.result.objectId }); return l.listeners.length; };
  const before = await docListeners();
  for (let i = 0; i < 5; i++) await js('renderCharts(analyzedData); true');
  check('no document listener leak across 5 rebuilds', await docListeners() === before, before + ' listeners');

  const rect = i => js(`(() => { const r = _charts[${i}].canvas.getBoundingClientRect(); return { x: r.left, y: r.top, w: r.width, h: r.height }; })()`);
  // scroll matrix into view and brush the high-score half
  await js('_charts[0].canvas.scrollIntoView({block: "center"}); true'); await sleep(200);
  let r0 = await rect(0);
  await mouse('mousePressed', r0.x + 72, r0.y + 31); await mouse('mouseMoved', r0.x + r0.w - 31, r0.y + 120); await mouse('mouseReleased', r0.x + r0.w - 31, r0.y + 120);
  await sleep(300);
  const sel = await js('_chartSelection ? _chartSelection.size : 0'), rows = await js('document.querySelectorAll("#result tr[data-path]").length');
  check('drag-select on Threat Matrix selects files', sel > 0 && sel < total, sel + ' of ' + total);
  check('table shows only the selection', rows === sel, rows + ' rows');
  check('selection bar visible', await js('document.getElementById("chartSelectionBar").style.display === "block"'));
  check('selected files are the high scorers', await js('analyzedData.filter(d => _chartSelection.has(d.path)).every(d => d.threatScore > 0)'));

  // Escape clears
  await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 }); await sleep(200);
  check('Escape clears selection', await js('_chartSelection === null') && await js('document.querySelectorAll("#result tr[data-path]").length') === total);

  // timeline: click the tallest bar
  await js('_charts[1].canvas.scrollIntoView({block: "center"}); true'); await sleep(200);
  const bar = await js('(() => { const m = _charts[1].marks.slice().sort((a, b) => b.bucket.files.length - a.bucket.files.length)[0]; return { x: (m.x0 + m.x1) / 2, n: m.bucket.files.length }; })()');
  let r1 = await rect(1);
  await mouse('mousePressed', r1.x + bar.x, r1.y + r1.h - 60); await mouse('mouseReleased', r1.x + bar.x, r1.y + r1.h - 60); await sleep(300);
  check('click on timeline bar selects its files', await js('_chartSelection ? _chartSelection.size : 0') === bar.n, bar.n + ' files');
  // Ctrl+click another bucket adds
  const bar2 = await js('(() => { const m = _charts[1].marks.filter(m => m.bucket.files.length).sort((a, b) => b.bucket.files.length - a.bucket.files.length)[1]; return m ? { x: (m.x0 + m.x1) / 2, n: m.bucket.files.length } : null; })()');
  if (bar2) {
    await mouse('mousePressed', r1.x + bar2.x, r1.y + r1.h - 60, { modifiers: 2 }); await mouse('mouseReleased', r1.x + bar2.x, r1.y + r1.h - 60, { modifiers: 2 }); await sleep(300);
    check('Ctrl+click adds to the selection', await js('_chartSelection.size') === bar.n + bar2.n);
  }
  await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 }); await sleep(200);

  // hover linking: chart dot -> table row, table row -> chart
  await js('_charts[3].canvas.scrollIntoView({block: "center"}); true'); await sleep(200);
  const dot = await js('(() => { const m = _charts[3].marks[_charts[3].marks.length - 1]; return { x: m.x, y: m.y, path: m.d.path }; })()');
  let r3 = await rect(3);
  await mouse('mouseMoved', r3.x + dot.x, r3.y + dot.y); await sleep(150);
  check('hovering a dot links its table row', await js(`_chartHover === ${JSON.stringify(dot.path)} && !!_rowByPath.get(${JSON.stringify(dot.path)}) && _rowByPath.get(${JSON.stringify(dot.path)}).classList.contains('row-linked')`));
  check('tooltip shown for the hovered dot', await js('document.getElementById("chart-tooltip").style.display === "block"'));
  await js('document.querySelector("#result tr[data-path]").scrollIntoView({block: "center"}); true'); await sleep(150);
  const row = await js('(() => { const tr = document.querySelector("#result tr[data-path]"); const r = tr.getBoundingClientRect(); return { x: r.left + 20, y: r.top + 5, path: tr.getAttribute("data-path") }; })()');
  await mouse('mouseMoved', row.x, row.y); await sleep(150);
  check('hovering a table row sets the chart hover', await js(`_chartHover === ${JSON.stringify(row.path)}`));
  check('hovered file is ringed in the entropy chart', await js(`_charts[3].marks.some(m => m.d.path === ${JSON.stringify(row.path)})`));

  // charts follow table filters
  await js('document.getElementById("severityFilter").value = "critical"; applySeverityFilter(); true'); await sleep(300);
  const visible = await js('analyzedData.filter(d => !d.is_unreadable && d.size !== null && d.mtime !== null && shouldShowFile(d)).length');
  check('timeline coloured bars count what the table shows', await js('_charts[1].marks.reduce((s, m) => s + m.shown, 0)') === visible, visible + ' visible');
  check('top-scores chart only lists files passing the filter', await js('_charts[2].marks.every(m => passesTableFilters(m.d))'));
  await js('clearFilters(); true'); await sleep(200);

  // zoom changes what is in view
  await js('_charts[0].canvas.scrollIntoView({block: "center"}); true'); await sleep(200);
  r0 = await rect(0);
  const inView = await js('_charts[0].marks.length');
  for (let i = 0; i < 12; i++) await send('Input.dispatchMouseEvent', { type: 'mouseWheel', x: r0.x + 80, y: r0.y + r0.h - 50, deltaX: 0, deltaY: -100 });
  await sleep(200);
  check('wheel zoom on Threat Matrix', await js('_charts[0].marks.length') < inView, inView + ' -> ' + await js('_charts[0].marks.length') + ' dots in view');

  // resize
  await send('Emulation.setDeviceMetricsOverride', { width: 800, height: 1000, deviceScaleFactor: 2, mobile: false }); await sleep(500);
  check('charts resize with the window', await js('_charts.every(c => c.canvas.width === Math.round(c.canvas.clientWidth * 2) && c.w === c.canvas.clientWidth)'), await js('_charts[0].canvas.clientWidth + "px"'));

  // XSS file name: click its row link and copy button
  await js(`(() => { document.getElementById('searchInput').value = 'alert'; applySearch(); return true; })()`); await sleep(200);
  const link = await js(`(() => { const el = document.querySelector('#result .file-link'); if (!el) return null; el.scrollIntoView({block: 'center'}); const r = el.getBoundingClientRect(); return { x: r.left + 5, y: r.top + 5, text: el.textContent }; })()`);
  if (link) { await mouse('mousePressed', link.x, link.y); await mouse('mouseReleased', link.x, link.y); await sleep(300); }
  check("clicking the file named a');alert(1);('.php runs no script", !!link && dialogs === 0, link ? link.text.split('/').pop() : 'row not found');

  check('no JavaScript errors on the page', errors.length === 0, errors.join(' | ').slice(0, 300));
  console.log(fails ? fails + ' FAILED' : 'all passed');
  await finish(fails ? 1 : 0);
})().catch(e => { console.log('ERROR', e.message); finish(1); });
