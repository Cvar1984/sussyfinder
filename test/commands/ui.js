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
const { sleep, md5 } = require('../lib/util');
const { findChrome, spawnManaged, openPage } = require('../lib/browser');
const { phpString } = require('../lib/php');

const VIEWPORT = { width: 1400, height: 1000 }, DPR = 2;
let DATA, VERIFIED; // VERIFIED: the WordPress file a local checksums.txt lists
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
    // Vendor checksums from a local list naming one copied WordPress file
    const checksums = path.join(box, 'checksums.txt');
    page = "<?php define('_WHITELIST_', false); define('_BLACKLIST_', false); define('_CHECKSUMS_URL_', " + phpString(checksums) + ");" + page.slice('<?php'.length);
    fs.writeFileSync(path.join(box, 'www', 'main.php'), page);
    // The same page with small listing pages, several batches at once, a
    // short table and an early switch to "Only Anomalies" (testPagedParallel())
    fs.writeFileSync(path.join(box, 'www', 'paged.php'), "<?php define('LIST_PAGE_FILES', 7); define('MAX_PARALLEL', 3); " +
        "define('TABLE_PAGE_ROWS', 50); define('ANOMALIES_ONLY_ABOVE', 100);" + page.slice('<?php'.length));
    const corpora = loadCorpora();
    fs.cpSync(path.join(corpus('blackarch-webshells', corpora).dir, 'php'), path.join(DATA, 'shells'), { recursive: true });
    const wp = path.join(corpus('wordpress-7.2-alpha', corpora).dir, 'wp-includes');
    fs.mkdirSync(path.join(DATA, 'wp'));
    fs.readdirSync(wp).filter(f => f.endsWith('.php')).forEach(f => fs.copyFileSync(path.join(wp, f), path.join(DATA, 'wp', f)));
    // the largest copied file, so it has needles whose display can be checked
    VERIFIED = fs.readdirSync(path.join(DATA, 'wp')).sort((a, b) => fs.statSync(path.join(DATA, 'wp', b)).size - fs.statSync(path.join(DATA, 'wp', a)).size || (a < b ? -1 : 1))[0];
    fs.writeFileSync(checksums, `${md5(fs.readFileSync(path.join(DATA, 'wp', VERIFIED)))} wordpress wp/${VERIFIED}\n`);
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
    // Small batches, so the scan has a middle: each batch is listed as it
    // arrives, and the bar counts what came back
    await js(`document.getElementById('chunkSizeInput').value = 20; document.querySelector('input[name="dir"]').value = ${JSON.stringify(DATA)}; startChunkedScan(); true`);
    check('the list fills in while the scan runs', await waitFor(`document.getElementById("ajaxProgress").style.display === "block" &&
        document.querySelectorAll("#result tr[data-path]").length > 0 && parseFloat(document.getElementById("ajaxBar").style.width) > 0`),
        await js('document.querySelectorAll("#result tr[data-path]").length') + ' rows, bar ' + await js('document.getElementById("ajaxBar").style.width'));
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

async function testVerified() {
    const d = await js(`(() => { const d = analyzedData.find(d => d.verified); return d ? { path: d.path, verified: d.verified, isAnomaly: d.isAnomaly,
        threatScore: d.threatScore, contentScore: d.contentScore, tokens: d.matched_tokens } : null; })()`);
    check('a file on the checksum list scans as verified and is not flagged', !!d && d.path.endsWith('/wp/' + VERIFIED) && d.isAnomaly === false
        && /^wordpress release file wp\//.test(d.verified), JSON.stringify(d));
    check('only that file is verified', await js('analyzedData.filter(d => d.verified).length') === 1);
    check('its threat score is held below VERIFIED_MAX', !!d && d.threatScore < await js('VERIFIED_MAX') && d.threatScore <= d.contentScore,
        d && `content ${d.contentScore} -> ${d.threatScore}`);
    await js(`(() => { document.getElementById('searchInput').value = ${JSON.stringify(VERIFIED)}; applySearch(); return true; })()`); await sleep(200);
    const row = await js(`(() => { const r = [...document.querySelectorAll('#result tr[data-path]')].find(r => r.innerHTML.includes('VERIFIED')); return r ? r.textContent : ''; })()`);
    check('its row shows the VERIFIED badge', row !== '');
    check('and still shows its matched tokens', !!d && d.tokens.length > 0 && d.tokens.every(t => row.includes(t)), d && d.tokens.join(', '));
    await js(`(() => { document.getElementById('searchInput').value = ''; applySearch(); return true; })()`); await sleep(200);
}

// The Refresh button clears the server's download cache. The page then offers a
// reload; confirm() is answered "no" in the page, so no dialog opens.
async function testRefreshDownloads() {
    await js(`window._asked = null; window.confirm = q => { window._asked = q; return false; }; document.getElementById('refreshDownloads').click(); true`);
    check('Refresh lists clears the download cache and offers a reload', await waitFor('window._asked !== null', 10000) &&
        /^Deleted \d+ cached download/.test(await js('window._asked')) && /download\(s\) kept in|No download cache/.test(await js("document.getElementById('refreshDownloads').title")),
        await js('window._asked'));
}

// What a scan found, for comparing two scans of the sandbox
const RESULT = 'JSON.stringify(analyzedData.map(d => [d.path, d.threatScore, d.isAnomaly, d.duplicate_of, d.verified, d.mlScore]).sort())';

// paged.php, with a stand-in for fetch() that answers some batches the way a
// busy host does (503) and one the way a crash on one file does (500), resets
// the connection the way Firefox reports NS_ERROR_NET_RESET (AbortError) for a
// listing page, a batch once, and every batch holding one file (the server
// dying on it), and counts the requests running at once. Cancelling a scan
// and starting another must leave nothing of the first. The result must equal
// main.php's plain scan, but for the one file, which is named as skipped.
async function testPagedParallel(port, reference) {
    await send('Page.navigate', { url: `http://127.0.0.1:${port}/paged.php` });
    await waitFor('document.readyState === "complete" && typeof startChunkedScan === "function"');
    await js(`(() => {
        const real = window.fetch;
        window._io = { running: 0, most: 0, process: 0, busy: 0, failed: 0, reset: 0, list: 0, smaller: false };
        const reset = () => { _io.reset++; return Promise.reject(new DOMException('The operation was aborted. ', 'AbortError')); };
        window.fetch = (url, opts) => {
            const action = opts.body.get('ajax_action');
            if (action === 'scan' && ++_io.list === 2) return reset();
            if (action === 'scan' && _io.list > 2 && opts.body.get('seconds') < LIST_PAGE.seconds) _io.smaller = true;
            const many = action === 'process' && opts.body.get('paths').includes(',');
            if (action === 'process' && (opts.body.get('paths').includes('alert%281%29') || many && _io.process >= 2 && !_io.once && (_io.once = true))) return reset();
            if (action === 'process' && ++_io.process % 4 === 0 && _io.process <= 40) { _io.busy++; return Promise.resolve(new Response('<html>busy</html>', { status: 503, headers: { 'Retry-After': '0' } })); }
            if (many && _io.process >= 6 && !_io.failed) { _io.failed++; return Promise.resolve(new Response('<html>error</html>', { status: 500 })); }
            _io.running++; _io.most = Math.max(_io.most, _io.running);
            return real(url, opts).finally(() => { _io.running--; });
        };
        document.getElementById('chunkSizeInput').value = 5;
        document.querySelector('input[name="dir"]').value = ${JSON.stringify(DATA)};
        startChunkedScan();
        return true;
    })()`);
    await waitFor('document.querySelectorAll("#result tr[data-path]").length > 0');
    // Each failure above once more, in the new scan
    await js('cancelChunkedScan(); Object.assign(_io, { list: 0, process: 0, once: false, failed: 0, most: 0 }); startChunkedScan(); true');
    check('paged, parallel scan with busy and failing replies finished', await waitFor('analyzedData.length > 0 && document.getElementById("ajaxProgress").style.display === "none"', 120000));
    const io = await js('_io');
    const without = list => JSON.stringify(JSON.parse(list).filter(r => !r[0].includes('alert(1)')));
    check('same results as one listing page and one batch at a time', without(await js(RESULT)) === without(reference), await js('analyzedData.length') + ' files');
    check('a reset listing page is asked for again, smaller', io.smaller);
    check('the file the server dies on is skipped by name, nothing else', await js(`_eventLog.filter(e => /^Skipped/.test(e.message)).length === 1 &&
        _eventLog.some(e => /^Skipped .*alert\\(1\\).*no answer from the server.*the server may crash/.test(e.message))`));
    check('busy replies were retried, then several batches ran at once again', io.most > 1 && io.most <= 3 && io.busy > 0 && io.failed === 1, JSON.stringify(io));
    check('busy host reported once', await js(`_eventLog.filter(e => /host is busy|got no answer/.test(e.message)).length === 1`));
    check('scan of more than ANOMALIES_ONLY_ABOVE files switched to "Only Anomalies"',
        await js('currentFilterMode === "anomalies" && document.getElementById("severityFilter").value === "anomalies"'));
    check('the page keeps one scored copy per file, without the ML bitmaps',
        await js('rawFileData === analyzedData && lastScanFeatures === analyzedData && analyzedData.every(d => !("ml_features" in d) && !("ml_units" in d))'));
    await js('document.getElementById("zThreshold").value = "2"; applyThreshold(); true'); await sleep(200);
    check('still one copy after moving the threshold', await js('rawFileData === analyzedData && lastScanFeatures === analyzedData'));
    await js('document.getElementById("severityFilter").value = "all"; applySeverityFilter(); true'); await sleep(200);
    const total = await js('analyzedData.filter(d => shouldShowFile(d)).length');
    await js('window.scrollTo(0, 0); renderTable(analyzedData); true'); await sleep(300);
    const first = await tableRows();
    check('table draws TABLE_PAGE_ROWS rows at a time', first >= 50 && first < total && first % 50 === 0 && await js('!!document.getElementById("showMoreRows")'), first + ' of ' + total + ' drawn');
    const steps = [];
    for (let i = 0; i < 40 && await js('!!document.getElementById("showMoreRows")'); i++) {
        await js('document.getElementById("showMoreRows").scrollIntoView({block: "end"}); true'); await sleep(250);
        steps.push(await tableRows());
    }
    check('scrolling to the end draws the next rows until all are shown (infinite scroll)', await tableRows() === total &&
        steps.every((n, i) => i === 0 || n >= steps[i - 1]), steps.join(' '));
    await js('window.scrollTo(0, 0); true');
}

// The search box's query language against the same predicates written out,
// "/" from anywhere, and Escape
async function testSearch() {
    await js('document.getElementById("severityFilter").value = "all"; applySeverityFilter(); true');
    const same = async (query, predicate) => {
        const r = await js(`(() => { document.getElementById('searchInput').value = ${JSON.stringify(query)}; applySearch();
            const got = analyzedData.filter(d => shouldShowFile(d)).length, want = analyzedData.filter(${predicate}).length;
            return { got, want, error: document.getElementById('searchInput').classList.contains('search-error') }; })()`);
        check(`search ${query}`, r.got === r.want && r.got > 0 && r.got < await js('analyzedData.length') && !r.error, r.got + ' files');
    };
    const has = 'd => (d.matched_tokens || []).some(t => t.toLowerCase().includes("eval"))';
    await same('eval', `d => d.path.toLowerCase().includes("eval") || (${has})(d)`);
    await same('ext:php -is:critical -token:eval', `d => /\\.php$/i.test(d.path) && !isCritical(d) && !(${has})(d)`);
    await same('token:eval OR token:system', 'd => (d.matched_tokens || []).some(t => /eval|system/i.test(t))');
    await same('score:>=15', 'd => d.threatScore >= 15');
    await same('score:8..15 size:>2k', 'd => d.threatScore >= 8 && d.threatScore < 15 && d.size > 2048');
    await same('/\\/wp-[a-z]+\\.php$/', 'd => /\\/wp-[a-z]+\\.php$/i.test(d.path) || (d.matched_tokens || []).some(t => /\\/wp-[a-z]+\\.php$/i.test(t))');
    await same('name:/^class-/ ext:php', 'd => /^class-/i.test(d.path.split("/").pop()) && /\\.php$/i.test(d.path)');
    await same('"alert(1)"', 'd => d.path.includes("alert(1)")');
    await same('date:2024', 'd => d.mtime >= new Date(2024, 0, 1) / 1000 && d.mtime < new Date(2025, 0, 1) / 1000');
    await same('is:verified', 'd => !!d.verified');
    const target = await js('analyzedData.find(d => d.path.endsWith("/wp/" + ' + JSON.stringify(VERIFIED) + ')).path');
    await same('dir:' + JSON.stringify(target.slice(0, target.lastIndexOf('/'))), `d => d.path.startsWith(${JSON.stringify(target.slice(0, target.lastIndexOf('/') + 1))}) && !d.path.slice(${target.lastIndexOf('/') + 1}).includes('/')`);
    await same('date:2024-03-01T00..2024-03-01T23', 'd => d.mtime >= new Date(2024, 2, 1, 0) / 1000 && d.mtime < new Date(2024, 2, 2, 0) / 1000');
    const xss = await js('analyzedData.find(d => d.path.includes("alert(1)")).path');
    await same('near:' + JSON.stringify(xss), `d => d.path.slice(0, d.path.lastIndexOf("/")) === ${JSON.stringify(xss.slice(0, xss.lastIndexOf('/')))} ||
        Math.abs(d.mtime - analyzedData.find(x => x.path === ${JSON.stringify(xss)}).mtime) <= 3600`);
    // near: of every file a query finds: in any of their folders, or changed
    // within the window of any of them
    const near = (targets, span) => `d => { const T = analyzedData.filter(${targets}), dir = p => p.slice(0, p.lastIndexOf("/"));
        return T.some(t => dir(t.path) === dir(d.path) || (t.mtime && d.mtime && Math.abs(t.mtime - d.mtime) <= ${span})); }`;
    await same('near:is:verified', near('d => !!d.verified', 3600));
    await same('near:("alert(1)" OR name:class-wp-error)', near('d => d.path.includes("alert(1)") || d.path.split("/").pop().includes("class-wp-error")', 3600));
    await same('near:(name:/^class-/ ext:php)~1m', near('d => /^class-.*\\.php$/i.test(d.path.split("/").pop())', 60));
    await same('-near:is:verified', `d => !(${near('d => !!d.verified', 3600)})(d)`);
    await same('(token:eval OR token:system) -ext:inc', 'd => (d.matched_tokens || []).some(t => /eval|system/i.test(t)) && !/\\.inc$/i.test(d.path)');
    await js(`document.getElementById('searchInput').value = 'near:is:mhr'; applySearch(); true`);
    check('near: with no target says so', await js(`/near: no file matches is:mhr/.test(document.getElementById('searchInput').title)`));
    // near: on made-up rows like a real intrusion: a deploy 700 files share,
    // a shell whose mtime was backdated into it (its ctime can't be), a file
    // dropped beside it, and three files edited at that ctime and set back to
    // the deploy's mtime. The deploy's time is too common to mean anything.
    await js(`(() => {
        window._realRows = analyzedData;
        const T0 = 1.7e9, T1 = T0 + 30 * 86400;
        const row = (path, mtime, ctime, extra) => Object.assign({ path, mtime, ctime, md5: path, size: 100, entropy: 4, total_tokens: 10, suspCount: 0,
            matched_tokens: [], threatScore: 0, ruleScore: 0, mlScore: null, mlPoints: 0, isAnomaly: false, mlOnly: false, duplicate_of: false, verified: false,
            is_blacklisted: false, is_htaccess: false, is_unreadable: false, rareOwner: false, owner: 1, date: '', zScores: { susp: 0, ctime: 0, mtime: 0, entropy: 0, size: 0, tokens: 0 } }, extra);
        const rows = [];
        for (let i = 0; i < 700; i++) rows.push(row('/site/core/f' + i + '.php', T0, T0));
        for (let i = 0; i < 100; i++) rows.push(row('/site/old/g' + i + '.php', T0 - 86400 * (i + 2), T0 - 86400 * (i + 2)));
        rows.push(row('/site/up/shell.php', T0, T1, { is_blacklisted: true, isAnomaly: true, threatScore: 100 }));
        rows.push(row('/site/up/x.jpg.php', T0 - 5e6, T0 - 5e6));
        for (let i = 0; i < 3; i++) rows.push(row('/site/core/edited' + i + '.php', T0, T1 + 600 * i));
        analyzedData = rows;
        document.getElementById('severityFilter').value = currentFilterMode = 'anomalies';
        return true;
    })()`);
    await js(`document.getElementById('searchInput').value = 'near:is:blacklisted'; applySearch(); true`);
    const found = await js('JSON.stringify(analyzedData.filter(d => shouldShowFile(d)).map(d => d.path).sort())');
    check('near:is:blacklisted finds the dropped and edited files by ctime, not the deploy the shell\'s mtime hides in', found ===
        JSON.stringify(['/site/core/edited0.php', '/site/core/edited1.php', '/site/core/edited2.php', '/site/up/shell.php', '/site/up/x.jpg.php']), found);
    check('it says it left the crowded time out', await js(`/near: left out 1 time\\(s\\) shared by more than 200 files/.test(document.getElementById('searchInput').title)`));
    check('typing near: shows all files, not only anomalies', await js('currentFilterMode === "all"'));
    await js(`document.getElementById('severityFilter').value = 'anomalies'; applySeverityFilter(); document.getElementById('searchInput').value = 'site'; applySearch(); true`);
    check('a search the filter hides says how many and offers them', await js(`/^804 more file\\(s\\) match the search but are hidden by the "Only Anomalies" filter/.test(document.getElementById('hiddenMatches').textContent.trim())`));
    await js('document.querySelector("#hiddenMatches button").click(); true');
    check('"Show them" switches to All Files', await js('currentFilterMode === "all" && !document.getElementById("hiddenMatches")'));
    // The compass on a file the first page of the table doesn't reach
    await js('searchNear("/site/core/f650.php"); true'); await sleep(200);
    check('the 🧭 draws the table down to its file and marks it', await js(`_rowByPath.has('/site/core/f650.php') && _rowByPath.get('/site/core/f650.php').classList.contains('row-near')`),
        await tableRows() + ' rows drawn');
    await js('analyzedData = _realRows; clearFilters(); true');
    // A row's compass: the files near it, newest first, the file itself marked
    await js('clearFilters(); document.getElementById("searchInput").value = ""; applySearch(); true');
    await js(`document.querySelector('#result tr[data-path] .near-btn[data-near=' + JSON.stringify(${JSON.stringify(target)}) + ']').click(); true`); await sleep(300);
    check('the 🧭 on a row searches near:"its path", sorted by time, and marks it', await js(`currentSearch === 'near:' + quoteQuery(${JSON.stringify(target)}) &&
        currentSort === 'mtime' && document.querySelector('#result tr.row-near') === _rowByPath.get(${JSON.stringify(target)})`), await tableRows() + ' rows');
    await js('clearFilters(); document.getElementById("sortSelect").value = currentSort = "threat"; renderTable(analyzedData); true');
    await js(`document.getElementById('searchInput').value = '/(/ score:>x'; applySearch(); true`);
    check('a broken regex or number marks the search box and says why', await js(`document.getElementById('searchInput').classList.contains('search-error') &&
        /regular expression/.test(document.getElementById('searchInput').title) && /isn.t a number/.test(document.getElementById('searchInput').title)`));
    // "/" from the page jumps to the box without typing a slash; Escape clears it, then leaves it
    await js(`document.getElementById('searchInput').value = ''; applySearch(); document.activeElement.blur(); true`);
    await send('Input.dispatchKeyEvent', { type: 'keyDown', key: '/', code: 'Slash', text: '/', windowsVirtualKeyCode: 191 });
    await send('Input.dispatchKeyEvent', { type: 'keyUp', key: '/', code: 'Slash', windowsVirtualKeyCode: 191 });
    check('"/" focuses the search box', await js('document.activeElement.id === "searchInput" && document.activeElement.value === ""'));
    await send('Input.insertText', { text: 'eval' }); await sleep(400);
    check('typing there searches', await js('currentSearch === "eval"'));
    await pressEscape();
    check('Escape clears the search', await js('document.getElementById("searchInput").value === "" && currentSearch === ""'));
    await pressEscape();
    check('Escape again leaves the box', await js('document.activeElement.id !== "searchInput"'));
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
        const reference = await js(RESULT);
        if (args.screenshot) await screenshots(args.screenshot);
        await testBrushSelection(await tableRows());
        await testTimeline();
        await testHoverLinking();
        await testFilters();
        await testZoomAndResize();
        await testVerified();
        await testHostileFileName();
        await testSearch();
        await testRefreshDownloads();
        await testPagedParallel(port, reference);
        check('no JavaScript errors on the page', errors.length === 0, errors.join(' | ').slice(0, 300));
        console.log(fails ? fails + ' FAILED' : 'all passed');
        return fails ? 1 : 0;
    },
};
