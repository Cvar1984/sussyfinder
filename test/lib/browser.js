// Headless Chrome over the DevTools protocol, for `test/run ui`: find a
// browser, open a page, evaluate JS in it and send real mouse and keyboard
// events. Uncaught page errors and JS dialogs (alert/confirm) are recorded.
const { spawn, execFileSync } = require('child_process');
const { atExit } = require('./cleanup');
const { sleep } = require('./util');

/** Chrome from CHROME_BIN or PATH, or null; as root it only starts with --no-sandbox */
function findChrome() {
    const bin = process.env.CHROME_BIN || ['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser'].find(b => {
        try { execFileSync('which', [b], { stdio: 'ignore' }); return true; } catch (e) { return false; }
    });
    return bin ? { bin, flags: process.getuid && process.getuid() === 0 ? ['--no-sandbox'] : [] } : null;
}

/** Start a process that is killed (and waited for) when the command ends */
function spawnManaged(cmd, args) {
    const child = spawn(cmd, args, { stdio: 'ignore' });
    atExit(async () => {
        child.kill();
        if (child.exitCode === null && !child.signalCode) await new Promise(r => child.once('exit', r));
    });
    return child;
}

/**
 * Open `url` in a new headless Chrome with its profile in `profileDir`.
 * Resolves to the page: send(method, params), js(expr), waitFor(expr, ms),
 * mouse(type, x, y, extra), click(x, y, modifiers), pressEscape(),
 * setViewport(width), and errors / dialogs() seen so far.
 */
async function openPage({ chrome, url, profileDir, viewport, dpr, port }) {
    spawnManaged(chrome.bin, chrome.flags.concat(['--headless=new', '--remote-debugging-port=' + port, '--user-data-dir=' + profileDir,
        '--force-device-scale-factor=' + dpr, `--window-size=${viewport.width},${viewport.height}`, 'about:blank']));
    let target;
    for (let i = 0; i < 100 && !target; i++) {
        try { target = await (await fetch(`http://127.0.0.1:${port}/json/new?` + url, { method: 'PUT' })).json(); } catch (e) { await sleep(200); }
    }
    if (!target) throw new Error(`${chrome.bin} did not start (see --no-sandbox, CHROME_BIN)`);

    const ws = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise(r => { ws.onopen = r; });
    let seq = 0, dialogs = 0;
    const pending = new Map(), errors = [];
    const send = (method, params = {}) => new Promise((res, rej) => { const id = ++seq; pending.set(id, { res, rej }); ws.send(JSON.stringify({ id, method, params })); });
    ws.onmessage = m => {
        const d = JSON.parse(m.data);
        if (d.id && pending.has(d.id)) { const p = pending.get(d.id); pending.delete(d.id); d.error ? p.rej(new Error(JSON.stringify(d.error))) : p.res(d.result); }
        if (d.method === 'Runtime.exceptionThrown') errors.push(d.params.exceptionDetails.exception ? d.params.exceptionDetails.exception.description : d.params.exceptionDetails.text);
        if (d.method === 'Page.javascriptDialogOpening') { dialogs++; send('Page.handleJavaScriptDialog', { accept: true }); }
    };
    atExit(() => ws.close());

    const js = async expr => {
        const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true });
        if (r.exceptionDetails) throw new Error(expr + ' -> ' + JSON.stringify(r.exceptionDetails).slice(0, 300));
        return r.result.value;
    };
    const page = {
        send, js, errors,
        dialogs: () => dialogs,
        waitFor: async (expr, ms = 60000) => { const t = Date.now(); while (Date.now() - t < ms) { if (await js(expr)) return true; await sleep(200); } return false; },
        mouse: (type, x, y, extra = {}) => send('Input.dispatchMouseEvent', Object.assign({ type, x, y, button: 'left', clickCount: 1 }, extra)),
        click: async (x, y, modifiers = 0) => { await page.mouse('mousePressed', x, y, { modifiers }); await page.mouse('mouseReleased', x, y, { modifiers }); await sleep(300); },
        pressEscape: async () => { await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 }); await sleep(200); },
        setViewport: width => send('Emulation.setDeviceMetricsOverride', { width, height: viewport.height, deviceScaleFactor: dpr, mobile: false }),
    };
    await send('Runtime.enable');
    await send('Page.enable');
    await page.setViewport(viewport.width);
    await send('Page.navigate', { url });
    await page.waitFor('document.readyState === "complete"');
    return page;
}

module.exports = { findChrome, spawnManaged, openPage };
