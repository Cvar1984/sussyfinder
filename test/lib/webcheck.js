// The page and its AJAX actions over HTTP, in a container: the page and its
// inline JS parse, scan lists files (and the fixture, without hanging on its
// FIFO), process returns rows with paths that round-trip byte for byte, and a
// request without the CSRF header is refused.
const { execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { ROOT } = require('./paths');
const { corpus } = require('./corpora');
const { LISTING_WANT } = require('./selfcheck');

function webCheck(t) {
    const url = `http://127.0.0.1:${t.port}/main.php`;
    const curl = (extra, csrfHeader = true) => {
        const a = ['-s', '-m', '120'].concat(csrfHeader ? ['-H', 'X-Sussy-Request: 1'] : [], extra, [url]);
        try { return execFileSync('curl', a, { maxBuffer: 1 << 26 }).toString(); } catch (e) { return ''; }
    };
    const json = s => { try { return JSON.parse(s); } catch (e) { return null; } };
    const shells = path.join(t.repo, corpus('blackarch-webshells').path, 'php');
    const page = curl([], false);
    const js = [...page.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]).join('\n;\n');
    let jsOk = page.includes('</html>');
    try { new vm.Script(js); } catch (e) { jsOk = false; }
    const scan = json(curl(['--data', 'ajax_action=scan', '--data', 'dir=' + shells]));
    // Must return (the FIFO can't hang it) and list the fixture's names
    const fixtureScan = json(curl(['--data', 'ajax_action=scan', '--data', 'dir=/work/fixture']));
    // Without the CSRF header every action is refused
    const noHeader = json(curl(['--data', 'ajax_action=scan', '--data', 'dir=/work/fixture'], false));
    // Paths are rawurlencoded on the wire, then form-encoded; the Latin-1 name must round-trip
    const micro = shells + '/micro.php';
    const microMd5 = crypto.createHash('md5').update(fs.readFileSync(path.join(ROOT, path.relative(t.repo, micro)))).digest('hex');
    const latin1 = '%2Fwork%2Ffixture%2Fcaf%E9.php';
    const wire = p => encodeURIComponent(encodeURIComponent(p));
    // comma-separated (%2C); a path that doesn't exist must come back as a warning, not vanish
    const paths = [wire(micro), wire('/work/fixture/it\'s "odd".php'), encodeURIComponent(latin1), wire('/work/fixture/missing.php')].join('%2C');
    const proc = json(curl(['--data', 'ajax_action=process', '--data', 'paths=' + paths]));
    const feats = proc && proc.features || [];
    const procOk = feats.length === 3 && feats[0].md5 === microMd5 &&
        feats[1].matched_tokens.includes('@concat_name') && feats[2].path === latin1 &&
        proc.warnings.some(w => w.indexOf('Skipped /work/fixture/missing.php') === 0);
    const fixtureOk = !!fixtureScan && fixtureScan.total === LISTING_WANT.length;
    const csrfOk = !!noHeader && noHeader.error === 'forbidden';
    return {
        ok: jsOk && !!scan && scan.total > 0 && fixtureOk && procOk && csrfOk,
        text: `page ${jsOk ? 'OK' : 'BROKEN'}, scan ${scan ? scan.total + ' files' : 'FAIL'}, fixture scan ${fixtureOk ? 'OK' : 'FAIL'}, ` +
            `process ${procOk ? 'OK' : 'FAIL'}, CSRF check ${csrfOk ? 'OK' : 'FAIL'}` + (proc ? ` (${proc.warnings.length} warnings)` : ''),
    };
}

/** All steps for one PHP; returns its result record (ok === false fails the run) */
module.exports = { webCheck };
