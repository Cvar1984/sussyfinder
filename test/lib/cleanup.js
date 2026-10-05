// Temporary directories and other things to undo when a command ends,
// normally or on Ctrl+C. test/run awaits run() before exiting.
const fs = require('fs');
const os = require('os');
const path = require('path');

const tasks = [];

/** Register fn (may be async) to run when the command ends, newest first */
const atExit = fn => { tasks.unshift(fn); };

/** A fresh temp directory, removed when the command ends */
function tempDir(prefix) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sussy-' + prefix + '-'));
    atExit(() => {
        try {
            // A browser's helper processes can still hold files for a moment
            fs.rmSync(dir, { recursive: true, force: true, maxRetries: 20, retryDelay: 250 });
        } catch (e) {
            console.log(`warning: could not remove ${dir}: ${e.message}`);
        }
    });
    return dir;
}

async function run() {
    while (tasks.length) {
        try { await tasks.shift()(); } catch (e) { console.error('cleanup: ' + e.message); }
    }
}

module.exports = { atExit, tempDir, run };
