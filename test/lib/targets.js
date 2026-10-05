// Where a benchmark runs: the local php, or Docker containers with the
// official php:<version>-apache images (or PHTest's legacy builds), each under
// a php.ini profile. A target knows the paths its PHP sees: repo (main.php and
// the samples), work (the run's temp dir) and state (extraction state).
//
// Containers mount the repository READ-ONLY, so a blacklist hit can never
// delete sample files, and are removed when the command ends.
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { ROOT, PHTEST, MAX_BUFFER } = require('./paths');
const { execAsync } = require('./php');
const { atExit } = require('./cleanup');
const { sleep } = require('./util');

// The versions `test/run matrix` runs by default: every official image this tests on
const DEFAULT_VERSIONS = '5.6,7.0,7.1,7.2,7.3,7.4,8.0,8.1,8.2,8.3,8.4,8.5';

function localTarget(work) {
    const state = path.join(work, 'state');
    fs.mkdirSync(state, { recursive: true });
    const php = file => execAsync('php', ['-d', 'error_log=' + path.join(work, 'php-errors.log'), file]); // not ./error_log in the repo
    return {
        name: 'local', supported: true, repo: ROOT, work, hostWork: work, state,
        php, read: file => { try { return fs.readFileSync(path.join(state, file), 'utf8'); } catch (e) { return ''; } },
    };
}

// php.ini environments for the containers, layered over each version's own php.ini (conf.d):
// how the scanner copes with typical shared hosting, and with functions missing
// that its compatibility layer has to provide itself.
const PROFILES = {
    default: { about: "the image's own php.ini", ini: '' },
    hardened: {
        about: 'shared-hosting style: no exec family, no cURL, no remote fopen',
        ini: 'disable_functions = exec,shell_exec,system,passthru,proc_open,popen,pcntl_exec,curl_init,curl_exec,curl_multi_exec,fsockopen,pfsockopen\nallow_url_fopen = Off\n',
    },
    minimal: {
        about: 'json_encode and cURL missing (as on PHP < 5.2 or a stripped build)',
        ini: 'disable_functions = json_encode,curl_init,curl_exec,curl_setopt,curl_error\n',
    },
};

function dockerTargets(spec, profileSpec, work) {
    const known = fs.readFileSync(path.join(PHTEST, 'versions.list'), 'utf8').split('\n')
        .filter(l => l.trim() && !l.startsWith('#')).map(l => { const [v, type] = l.split('|'); return { v, type }; });
    const want = spec === 'all' ? known : spec.split(',').map(v => known.find(k => k.v === v) || { v, type: 'official' });
    const profiles = (profileSpec || 'default').split(',');
    const unknown = profiles.filter(p => !PROFILES[p]);
    if (unknown.length) throw new Error(`unknown profile ${unknown.join(', ')} (have: ${Object.keys(PROFILES).join(', ')})`);
    const supported = v => { const [a, b] = v.split('.').map(Number); return a > 4 || (a === 4 && b >= 3); };
    const targets = [];
    for (const { v, type } of want) for (const profile of profiles) {
        const legacy = type === 'legacy';
        if (profile !== 'default' && legacy) continue; // profiles go into the official images' conf.d
        const container = `sf-test-${v}-${profile}`;
        const exec = (cmd, opts = {}) => execAsync('docker', ['exec', container].concat(cmd), Object.assign({ stdio: ['ignore', 'pipe', 'ignore'] }, opts));
        targets.push({
            name: `PHP ${v}` + (profile === 'default' ? '' : ` (${profile})`), v, profile, legacy, supported: supported(v), container, port: 18100 + targets.length,
            repo: '/var/www/html', work: '/work', state: '/tmp', hostWork: work,
            php: file => exec((legacy ? ['php-cgi', '-q'] : ['php']).concat(file)),
            read: file => { try { return execFileSync('docker', ['exec', container, 'cat', '/tmp/' + file], { maxBuffer: MAX_BUFFER, stdio: ['ignore', 'pipe', 'ignore'] }).toString(); } catch (e) { return ''; } },
        });
    }
    return targets;
}

/** Start t's container; resolves to null, or the reason it failed */
async function startContainer(t) {
    const work = t.hostWork;
    const image = t.legacy ? 'phtest-php:' + t.v : `php:${t.v}-apache`;
    const mounts = ['-v', ROOT + ':/var/www/html:ro', '-v', work + ':/work:ro'];
    const conf = path.join(PHTEST, 'conf', t.v, 'php.ini');
    if (fs.existsSync(conf)) mounts.push('-v', conf + ':' + (t.legacy ? '/usr/local/lib/php.ini' : '/usr/local/etc/php/php.ini') + ':ro');
    if (!t.legacy) {
        const profileIni = path.join(work, `profile-${t.profile}.ini`);
        fs.writeFileSync(profileIni, `; test/run matrix profile "${t.profile}": ${PROFILES[t.profile].about}\n` + PROFILES[t.profile].ini);
        mounts.push('-v', profileIni + ':/usr/local/etc/php/conf.d/zz-sussy-profile.ini:ro');
    }
    try {
        execFileSync('docker', ['rm', '-f', t.container], { stdio: 'ignore' });
        execFileSync('docker', ['run', '-d', '--rm', '--name', t.container, '-p', t.port + ':80'].concat(mounts, [image]), { stdio: 'ignore' });
        atExit(() => { try { execFileSync('docker', ['rm', '-f', t.container], { stdio: 'ignore' }); } catch (e) { } });
    } catch (e) {
        return `container failed to start (image ${image} built or pulled?)`;
    }
    for (let i = 0; i < 40; i++) {
        try { execFileSync('curl', ['-s', '-o', '/dev/null', `http://127.0.0.1:${t.port}/`]); break; } catch (e) { await sleep(250); }
    }
    return null;
}

module.exports = { DEFAULT_VERSIONS, PROFILES, localTarget, dockerTargets, startContainer };
