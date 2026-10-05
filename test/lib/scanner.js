// main.php as the tests see it: its detection policy (from the local php),
// its client-side scoring block run in a vm, its PHP constants, the shipped
// model, and the slice of PHP that shapes a feature row (for cache keys).
const { execFileSync } = require('child_process');
const fs = require('fs');
const vm = require('vm');
const { MAIN, MODEL } = require('./paths');
const { phpString } = require('./php');

const SCORING_START = '// --- Client-side threat scoring';
const SCORING_END = '// --- End client-side threat scoring ---';
const LIB_END = '// The test scripts include this file'; // end of the PHP the tests include

const source = () => fs.readFileSync(MAIN, 'utf8');

/** A slice of main.php between two markers; throws if they moved */
function between(src, start, end) {
    const a = src.indexOf(start), b = src.indexOf(end, a);
    if (a < 0 || b < 0) throw new Error(`main.php markers not found: "${start}" .. "${end}"`);
    return src.slice(a, b);
}

/** A numeric define() from main.php, e.g. ML_BUCKETS */
function phpConstant(name) {
    const m = source().match(new RegExp(`define\\('${name}', (\\d+)\\)`));
    if (!m) throw new Error(`main.php has no define('${name}', <number>)`);
    return parseInt(m[1], 10);
}

/** The detection policy from the local php: { weights: $tokenNeedles, roles: $tokenRoles } */
let policy = null;
function tokenPolicy() {
    if (!policy) {
        const php = `define('SUSSY_LIB', true); include ${phpString(MAIN)}; echo jsonEncode(array('weights' => $tokenNeedles, 'roles' => $tokenRoles));`;
        policy = JSON.parse(execFileSync('php', ['-r', php]).toString());
    }
    return policy;
}

/**
 * main.php's scoring block (calculateThreatScore, analyzeData, mlScore, ...),
 * run as-is in a vm context with the page's globals. `weights` and `roles`
 * default to the local php's policy; `model` null scores rules only.
 */
function loadScoring({ weights, roles, model = null } = {}) {
    const ctx = vm.createContext({ tokenWeights: weights || tokenPolicy().weights, tokenRoles: roles || tokenPolicy().roles, ML_MODEL: model });
    vm.runInContext(between(source(), SCORING_START, SCORING_END), ctx);
    return ctx;
}

/** A top-level const of the scoring block, e.g. Z_THRESHOLD, ML_THRESHOLD */
const constant = (ctx, name) => vm.runInContext(name, ctx);

const readModel = () => JSON.parse(fs.readFileSync(MODEL, 'utf8'));

/** Everything in main.php that shapes an extracted row (for cache keys) */
const extractorSource = () => between(source(), '<?php', LIB_END);

module.exports = { phpConstant, tokenPolicy, loadScoring, constant, readModel, extractorSource };
