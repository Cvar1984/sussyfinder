// Small helpers: hashing, grouping, rates.
const crypto = require('crypto');

const sha1 = s => crypto.createHash('sha1').update(s).digest('hex');

const groupBy = (list, key) => {
    const m = new Map();
    for (const x of list) { const k = key(x); if (!m.has(k)) m.set(k, []); m.get(k).push(x); }
    return m;
};

const pct = (a, b) => (100 * a / Math.max(1, b)).toFixed(1) + '%';

/** True/false positives of predicate `hit` over shells `mal` and benign `ben` */
const rates = (mal, ben, hit) => ({ tp: mal.filter(hit).length, fp: ben.filter(hit).length, nMal: mal.length, nBen: ben.length });

const sleep = ms => new Promise(r => setTimeout(r, ms));

module.exports = { sha1, groupBy, pct, rates, sleep };
