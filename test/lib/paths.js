// Where everything is. Every other module takes its paths from here.
const path = require('path');

const ROOT = path.join(__dirname, '..', '..');
const TEST = path.join(ROOT, 'test');

module.exports = {
    ROOT,
    TEST,
    MAIN: path.join(ROOT, 'main.php'),               // the scanner under test
    MODEL: path.join(ROOT, 'ml-model.json'),         // the shipped ML weights
    PHP_JOBS: path.join(TEST, 'php'),                // PHP-side jobs (extract.php, selfcheck.php)
    CORPORA: path.join(TEST, 'corpora'),             // sample submodules: positive/ (webshells), noise/ (legit code)
    ROW_CACHE: path.join(TEST, 'corpora', '.rows'),  // extracted features, one file per corpus commit
    PHTEST: path.join(TEST, 'PHTest'),               // Docker images for every PHP version (submodule)
    MAX_BUFFER: 1 << 28,
};
