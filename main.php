<?php

/**
 * Written by Cvar1984 <Cvar1984@pm.me>, November 2022
 * Copyright (C) 2022 Cvar1984
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * SussyFinder is this one file and runs on PHP 4.3 to 8.5. Its parts, in order:
 *
 *   1. Configuration     every setting and the detection policy (file pattern, needles)
 *   2. Compatibility     what differs between PHP versions and hosts, normalised once
 *   3. Utilities         small helpers used throughout
 *   4. Detection engine  file listing, tokens, signals, ML features, feature rows
 *   5. Network           one HTTP client; hash lists, ML model, Malware Hash Registry
 *   6. Actions           the AJAX endpoints
 *   7. Bootstrap         runs only when the file is served, not when included as a library
 *   8. Page              HTML, CSS and the JS app
 *
 * The test scripts (test/) include it with define('SUSSY_LIB', true) to use
 * parts 1-6 without serving anything.
 */

// =============================================================================
// 1. Configuration
// =============================================================================

/**
 * Define a setting unless it is already defined. Every setting below can be
 * overridden without editing this file: define it before this file runs, from
 * a script that includes it or from php.ini's auto_prepend_file.
 *
 * @param string $name
 * @param mixed $value
 * @return void
 */
function settingDefault($name, $value)
{
    if (!defined($name)) {
        define($name, $value);
    }
}

settingDefault('_WHITELIST_', true);    // skip files whose MD5 is on the known-good list
settingDefault('_BLACKLIST_', true);    // delete files whose MD5 is on the known-bad list
settingDefault('_MHR_', true);          // Team Cymru Malware Hash Registry lookups
settingDefault('_ML_', true);           // ML second opinion; false skips its feature extraction (~40% less analysis time)
settingDefault('_MHR_USER_', '');       // MHR account; the page can also send one
settingDefault('_MHR_PASS_', '');

// Where the lists and the ML weights come from (http(s) URLs; the model may also be a local file)
settingDefault('_REPO_RAW_', 'https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/');
settingDefault('_WHITELIST_URL_', _REPO_RAW_ . 'whitelist.txt');
settingDefault('_BLACKLIST_URL_', _REPO_RAW_ . 'blacklist.txt');
settingDefault('_ML_MODEL_URL_', _REPO_RAW_ . 'ml-model.json');
settingDefault('_MHR_URL_', 'https://hash.cymru.com/v2/submitHashes');

settingDefault('TIME_LIMIT', 3600);          // seconds a request may run
settingDefault('HTTP_CONNECT_TIMEOUT', 10);  // seconds
settingDefault('HTTP_TIMEOUT', 30);          // seconds
settingDefault('MHR_BATCH', 1000);           // hashes per MHR request (the API's limit)
settingDefault('LIST_CACHE_SECONDS', 900);   // a scan's requests share the downloaded hash lists this long (0: download each time)
settingDefault('LONG_LINE_BYTES', 5000);     // a longer line is @long_line
settingDefault('HALT_PAYLOAD_BYTES', 1024);  // more data after __halt_compiler() is @halt_payload

// Hashed feature space for the ML model (a power of two; the model's weight count must match)
define('ML_BUCKETS', 2048);
// Bump whenever mlFeatures() changes what it emits: a model trained on other
// features is refused (ml-model.json carries the version it was trained on)
define('ML_FEATURE_VERSION', 2);

// Which files to scan, matched against the file name: a PHP-ish or SSI last
// extension, "php" as an inner extension ("x.php.jpg" and "x.php." run as PHP
// under Apache's AddHandler), .htaccess, and the per-directory PHP config files
$pattern = '/\.(ph[^.]+|sh[^.]+|inc|htaccess)$|\.(php[0-9]*|phtml|pht|phar)\.|^(\.user|php[0-9]*)\.ini$/i';

// Needles: code tokens (and "@" structural signals, see findStructuralSignals())
// by threat weight. The page's scoring adds these up; $tokenRoles says how
// they combine.
$tokenTiers = array(
    // Critical RCE
    '10.0' => array('eval', 'exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'create_function', 'pcntl_fork',
        'posix_kill', 'posix_setuid',
        '`',             // backtick operator = shell_exec
        '@input_call',   // $_GET['a']($_GET['b'])
        '@preg_e',       // preg_replace('/.../e') evaluates the replacement
        '@foreign_code', // ASP/JSP/CGI code in a PHP-named file
    ),
    // High obfuscation and de-encoding
    '5.0' => array('base64_decode', 'gzinflate', 'str_rot13', 'gzuncompress', 'convert_uu', 'rawurldecode', 'urldecode',
        'hex2bin', 'bin2hex', 'exif_read_data', 'readgzfile', '$SISTEMIT_COM_ENC',
        '@concat_name',  // function name hidden in a string: 'ba'.'se64_decode', "\x73ystem"
        '@halt_payload', // data appended after __halt_compiler()
    ),
    // Obfuscation helpers and I/O manipulation
    '2.0' => array('assert', 'htmlspecialchars_decode', 'hexdec', 'chr', 'strrev', 'goto', 'extract', 'parse_str', 'popen',
        'fsockopen', 'posix_setsid', 'posix_setpgid', 'proc_nice', 'proc_close', 'proc_terminate', 'apache_child_terminate',
        'move_uploaded_file', '$_files', '$auth_pass', '$password', '$pass', 'proc_get_status', 'posix_mkfifo', 'php_uname',
        '@dyn_call',     // call through a variable/expression: $f(), $a['x'](), (...)()
        '@long_line',    // a line over LONG_LINE_BYTES
    ),
    // User input: everywhere in legit code, only matters in combination
    '0.5' => array('$_get', '$_post', '$_request', '$_cookie', 'getallheaders'),
    // Low / routine
    '0.1' => array('preg_replace', // the dangerous /e form is scored as @preg_e
        'call_user_func', 'call_user_func_array', 'register_shutdown_function', 'register_tick_function', 'implode', 'strtr',
        'substr', 'mb_substr', 'str_replace', 'substr_replace', 'basename', 'getcwd', 'pathinfo', 'getenv', 'get_current_user',
        'fileowner', 'filegroup', 'disk_free_space', 'disk_total_space', 'sys_get_temp_dir', 'fopen', 'file_put_contents',
        'file_get_contents', 'url_get_contents', 'stream_get_meta_data', 'copy', 'include', 'require', 'include_once',
        'require_once', '__file__', 'mail', 'putenv', 'curl_init', 'tmpfile', 'allow_url_fopen', 'ini_set', 'set_time_limit',
        'session_start', 'symlink', '__halt_compiler', '__compiler_halt_offset__', 'error_reporting', 'get_magic_quotes_gpc',
        'phpinfo', 'posix_getuid', 'posix_geteuid', 'posix_getegid', 'posix_getpwuid', 'posix_getgrgid', 'posix_getlogin',
        'posix_ttyname', 'get_cfg_var', 'diskfreespace', 'getlastmod', 'getmyinode', 'getmypid', 'getmyuid', 'getmygid',
        'mysql_connect', 'mysqli_connect', 'mysql_query', 'mysqli_query'),
);

// needle => weight, the form the engine and the page use
$tokenNeedles = array();
foreach ($tokenTiers as $weight => $needles) {
    foreach ($needles as $needle) {
        $tokenNeedles[$needle] = (float) $weight;
    }
}

// How needles combine in the page's threat score (calculateThreatScore()):
// critical + obfuscation, upload or input multiplies the score; obfuscation
// and upload alone are dampened; two or more recon calls add a bonus.
// "highlight" is only display: the needles shown in red in the results.
$tokenRoles = array(
    'critical'    => array('eval', 'exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'create_function', '`',
        '@input_call', '@preg_e', '@foreign_code'),
    'obfuscation' => $tokenTiers['5.0'],
    'upload'      => array('move_uploaded_file', '$_files', 'file_put_contents'),
    'input'       => $tokenTiers['0.5'],
    // Server reconnaissance: a webshell's header shows the box it landed on
    'recon'       => array('php_uname', 'phpinfo', 'get_cfg_var', 'get_current_user', 'getmyuid', 'getmygid', 'getmypid',
        'getmyinode', 'posix_getuid', 'posix_geteuid', 'posix_getegid', 'posix_getlogin', 'disk_total_space',
        'disk_free_space', 'diskfreespace', 'getlastmod'),
    'highlight'   => array('eval', 'exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'assert', 'create_function',
        '`', '@input_call', '@preg_e', '@concat_name', '@halt_payload', 'base64_decode', 'str_rot13', 'bin2hex',
        'hex2bin', 'gzinflate', 'gzuncompress', '$_files', '$auth_pass', '$password', '$pass', '$SISTEMIT_COM_ENC'),
);

// =============================================================================
// 2. Compatibility
// =============================================================================
// Everything that differs between PHP 4.3 and 8.5, or between hosts, is
// settled here once, so the code below can assume one environment.

$GLOBALS['phpWarnings'] = array();

/**
 * Collect warnings instead of printing them: they reach the page or the AJAX
 * response as a list, and unlinkWithReason() reads a failure's own message
 * from it (PHP 4 has no error_get_last()).
 *
 * @return bool
 */
function errorHandler($errno, $errstr, $errfile, $errline)
{
    if (!(error_reporting() & $errno)) {
        return false; // respect @ suppression
    }
    error_log($errstr . ' in ' . $errfile . ' on line ' . $errline);
    $GLOBALS['phpWarnings'][] = $errstr;
    return true;
}
set_error_handler('errorHandler');
error_reporting(E_ALL);

/**
 * Whether a function can be called: it exists and the host hasn't listed it
 * in disable_functions (on PHP < 8 a disabled function still "exists").
 *
 * @param string $name
 * @return bool
 */
function functionAvailable($name)
{
    static $disabled = null;
    if ($disabled === null) {
        $disabled = array();
        foreach (explode(',', (string) ini_get('disable_functions')) as $function) {
            $function = strtolower(trim($function));
            if ($function !== '') {
                $disabled[$function] = true;
            }
        }
    }
    return function_exists($name) && !isset($disabled[strtolower($name)]);
}

/**
 * Call a function only when the host allows it (set_time_limit, ini_set and
 * the like are often disabled). Extra arguments are passed on.
 *
 * @param string $name
 * @return mixed false when the function isn't available
 */
function callIfAvailable($name)
{
    if (!functionAvailable($name)) {
        return false;
    }
    $args = func_get_args();
    return call_user_func_array($name, array_slice($args, 1));
}

callIfAvailable('ini_set', 'display_errors', '0');
// PHP < 5.4 can add slashes to every file read (magic_quotes_runtime)
if (function_exists('get_magic_quotes_runtime') && @get_magic_quotes_runtime()) {
    @set_magic_quotes_runtime(0);
}

// Token ids this PHP doesn't have become distinct negative numbers, which
// token_get_all() never returns, so the token code needs no version checks.
// (0 means a single-character token in this file.)
$compatTokenId = -1;
foreach (array('T_DOC_COMMENT', 'T_ML_COMMENT', 'T_NULLSAFE_OBJECT_OPERATOR', 'T_NS_SEPARATOR', 'T_NAMESPACE',
    'T_NAME_QUALIFIED', 'T_NAME_FULLY_QUALIFIED', 'T_NAME_RELATIVE', 'T_ATTRIBUTE', 'T_MATCH', 'T_ENUM', 'T_READONLY',
    'T_AMPERSAND_FOLLOWED_BY_VAR_OR_VARARG', 'T_AMPERSAND_NOT_FOLLOWED_BY_VAR_OR_VARARG') as $compatToken) {
    if (!defined($compatToken)) {
        define($compatToken, $compatTokenId--);
    }
}
unset($compatTokenId, $compatToken);

/**
 * JSON for PHP < 5.2, or a host that disabled json_encode: null, bools,
 * numbers, strings and (nested) arrays. Lists become [...], other arrays
 * {...}. "/" is escaped like the native one so "</script>" can't end an
 * inline <script> early. Never named json_encode: PHP 5/7 can't redefine a
 * disabled built-in.
 *
 * @param mixed $value
 * @return string
 */
function jsonEncodeFallback($value)
{
    static $escape = null;
    if ($escape === null) {
        $escape = array('"' => '\\"', '\\' => '\\\\', '/' => '\\/');
        for ($i = 0; $i < 0x20; $i++) {
            $escape[chr($i)] = sprintf('\\u%04x', $i);
        }
    }
    if (is_null($value)) {
        return 'null';
    }
    if (is_bool($value)) {
        return $value ? 'true' : 'false';
    }
    if (is_int($value) || is_float($value)) {
        return str_replace(',', '.', (string) $value); // locales with a decimal comma
    }
    if (!is_array($value)) {
        return '"' . strtr((string) $value, $escape) . '"';
    }
    $isList = true;
    $expected = 0;
    foreach ($value as $key => $item) {
        if ($key !== $expected++) {
            $isList = false;
            break;
        }
    }
    $parts = array();
    foreach ($value as $key => $item) {
        $parts[] = $isList ? jsonEncodeFallback($item) : jsonEncodeFallback((string) $key) . ':' . jsonEncodeFallback($item);
    }
    return $isList ? '[' . implode(',', $parts) . ']' : '{' . implode(',', $parts) . '}';
}

/**
 * The one way this file writes JSON (AJAX responses, page data). Strings are
 * made valid UTF-8 first, since json_encode() fails on invalid bytes (false
 * on 5.5+, a warning and null before).
 *
 * @param mixed $value
 * @return string
 */
function jsonEncode($value)
{
    $value = utf8Safe($value);
    if (functionAvailable('json_encode')) {
        $json = json_encode($value);
        if (is_string($json)) {
            return $json;
        }
    }
    return jsonEncodeFallback($value);
}

/**
 * Undo magic_quotes_gpc (PHP < 5.4 escapes quotes, backslashes and NUL in
 * request values) so every value arrives exactly as sent.
 *
 * @param mixed $value
 * @return mixed
 */
function stripRequestSlashes($value)
{
    if (is_array($value)) {
        foreach ($value as $key => $item) {
            $value[$key] = stripRequestSlashes($item);
        }
        return $value;
    }
    return is_string($value) ? stripslashes($value) : $value;
}

// =============================================================================
// 3. Utilities
// =============================================================================

/**
 * Make every string in $value valid UTF-8 for JSON. Invalid strings are read
 * as Latin-1. Only for text shown to the user: paths travel rawurlencode()d,
 * so they survive byte for byte.
 *
 * @param mixed $value
 * @return mixed
 */
function utf8Safe($value)
{
    if (is_array($value)) {
        foreach ($value as $key => $item) {
            $value[$key] = utf8Safe($item);
        }
        return $value;
    }
    if (!is_string($value) || preg_match('//u', $value)) {
        return $value;
    }
    $out = '';
    $len = strlen($value);
    for ($i = 0; $i < $len; $i++) {
        $byte = ord($value[$i]);
        $out .= $byte < 0x80 ? $value[$i] : chr(0xC0 | ($byte >> 6)) . chr(0x80 | ($byte & 0x3F));
    }
    return $out;
}

/**
 * Length of the longest line, without splitting the content into an array.
 *
 * @param string $content
 * @return int
 */
function maxLineLength($content)
{
    $max = 0;
    $start = 0;
    $length = strlen($content);
    while ($start <= $length) {
        $end = strpos($content, "\n", $start);
        if ($end === false) {
            $end = $length;
        }
        if ($end - $start > $max) {
            $max = $end - $start;
        }
        $start = $end + 1;
    }
    return $max;
}

/**
 * Shannon entropy in bits per byte (0 = one repeated byte, 8 = random)
 *
 * @param string $data
 * @return float
 */
function shannonEntropy($data)
{
    $len = strlen($data);
    $entropy = 0.0;
    if ($len == 0) {
        return $entropy;
    }
    foreach (count_chars($data, 1) as $count) {
        $p = $count / $len;
        $entropy -= $p * log($p) / log(2);
    }
    return $entropy;
}

/**
 * Delete a file and return the specific failure reason (e.g. "unlink(...):
 * Permission denied") instead of a generic one. The captured warning is
 * consumed, so it surfaces once, attached to the file, rather than also in
 * the general warnings list.
 *
 * @param string $filePath
 * @return string|null null on success, the reason on failure
 */
function unlinkWithReason($filePath)
{
    $before = count($GLOBALS['phpWarnings']);
    if (unlink($filePath)) {
        return null;
    }
    if (count($GLOBALS['phpWarnings']) > $before) {
        $captured = array_splice($GLOBALS['phpWarnings'], $before);
        return end($captured);
    }
    return 'Failed to unlink';
}

/**
 * An error response for the page: a short code and a message to show.
 *
 * @param string $code
 * @param string $msg
 * @return array
 */
function ajaxError($code, $msg)
{
    return array('error' => $code, 'msg' => $msg);
}

/**
 * A request value as a string, or $default when it's missing.
 *
 * @param string $key
 * @param mixed $default
 * @return mixed
 */
function inputValue($key, $default = null)
{
    return (isset($_POST[$key]) && is_string($_POST[$key])) ? $_POST[$key] : $default;
}

/**
 * A request value holding a comma-separated list. One field (unlike
 * x[]=...) stays clear of max_input_vars however many entries it holds.
 * Entries that may contain commas (paths) travel rawurlencode()d. (NUL was
 * used before, but hardened hosts drop request values containing NUL, e.g.
 * Suhosin's default disallow_nul.)
 *
 * @param string $key
 * @return array
 */
function postList($key)
{
    $value = inputValue($key, '');
    return $value === '' ? array() : explode(',', $value);
}

/**
 * A list of paths sent rawurlencode()d, decoded.
 *
 * @param string $key
 * @return array
 */
function postPathList($key)
{
    return array_map('rawurldecode', postList($key));
}

// =============================================================================
// 4. Detection engine
// =============================================================================

/**
 * Collect the files under $directory whose name matches $pattern into
 * $entries. Each directory is read fully and closed before recursing, so depth
 * isn't capped by open file handles. Symlinked directories are followed only
 * when they resolve inside $root (a "root -> /" link would otherwise walk the
 * whole filesystem); symlinked files are listed like regular files. FIFOs,
 * sockets and devices are skipped: opening a FIFO blocks forever. Anything
 * that can't be scanned is reported as a warning rather than skipped silently.
 *
 * @param string $directory
 * @param string $pattern regex matched against each file's name
 * @param string $root realpath of the scanned directory, "/"-separated
 * @param array $entries 'file_readable' / 'file_not_readable' lists, filled in place
 * @param array $visited realpath => true, filled in place
 * @return void
 */
function recursiveScan($directory, $pattern, $root, &$entries, &$visited)
{
    $realPath = realpath($directory);
    if (!$realPath || isset($visited[$realPath])) {
        return; // symlink loop or already scanned
    }
    $visited[$realPath] = true;

    $handle = @opendir($realPath);
    if (!$handle) {
        trigger_error('Cannot list directory ' . $realPath . ' (files inside it are not scanned)', E_USER_WARNING);
        return;
    }
    $names = array();
    while (($name = readdir($handle)) !== false) {
        if ($name !== '.' && $name !== '..') {
            $names[] = $name;
        }
    }
    closedir($handle);

    foreach ($names as $name) {
        $entryPath = str_replace(DIRECTORY_SEPARATOR, '/', $realPath . '/' . $name);
        if (is_dir($entryPath)) {
            if (is_link($entryPath)) {
                $target = str_replace(DIRECTORY_SEPARATOR, '/', realpath($entryPath));
                if (strpos($target . '/', rtrim($root, '/') . '/') !== 0) {
                    trigger_error('Not following symlink ' . $entryPath . ' -> ' . $target . ' (outside the scanned directory)', E_USER_WARNING);
                    continue;
                }
            }
            recursiveScan($entryPath, $pattern, $root, $entries, $visited);
        } elseif (!preg_match($pattern, $name) || !is_file($entryPath)) {
            continue;
        } elseif (is_readable($entryPath)) {
            $entries['file_readable'][] = $entryPath;
        } else {
            $entries['file_not_readable'][] = $entryPath;
        }
    }
}

/**
 * List the files under $path whose name matches $pattern, readable ones
 * newest first.
 *
 * @param string $path directory to scan
 * @param string $pattern complete regex, matched against each file's name
 * @return array 'file_readable' and 'file_not_readable' path lists
 */
function getSortedByPattern($path, $pattern)
{
    $entries = array('file_readable' => array(), 'file_not_readable' => array());
    $root = realpath($path);
    if ($root === false || !is_dir($root)) {
        trigger_error('Not a directory: ' . $path, E_USER_WARNING);
        return $entries;
    }
    if (@preg_match($pattern, '') === false) {
        trigger_error('Invalid file name pattern: ' . $pattern, E_USER_WARNING);
        return $entries;
    }
    $visited = array();
    recursiveScan($root, $pattern, str_replace(DIRECTORY_SEPARATOR, '/', $root), $entries, $visited);
    @array_multisort(array_map('filemtime', $entries['file_readable']), SORT_DESC, $entries['file_readable']);
    return $entries;
}

/**
 * Tokenize PHP source, normalising short open tags first. Inside "...",
 * `...` and heredocs only variables and {$...} expressions are kept: the rest
 * is literal text, which PHP 4/5.0 (and array keys in "$a[key]" on any
 * version) hand out as T_STRING tokens that would otherwise read as code.
 * PHP 8's new tokens are turned back into PHP 7's, so 7.x and 8.x see the
 * same tokens: namespaced names are split (T_NS_SEPARATOR, T_STRING, ...),
 * "&" is one character again, match/enum/readonly are T_STRING, and
 * #[attributes] are left out (comments to PHP 7, metadata to PHP 8).
 *
 * @param string $fileContent
 * @return array token_get_all() output minus literal string text
 */
function getFileTokens($fileContent)
{
    $fileContent = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $fileContent);
    // Short open tags ("<?if(...)", "<? echo") become "<?php " and "<?xml" stops
    // being one, so detection doesn't depend on this host's short_open_tag
    $fileContent = preg_replace(array('/<\?(?!php|=|xml)/i', '/<\?(xml)/i'), array('<?php ', '< ?$1'), $fileContent);
    $tokens = @token_get_all($fileContent);

    $output = array();
    $quote = null;      // closing '"' or '`', or T_END_HEREDOC, while inside a string
    $depth = 0;         // brace depth inside a {$...} expression
    $attribute = 0;     // bracket depth inside a #[...] attribute
    $ampersand = array(T_AMPERSAND_FOLLOWED_BY_VAR_OR_VARARG => true, T_AMPERSAND_NOT_FOLLOWED_BY_VAR_OR_VARARG => true);
    $keyword = array(T_MATCH => true, T_ENUM => true, T_READONLY => true);
    foreach ($tokens as $token) {
        $id = is_array($token) ? $token[0] : 0;
        $text = is_array($token) ? $token[1] : $token;
        if ($attribute > 0 || $id == T_ATTRIBUTE) {
            if ($text == '[' || $id == T_ATTRIBUTE) {
                $attribute++;
            } elseif ($text == ']') {
                $attribute--;
            }
            continue;
        }
        if (isset($ampersand[$id])) {
            $id = 0;
            $token = $text;
        } elseif (isset($keyword[$id])) {
            $token = array(T_STRING, $text);
        }
        if ($depth > 0) {
            if ($text == '{') {
                $depth++;
            } elseif ($text == '}') {
                $depth--;
            }
        } elseif ($quote !== null) {
            if ($id == T_CURLY_OPEN || $id == T_DOLLAR_OPEN_CURLY_BRACES) {
                $depth = 1;
            } elseif (($id == 0 && $text === $quote) || ($id != 0 && $id === $quote)) {
                $quote = null;
            } elseif ($id != T_VARIABLE) {
                continue;
            }
        } elseif ($id == T_START_HEREDOC) {
            $quote = T_END_HEREDOC;
        } elseif ($id == 0 && ($text == '"' || $text == '`')) {
            $quote = $text;
        }
        if ($id == T_NAME_QUALIFIED || $id == T_NAME_FULLY_QUALIFIED || $id == T_NAME_RELATIVE) {
            foreach (splitName($text) as $part) {
                $output[] = $part;
            }
            continue;
        }
        $output[] = $token;
    }
    return $output;
}

/**
 * PHP 8's single token for a namespaced name ("\foo\bar", "foo\bar",
 * "namespace\foo") as the tokens PHP 7 gives for it.
 *
 * @param string $name
 * @return array
 */
function splitName($name)
{
    $tokens = array();
    $parts = explode('\\', $name);
    foreach ($parts as $i => $part) {
        if ($i > 0) {
            $tokens[] = array(T_NS_SEPARATOR, '\\');
        }
        if ($part !== '') {
            $tokens[] = array(($i == 0 && strtolower($part) == 'namespace') ? T_NAMESPACE : T_STRING, $part);
        }
    }
    return $tokens;
}

/**
 * Token ids that carry no code: whitespace and comments.
 *
 * @return array id => true
 */
function insignificantTokenIds()
{
    return array(T_WHITESPACE => true, T_COMMENT => true, T_DOC_COMMENT => true, T_ML_COMMENT => true);
}

/**
 * Tokens that make a following T_STRING a member or declaration name
 * (->exec(), ::system(), function eval()), not a call to a global function.
 *
 * @return array id => true
 */
function memberTokenIds()
{
    return array(T_OBJECT_OPERATOR => true, T_NULLSAFE_OBJECT_OPERATOR => true, T_PAAMAYIM_NEKUDOTAYIM => true, T_FUNCTION => true);
}

/**
 * One pass over a file's tokens for everything that reads them: the tokens
 * that carry code, as array(id, text) pairs (a single-character token gets
 * id 0), and where __halt_compiler() ends the code.
 *
 * @param array $tokens getFileTokens() output
 * @return array 'sig' => code tokens; 'code' => how many of them come up to
 *               and including __halt_compiler (all when there is none);
 *               'haltBytes' => bytes after it (-1 when there is none)
 */
function codeTokens($tokens)
{
    $skip = insignificantTokenIds();
    $sig = array();
    $code = -1;
    $haltBytes = -1;
    foreach ($tokens as $token) {
        if (!is_array($token)) {
            $token = array(0, $token);
        }
        if ($haltBytes >= 0) {
            $haltBytes += strlen($token[1]);
        } elseif (strlen($token[1]) == 15 && strtolower($token[1]) == '__halt_compiler') {
            $haltBytes = 0;
            $code = count($sig) + 1;
        }
        if (!isset($skip[$token[0]])) {
            $sig[] = $token;
        }
    }
    return array('sig' => $sig, 'code' => $code < 0 ? count($sig) : $code, 'haltBytes' => $haltBytes);
}

/**
 * Lowercased, trimmed, de-duplicated code token texts as a lookup set.
 * String/HTML/comment content is left out ("...`{$t}`..." would otherwise
 * yield a lone "`"), as are member and declaration names (->exec(),
 * ::system(), function eval()), since those aren't the global functions.
 *
 * @param array $sig codeTokens() 'sig'
 * @return array text => true
 */
function tokenTextSet($sig)
{
    $content = array(T_ENCAPSED_AND_WHITESPACE => true, T_INLINE_HTML => true);
    $member = memberTokenIds();
    $set = array();
    $prev = 0;
    foreach ($sig as $token) {
        if (!isset($content[$token[0]]) && !($token[0] == T_STRING && isset($member[$prev]))) {
            $set[ltrim(strtolower(trim($token[1])), '\\')] = true;
        }
        $prev = $token[0];
    }
    unset($set['']);
    return $set;
}

/**
 * The needles (keys of the weight map) present in a token set
 *
 * @param array $tokenNeedles needle => weight
 * @param array $tokenSet from tokenTextSet()
 * @return array
 */
function compareTokens($tokenNeedles, $tokenSet)
{
    $output = array();
    foreach ($tokenNeedles as $needle => $weight) {
        if (isset($tokenSet[strtolower($needle)])) {
            $output[] = $needle;
        }
    }
    return $output;
}

/**
 * Everything a file matches: needles found as tokens plus structural signals.
 *
 * @param string $content
 * @param array $tokenNeedles
 * @return array
 */
function matchTokens($content, $tokenNeedles)
{
    $analysis = analyzeContent($content, $tokenNeedles, false);
    return $analysis['matched_tokens'];
}

/**
 * Analyse a file's content: what it matches, its entropy, its distinct code
 * token count and (with $withMl) its ML features. The tokens are read once
 * and shared by every check.
 *
 * @param string $content
 * @param array $tokenNeedles
 * @param bool $withMl
 * @return array the content fields of a feature row (see featureRow())
 */
function analyzeContent($content, $tokenNeedles, $withMl)
{
    $code = codeTokens(getFileTokens($content));
    $textSet = tokenTextSet($code['sig']);
    $maxLine = maxLineLength($content);
    $entropy = shannonEntropy($content);
    return array(
        'entropy'        => $entropy,
        'total_tokens'   => count($textSet),
        'ml_features'    => $withMl ? mlFeatures($code['sig'], $maxLine, $entropy) : null,
        'matched_tokens' => array_values(array_unique(array_merge(
            compareTokens($tokenNeedles, $textSet),
            findStructuralSignals($code, $content, $tokenNeedles, $maxLine)
        ))),
        'has_php'        => hasPhpCode($content),
    );
}

/**
 * Value of a T_CONSTANT_ENCAPSED_STRING token, escapes decoded
 *
 * @param string $text the token text, quotes included
 * @return string
 */
function stringTokenValue($text)
{
    $value = substr($text, 1, -1);
    if (substr($text, 0, 1) == '"') {
        return stripcslashes($value);
    }
    return str_replace(array("\\'", '\\\\'), array("'", '\\'), $value);
}

/**
 * Whether a file holds any PHP: any "<?" except "<?xml" ("<?$d=..." is PHP).
 *
 * @param string $content
 * @return bool
 */
function hasPhpCode($content)
{
    return (bool) preg_match('/<\?(?!xml)/i', $content);
}

/**
 * Whether a file holds server code in another language: an ASP/JSP directive
 * or ASP/JSP code using its server objects, or a Perl CGI script.
 *
 * @param string $content
 * @return bool
 */
function hasForeignServerCode($content)
{
    return (bool) (preg_match('/<%@\s*(page|language)\b|<%.*?(Response\.Write|CreateObject|Server\.MapPath|Request\.(Form|QueryString)|WScript\.Shell|FileSystemObject|Runtime\.getRuntime|java\.io\.)/is', $content) ||
        preg_match('/^#!.*\bperl\b|^\s*use CGI\b/m', $content));
}

/**
 * Index of the variable an indexed call reads from: for "$a['x'][0](" with
 * $close at the last "]", walk back over each [...] to the token before it.
 *
 * @param array $sig codeTokens() 'sig'
 * @param int $close index of the last "]"
 * @return int index of the token before the first "[" (-1 if none)
 */
function indexedBase($sig, $close)
{
    $j = $close;
    while ($j >= 0 && $sig[$j][1] == ']') {
        $depth = 0;
        for (; $j >= 0; $j--) {
            if ($sig[$j][1] == ']') {
                $depth++;
            } elseif ($sig[$j][1] == '[' && --$depth == 0) {
                break;
            }
        }
        $j--;
    }
    return $j;
}

/**
 * Detect code shapes that plain token matching can't see. Returns
 * "@"-prefixed pseudo-needles (no PHP token is "@" + letters, so they never
 * collide with real ones) plus any needle function name that was hidden in
 * a string: 'ba'.'se64_decode', "\x73ystem", 'system'('id').
 *
 * @param array  $code         codeTokens() output
 * @param string $content      raw file content
 * @param array  $tokenNeedles needle => weight
 * @param int    $maxLine      maxLineLength($content)
 * @return array
 */
function findStructuralSignals($code, $content, $tokenNeedles, $maxLine)
{
    $needleSet = array_change_key_case($tokenNeedles, CASE_LOWER);
    $inputVars = array('$_get' => 1, '$_post' => 1, '$_request' => 1, '$_cookie' => 1, '$_server' => 1, '$_files' => 1);

    // Code up to __halt_compiler(); what follows it is data
    $sig = $code['sig'];
    $n = $code['code'];
    $found = array();
    for ($i = 0; $i < $n; $i++) {
        $id = $sig[$i][0];
        $text = $sig[$i][1];

        // String literal, or a chain of them joined with "."
        if ($id == T_CONSTANT_ENCAPSED_STRING) {
            $value = stringTokenValue($text);
            $parts = 1;
            $escaped = (substr($text, 0, 1) == '"' && strpos($text, '\\') !== false);
            while ($i + 2 < $n && $sig[$i + 1][1] == '.' && $sig[$i + 2][0] == T_CONSTANT_ENCAPSED_STRING) {
                $i += 2;
                $value .= stringTokenValue($sig[$i][1]);
                $parts++;
            }
            $isCall = ($i + 1 < $n && $sig[$i + 1][1] == '(');
            if ($isCall) {
                $found['@dyn_call'] = true;
            }
            $name = strtolower($value);
            if (($parts > 1 || $escaped || $isCall) && isset($needleSet[$name]) && preg_match('/^[a-z_][a-z0-9_]*$/', $name)) {
                $found[$name] = true;
                $found['@concat_name'] = true;
            }
            continue;
        }

        // preg_replace('/.../e', ...) evaluates the replacement as PHP
        if ($id == T_STRING && strtolower($text) == 'preg_replace' && $i + 2 < $n && $sig[$i + 1][1] == '(' && $sig[$i + 2][0] == T_CONSTANT_ENCAPSED_STRING) {
            $regex = stringTokenValue($sig[$i + 2][1]);
            $delim = substr($regex, 0, 1);
            $pairs = array('(' => ')', '[' => ']', '{' => '}', '<' => '>');
            if (isset($pairs[$delim])) {
                $delim = $pairs[$delim];
            }
            $end = strrpos($regex, $delim);
            if ($end > 0 && strpos(substr($regex, $end + 1), 'e') !== false) {
                $found['@preg_e'] = true;
            }
            continue;
        }

        // Call through something other than a function name: $f(), $a['x'](), (...)()
        if ($text == '(' && $id == 0 && $i > 0) {
            $prev = $sig[$i - 1];
            $before = ($i > 1) ? $sig[$i - 2][0] : 0;
            if ($prev[0] == T_VARIABLE) {
                if ($before != T_NEW && $before != T_OBJECT_OPERATOR && $before != T_PAAMAYIM_NEKUDOTAYIM) {
                    $found['@dyn_call'] = true;
                }
            } elseif ($prev[1] == ')') {
                $found['@dyn_call'] = true;
            } elseif ($prev[1] == ']') {
                $j = indexedBase($sig, $i - 1);
                if ($j >= 0 && $sig[$j][0] == T_VARIABLE) {
                    $found['@dyn_call'] = true;
                    if (isset($inputVars[strtolower($sig[$j][1])])) {
                        $found['@input_call'] = true;
                    }
                }
            }
        }
    }

    // ASP/JSP/CGI shell code in a file named like PHP (no PHP in it at all):
    // nothing for the PHP checks above to see
    if (!hasPhpCode($content) && hasForeignServerCode($content)) {
        $found['@foreign_code'] = true;
    }
    // Packed payloads tend to sit on one huge line
    if ($maxLine > LONG_LINE_BYTES) {
        $found['@long_line'] = true;
    }
    if ($code['haltBytes'] > HALT_PAYLOAD_BYTES) {
        $found['@halt_payload'] = true;
    }

    return array_keys($found);
}

/**
 * Binary feature vector for the client-side ML model, as a hex bitmap of
 * ML_BUCKETS bits. Each feature is a short string (a token-type bigram, a
 * called function's name, a variable's name, a string literal's shape, a
 * bucketed file statistic) hashed into a bucket with crc32. "& mask" keeps
 * the low bits the same on 32- and 64-bit PHP.
 *
 * @param array $sig     codeTokens() 'sig'
 * @param int   $maxLine maxLineLength() of the content
 * @param float $entropy shannonEntropy() of the content
 * @return string
 */
function mlFeatures($sig, $maxLine, $entropy)
{
    static $names = array(); // token_name() cache
    $member = memberTokenIds();
    $member[T_NEW] = true;

    $set = array();
    $prev = 'START';
    $n = count($sig);
    for ($i = 0; $i < $n; $i++) {
        $id = $sig[$i][0];
        $text = $sig[$i][1];
        if ($id == 0) {
            $type = $text;
        } else {
            if (!isset($names[$id])) {
                $names[$id] = token_name($id);
            }
            $type = $names[$id];
        }
        $set['b:' . $prev . ' ' . $type] = 1;
        $prev = $type;

        if ($id == T_STRING || $id == T_EVAL || $id == T_VARIABLE) {
            $before = ($i > 0) ? $sig[$i - 1][0] : 0;
            $isCall = ($i + 1 < $n && $sig[$i + 1][1] == '(');
            if ($id == T_VARIABLE) {
                $set['v:' . strtolower($text)] = 1;
            } elseif (!isset($member[$before]) && ($isCall || $id == T_EVAL)) {
                $set['c:' . ltrim(strtolower($text), '\\')] = 1;
            }
        } elseif ($id == T_CONSTANT_ENCAPSED_STRING) {
            $len = strlen($text) - 2;
            $set['s:len' . (strlen(decbin(max(0, $len))) >> 1)] = 1;
            if ($len >= 40 && preg_match('/^.[A-Za-z0-9+\/=\s]+.$/', $text)) {
                $set['s:b64'] = 1;
            }
            if (preg_match('/\\\\(x[0-9a-f]{2}|[0-7]{3})/i', $text)) {
                $set['s:esc'] = 1;
            }
        }
    }

    // Bit lengths, i.e. log2 buckets, in integer math so no PHP build rounds differently
    $set['f:line' . strlen(decbin($maxLine))] = 1;
    $set['f:tok' . strlen(decbin($n))] = 1;
    $set['f:ent' . (int) ($entropy * 4)] = 1;

    $mask = ML_BUCKETS - 1;
    $bits = array_fill(0, ML_BUCKETS / 4, 0);
    foreach ($set as $feature => $one) {
        $b = crc32($feature) & $mask;
        $bits[$b >> 2] |= 1 << ($b & 3);
    }
    $hex = '';
    foreach ($bits as $nibble) {
        $hex .= dechex($nibble);
    }
    return $hex;
}

/**
 * A feature row as the page expects it; $fields override the defaults, which
 * describe a file that couldn't be read.
 *
 * @param string $path
 * @param array $fields
 * @return array
 */
function featureRow($path, $fields)
{
    $row = array(
        'path'           => $path,
        'size'           => null,
        'mtime'          => 0,
        'ctime'          => 0,
        'owner'          => null,
        'entropy'        => null,
        'total_tokens'   => null,
        'ml_features'    => null,
        'matched_tokens' => array('NOT_READABLE'),
        'md5'            => 'N/A',
        'is_blacklisted' => false,
        'is_htaccess'    => false,
        'has_php'        => null,
        'duplicate_of'   => false,
        'error'          => null,
        'is_unreadable'  => true,
    );
    foreach ($fields as $key => $value) {
        $row[$key] = $value;
    }
    return $row;
}

/**
 * Analyse readable files into feature rows: token matching, structural
 * signals, entropy, ML features, list membership and duplicate-of. Files
 * whose MD5 is whitelisted are left out. Deleting blacklisted files is the
 * caller's business (actionProcess()).
 *
 * @param array $paths
 * @param array $whitelistMD5Sums md5 => anything
 * @param array $blacklistMD5Sums md5 => anything
 * @param array $tokenNeedles
 * @param array $localSeen md5 => first path seen with it; read and updated in place
 * @param bool $withMl compute ml_features (default: when _ML_ is on)
 * @return array feature rows
 */
function scanReadablePaths($paths, $whitelistMD5Sums, $blacklistMD5Sums, $tokenNeedles, &$localSeen, $withMl = null)
{
    if ($withMl === null) {
        $withMl = _ML_;
    }
    $rows = array();
    foreach ($paths as $filePath) {
        if (!file_exists($filePath) || !is_readable($filePath)) {
            trigger_error('Skipped ' . $filePath . ': it no longer exists or is not readable', E_USER_WARNING);
            continue;
        }
        $content = file_get_contents($filePath);
        if ($content === false) {
            $rows[] = scanUnreadablePath($filePath);
            continue;
        }
        $md5 = md5($content);
        if (isset($whitelistMD5Sums[$md5])) {
            continue;
        }

        $duplicateOf = false;
        if (isset($localSeen[$md5])) {
            $duplicateOf = $localSeen[$md5];
        } else {
            $localSeen[$md5] = $filePath;
        }
        $fields = analyzeContent($content, $tokenNeedles, $withMl);
        $fields['size'] = strlen($content);
        $fields['mtime'] = filemtime($filePath);
        $fields['ctime'] = filectime($filePath);
        $fields['owner'] = fileowner($filePath);
        $fields['md5'] = $md5;
        $fields['is_blacklisted'] = isset($blacklistMD5Sums[$md5]);
        $fields['is_htaccess'] = substr($filePath, -9) == '.htaccess'; // PATHINFO_EXTENSION is PHP 5.2+
        $fields['duplicate_of'] = $duplicateOf;
        $fields['is_unreadable'] = false;
        $rows[] = featureRow($filePath, $fields);
    }
    return $rows;
}

/**
 * Feature row for a path that could not be read.
 *
 * @param string $filePath
 * @return array
 */
function scanUnreadablePath($filePath)
{
    $mtime = @filemtime($filePath);
    return featureRow($filePath, array('mtime' => $mtime ? $mtime : 0));
}

// =============================================================================
// 5. Network
// =============================================================================

/**
 * One HTTP(S) request, over cURL or else PHP's URL streams, whichever the host
 * allows. TLS is always verified: the downloaded blacklist deletes files, so
 * it must really come from GitHub. Each call gets a fresh cURL handle, so one
 * request's method, body or credentials can't leak into the next. HTTP/1.1:
 * hash.cymru.com's HTTP/2 endpoint drops streams mid-response.
 *
 * @param string $url
 * @param string|null $body POST body; null for a GET
 * @param array $headers extra request headers
 * @return array|false array('status' => int, 'body' => string), false when unreachable
 */
function httpRequest($url, $body = null, $headers = array())
{
    $headers = array_merge(array('Cache-Control: no-cache, no-store, must-revalidate', 'Pragma: no-cache'), $headers);
    $tried = false;
    if (functionAvailable('curl_init') && functionAvailable('curl_exec') && functionAvailable('curl_setopt')) {
        $tried = true;
        $ch = curl_init($url);
        $options = array(
            CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => true, CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_HTTPHEADER => $headers,
            CURLOPT_CONNECTTIMEOUT => HTTP_CONNECT_TIMEOUT, CURLOPT_TIMEOUT => HTTP_TIMEOUT,
        );
        if (defined('CURL_HTTP_VERSION_1_1')) {
            $options[CURLOPT_HTTP_VERSION] = constant('CURL_HTTP_VERSION_1_1');
        }
        if ($body !== null) {
            $options[CURLOPT_POST] = true;
            $options[CURLOPT_POSTFIELDS] = $body;
        }
        foreach ($options as $option => $value) { // curl_setopt_array() is PHP 5.1.3+
            curl_setopt($ch, $option, $value);
        }
        $response = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        if (version_compare(PHP_VERSION, '8.0', '<')) { // a no-op since 8.0, deprecated in 8.5
            curl_close($ch);
        }
        if (is_string($response)) {
            return array('status' => $status, 'body' => $response);
        }
        trigger_error('cURL could not fetch ' . $url . ': ' . $error, E_USER_WARNING);
    }
    if (ini_get('allow_url_fopen')) {
        $tried = true;
        $http = array('header' => implode("\r\n", $headers), 'ignore_errors' => true, 'timeout' => HTTP_TIMEOUT);
        if ($body !== null) {
            $http['method'] = 'POST';
            $http['content'] = $body;
        }
        $context = stream_context_create(array('http' => $http, 'ssl' => array('verify_peer' => true, 'verify_peer_name' => true)));
        $fp = @fopen($url, 'rb', false, $context);
        if (!$fp && $body === null && version_compare(PHP_VERSION, '5', '<')) {
            $fp = @fopen($url, 'rb'); // PHP 4's fopen() takes no context
        }
        if ($fp) {
            // The response headers, read here rather than from $http_response_header,
            // which PHP 8.5 deprecates
            $meta = stream_get_meta_data($fp);
            $response = '';
            while (!feof($fp)) {
                $chunk = fread($fp, 65536);
                if ($chunk === false || $chunk === '') {
                    break;
                }
                $response .= $chunk;
            }
            fclose($fp);
            $status = 0;
            $lines = isset($meta['wrapper_data']) ? $meta['wrapper_data'] : array();
            if (isset($lines['headers'])) {
                $lines = $lines['headers']; // the cURL stream wrapper's layout
            }
            foreach ((array) $lines as $line) { // the last status line counts, after redirects
                if (is_string($line) && preg_match('#^HTTP/\S+\s+(\d+)#', $line, $m)) {
                    $status = (int) $m[1];
                }
            }
            return array('status' => $status, 'body' => $response);
        }
        trigger_error('Could not fetch ' . $url . ' through PHP streams', E_USER_WARNING);
    }
    if (!$tried) {
        trigger_error('No way to fetch ' . $url . ' (cURL and allow_url_fopen are both unavailable)', E_USER_WARNING);
    }
    return false;
}

/**
 * The body of a successful (2xx) GET, or false.
 *
 * @param string $url
 * @return string|false
 */
function httpGet($url)
{
    $response = httpRequest($url);
    if ($response === false) {
        return false;
    }
    if ($response['status'] < 200 || $response['status'] > 299) {
        trigger_error('Could not fetch ' . $url . ' (HTTP ' . $response['status'] . ')', E_USER_WARNING);
        return false;
    }
    return $response['body'];
}

/**
 * Open this script's own PHP session (its own cookie name, so an application
 * on the same host keeps its session untouched). Used only to share the hash
 * lists between the requests of one scan; the lists stay on the server, so
 * the browser can't substitute its own blacklist.
 *
 * @return bool whether $_SESSION can be used
 */
function listSessionStart()
{
    if (LIST_CACHE_SECONDS <= 0 || !functionAvailable('session_start') || headers_sent()) {
        return false;
    }
    if (session_id() === '') {
        session_name('SUSSYFINDER');
    }
    @session_start();
    return isset($_SESSION) && is_array($_SESSION);
}

/**
 * Download a list of MD5 sums, one per line.
 *
 * @param string $url
 * @return array|false md5 => true, false when it can't be fetched (with a warning)
 */
function downloadHashList($url)
{
    $body = httpGet($url);
    if ($body === false) {
        return false;
    }
    $list = array();
    foreach (explode("\n", $body) as $line) {
        $line = strtolower(trim($line));
        if ($line !== '') {
            $list[$line] = true;
        }
    }
    return $list;
}

/**
 * A hash list as md5 => true; empty when it can't be fetched. Downloaded at
 * most once per request, and kept in the session for LIST_CACHE_SECONDS so
 * the batches of a scan reuse it.
 *
 * @param string $url
 * @param bool $refresh download it again even when a copy is kept (a new scan)
 * @return array
 */
function hashList($url, $refresh = false)
{
    static $lists = array();
    if (isset($lists[$url]) && !$refresh) {
        return $lists[$url];
    }
    $session = listSessionStart();
    $kept = $session && isset($_SESSION['sussy_lists'][$url]) ? $_SESSION['sussy_lists'][$url] : null;
    if (!$refresh && is_array($kept) && time() - $kept['time'] < LIST_CACHE_SECONDS) {
        $lists[$url] = $kept['md5s'];
    } else {
        $list = downloadHashList($url);
        $lists[$url] = $list === false ? array() : $list;
        if ($session && $list !== false) {
            $_SESSION['sussy_lists'][$url] = array('time' => time(), 'md5s' => $list);
        }
    }
    if ($session) {
        session_write_close(); // don't hold the session lock while the batch runs
    }
    return $lists[$url];
}

/**
 * @param bool $refresh see hashList()
 * @return array the known-good list, md5 => true (empty when _WHITELIST_ is off)
 */
function whitelist($refresh = false)
{
    return _WHITELIST_ ? hashList(_WHITELIST_URL_, $refresh) : array();
}

/**
 * @param bool $refresh see hashList()
 * @return array the known-bad list, md5 => true (empty when _BLACKLIST_ is off)
 */
function blacklist($refresh = false)
{
    return _BLACKLIST_ ? hashList(_BLACKLIST_URL_, $refresh) : array();
}

/**
 * Download the ML model (ml-model.json) and check it fits this main.php.
 * Returns the JSON text to embed in the page, or 'null' with a warning when
 * it's unavailable, malformed, or trained for different features. The text
 * is matched against a strict pattern (digits, hex and fixed keys only), so
 * nothing from the download can break out of the <script> it goes into.
 *
 * @param string $url an http(s) URL or a local file
 * @return string
 */
function mlModelJson($url)
{
    if (preg_match('#^https?://#i', $url)) {
        $json = trim((string) httpGet($url));
    } else {
        $json = is_readable($url) ? trim(file_get_contents($url)) : ''; // a local copy, e.g. offline
    }
    if (!preg_match('/^\{"features":(\d+),"buckets":(\d+),"scale":-?[0-9.]+(e[-+]?\d+)?,"bias":-?[0-9.]+(e[-+]?\d+)?,"weights":"([0-9a-f]+)"\}$/', $json, $m)) {
        trigger_error('ML model unavailable or malformed (' . $url . '); ML scoring is off for this scan', E_USER_WARNING);
        return 'null';
    }
    if ($m[1] != ML_FEATURE_VERSION || $m[2] != ML_BUCKETS || strlen($m[5]) != 2 * ML_BUCKETS) {
        trigger_error('ML model was trained for feature version ' . $m[1] . ' / ' . $m[2] . ' buckets, this main.php uses ' . ML_FEATURE_VERSION . ' / ' . ML_BUCKETS . '; update main.php. ML scoring is off for this scan', E_USER_WARNING);
        return 'null';
    }
    return $json;
}

/**
 * Look up MD5/SHA1/SHA256 hashes in Team Cymru's Malware Hash Registry
 * (https://hash.cymru.com/docs_rest), at most MHR_BATCH per call.
 *
 * @param array $hashes
 * @param string $username
 * @param string $password
 * @return array the API's response ({results, queries_remaining}), or {error, msg}
 */
function mhrSubmitHashes($hashes, $username, $password)
{
    if ($username === '' || $password === '') {
        return ajaxError('not configured', 'MHR username/password not set (_MHR_ requires an account — see https://hash.cymru.com/signup)');
    }
    if (empty($hashes)) {
        return array('results' => array(), 'queries_remaining' => null);
    }
    if (!functionAvailable('json_decode')) {
        return ajaxError('unsupported', 'MHR lookups need PHP 5.2+ (json_decode)');
    }
    $response = httpRequest(_MHR_URL_, implode("\n", array_slice($hashes, 0, MHR_BATCH)), array(
        'Content-Type: text/plain; charset=utf-8',
        'Authorization: Basic ' . base64_encode($username . ':' . $password),
    ));
    $decoded = $response === false ? null : json_decode($response['body'], true);
    if (is_array($decoded)) {
        return $decoded; // including the API's own error replies (bad credentials, quota)
    }
    trigger_error('Unable to reach Malware Hash Registry', E_USER_WARNING);
    return ajaxError('request failed', 'Unable to reach Malware Hash Registry');
}

// =============================================================================
// 6. Actions
// =============================================================================
// Each action reads its request fields and returns the response array.

/** @return array MHR username and password: the page's, else the configured ones */
function mhrCredentials()
{
    $user = trim(inputValue('mhr_user', ''));
    $pass = inputValue('mhr_pass', '');
    return array($user !== '' ? $user : _MHR_USER_, $pass !== '' ? $pass : _MHR_PASS_);
}

/**
 * List the files to analyse (phase 1 of a scan), and fetch fresh hash lists
 * for the batches that follow.
 *
 * @return array
 */
function actionScan()
{
    whitelist(true);
    blacklist(true);
    $result = getSortedByPattern(inputValue('dir', getcwd()), $GLOBALS['pattern']);
    return array(
        'readable'     => array_map('rawurlencode', $result['file_readable']),
        'not_readable' => array_map('rawurlencode', $result['file_not_readable']),
        'total'        => count($result['file_readable']) + count($result['file_not_readable']),
    );
}

/**
 * Analyse one batch of files (phase 2), deleting blacklisted ones. The page
 * works out duplicate_of across batches itself, from each row's md5.
 *
 * @return array
 */
function actionProcess()
{
    $paths = postPathList('paths');
    if (inputValue('is_not_readable') === '1') {
        $rows = array_map('scanUnreadablePath', $paths);
    } else {
        $seen = array();
        $withMl = _ML_ && inputValue('ml') !== '0'; // '0': the page has no model to score with
        $rows = scanReadablePaths($paths, whitelist(), blacklist(), $GLOBALS['tokenNeedles'], $seen, $withMl);
    }
    foreach ($rows as $i => $row) {
        if ($row['is_blacklisted']) {
            $rows[$i]['error'] = unlinkWithReason($row['path']);
        }
        $rows[$i]['path'] = rawurlencode($row['path']);
        $rows[$i]['duplicate_of'] = false;
    }
    return array('features' => $rows);
}

/**
 * Look a batch of hashes up in the Malware Hash Registry.
 *
 * @return array
 */
function actionMhrCheck()
{
    $credentials = mhrCredentials();
    return mhrSubmitHashes(array_values(array_unique(array_filter(postList('hashes')))), $credentials[0], $credentials[1]);
}

/**
 * Delete files MHR flags. The paths come from the browser, so only files
 * whose current hash MHR itself confirms are deleted; trusting the list would
 * make this an arbitrary-file-delete endpoint.
 *
 * @return array
 */
function actionMhrUnlink()
{
    $sums = array();
    foreach (postPathList('paths') as $filePath) {
        $sums[$filePath] = is_file($filePath) ? md5_file($filePath) : false;
    }
    $credentials = mhrCredentials();
    $lookup = mhrSubmitHashes(array_values(array_unique(array_filter($sums))), $credentials[0], $credentials[1]);
    if (isset($lookup['error'])) {
        return $lookup;
    }
    $hits = array();
    foreach (isset($lookup['results']) ? $lookup['results'] : array() as $r) {
        if (isset($r['md5']) && isset($r['antivirus_detection_rate'])) {
            $hits[strtolower($r['md5'])] = true;
        }
    }
    $results = array();
    foreach ($sums as $filePath => $sum) {
        if ($sum === false) {
            $error = file_exists($filePath) ? 'Not a regular file; not deleted' : null; // null: already gone
        } elseif (!isset($hits[$sum])) {
            $error = 'MHR does not flag its current contents; not deleted';
        } else {
            $error = unlinkWithReason($filePath);
        }
        $results[] = array('path' => rawurlencode($filePath), 'error' => $error);
    }
    return array('results' => $results);
}

/**
 * Answer an AJAX request with JSON and stop. Captured PHP warnings go along
 * in "warnings"; any stray output (which would corrupt the JSON) is dropped
 * and reported there instead.
 *
 * @param array $data
 * @return void
 */
function ajaxRespond($data)
{
    $stray = trim((string) ob_get_clean());
    $warnings = (isset($data['warnings']) && is_array($data['warnings'])) ? $data['warnings'] : array();
    $warnings = array_merge($warnings, $GLOBALS['phpWarnings']);
    if ($stray !== '') {
        $warnings[] = 'Unexpected output suppressed: ' . substr($stray, 0, 500);
    }
    $data['warnings'] = array_values($warnings);
    echo jsonEncode($data);
    exit;
}

/**
 * Run the requested action. A browser sends the custom X-Sussy-Request
 * header cross-site only after a CORS preflight this script never approves,
 * so its presence proves the page itself sent the request (CSRF check).
 *
 * @return void
 */
function dispatchAjax()
{
    ob_start();
    header('Content-Type: application/json');
    if (!isset($_SERVER['HTTP_X_SUSSY_REQUEST'])) {
        ajaxRespond(ajaxError('forbidden', 'Missing X-Sussy-Request header'));
    }
    $actions = array('scan' => 'actionScan', 'process' => 'actionProcess', 'mhr_check' => 'actionMhrCheck', 'mhr_unlink' => 'actionMhrUnlink');
    $mhrActions = array('mhr_check' => true, 'mhr_unlink' => true);
    $action = inputValue('ajax_action', '');
    if (!isset($actions[$action])) {
        ajaxRespond(ajaxError('unknown action', 'Unknown action: ' . $action));
    }
    if (isset($mhrActions[$action]) && !_MHR_) {
        ajaxRespond(ajaxError('not configured', 'MHR integration is disabled (_MHR_ is false)'));
    }
    ajaxRespond(call_user_func($actions[$action]));
}

// =============================================================================
// 7. Bootstrap
// =============================================================================

// The test scripts include this file for parts 1-6 only (define('SUSSY_LIB', true) first)
if (defined('SUSSY_LIB')) {
    return;
}

callIfAvailable('set_time_limit', TIME_LIMIT);
callIfAvailable('ini_set', 'memory_limit', '-1');
if (function_exists('get_magic_quotes_gpc') && @get_magic_quotes_gpc()) {
    $_POST = stripRequestSlashes($_POST);
}
if (isset($_POST['ajax_action'])) {
    dispatchAjax();
}

// =============================================================================
// 8. Page
// =============================================================================
?>
<!DOCTYPE html>
<html lang="en-us">

    <head>
        <title>Sussy Finder</title>
        <style>
            body {
                font-family: 'Ubuntu Mono', monospace;
                background-color: #1e1e1e;
                color: #d0d0d0;
                font-size: 14px;
            }

            table {
                border-spacing: 0;
                padding: 5px;
                border-radius: 5px;
                border: 1px solid #444;
                width: 90%;
                margin: auto;
                background-color: #2a2a2a;
            }

            tr,
            td {
                padding: 5px;
            }

            th {
                color: #f0f0f0;
                padding: 5px;
                font-size: 20px;
            }

            input,
            button,
            select {
                font-family: 'Ubuntu Mono', monospace;
                font-size: 13px;
                padding: 6px 10px;
                border-radius: 6px;
                border: 1px solid #444;
                background: #2a2a2a;
                color: #d0d0d0;
            }

            button {
                cursor: pointer;
                transition: background 0.15s, border-color 0.15s, color 0.15s;
            }

            button:hover,
            input[type=text]:hover,
            input[type=number]:hover {
                border-color: #ff6666;
                color: #ff6666;
            }

            button.btn-primary {
                background: #2f5f8a;
                border-color: #2f5f8a;
                color: #fff;
                font-weight: bold;
            }

            button.btn-primary:hover {
                background: #3a75a8;
                border-color: #3a75a8;
                color: #fff;
            }

            .navbar {
                display: flex;
                align-items: center;
                flex-wrap: wrap;
                gap: 10px;
                width: 90%;
                margin: 15px auto;
                padding: 10px 16px;
                background: #242424;
                border: 1px solid #3a3a3a;
                border-radius: 8px;
            }

            .navbar-brand {
                font-size: 18px;
                font-weight: bold;
                color: #f0f0f0;
                white-space: nowrap;
            }

            .navbar-group {
                display: flex;
                flex: 1;
                align-items: center;
                flex-wrap: wrap;
                gap: 8px;
            }

            .navbar .dir-input {
                flex: 1 1 100%;
                min-width: 160px;
            }

            .navbar .chunk-input {
                width: 70px;
            }

            .toolbar {
                display: flex;
                align-items: center;
                flex-wrap: wrap;
                gap: 8px;
                width: 90%;
                margin: 0 auto 15px;
                padding: 8px 16px;
                background: #242424;
                border: 1px solid #3a3a3a;
                border-radius: 8px;
                font-size: 12px;
            }

            .toolbar label {
                display: flex;
                align-items: center;
                gap: 4px;
                white-space: nowrap;
            }

            .toolbar .search-input {
                width: 160px;
            }

            .toolbar .z-input {
                width: 55px;
            }

            #result td {
                font-size: 12px;
                padding: 3px 6px;
                line-height: 1.4em;
                border-bottom: 1px solid #333;
                white-space: normal;
                word-wrap: break-word;
                overflow-wrap: anywhere;
                max-width: 95vw;
            }

            #result tr:nth-child(even) td {
                background: #242424;
            }

            .error-banner {
                background: #3a1a1a;
                color: #ff6b6b;
                padding: 10px;
                border: 1px solid #ff4444;
                border-radius: 5px;
                margin: 10px auto;
                width: 90%;
                text-align: center;
            }

            .file-link {
                cursor: pointer;
                text-decoration: underline;
                text-decoration-style: dotted;
            }

            .file-link:hover {
                color: #ffcc66;
            }

            .verbosity {
                font-size: 11px;
                color: #888;
            }

            .token-highlight {
                color: #ff8a03ff;
            }

            .badge {
                color: #fff;
                padding: 2px 6px;
                border-radius: 3px;
                font-weight: bold;
                font-size: 11px;
            }

            .badge-muted {
                background: #444;
                color: #aaa;
                font-weight: normal;
            }

            .dashboard-panel {
                display: none;
                width: 95%;
                margin: 0 auto 20px;
            }

            .dashboard-panel.visible {
                display: block;
            }

            .dashboard-panel h3 {
                text-align: center;
                color: #ccc;
                margin: 8px 0 15px;
            }

            .insights-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                gap: 12px;
                margin-bottom: 15px;
            }

            .insight-card {
                background: #2a2a2a;
                border-radius: 8px;
                padding: 12px;
                border-left: 4px solid #4a8bc2;
                text-align: center;
                cursor: pointer;
                transition: border-color 0.2s, background 0.2s;
            }

            .insight-card:hover {
                background: #333;
                border-color: #ffcc66;
            }

            .insight-card.danger { border-left-color: #ff4444; }
            .insight-card.warning { border-left-color: #ffaa00; }
            .insight-card.success { border-left-color: #4CAF50; }
            .insight-card.info { border-left-color: #4a8bc2; }
            .insight-card.purple { border-left-color: #9b59b6; }

            .insight-card .label {
                font-size: 11px;
                color: #888;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }

            .insight-card .value {
                font-size: 22px;
                font-weight: bold;
                color: #f0f0f0;
                margin-top: 5px;
            }

            .insight-card .sub {
                font-size: 11px;
                color: #aaa;
                margin-top: 2px;
            }

            .insight-columns {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 15px;
            }

            .insight-list {
                background: #2a2a2a;
                border-radius: 8px;
                padding: 12px;
            }

            .insight-list h4 {
                color: #ccc;
                margin: 0 0 10px;
            }

            .insight-list table {
                width: 100%;
                border-collapse: collapse;
                font-size: 12px;
            }

            .insight-list th {
                text-align: left;
                color: #888;
                font-weight: normal;
                padding: 4px 6px;
                border-bottom: 1px solid #444;
            }

            .insight-list td {
                padding: 4px 6px;
                border-bottom: 1px solid #333;
            }
            .insight-list .clickable-row {
                cursor: pointer;
            }
            .insight-list .clickable-row:hover td {
                background: #333;
                color: #ffcc66;
            }

            .charts-grid {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 15px;
            }

            .chart-box {
                background: #2a2a2a;
                border-radius: 8px;
                padding: 10px;
                position: relative;
            }

            .chart-box canvas {
                display: block;
                width: 100%;
                height: 300px;
                cursor: crosshair;
            }

            .chart-title {
                text-align: center;
                color: #ccc;
                margin-bottom: 8px;
                font-weight: bold;
            }

            .chart-help {
                color: #888;
                font-size: 12px;
                margin: -6px 0 10px;
            }

            .selection-bar {
                width: 90%;
                margin: 8px auto;
                padding: 6px 12px;
                background: #1f3346;
                border: 1px solid #2f5f8a;
                border-radius: 6px;
                font-size: 13px;
            }

            .selection-bar .hint {
                color: #888;
                font-size: 11px;
            }

            #result tr.row-linked td {
                background: #3a3a3a;
            }

            .dashboard-empty {
                color: #888;
                text-align: center;
                padding: 20px;
            }

            /* Tooltip for charts - fixed positioning */
            #chart-tooltip {
                display: none;
                position: fixed;
                background: #1e1e1e;
                border: 1px solid #555;
                border-radius: 6px;
                padding: 8px 12px;
                color: #eee;
                font-size: 12px;
                line-height: 1.5;
                pointer-events: none;
                z-index: 9999;
                max-width: 350px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.7);
                font-family: 'Ubuntu Mono', monospace;
            }
            #chart-tooltip .label {
                color: #aaa;
            }
            #chart-tooltip .value {
                color: #ffcc66;
            }
            #chart-tooltip .mono {
                font-family: 'Ubuntu Mono', monospace;
                word-break: break-all;
            }

            /* Copy MD5 button */
            .copy-hash-btn {
                cursor: pointer;
                color: #4a8bc2;
                margin-left: 6px;
                font-size: 13px;
                background: none;
                border: none;
                padding: 0 4px;
                display: inline-block;
            }
            .copy-hash-btn:hover {
                color: #ffcc66;
            }

            /* VirusTotal lookup badge */
            .vt-badge {
                cursor: pointer;
                background: #75799a;
                color: #fff;
                margin-left: 6px;
                padding: 2px 6px;
                border-radius: 3px;
                font-weight: bold;
                font-size: 11px;
            }
            .vt-badge:hover {
                background: #989dcb;
            }

            @media (max-width: 768px) {
                .insight-columns,
                .charts-grid {
                    grid-template-columns: 1fr;
                }
            }
        </style>
    </head>

    <body>
        <nav class="navbar">
            <span class="navbar-brand">Sussy Finder</span>
            <div class="navbar-group">
                <input type="text" name="dir" class="dir-input" value="<?php echo htmlspecialchars(getcwd()); ?>" title="Directory to scan" onkeydown="if (event.key === 'Enter') { startChunkedScan(); }">
                <input type="number" id="chunkSizeInput" class="chunk-input" value="500" step="50" title="Files processed per AJAX request">
                <button type="button" class="btn-primary" onclick="startChunkedScan()" title="Chunked scan — safe for large directories">Scan</button>
            </div>
        </nav>

        <!-- AJAX progress panel -->
        <div id="ajaxProgress" style="display:none;width:90%;margin:10px auto;">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">
                <span id="ajaxStatus" style="color:#ccc;font-size:13px;">Scanning...</span>
                <button type="button" onclick="cancelChunkedScan()" style="padding:3px 10px;font-size:12px;">Cancel</button>
            </div>
            <div style="background:#333;border-radius:4px;height:12px;overflow:hidden;">
                <div id="ajaxBar" style="height:100%;width:0%;background:linear-gradient(90deg,#4a8bc2,#ffaa00);transition:width 0.2s;"></div>
            </div>
            <div style="margin-top:4px;font-size:11px;color:#888;" id="ajaxSubStatus"></div>
        </div>

        <!-- Malware Hash Registry (Team Cymru) bulk lookup — manual, run after a scan -->
        <div id="mhrPanel" style="display:none;width:90%;margin:10px auto;padding:8px 12px;background:#252525;border-radius:6px;font-size:13px;">
            <label>MHR Username: <input type="text" id="mhrUsername" autocomplete="username" style="width:140px;"></label>
            &nbsp;
            <label>MHR Password: <input type="password" id="mhrPassword" autocomplete="current-password" style="width:140px;"></label>
            &nbsp;
            <button type="button" onclick="runMhrCheckClick()" title="Submit non-blacklisted/non-whitelisted MD5s to hash.cymru.com in batches of <?php echo MHR_BATCH; ?>">MHR SCAN</button>
            <span id="mhrStatus" style="margin-left:10px;color:#888;"></span>
        </div>

        <?php
        // The page's data: the scoring policy (so the page scores exactly like the
        // tests), the ML model, settings, and the warnings so far (last, so it
        // includes the model download's)
        echo '<script>const tokenWeights = ' . jsonEncode($tokenNeedles) . ";\n" .
            'const tokenRoles = ' . jsonEncode($tokenRoles) . ";\n" .
            'const ML_MODEL = ' . (_ML_ ? mlModelJson(_ML_MODEL_URL_) : 'null') . ";\n" .
            'const mhrEnabled = ' . jsonEncode((bool) _MHR_) . ";\n" .
            'const MHR_BATCH = ' . jsonEncode(MHR_BATCH) . ";\n" .
            'const serverWarnings = ' . jsonEncode(array_values($GLOBALS['phpWarnings'])) . ";</script>\n";
        ?>
        <!-- Warning banner for critical errors & failed deletions -->
        <div id="warningBanner" class="error-banner" style="display:none;"></div>

        <!-- Result controls -->
        <div class="toolbar">
            <button type="button" onclick="copyResults()">Copy</button>

            <select id="sortSelect" onchange="sortResults(this.value)" title="Sort results">
                <option value="threat">Sort: Threat Score</option>
                <option value="mtime">Sort: Time</option>
                <option value="tokens">Sort: Tokens</option>
                <option value="zSusp">Sort: Z‑Score</option>
                <option value="residual">Sort: Residual</option>
<?php if (_ML_) { ?>
                <option value="ml">Sort: ML Score</option>
<?php } ?>
            </select>

            <select id="severityFilter" onchange="applySeverityFilter()" title="Filter results">
                <option value="all">All Files</option>
                <option value="anomalies">Only Anomalies</option>
                <option value="critical">Critical Threat</option>
                <option value="obfuscated">High Entropy</option>
            </select>

            <label>Z‑threshold: <input type="number" id="zThreshold" class="z-input" value="3.5" step="0.1" onchange="applyThreshold()"></label>

            <label>🔍 <input type="text" id="searchInput" class="search-input" placeholder="e.g. eval or .php" oninput="applySearchSoon()"></label>

            <label><input type="checkbox" id="searchTokensOnly" onchange="applySearch()"> Tokens only</label>

            <button type="button" onclick="toggleInsights()">Insights</button>
            <button type="button" onclick="toggleCharts()">Charts</button>
            <button type="button" onclick="clearFilters()">Clear</button>
        </div>

        <div id="insightsPanel" class="dashboard-panel">
            <h3>File System & Threat Insights</h3>
            <div id="insightsGrid" class="insights-grid"></div>
            <div class="insight-columns">
                <div id="topSuspicious" class="insight-list">
                    <h4>Top Suspicious Files</h4>
                </div>
                <div id="topRecent" class="insight-list">
                    <h4>Most Recent Files</h4>
                </div>
            </div>
        </div>

        <div id="chartsPanel" class="dashboard-panel">
            <h3>Threat Matrix & Anomaly Visualizations</h3>
            <div class="chart-help">Drag to select files (Ctrl/⌘ adds to the selection) · click a dot or bar to select it · the table follows · Esc clears</div>
            <div id="chartsGrid" class="charts-grid"></div>
        </div>

        <!-- Tooltip for charts -->
        <div id="chart-tooltip"></div>

        <div id="chartSelectionBar" class="selection-bar" style="display:none;"></div>

        <table align="center">
            <tbody id="result"></tbody>
        </table>

        <script>
            // Client-side statistical analysis and graph rendering
            let analyzedData = [];
            let currentSort = 'threat';
            let currentFilterMode = 'all';
            let currentThreshold; // set to Z_THRESHOLD after the scoring block below
            let insightsVisible = false;
            let chartsVisible = false;
            let currentSearch = '';
            let searchTokensOnly = false;

            // --- Client-side threat scoring (offloaded from PHP) ---

            // Default robust Z-score above which a statistic is an outlier
            // (the Z-threshold control; test/run bench and train use it too)
            const Z_THRESHOLD = 3.5;
            // Threat score at which a file is an anomaly (HIGH RISK), and CRITICAL
            const ANOMALY_SCORE = 8;
            const CRITICAL_SCORE = 15;

            // Whole-file Shannon entropy (bits/byte, computed server-side) above
            // this means packed/encoded content: 98/202 test webshells vs 1/1927
            // benign files (test/run bench).
            const HIGH_ENTROPY = 5.5;

            // Needles by role ($tokenRoles in PHP: critical, obfuscation, upload,
            // input, recon, highlight), lowercased like the matched tokens
            const ROLES = {};
            ['critical', 'obfuscation', 'upload', 'input', 'recon', 'highlight'].forEach(function (role) {
                const list = (typeof tokenRoles !== 'undefined' && tokenRoles[role]) || [];
                ROLES[role] = new Set(list.map(function (t) { return t.toLowerCase(); }));
            });

            /**
             * Compute composite threat score for one feature row.
             * @param {Object} d       feature row from the server
             * @param {Object} weights tokenWeights map (key -> weight)
             */
            function calculateThreatScore(d, weights) {
                var score = 0.0;
                var hasCritical = false;
                var hasObfuscation = false;
                var hasUploadReq = false;
                var hasInput = false;

                var tokens = Array.isArray(d.matched_tokens) ? d.matched_tokens.map(function (t) { return t.toLowerCase(); }) : [];

                // Obfuscation/upload-handling functions (compression, encoding, file upload
                // helpers) are everyday building blocks of legitimate code — ZIP libraries,
                // mail clients, HTTP clients, media parsers. They're only a strong signal in
                // combination with a real code-execution primitive (already captured by the
                // combo multipliers below); standing alone they get a reduced weight so a
                // large legitimate library doesn't cross the anomaly bar on that basis alone.
                for (var c = 0; c < tokens.length; c++) {
                    if (ROLES.critical.has(tokens[c])) { hasCritical = true; }
                    if (ROLES.input.has(tokens[c])) { hasInput = true; }
                }
                var nonCriticalDampen = hasCritical ? 1.0 : 0.3;

                for (var i = 0; i < tokens.length; i++) {
                    var token = tokens[i];
                    var w = (weights && typeof weights[token] !== 'undefined') ? parseFloat(weights[token]) : 1.0;
                    var isObf = ROLES.obfuscation.has(token);
                    var isReq = ROLES.upload.has(token);
                    if (isObf) hasObfuscation = true;
                    if (isReq) hasUploadReq = true;
                    if (isObf || isReq) w *= nonCriticalDampen;
                    score += w;
                }

                if (hasCritical && hasObfuscation) score *= 2.5;
                if (hasCritical && hasUploadReq)   score *= 1.8;
                if (hasCritical && hasInput)       score *= 2.0;

                // Directory only — a legitimately-named file like media.php or cache.php
                // shouldn't trip the "suspicious location" bonus just from its filename.
                var dirs = (d.path || '').toLowerCase().replace(/\\/g, '/').split('/');
                dirs.pop();
                var dirLow = dirs.join('/');
                if (dirs.indexOf('uploads') !== -1 && !d.is_htaccess && d.total_tokens > 5) {
                    // Upload folders hold user files; real code in one was almost always planted
                    score += 10.0;
                } else if (dirLow.indexOf('upload')  !== -1 ||
                    dirLow.indexOf('cache')   !== -1 ||
                    dirLow.indexOf('tmp')     !== -1 ||
                    dirLow.indexOf('images')  !== -1 ||
                    dirLow.indexOf('media')   !== -1) {
                    if (score > 0 || d.entropy > HIGH_ENTROPY) score += 5.0;
                }

                if (d.entropy > HIGH_ENTROPY) score += 3.0;

                // A webshell's header shows the box it landed on: OS, user and uid,
                // disk space, PHP settings. Benign code rarely asks for two of these
                // at once (2+: 79/211 test webshells, 0/1927 benign files)
                let recon = 0;
                for (var r = 0; r < tokens.length; r++) {
                    if (ROLES.recon.has(tokens[r])) recon++;
                }
                if (recon >= 2) score += 6.0;

                return Math.round(score * 100) / 100;
            }

            // Tiny ML model: logistic regression over the hashed token features
            // from mlFeatures() in PHP (one bit per bucket), int8 weights as hex.
            // Trained and cross-validated by test/run train --write, which
            // writes ml-model.json; the server embeds it in the page as ML_MODEL
            // (null when unavailable or disabled).
            // Score at or above which the model alone flags a file (a ranking
            // score from training, not a calibrated probability)
            const ML_THRESHOLD = 0.9;
            // The ML score adds threat points: none at or below ML_FLOOR, rising
            // linearly to 8 (the anomaly / HIGH RISK bar) at ML_THRESHOLD and 10 at 1.0.
            // 0.6 on test/run bench: lower adds false positives, higher loses catches
            // (test/run train reports the same sweep on held-out scores)
            const ML_FLOOR = 0.6;

            // floor: ML_FLOOR unless given (test/run train sweeps it)
            function mlPoints(ml, floor) {
                if (floor === undefined) floor = ML_FLOOR;
                if (ml === null || ml <= floor) return 0;
                const pts = ml < ML_THRESHOLD
                    ? 8 * (ml - floor) / (ML_THRESHOLD - floor)
                    : 8 + 2 * (Math.min(ml, 1) - ML_THRESHOLD) / (1 - ML_THRESHOLD);
                return Math.round(pts * 100) / 100;
            }
            const _mlWeightCache = new Map();
            // Hex digit -> value by char code: parseInt() per digit was 36x slower
            const _mlNibble = new Uint8Array(128);
            '0123456789abcdef'.split('').forEach(function (c, i) {
                _mlNibble[c.charCodeAt(0)] = i;
                _mlNibble[c.toUpperCase().charCodeAt(0)] = i;
            });

            /**
             * ML webshell score (0..1, higher = more shell-like).
             * @param {string} hex   ml_features bitmap from the server
             * @param {Object} model defaults to ML_MODEL
             * @return {number|null} null when there is nothing to score
             */
            function mlScore(hex, model) {
                model = model || (typeof ML_MODEL !== 'undefined' ? ML_MODEL : null);
                if (!hex || !model || !model.weights) return null;
                let w = _mlWeightCache.get(model.weights);
                if (!w) {
                    w = new Int8Array(model.weights.length / 2);
                    for (let i = 0; i < w.length; i++) w[i] = parseInt(model.weights.substr(i * 2, 2), 16);
                    _mlWeightCache.clear();
                    _mlWeightCache.set(model.weights, w);
                }
                // A bitmap from a different ML_BUCKETS than the model was trained with
                if (hex.length * 4 !== w.length) return null;
                let sum = 0;
                for (let i = 0, k = 0; i < hex.length; i++, k += 4) {
                    const nibble = _mlNibble[hex.charCodeAt(i) & 127];
                    if (nibble === 0) continue;
                    if (nibble & 1) sum += w[k];
                    if (nibble & 2) sum += w[k + 1];
                    if (nibble & 4) sum += w[k + 2];
                    if (nibble & 8) sum += w[k + 3];
                }
                return 1 / (1 + Math.exp(-(model.bias + sum * model.scale)));
            }

            function medianOf(sorted) {
                const m = sorted.length >> 1;
                return sorted.length % 2 ? sorted[m] : (sorted[m - 1] + sorted[m]) / 2;
            }

            // Median/MAD instead of mean/std: the outliers being hunted (and huge
            // vendor files) can't inflate the spread and hide themselves. Scaled so
            // z matches a standard z-score on normal data (Iglewicz & Hoaglin).
            // minScale stops a near-constant metric from turning noise into outliers.
            function computeStats(values, minScale) {
                const v = values.filter(x => x !== null && !isNaN(x)).sort((a, b) => a - b);
                if (v.length === 0) return { median: 0, scale: 0 };
                const median = medianOf(v);
                const mad = medianOf(v.map(x => Math.abs(x - median)).sort((a, b) => a - b));
                // MAD is 0 when over half the values tie (e.g. most files match no
                // tokens) — fall back to the mean absolute deviation
                const meanAD = v.reduce((a, x) => a + Math.abs(x - median), 0) / v.length;
                const scale = mad > 0 ? 1.4826 * mad : 1.253314 * meanAD;
                return { median: median, scale: Math.max(scale, minScale || 0) };
            }

            function zScore(value, s) {
                if (s.scale === 0 || value === null) return 0;
                return (value - s.median) / s.scale;
            }

            function formatDate(timestamp) {
                if (!timestamp) return 'N/A';
                const d = new Date(timestamp * 1000);
                const day = String(d.getDate()).padStart(2, '0');
                const month = String(d.getMonth() + 1).padStart(2, '0');
                const year = d.getFullYear();
                const hours = String(d.getHours()).padStart(2, '0');
                const minutes = String(d.getMinutes()).padStart(2, '0');
                const seconds = String(d.getSeconds()).padStart(2, '0');
                return `${day}/${month}/${year}, ${hours}:${minutes}:${seconds}`;
            }

            // Score rows and flag the anomalies at a Z-threshold
            function analyzeData(rawData, threshold) {
                return flagAnomalies(scoreRows(rawData), threshold);
            }

            // Everything about a row that doesn't depend on the Z-threshold (the
            // expensive part); isAnomaly and mlOnly are set by flagAnomalies()
            function scoreRows(rawData) {
                const valid = rawData.filter(d => !d.is_unreadable);
                const tokens = valid.map(d => d.total_tokens);
                const susp = valid.map(d => d.matched_tokens ? d.matched_tokens.length : 0);
                const sum = a => a.reduce((x, y) => x + y, 0);

                const weights = (typeof tokenWeights !== 'undefined') ? tokenWeights : {};

                const stats = {
                    size: computeStats(valid.map(d => d.size)),
                    mtime: computeStats(valid.map(d => d.mtime)),
                    tokens: computeStats(tokens),
                    susp: computeStats(susp),
                    entropy: computeStats(valid.map(d => d.entropy)),
                    // Attackers backdate mtime with touch, but can't set ctime that way,
                    // so a planted file's ctime-mtime gap stands out from its neighbours'.
                    // Gaps under a day (chmod, in-place edits) aren't meaningful.
                    ctimeGap: computeStats(valid.map(d => d.ctime - d.mtime), 86400),
                };

                const avgSuspPerToken = sum(susp) / Math.max(1, sum(tokens));

                // A file owned by a user who owns almost nothing else (e.g. the web
                // server user among FTP-deployed files) was likely written by the app.
                const ownerCount = {};
                valid.forEach(d => { ownerCount[d.owner] = (ownerCount[d.owner] || 0) + 1; });

                return rawData.map((d, idx) => {
                    if (d.is_unreadable) {
                        return {
                            ...d,
                            entropy: 0,
                            zScores: { size: 0, mtime: 0, tokens: 0, susp: 0, entropy: 0, ctime: 0 },
                            residual: 0,
                            rareOwner: false,
                            isAnomaly: false,
                            mlScore: null,
                            mlPoints: 0,
                            mlOnly: false,
                            ruleScore: 0,
                            threatScore: 0,
                            date: formatDate(d.mtime),
                            suspCount: 0
                        };
                    }

                    // The ML model was trained on PHP, so .htaccess files aren't scored.
                    // Its points are added after the rule multipliers, never multiplied.
                    const ml = d.is_htaccess ? null : mlScore(d.ml_features);
                    const mlPts = mlPoints(ml);
                    const ruleScore = calculateThreatScore(d, weights);
                    let threatScore = Math.round((ruleScore + mlPts) * 100) / 100;

                    if (d.is_blacklisted) {
                        threatScore = Math.max(threatScore, 100.0);
                    }

                    if (d.mhr_hit) {
                        threatScore = Math.max(threatScore, 100.0);
                    }

                    const suspCount = d.matched_tokens ? d.matched_tokens.length : 0;
                    const zSize = zScore(d.size, stats.size);
                    const zMtime = zScore(d.mtime, stats.mtime);
                    const zTokens = zScore(d.total_tokens, stats.tokens);
                    const zSusp = zScore(suspCount, stats.susp);
                    const zEntropy = zScore(d.entropy, stats.entropy);
                    const zCtime = zScore(d.ctime - d.mtime, stats.ctimeGap);
                    const rareOwner = valid.length >= 20 && ownerCount[d.owner] / valid.length < 0.05;

                    const expectedSusp = d.total_tokens * avgSuspPerToken;
                    const residual = suspCount - expectedSusp;

                    return {
                        ...d,
                        zScores: { size: zSize, mtime: zMtime, tokens: zTokens, susp: zSusp, entropy: zEntropy, ctime: zCtime },
                        residual: residual,
                        rareOwner: rareOwner,
                        isAnomaly: false,
                        mlScore: ml,
                        mlPoints: mlPts,
                        mlOnly: false,
                        ruleScore: ruleScore,
                        threatScore: threatScore,
                        date: d.mtime ? formatDate(d.mtime) : 'N/A',
                        suspCount: suspCount
                    };
                });
            }

            // Which scored rows are anomalies at a Z-threshold: cheap, so moving the
            // threshold control reruns only this
            function flagAnomalies(rows, threshold) {
                return rows.map(d => {
                    if (d.is_unreadable) return { ...d, isAnomaly: true, mlOnly: false };
                    // is_htaccess and duplicate_of are informational categories (still
                    // shown via their own badges/stat cards) but aren't content signals
                    // by themselves — an .htaccess file or a byte-identical duplicate
                    // (e.g. WordPress's dozens of stock "Silence is golden" index.php
                    // stubs) is not inherently suspicious, so they no longer force
                    // isAnomaly on their own. Only content/threat-based signals do.
                    //
                    // zSize is computed and still shown (chart/columns/tooltips) but not
                    // used as a trigger: tested against 203 real webshells + ~1450 legit
                    // WordPress/Laravel files, it never uniquely caught a webshell (every
                    // one it flagged was already caught by threatScore or another signal)
                    // while being the single largest false-positive source — plain file
                    // size just isn't a meaningful malice signal on its own. zSusp
                    // dropped out for the same reason (0 unique catches, 5 false
                    // positives in test/run bench): the weighted threatScore
                    // already covers "many suspicious tokens". The residual (more
                    // matched tokens than the file's size predicts) dropped out once
                    // the recon bonus scored what it was catching: its only unique
                    // webshell catches were recon-heavy shells, for 7 false positives.
                    //
                    // Entropy only matters on the high side; a near-empty stub
                    // isn't an outlier worth reviewing.
                    const otherTriggers = (d.zScores.entropy > threshold) ||
                        (Math.abs(d.zScores.mtime) > threshold) ||
                        (Math.abs(d.zScores.ctime) > threshold) ||
                        d.rareOwner ||
                        d.is_blacklisted ||
                        d.mhr_hit === true;
                    // ML points can lift a file over the bar, never pull one under it;
                    // mlOnly marks files flagged only because of them
                    const ruleAnomaly = d.ruleScore >= ANOMALY_SCORE || otherTriggers;
                    const isAnomaly = d.threatScore >= ANOMALY_SCORE || otherTriggers;
                    const mlOnly = isAnomaly && !ruleAnomaly;
                    return { ...d, isAnomaly: isAnomaly, mlOnly: mlOnly };
                });
            }

            // --- End client-side threat scoring ---
            currentThreshold = Z_THRESHOLD;

            // Colour of a threat score: CRITICAL, HIGH RISK, or neither
            function scoreColor(score) {
                return score >= CRITICAL_SCORE ? '#ff4444' : (score >= ANOMALY_SCORE ? '#ffaa00' : '#4a8bc2');
            }

            function isCritical(d) {
                return d.threatScore >= CRITICAL_SCORE || d.is_blacklisted;
            }

            // A status badge in the results; label is HTML, title plain text
            function badgeHtml(label, background, title) {
                return '<span class="badge" style="background:' + background + '"' +
                    (title ? ' title="' + escapeHtml(title) + '"' : '') + '>' + label + '</span> ';
            }

            // Score features with the current Z-threshold and show them
            function reanalyze(features) {
                currentThreshold = parseFloat(document.getElementById('zThreshold').value) || Z_THRESHOLD;
                analyzedData = analyzeData(features, currentThreshold);
                renderTable(analyzedData);
            }

            function shortenUnlinkError(msg) {
                if (!msg) return msg;
                // The file path is already shown right next to this message
                // (the row's own file link, or the <code> path beside it in
                // the warning panel) — repeating it inside "unlink(/long/
                // path): reason" just pushes the actual reason off-screen for
                // anything with a longish path. Keep only the reason.
                return msg.replace(/^unlink\([^)]*\):\s*/, '');
            }

            // Every AJAX call goes through here: fields is {name: value}, the result
            // the parsed JSON (a SyntaxError when the reply isn't JSON, e.g. a host's
            // security rule answered with an HTML page). The custom header is the
            // server's CSRF check (another site can't send it).
            function postAction(fields) {
                var body = new URLSearchParams();
                Object.keys(fields).forEach(function (name) { body.set(name, fields[name]); });
                return fetch('', { method: 'POST', body: body, headers: { 'X-Sussy-Request': '1' } })
                    .then(function (r) { return r.json(); });
            }

            // Paths arrive percent-encoded (byte-exact even when not valid UTF-8);
            // decode for display, falling back to Latin-1 for non-UTF-8 names
            function decodePath(encoded) {
                try { return decodeURIComponent(encoded); } catch (e) { return unescape(encoded); }
            }

            // Row actions use data- attributes and this one listener, not inline
            // onclick="f('...')": the browser undoes HTML escaping before running
            // inline JS, so a file name could break out of the string literal
            document.addEventListener('click', function (e) {
                var el = e.target.closest ? e.target.closest('[data-copy], [data-vt], [data-filter-path]') : null;
                if (!el) return;
                if (el.hasAttribute('data-copy')) copyText(el.getAttribute('data-copy'));
                else if (el.hasAttribute('data-vt')) checkVT(el.getAttribute('data-vt'));
                else filterByPath(el.getAttribute('data-filter-path'));
            });

            function escapeHtml(value) {
                if (value === undefined || value === null) return '';
                return String(value)
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;')
                    .replace(/'/g, '&#039;');
            }

            function copyText(text) {
                if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
                    return navigator.clipboard.writeText(text);
                }
                return new Promise((resolve, reject) => {
                    const textarea = document.createElement('textarea');
                    textarea.value = text;
                    textarea.style.position = 'fixed';
                    textarea.style.left = '-9999px';
                    textarea.style.top = '-9999px';
                    document.body.appendChild(textarea);
                    textarea.focus();
                    textarea.select();
                    try {
                        const success = document.execCommand('copy');
                        document.body.removeChild(textarea);
                        if (success) resolve();
                        else reject(new Error('Copy failed'));
                    } catch (e) {
                        document.body.removeChild(textarea);
                        reject(e);
                    }
                });
            }

            function checkVT(hash) {
                window.open('https://www.virustotal.com/gui/file/' + encodeURIComponent(hash), '_blank', 'noopener');
            }

            // What the table shows: its filters plus any selection made in the charts
            function shouldShowFile(d) {
                return (!_chartSelection || _chartSelection.has(d.path)) && passesTableFilters(d);
            }

            // The search term lowercased, '' for none; worked out once per change, not per row
            let _searchKey = null, _searchLower = '';
            function searchTerm() {
                if (currentSearch !== _searchKey) {
                    _searchKey = currentSearch;
                    _searchLower = currentSearch.trim() ? currentSearch.toLowerCase() : '';
                }
                return _searchLower;
            }

            function passesTableFilters(d) {
                if (currentSearch === '__BLACKLIST__') return d.is_blacklisted === true;
                if (currentFilterMode === 'anomalies' && !d.isAnomaly) return false;
                if (currentFilterMode === 'critical' && !isCritical(d)) return false;
                if (currentFilterMode === 'obfuscated' && (d.entropy <= HIGH_ENTROPY || d.is_unreadable)) return false;

                const term = searchTerm();
                if (!term) return true;
                // Lowercased once per row (rows are rebuilt whenever they are rescored)
                if (d._pathLower === undefined) {
                    d._pathLower = d.path.toLowerCase();
                    d._tokensLower = (d.matched_tokens || []).map(t => t.toLowerCase());
                }
                if (!searchTokensOnly && d._pathLower.includes(term)) return true;
                return d._tokensLower.some(t => t.includes(term));
            }

            // ── Unified warning panel ──────────────────────────────────────────
            // Every failed action, warning, and error — client or server side —
            // surfaces through here instead of scattered alerts/console logs/
            // one-off banners that can say the same thing twice in different
            // places. Two kinds of content are combined into one render:
            //  1. Data-driven: recomputed fresh from the current result set
            //     every render (failed deletions with their file paths,
            //     unreadable files) — never stale, never duplicated.
            //  2. Event log: one-off occurrences that aren't derivable from
            //     the result set (a scan request failing outright, an MHR
            //     auth error) — accumulated across the session, only cleared
            //     when a new scan starts.
            var _eventLog = [];
            var _lastRenderedData = [];

            function resetWarningPanel() {
                _eventLog = [];
                renderWarningPanel(_lastRenderedData);
            }

            function logWarning(message, level) {
                logWarnings([message], level);
            }

            // Several messages, one render
            function logWarnings(messages, level) {
                if (!messages.length) return;
                var time = new Date();
                messages.forEach(function (m) { _eventLog.push({ message: m, level: level || 'warning', time: time }); });
                renderWarningPanel(_lastRenderedData);
                var banner = document.getElementById('warningBanner');
                if (banner) { banner.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }
            }

            // Folds warnings reported by the server (see $phpWarnings / the
            // ajaxRespond() "warnings" field in main.php) into the same panel,
            // instead of letting PHP print them inline and risk corrupting
            // the JSON response they'd be riding along in.
            function reportServerWarnings(data) {
                if (data && Array.isArray(data.warnings)) {
                    logWarnings(data.warnings, 'warning');
                }
            }

            var _renderedEventCount = -1;
            function renderWarningPanel(data) {
                data = data || _lastRenderedData;
                // Sorting and filtering re-render the table, not this
                if (data === _lastRenderedData && _eventLog.length === _renderedEventCount) return;
                _lastRenderedData = data;
                _renderedEventCount = _eventLog.length;
                var banner = document.getElementById('warningBanner');
                if (!banner) return;

                var failedUnlinks = [];
                var unreadable = [];

                (_lastRenderedData || []).forEach(function (d) {
                    if ((d.is_blacklisted || d.mhr_hit) && d.error) {
                        failedUnlinks.push(d);
                    }
                    if (d.is_unreadable) {
                        unreadable.push(d);
                    }
                });

                var html = '';

                if (failedUnlinks.length > 0) {
                    html += '<div style="margin-bottom:6px;">' +
                        '<div style="font-size:11px;color:#ff9999;margin-top:6px;">Failed to delete (' + failedUnlinks.length + ') — file path and reason:</div>' +
                        '<div style="margin-top:4px;text-align:left;max-height:200px;overflow-y:auto;background:#200;padding:8px 12px;border-radius:4px;border:1px solid #900;">';

                    failedUnlinks.forEach(function (f) {
                        html += '<div style="margin:3px 0;font-family:monospace;font-size:12px;"><span style="color:#ff6666;">✖</span> <code style="color:#ffaaaa;">' + escapeHtml(f.path) + '</code> <span style="color:#888;">(' + escapeHtml(shortenUnlinkError(f.error)) + ')</span></div>';
                    });

                    html += '</div></div>';
                }

                if (unreadable.length > 0) {
                    if (html !== '') {
                        html += '<hr style="border:0;border-top:1px solid #633;margin:8px 0;">';
                    }
                    html += '<div style="margin-bottom:6px;">' +
                        '<div style="margin-top:8px;text-align:left;max-height:160px;overflow-y:auto;background:#332b00;padding:8px 12px;border-radius:4px;border:1px solid #b37700;">';

                    unreadable.forEach(function (u) {
                        html += '<div style="margin:3px 0;font-family:monospace;font-size:12px;"><span style="color:#ffaa00;">⚠️</span> <code style="color:#ffcc66;">' + escapeHtml(u.path) + '</code> <span style="color:#888;">(Permission denied)</span></div>';
                    });

                    html += '</div></div>';
                }

                if (_eventLog.length > 0) {
                    if (html !== '') {
                        html += '<hr style="border:0;border-top:1px solid #555;margin:8px 0;">';
                    }
                    html += '<div style="text-align:left;max-height:200px;overflow-y:auto;background:#2a2200;padding:8px 12px;border-radius:4px;border:1px solid #665500;">';

                    _eventLog.forEach(function (e) {
                        var isError = e.level === 'error';
                        var icon = isError ? '✖' : '⚠️';
                        var color = isError ? '#ff6666' : '#ffcc66';
                        html += '<div style="margin:3px 0;font-family:monospace;font-size:12px;">' +
                            '<span style="color:' + color + ';">' + icon + '</span> ' +
                            '<span style="color:#888;">[' + e.time.toLocaleTimeString() + ']</span> ' +
                            '<span style="color:' + color + ';">' + escapeHtml(e.message) + '</span></div>';
                    });

                    html += '</div>';
                }

                if (html !== '') {
                    banner.innerHTML = html;
                    banner.style.display = 'block';
                } else {
                    banner.style.display = 'none';
                    banner.innerHTML = '';
                }
            }
            // ────────────────────────────────────────────────────────────────

            // The rows the table shows, for the charts (a Set lookup per dot rather
            // than the filters), and a counter that changes with every render
            let _shown = new Set();
            let _shownVersion = 0;
            function isShown(d) {
                return _shown.has(d);
            }

            function renderTable(data) {
                renderWarningPanel(data);
                let filtered = data.filter(d => shouldShowFile(d));
                _shown = new Set(filtered);
                _shownVersion++;

                if (currentSort === 'threat') filtered.sort((a, b) => (b.threatScore || 0) - (a.threatScore || 0));
                else if (currentSort === 'mtime') filtered.sort((a, b) => (b.mtime || 0) - (a.mtime || 0));
                else if (currentSort === 'tokens') filtered.sort((a, b) => (b.total_tokens || 0) - (a.total_tokens || 0));
                else if (currentSort === 'zSusp') filtered.sort((a, b) => Math.abs(b.zScores.susp) - Math.abs(a.zScores.susp));
                else if (currentSort === 'residual') filtered.sort((a, b) => (b.residual || 0) - (a.residual || 0));
                else if (currentSort === 'ml') filtered.sort((a, b) => (b.mlScore || 0) - (a.mlScore || 0));

                let html = '';
                if (filtered.length === 0) {
                    html = '<tr><td style="color:#888;text-align:center;padding:15px;">No files match the current search or filters.</td></tr>';
                } else {
                    filtered.forEach(d => {
                        let color = '#dddbdb';
                        let badge = '';
                        let status = '';
                        let verbosity = '';

                        if (d.is_unreadable) {
                            color = '#f72f2f';
                            badge = badgeHtml('NOT READABLE', '#8b0000');
                        } else if (d.is_blacklisted) {
                            color = '#f72f2f';
                            badge = badgeHtml('BLACKLIST', '#cc0000');
                            if (d.error) status = escapeHtml(shortenUnlinkError(d.error));
                        } else if (d.mhr_hit) {
                            color = '#f72f2f';
                            badge = badgeHtml('MHR HIT (' + escapeHtml(String(d.mhr_detection_rate)) + '%)', '#cc0000');
                            status = escapeHtml(d.error ? shortenUnlinkError(d.error) : ('last seen ' + (d.mhr_last_seen || 'unknown')));
                        } else if (d.threatScore >= CRITICAL_SCORE) {
                            color = '#dddbdb';
                            badge = badgeHtml('CRITICAL (' + d.threatScore.toFixed(1) + ')', '#990000');
                        } else if (d.threatScore >= ANOMALY_SCORE) {
                            color = '#dddbdb';
                            badge = badgeHtml('HIGH RISK (' + d.threatScore.toFixed(1) + ')', '#b37700');
                        } else if (d.is_htaccess) {
                            color = '#66ccff';
                            badge = badgeHtml('HTACCESS', '#005580');
                        } else if (d.duplicate_of !== false) {
                            badge = '<span class="badge badge-muted">DUPLICATE</span> ';
                            status = escapeHtml(d.duplicate_of);
                        }

                        if (d.mlPoints > 0) {
                            const why = `ML model ${Math.round(d.mlScore * 100)}%: +${d.mlPoints.toFixed(1)} of the threat score` +
                                (d.mlOnly ? '. Flagged only because of it' : '');
                            badge += badgeHtml('ML +' + d.mlPoints.toFixed(1), '#6a3d9a', why);
                        }

                        if (!status && d.matched_tokens && d.matched_tokens.length > 0) {
                            let tokens = d.matched_tokens.map(t => {
                                if (ROLES.highlight.has(t.toLowerCase())) return '<span class="token-highlight">' + escapeHtml(t) + '</span>';
                                return escapeHtml(t);
                            });
                            status = tokens.join(', ');
                        }

                        if (d.is_unreadable) {
                            verbosity = d.date;
                        } else {
                            const sizeKB = (d.size / 1024).toFixed(1);
                            const entStr = d.entropy !== null ? d.entropy.toFixed(2) : 'N/A';
                            verbosity = `${d.date} | Size: ${sizeKB} KB | Tokens: ${d.total_tokens || 0} | Suspicious: ${d.suspCount} | Entropy: ${entStr} | Score: ${d.threatScore.toFixed(1)}${d.mlScore !== null ? ' (rules ' + d.ruleScore.toFixed(1) + ' + ML ' + d.mlPoints.toFixed(1) + ' from ' + Math.round(d.mlScore * 100) + '%)' : ''} | Z‑Susp: ${d.zScores.susp.toFixed(1)} | Z‑Ctime: ${d.zScores.ctime.toFixed(1)} | Owner: ${d.owner}${d.rareOwner ? ' (RARE)' : ''}`;
                        }

                        const fileLink = `<span class="file-link" data-copy="${escapeHtml(d.path)}">${escapeHtml(d.path)}</span>`;
                        let md5Btn = '';
                        let vtBadge = '';
                        if (!d.is_unreadable && d.md5 && d.md5 !== 'N/A') {
                            md5Btn = `<span class="copy-hash-btn" data-copy="${escapeHtml(d.md5)}" title="Copy MD5 hash">📋</span>`;
                            vtBadge = `<span class="vt-badge" data-vt="${escapeHtml(d.md5)}" title="check on VirusTotal">VT</span>`;
                        }
                        let mainLine = badge + fileLink + md5Btn + vtBadge;
                        if (status) mainLine += ' (' + status + ')';

                        html += `<tr data-path="${escapeHtml(d.path)}">
                            <td style="color:${color}; font-size:13px;">
                                ${mainLine}
                                <br><span class="verbosity">${verbosity}</span>
                            </td>
                        </tr>`;
                    });
                }
                document.getElementById('result').innerHTML = html;
                _rowByPath = new Map();
                _linkedRow = null;
                document.querySelectorAll('#result tr[data-path]').forEach(tr => _rowByPath.set(tr.getAttribute('data-path'), tr));
                syncCharts(data);
            }

            function copyResults() {
                let text = analyzedData
                    .filter(d => shouldShowFile(d))
                    .map(d => {
                        let line = d.path;
                        if (d.is_unreadable) line += ' (NOT_READABLE)';
                        else if (d.is_blacklisted) line += ' (BLACKLIST)';
                        else if (d.mhr_hit) line += ' (MHR HIT ' + d.mhr_detection_rate + '%)';
                        else if (d.mlOnly) line += ' (flagged by ML ' + Math.round(d.mlScore * 100) + '%)';
                        else if (d.is_htaccess) line += ' (HTACCESS)';
                        else if (d.duplicate_of !== false) line += ' (' + d.duplicate_of + ')';
                        else if (d.matched_tokens && d.matched_tokens.length > 0) {
                            line += ' (' + d.matched_tokens.join(', ') + ')';
                        }
                        if (!d.is_unreadable && d.size !== null) {
                            const sizeKB = (d.size / 1024).toFixed(1);
                            line += ` | ${d.date} | Size: ${sizeKB} KB | ThreatScore: ${d.threatScore.toFixed(1)}${d.mlScore !== null ? ' (rules ' + d.ruleScore.toFixed(1) + ' + ML ' + d.mlPoints.toFixed(1) + ' from ' + Math.round(d.mlScore * 100) + '%)' : ''} | Tokens: ${d.total_tokens} | Suspicious: ${d.suspCount} | Z-Susp: ${d.zScores.susp.toFixed(1)}`;
                            if (d.md5 && d.md5 !== 'N/A') line += ` | MD5: ${d.md5}`;
                        } else {
                            line += ` | ${d.date}`;
                        }
                        return line;
                    })
                    .join('\n');
                copyText(text)
                    .then(() => alert('Results copied!'))
                    .catch(() => logWarning('Failed to copy results to clipboard.', 'error'));
            }

            function sortResults(mode) {
                currentSort = mode;
                renderTable(analyzedData);
            }

            function applySeverityFilter() {
                currentFilterMode = document.getElementById('severityFilter').value;
                renderTable(analyzedData);
            }

            function applyThreshold() {
                const input = document.getElementById('zThreshold');
                const val = parseFloat(input.value);
                if (!isNaN(val) && val >= 0) {
                    currentThreshold = val;
                    if (typeof rawFileData !== 'undefined') {
                        analyzedData = flagAnomalies(analyzedData, currentThreshold);
                        renderTable(analyzedData);
                        if (insightsVisible) renderInsights(analyzedData);
                    }
                }
            }

            // While typing: search once the user pauses, not on every keystroke
            var _searchTimer = null;
            function applySearchSoon() {
                clearTimeout(_searchTimer);
                _searchTimer = setTimeout(applySearch, 150);
            }

            function applySearch() {
                clearTimeout(_searchTimer);
                currentSearch = document.getElementById('searchInput').value;
                searchTokensOnly = document.getElementById('searchTokensOnly').checked;
                renderTable(analyzedData);
            }

            function clearFilters() {
                document.getElementById('severityFilter').value = 'all';
                document.getElementById('searchInput').value = '';
                document.getElementById('searchTokensOnly').checked = false;
                currentFilterMode = 'all';
                currentSearch = '';
                searchTokensOnly = false;
                _chartSelection = null;
                renderTable(analyzedData);
            }

            function toggleInsights() {
                insightsVisible = !insightsVisible;
                const panel = document.getElementById('insightsPanel');
                panel.classList.toggle('visible', insightsVisible);
                if (insightsVisible) renderInsights(analyzedData);
            }

            function renderInsights(data) {
                const grid = document.getElementById('insightsGrid');
                const topSuspicious = document.getElementById('topSuspicious');
                const topRecentPanel = document.getElementById('topRecent');

                if (!data || data.length === 0) {
                    grid.innerHTML = '<div class="dashboard-empty">No scan data available. Run SEARCH first.</div>';
                    topSuspicious.innerHTML = '<h4>Top Suspicious Files</h4><div class="dashboard-empty">No data.</div>';
                    topRecentPanel.innerHTML = '<h4>Most Recent Files</h4><div class="dashboard-empty">No data.</div>';
                    return;
                }

                const valid = data.filter(d => !d.is_unreadable && d.size !== null);
                const readable = data.filter(d => !d.is_unreadable);
                const unreadable = data.filter(d => d.is_unreadable).length;
                const blacklisted = data.filter(d => d.is_blacklisted).length;
                const duplicates = data.filter(d => d.duplicate_of !== false).length;
                const htaccess = data.filter(d => d.is_htaccess).length;
                const anomalies = data.filter(d => d.isAnomaly).length;
                const criticalCount = data.filter(isCritical).length;

                let avgSize = 0, minSize = 0, maxSize = 0;
                let avgTokens = 0, minTokens = 0, maxTokens = 0;
                let minMtime = 0, maxMtime = 0;

                if (valid.length > 0) {
                    const sizes = valid.map(d => Number(d.size) || 0);
                    const tokens = valid.map(d => Number(d.total_tokens) || 0);
                    const mtimes = valid.map(d => Number(d.mtime) || 0);

                    avgSize = sizes.reduce((a, b) => a + b, 0) / sizes.length;
                    minSize = Math.min.apply(null, sizes);
                    maxSize = Math.max.apply(null, sizes);

                    avgTokens = tokens.reduce((a, b) => a + b, 0) / tokens.length;
                    minTokens = Math.min.apply(null, tokens);
                    maxTokens = Math.max.apply(null, tokens);

                    minMtime = Math.min.apply(null, mtimes);
                    maxMtime = Math.max.apply(null, mtimes);
                }

                function makeCard(label, value, sub, cls, filterType) {
                    return `<div class="insight-card ${cls}" onclick="applyInsightFilter('${filterType}')">
                        <div class="label">${label}</div>
                        <div class="value">${value}</div>
                        <div class="sub">${sub}</div>
                    </div>`;
                }

                grid.innerHTML = `
                    ${makeCard('Total Files', data.length, `${readable.length} readable, ${unreadable} unreadable`, 'info', 'all')}
                    ${makeCard('Critical Threats', criticalCount, `${anomalies} total anomalies flagged`, criticalCount > 0 ? 'danger' : 'success', 'critical')}
                    ${makeCard('Blacklisted', blacklisted, `${duplicates} duplicates, ${htaccess} .htaccess`, 'warning', 'blacklisted')}
                    ${makeCard('Average Size', `${(avgSize / 1024).toFixed(1)} KB`, `Min ${(minSize / 1024).toFixed(1)} | Max ${(maxSize / 1024).toFixed(1)}`, 'info', 'all')}
                    ${makeCard('Average Tokens', avgTokens.toFixed(0), `Min ${minTokens} | Max ${maxTokens}`, 'purple', 'all')}
                    ${makeCard('Modification Range', formatDate(minMtime), `to ${formatDate(maxMtime)}`, 'info', 'all')}
                `;

                const topSusp = valid.slice().sort((a, b) => (b.threatScore || 0) - (a.threatScore || 0)).slice(0, 5);

                let suspHtml = '<h4>Top Threat Score Files</h4>';
                if (topSusp.length === 0) {
                    suspHtml += '<div class="dashboard-empty">No readable files.</div>';
                } else {
                    suspHtml += '<table>';
                    suspHtml += '<tr><th>File</th><th>Threat Score</th><th>Tokens</th></tr>';
                    topSusp.forEach(d => {
                        const name = String(d.path || '').split('/').pop() || d.path;
                        suspHtml += `<tr class="clickable-row" data-filter-path="${escapeHtml(d.path)}">
                            <td>${escapeHtml(name)}</td>
                            <td><strong style="color:${d.threatScore >= CRITICAL_SCORE ? '#ff4444' : '#ffaa00'}">${d.threatScore.toFixed(1)}</strong></td>
                            <td>${d.suspCount || 0} matched</td>
                        </tr>`;
                    });
                    suspHtml += '</table>';
                }
                topSuspicious.innerHTML = suspHtml;

                const topRecent = valid.slice().sort((a, b) => (Number(b.mtime) || 0) - (Number(a.mtime) || 0)).slice(0, 5);

                let recentHtml = '<h4>Most Recent Files</h4>';
                if (topRecent.length === 0) {
                    recentHtml += '<div class="dashboard-empty">No readable files.</div>';
                } else {
                    recentHtml += '<table><tr><th>File</th><th>Modified</th><th>Size</th></tr>';
                    topRecent.forEach(d => {
                        const name = String(d.path || '').split('/').pop() || d.path;
                        recentHtml += `<tr class="clickable-row" data-filter-path="${escapeHtml(d.path)}">
                            <td>${escapeHtml(name)}</td>
                            <td>${escapeHtml(d.date || 'N/A')}</td>
                            <td>${((Number(d.size) || 0) / 1024).toFixed(1)} KB</td>
                        </tr>`;
                    });
                    recentHtml += '</table>';
                }
                topRecentPanel.innerHTML = recentHtml;
            }

            function applyInsightFilter(type) {
                document.getElementById('searchInput').value = '';
                document.getElementById('searchTokensOnly').checked = false;
                currentSearch = '';
                searchTokensOnly = false;

                if (type === 'critical') {
                    currentFilterMode = 'critical';
                } else if (type === 'blacklisted') {
                    currentSearch = '__BLACKLIST__';
                    currentFilterMode = 'all';
                } else if (type === 'anomaly') {
                    currentFilterMode = 'anomalies';
                } else {
                    currentFilterMode = 'all';
                }
                document.getElementById('severityFilter').value = currentFilterMode;
                renderTable(analyzedData);
            }

            function filterByPath(path) {
                document.getElementById('searchInput').value = path;
                currentSearch = path;
                searchTokensOnly = false;
                document.getElementById('searchTokensOnly').checked = false;
                currentFilterMode = 'all';
                document.getElementById('severityFilter').value = 'all';
                _chartSelection = null;
                renderTable(analyzedData);
            }

            function toggleCharts() {
                chartsVisible = !chartsVisible;
                const panel = document.getElementById('chartsPanel');
                panel.classList.toggle('visible', chartsVisible);
                if (chartsVisible) renderCharts(analyzedData);
            }

            function positionTooltip(e, tooltip) {
                let leftPos = e.clientX + 12;
                let topPos = e.clientY + 12;
                const rect = tooltip.getBoundingClientRect();
                if (leftPos + rect.width > window.innerWidth) {
                    leftPos = e.clientX - rect.width - 12;
                }
                if (topPos + rect.height > window.innerHeight) {
                    topPos = e.clientY - rect.height - 12;
                }
                leftPos = Math.max(0, leftPos);
                topPos = Math.max(0, topPos);
                tooltip.style.left = leftPos + 'px';
                tooltip.style.top = topPos + 'px';
            }

            // ── Charts ───────────────────────────────────────────────────────
            // Four linked views of analyzedData. They share one selection
            // (_chartSelection, a Set of paths) that also filters the table, fade
            // what the table's filters hide, and highlight the file hovered in any
            // chart or table row. Charts are built once per dataset and only
            // redrawn on filter, selection, hover and resize changes; mouse
            // gestures go through one set of document listeners, added once.
            //   drag: select a box (a time range on the timeline); Ctrl/Cmd adds
            //   click: select that file or time bucket; click empty space: clear
            //   Threat Matrix: wheel zooms, Shift+drag pans, double-click resets
            //   Esc or "Clear selection": back to everything
            let _chartSelection = null;
            let _chartSelectionLabel = '';
            let _chartHover = null;          // path hovered in a chart or a table row
            let _charts = [];
            let _chartsData = null;          // the dataset the charts were built from
            let _chartDrag = null;
            let _rowByPath = new Map();
            let _linkedRow = null;
            const CHART_HEIGHT = 300;

            function setChartSelection(paths, label, additive) {
                if (additive && _chartSelection) {
                    paths.forEach(p => _chartSelection.add(p));
                    _chartSelectionLabel = 'several selections';
                } else {
                    _chartSelection = paths.length ? new Set(paths) : null;
                    _chartSelectionLabel = label;
                }
                renderTable(analyzedData);
            }

            function clearChartSelection() {
                if (!_chartSelection) return;
                _chartSelection = null;
                renderTable(analyzedData);
            }

            // renderTable() calls this after every change: rebuild the charts for a
            // new dataset, otherwise just redraw them with the current filters
            function syncCharts(data) {
                const bar = document.getElementById('chartSelectionBar');
                if (_chartSelection) {
                    bar.innerHTML = '<strong>' + _chartSelection.size + '</strong> file(s) selected in the charts (' +
                        escapeHtml(_chartSelectionLabel) + '); the table shows only these. ' +
                        '<button type="button" onclick="clearChartSelection()">Clear selection</button> <span class="hint">or press Esc</span>';
                    bar.style.display = 'block';
                } else {
                    bar.style.display = 'none';
                }
                if (!chartsVisible) return;
                if (data !== _chartsData) renderCharts(data);
                else requestChartRedraw();
            }

            function requestChartRedraw() {
                _charts.forEach(requestDraw);
            }

            // Redraw one chart at the next frame, however many events ask for it
            function requestDraw(c) {
                if (c.queued) return;
                c.queued = true;
                requestAnimationFrame(function () {
                    c.queued = false;
                    c.draw();
                });
            }

            // A dot hovered in a chart outlines its table row; a row hovered in
            // the table rings its dot in every chart
            function setChartHover(path) {
                path = path || null;
                if (path === _chartHover) return;
                _chartHover = path;
                if (_linkedRow) _linkedRow.classList.remove('row-linked');
                _linkedRow = path !== null ? (_rowByPath.get(path) || null) : null;
                if (_linkedRow) _linkedRow.classList.add('row-linked');
                requestChartRedraw();
            }

            document.getElementById('result').addEventListener('mouseover', function (e) {
                const tr = e.target.closest('tr[data-path]');
                setChartHover(tr ? tr.getAttribute('data-path') : null);
            });
            document.getElementById('result').addEventListener('mouseleave', function () { setChartHover(null); });

            function chartPoint(c, e) {
                const r = c.canvas.getBoundingClientRect();
                return { x: e.clientX - r.left, y: e.clientY - r.top };
            }

            // Backing store at the device pixel ratio (sharp on HiDPI), drawn in CSS pixels
            function sizeChart(c) {
                const dpr = window.devicePixelRatio || 1;
                c.w = c.canvas.clientWidth || 900;
                c.h = CHART_HEIGHT;
                c.canvas.width = Math.round(c.w * dpr);
                c.canvas.height = Math.round(c.h * dpr);
                c.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            }

            // spec: draw(c) fills c.marks for hit testing; hit(c, x, y) returns
            // { paths, label, html, hoverPath } or null; optional brush ('xy' box or
            // 'x' range) with pathsIn(c, rect); optional zoom/pan/reset
            function makeChart(grid, title, spec) {
                const box = document.createElement('div');
                box.className = 'chart-box';
                const titleEl = document.createElement('div');
                titleEl.className = 'chart-title';
                titleEl.textContent = title;
                box.appendChild(titleEl);
                const canvas = document.createElement('canvas');
                box.appendChild(canvas);
                grid.appendChild(box);

                const c = { title: title, canvas: canvas, ctx: canvas.getContext('2d'), marks: [], brush: spec.brush || null };
                ['hit', 'pathsIn', 'zoom', 'pan', 'reset'].forEach(k => { if (spec[k]) c[k] = spec[k].bind(null, c); });
                c.draw = function () {
                    c.ctx.clearRect(0, 0, c.w, c.h);
                    c.ctx.fillStyle = '#2a2a2a';
                    c.ctx.fillRect(0, 0, c.w, c.h);
                    c.marks = [];
                    spec.draw(c);
                    drawBrush(c);
                };
                sizeChart(c);
                bindChartEvents(c);
                _charts.push(c);
                c.draw();
            }

            function bindChartEvents(c) {
                const canvas = c.canvas;
                const tooltip = document.getElementById('chart-tooltip');
                canvas.addEventListener('mousemove', function (e) {
                    if (_chartDrag) return;
                    const p = chartPoint(c, e);
                    const hit = c.hit(p.x, p.y);
                    if (hit) {
                        tooltip.innerHTML = hit.html;
                        tooltip.style.display = 'block';
                        positionTooltip(e, tooltip);
                    } else {
                        tooltip.style.display = 'none';
                    }
                    canvas.style.cursor = hit ? 'pointer' : 'crosshair';
                    setChartHover(hit ? hit.hoverPath : null);
                });
                canvas.addEventListener('mouseleave', function () {
                    tooltip.style.display = 'none';
                    if (!_chartDrag) setChartHover(null);
                });
                canvas.addEventListener('mousedown', function (e) {
                    if (e.button !== 0) return;
                    e.preventDefault();
                    const p = chartPoint(c, e);
                    tooltip.style.display = 'none';
                    _chartDrag = { c: c, x0: p.x, y0: p.y, x: p.x, y: p.y, moved: false,
                        pan: e.shiftKey && !!c.pan, additive: e.ctrlKey || e.metaKey };
                });
                if (c.zoom) {
                    canvas.addEventListener('wheel', function (e) {
                        e.preventDefault();
                        const p = chartPoint(c, e);
                        c.zoom(p.x, p.y, e.deltaY > 0 ? 1.08 : 0.925);
                        requestDraw(c);
                    }, { passive: false });
                }
                if (c.reset) {
                    canvas.addEventListener('dblclick', function () { c.reset(); c.draw(); });
                }
            }

            document.addEventListener('mousemove', function (e) {
                const g = _chartDrag;
                if (!g) return;
                const p = chartPoint(g.c, e);
                if (Math.abs(p.x - g.x0) + Math.abs(p.y - g.y0) > 4) g.moved = true;
                if (g.pan) g.c.pan(p.x - g.x, p.y - g.y);
                g.x = p.x;
                g.y = p.y;
                requestDraw(g.c);
            });
            document.addEventListener('mouseup', function () {
                const g = _chartDrag;
                if (!g) return;
                _chartDrag = null;
                if (!g.moved) {
                    const hit = g.c.hit(g.x0, g.y0);
                    if (hit) setChartSelection(hit.paths, hit.label, g.additive);
                    else if (!g.additive) clearChartSelection();
                } else if (!g.pan && g.c.brush) {
                    const rect = { x0: Math.min(g.x0, g.x), x1: Math.max(g.x0, g.x), y0: Math.min(g.y0, g.y), y1: Math.max(g.y0, g.y) };
                    setChartSelection(g.c.pathsIn(rect), (g.c.brush === 'x' ? 'range' : 'box') + ' on ' + g.c.title, g.additive);
                }
                g.c.draw();
            });
            document.addEventListener('keydown', function (e) {
                if (e.key === 'Escape') clearChartSelection();
            });
            let _chartResizeTimer = null;
            window.addEventListener('resize', function () {
                clearTimeout(_chartResizeTimer);
                _chartResizeTimer = setTimeout(function () {
                    if (!chartsVisible) return;
                    _charts.forEach(function (c) { sizeChart(c); c.draw(); });
                }, 150);
            });

            function drawBrush(c) {
                const g = _chartDrag;
                if (!g || g.c !== c || !g.moved || g.pan || !c.brush) return;
                const x = Math.min(g.x0, g.x), w = Math.abs(g.x - g.x0);
                const y = c.brush === 'x' ? 0 : Math.min(g.y0, g.y), h = c.brush === 'x' ? c.h : Math.abs(g.y - g.y0);
                const ctx = c.ctx;
                ctx.save();
                ctx.fillStyle = 'rgba(74, 139, 194, 0.15)';
                ctx.strokeStyle = '#4a8bc2';
                ctx.setLineDash([4, 3]);
                ctx.fillRect(x, y, w, h);
                ctx.strokeRect(x + 0.5, y + 0.5, w, h);
                ctx.restore();
            }

            function drawAxes(ctx, left, top, right, bottom) {
                ctx.strokeStyle = '#555';
                ctx.lineWidth = 1;
                ctx.beginPath();
                ctx.moveTo(left, top);
                ctx.lineTo(left, bottom);
                ctx.lineTo(right, bottom);
                ctx.stroke();
            }

            function drawLabel(ctx, text, x, y, align, color) {
                ctx.fillStyle = color || '#aaa';
                ctx.font = '12px Ubuntu Mono, monospace';
                ctx.textAlign = align || 'left';
                ctx.fillText(text, x, y);
            }

            // Dots ({x, y, d, color}): files the table currently hides are faded and
            // drawn first so the visible ones stay on top; the hovered file gets a ring
            function drawDots(c, dots, radius) {
                const ctx = c.ctx;
                const faded = [], shown = [];
                dots.forEach(p => (isShown(p.d) ? shown : faded).push(p));
                const paint = p => { ctx.fillStyle = p.color; ctx.beginPath(); ctx.arc(p.x, p.y, radius, 0, Math.PI * 2); ctx.fill(); };
                ctx.globalAlpha = 0.15;
                faded.forEach(paint);
                ctx.globalAlpha = 1;
                shown.forEach(paint);
                c.marks = faded.concat(shown);
                const hover = _chartHover !== null ? c.marks.find(p => p.d.path === _chartHover) : null;
                if (hover) {
                    ctx.strokeStyle = '#fff';
                    ctx.lineWidth = 2;
                    ctx.beginPath(); ctx.arc(hover.x, hover.y, radius + 4, 0, Math.PI * 2); ctx.stroke();
                }
            }

            function dotAt(c, x, y) {
                for (let i = c.marks.length - 1; i >= 0; i--) { // top-most first
                    const m = c.marks[i];
                    if ((m.x - x) ** 2 + (m.y - y) ** 2 < 64) return m;
                }
                return null;
            }

            function dotsIn(c, r) {
                return c.marks.filter(m => m.x >= r.x0 && m.x <= r.x1 && m.y >= r.y0 && m.y <= r.y1).map(m => m.d.path);
            }

            function tooltipRows(rows) {
                return rows.map(r => '<div><span class="label">' + r[0] + ':</span> <span class="value">' + r[1] + '</span></div>').join('');
            }

            function fileHit(m, extraRows) {
                if (!m) return null;
                const d = m.d;
                const rows = [['File', escapeHtml(d.path)], ['Threat Score', d.threatScore.toFixed(1)]]
                    .concat(extraRows(d), [['Matched', escapeHtml((d.matched_tokens || []).join(', '))]]);
                return { paths: [d.path], label: d.path.split('/').pop(), hoverPath: d.path, html: tooltipRows(rows) };
            }

            function renderCharts(data) {
                const grid = document.getElementById('chartsGrid');
                grid.innerHTML = '';
                _charts = [];
                _chartsData = data;

                const valid = (data || []).filter(d => !d.is_unreadable && d.size !== null && d.mtime !== null);
                if (valid.length < 2) {
                    grid.innerHTML = '<div class="dashboard-empty">Not enough readable files to render charts.</div>';
                    return;
                }

                // 1. THREAT MATRIX: the threat score's two parts against each other.
                // Up: the rule score (log scale: it runs from 0 to the thousands, and
                // the anomaly bar at 8 must stay visible). Right: the ML score. The
                // dividers are the scanner's own bars (ANOMALY_SCORE, ML_THRESHOLD), so
                // the quadrants say which detector flags a file; each dot is coloured
                // by the file's verdict, as in the table. Without a model the x axis
                // falls back to the share of a file's tokens that are needles.
                {
                    const withMl = valid.some(d => d.mlScore !== null);
                    const xOf = withMl ? (d => d.mlScore || 0) : (d => d.total_tokens > 0 ? (d.suspCount || 0) / d.total_tokens : 0);
                    const toY = v => Math.log10(1 + Math.max(0, v));   // rule score -> axis units
                    const pts = valid.map(d => ({ d: d, x: xOf(d), y: toY(d.ruleScore || 0) }));
                    const maxX = withMl ? 1 : Math.max(0.01, ...pts.map(p => p.x)) * 1.1;
                    const maxY = Math.max(toY(CRITICAL_SCORE) * 1.3, ...pts.map(p => p.y)) * 1.08;
                    const fit = () => ({ xLo: 0, xHi: maxX, yLo: 0, yHi: maxY });
                    let view = fit();
                    const area = c => ({ left: 70, top: 30, right: c.w - 30, bottom: c.h - 45 });
                    const verdictColor = d => isCritical(d) ? '#ff4444' : (d.isAnomaly ? '#ffaa00' : '#5a6b7a');

                    makeChart(grid, withMl ? 'Threat Matrix: Rule Score vs ML Score' : 'Threat Matrix: Rule Score vs Suspicious Token Ratio', {
                        brush: 'xy',
                        draw: function (c) {
                            const ctx = c.ctx, b = area(c), W = b.right - b.left, H = b.bottom - b.top;
                            const xR = view.xHi - view.xLo || 1, yR = view.yHi - view.yLo || 1;
                            const sx = v => b.left + ((v - view.xLo) / xR) * W;
                            const sy = t => b.bottom - ((t - view.yLo) / yR) * H;
                            drawAxes(ctx, b.left, b.top, b.right, b.bottom);

                            // dividers at the scanner's own bars
                            const qy = sy(toY(ANOMALY_SCORE)), qx = withMl ? sx(ML_THRESHOLD) : null;
                            ctx.save(); ctx.strokeStyle = '#666'; ctx.lineWidth = 1; ctx.setLineDash([5, 4]);
                            ctx.beginPath();
                            if (qy > b.top && qy < b.bottom) { ctx.moveTo(b.left, qy); ctx.lineTo(b.right, qy); }
                            if (qx !== null && qx > b.left && qx < b.right) { ctx.moveTo(qx, b.top); ctx.lineTo(qx, b.bottom); }
                            ctx.stroke(); ctx.restore();
                            ctx.font = '10px Ubuntu Mono, monospace'; ctx.fillStyle = '#999';
                            if (withMl) {
                                ctx.textAlign = 'right'; ctx.fillText('RULES + ML', b.right - 4, b.top + 14);
                                ctx.textAlign = 'left';  ctx.fillText('RULES ONLY', b.left + 4, b.top + 14);
                                ctx.textAlign = 'right'; ctx.fillText('ML ONLY', b.right - 4, b.bottom - 6);
                                ctx.textAlign = 'left';  ctx.fillText('NEITHER', b.left + 4, b.bottom - 6);
                            } else {
                                ctx.textAlign = 'left'; ctx.fillText('RULES FLAG', b.left + 4, b.top + 14);
                                ctx.fillText('BELOW THE RULES BAR', b.left + 4, b.bottom - 6);
                            }

                            // y ticks at round scores (log axis); x ticks evenly
                            ctx.fillStyle = '#888'; ctx.font = '10px Ubuntu Mono, monospace'; ctx.textAlign = 'right';
                            [0, 1, 3, ANOMALY_SCORE, CRITICAL_SCORE, 30, 100, 300, 1000, 3000, 10000].forEach(v => {
                                const y = sy(toY(v));
                                if (y >= b.top - 1 && y <= b.bottom + 1) ctx.fillText(String(v), b.left - 4, y + 4);
                            });
                            ctx.textAlign = 'center';
                            for (let t = 0; t <= 5; t++) {
                                const vx = view.xLo + (xR * t) / 5;
                                ctx.fillText(withMl ? vx.toFixed(2) : (vx * 100).toFixed(1) + '%', sx(vx), b.bottom + 14);
                            }

                            // axis labels and colour key
                            ctx.fillStyle = '#aaa'; ctx.font = '11px Ubuntu Mono, monospace'; ctx.textAlign = 'center';
                            ctx.fillText((withMl ? 'ML Score' : 'Suspicious Token Ratio') + ' (wheel: zoom · Shift+drag: pan · double-click: reset)', b.left + W / 2, b.bottom + 30);
                            ctx.save(); ctx.translate(14, b.top + H / 2); ctx.rotate(-Math.PI / 2);
                            ctx.fillText('Rule Score (log)', 0, 0); ctx.restore();
                            let lx = b.left + W / 2 - 150;
                            [['#ff4444', 'critical'], ['#ffaa00', 'anomaly'], ['#5a6b7a', 'not flagged']].forEach(([color, label]) => {
                                ctx.fillStyle = color; ctx.beginPath(); ctx.arc(lx, b.top - 12, 4, 0, Math.PI * 2); ctx.fill();
                                ctx.fillStyle = '#aaa'; ctx.textAlign = 'left'; ctx.fillText(label, lx + 8, b.top - 8);
                                lx += ctx.measureText(label).width + 30;
                            });

                            const dots = [];
                            pts.forEach(p => {
                                const x = sx(p.x), y = sy(p.y);
                                if (x < b.left || x > b.right || y < b.top || y > b.bottom) return;
                                dots.push({ x: x, y: y, d: p.d, color: verdictColor(p.d) });
                            });
                            drawDots(c, dots, 3.5);
                        },
                        hit: (c, x, y) => fileHit(dotAt(c, x, y), d => [
                            ['Rule Score', (d.ruleScore || 0).toFixed(1)],
                            ['ML Score', d.mlScore === null ? 'n/a' : d.mlScore.toFixed(3) + ' (+' + d.mlPoints.toFixed(1) + ' points)'],
                            ['Verdict', isCritical(d) ? 'critical' : (d.isAnomaly ? 'anomaly' : 'not flagged')],
                        ]),
                        pathsIn: dotsIn,
                        zoom: function (c, x, y, f) {
                            const b = area(c);
                            const fx = Math.max(0, Math.min(1, (x - b.left) / (b.right - b.left)));
                            const fy = Math.max(0, Math.min(1, (y - b.top) / (b.bottom - b.top)));
                            const xR = view.xHi - view.xLo, yR = view.yHi - view.yLo;
                            const pivX = view.xLo + fx * xR, pivY = view.yHi - fy * yR;
                            view.xLo = Math.max(0, pivX - fx * xR * f);
                            view.xHi = pivX + (1 - fx) * xR * f;
                            view.yLo = Math.max(0, pivY - (1 - fy) * yR * f);
                            view.yHi = pivY + fy * yR * f;
                        },
                        pan: function (c, dx, dy) {
                            const b = area(c);
                            const ux = dx / (b.right - b.left) * (view.xHi - view.xLo);
                            const uy = dy / (b.bottom - b.top) * (view.yHi - view.yLo);
                            view.xLo -= ux; view.xHi -= ux;
                            view.yLo += uy; view.yHi += uy;
                            if (view.xLo < 0) { view.xHi -= view.xLo; view.xLo = 0; }
                            if (view.yLo < 0) { view.yHi -= view.yLo; view.yLo = 0; }
                        },
                        reset: function () { view = fit(); },
                    });
                }

                // 2. TIMELINE: modifications per time bucket. The grey bar counts every
                // file in the bucket, the coloured part only those the table shows.
                {
                    const mtimes = valid.map(d => d.mtime).filter(t => t > 0).sort((a, b) => a - b);
                    if (mtimes.length > 0) {
                        const minT = mtimes[0];
                        const maxT = mtimes[mtimes.length - 1];
                        const span = Math.max(1, maxT - minT);

                        // Quantize into "nice" round time units (sec/min/hour/day/week/month)
                        // instead of an arbitrary span/20 slice, so each bucket boundary
                        // lands on a human-readable interval.
                        const NICE_BUCKETS = [
                            1, 5, 10, 15, 30,
                            60, 300, 600, 900, 1800,
                            3600, 7200, 21600, 43200,
                            86400, 2 * 86400, 7 * 86400, 14 * 86400,
                            30 * 86400, 90 * 86400, 180 * 86400, 365 * 86400
                        ];
                        const idealSize = span / 20;
                        let bucketSize = NICE_BUCKETS[NICE_BUCKETS.length - 1];
                        for (const candidate of NICE_BUCKETS) {
                            if (candidate >= idealSize) { bucketSize = candidate; break; }
                        }

                        // Align the first bucket to a clean boundary (e.g. day buckets
                        // start at UTC midnight) rather than the raw earliest timestamp.
                        const startT = Math.floor(minT / bucketSize) * bucketSize;
                        const numBuckets = Math.max(1, Math.ceil((maxT - startT + 1) / bucketSize));
                        const buckets = [];
                        for (let i = 0; i < numBuckets; i++) buckets.push({ files: [], maxThreat: 0, time: startT + i * bucketSize });
                        valid.forEach(d => {
                            if (!d.mtime) return;
                            const idx = Math.max(0, Math.min(numBuckets - 1, Math.floor((d.mtime - startT) / bucketSize)));
                            buckets[idx].files.push(d);
                            if (d.threatScore > buckets[idx].maxThreat) buckets[idx].maxThreat = d.threatScore;
                        });
                        const maxCount = Math.max(1, ...buckets.map(k => k.files.length));
                        const area = c => ({ left: 60, top: 25, right: c.w - 30, bottom: c.h - 50 });

                        makeChart(grid, 'Incident Timeline: File Modifications over Time', {
                            brush: 'x',
                            draw: function (c) {
                                const ctx = c.ctx, b = area(c), H = b.bottom - b.top;
                                const slot = (b.right - b.left) / numBuckets;
                                drawAxes(ctx, b.left, b.top, b.right, b.bottom);
                                buckets.forEach((k, i) => {
                                    const x = b.left + i * slot + 1, w = Math.max(1, slot - 3);
                                    const shown = k.files.filter(isShown);
                                    const hAll = (k.files.length / maxCount) * H, hShown = (shown.length / maxCount) * H;
                                    ctx.fillStyle = '#3a3a3a';
                                    ctx.fillRect(x, b.bottom - hAll, w, hAll);
                                    const top = shown.reduce((m, d) => Math.max(m, d.threatScore || 0), 0);
                                    ctx.fillStyle = scoreColor(top);
                                    ctx.fillRect(x, b.bottom - hShown, w, hShown);
                                    if (_chartHover !== null && k.files.some(d => d.path === _chartHover)) {
                                        ctx.strokeStyle = '#fff'; ctx.lineWidth = 2;
                                        ctx.strokeRect(x - 1, b.bottom - hAll - 1, w + 2, hAll + 2);
                                    }
                                    c.marks.push({ x0: b.left + i * slot, x1: b.left + (i + 1) * slot, bucket: k, shown: shown.length });
                                });
                                drawLabel(ctx, formatDate(minT), b.left, b.bottom + 20, 'left');
                                drawLabel(ctx, formatDate(maxT), b.right, b.bottom + 20, 'right');
                                drawLabel(ctx, 'File Count', 8, b.top - 8, 'left');
                                ctx.fillStyle = '#aaa'; ctx.font = '11px Ubuntu Mono, monospace'; ctx.textAlign = 'center';
                                ctx.fillText('Grey: all files · colour: files the table shows (click a bar or drag a range to select)', b.left + (b.right - b.left) / 2, b.bottom + 38);
                            },
                            hit: function (c, x, y) {
                                const b = area(c);
                                if (y < b.top || y > b.bottom) return null;
                                const m = c.marks.find(m => x >= m.x0 && x < m.x1);
                                if (!m || m.bucket.files.length === 0) return null;
                                const k = m.bucket;
                                return {
                                    paths: k.files.map(d => d.path),
                                    label: formatDate(k.time) + ' to ' + formatDate(k.time + bucketSize),
                                    hoverPath: null,
                                    html: tooltipRows([
                                        ['Timeframe', formatDate(k.time)],
                                        ['Files Modified', k.files.length + (m.shown !== k.files.length ? ' (' + m.shown + ' shown)' : '')],
                                        ['Max Threat Score', k.maxThreat.toFixed(1)],
                                    ]),
                                };
                            },
                            pathsIn: function (c, r) {
                                let paths = [];
                                c.marks.forEach(m => { if (m.x1 > r.x0 && m.x0 < r.x1) paths = paths.concat(m.bucket.files.map(d => d.path)); });
                                return paths;
                            },
                        });
                    }
                }

                // 3. TOP THREAT SCORES among the files the table's filters let
                // through; bars outside the chart selection are faded
                {
                    const area = c => ({ left: 200, top: 20, right: c.w - 30, bottom: c.h - 20 });
                    let topFor = -1, top = [];
                    makeChart(grid, 'Top Composite Threat Scores', {
                        draw: function (c) {
                            const ctx = c.ctx, b = area(c);
                            if (topFor !== _shownVersion) { // a hover redraw reuses it
                                topFor = _shownVersion;
                                top = valid.filter(d => passesTableFilters(d))
                                    .sort((a, z) => (z.threatScore || 0) - (a.threatScore || 0)).slice(0, 12);
                            }
                            if (!top.length) {
                                drawLabel(ctx, 'No files match the current filters.', c.w / 2, c.h / 2, 'center', '#888');
                                return;
                            }
                            const rowH = (b.bottom - b.top) / 12;
                            const maxScore = Math.max(10.0, ...top.map(d => d.threatScore || 0));
                            top.forEach((d, i) => {
                                const score = d.threatScore || 0;
                                const y = b.top + i * rowH + 3, h = Math.max(8, rowH - 6);
                                const w = (score / maxScore) * (b.right - b.left);
                                ctx.globalAlpha = _chartSelection && !_chartSelection.has(d.path) ? 0.25 : 1;
                                ctx.fillStyle = scoreColor(score);
                                ctx.fillRect(b.left, y, w, h);
                                const name = String(d.path || '').split('/').pop() || d.path;
                                drawLabel(ctx, name.length > 26 ? name.slice(0, 23) + '...' : name, b.left - 8, y + h / 2 + 4, 'right');
                                // The value goes after the bar, or inside its end when there's no room
                                const text = score.toFixed(1);
                                ctx.font = '12px Ubuntu Mono, monospace';
                                if (b.left + w + 6 + ctx.measureText(text).width <= c.w - 4) drawLabel(ctx, text, b.left + w + 6, y + h / 2 + 4, 'left');
                                else drawLabel(ctx, text, b.left + w - 6, y + h / 2 + 4, 'right', '#fff');
                                ctx.globalAlpha = 1;
                                if (d.path === _chartHover) {
                                    ctx.strokeStyle = '#fff'; ctx.lineWidth = 2;
                                    ctx.strokeRect(b.left - 1, y - 1, w + 2, h + 2);
                                }
                                c.marks.push({ y: y, h: h, d: d });
                            });
                        },
                        hit: function (c, x, y) {
                            const m = c.marks.find(m => y >= m.y && y <= m.y + m.h);
                            return fileHit(m, d => [['MD5', '<span class="mono">' + escapeHtml(d.md5) + '</span>']]);
                        },
                    });
                }

                // 4. ENTROPY: every file sorted by entropy, so packed payloads sit
                // top-right; the Y range follows the data
                {
                    const sorted = valid.slice().sort((a, b) => (a.entropy || 0) - (b.entropy || 0));
                    const vals = sorted.map(d => d.entropy || 0);
                    const eMin = vals[0] || 0, eMax = vals[vals.length - 1] || 1;
                    const pad = Math.max(0.05, (eMax - eMin) * 0.06);
                    const yLo = Math.max(0, eMin - pad), yHi = eMax + pad, yR = yHi - yLo || 1;
                    const pct = q => vals[Math.floor(vals.length * q)] || 0;
                    const area = c => ({ left: 55, top: 25, right: c.w - 30, bottom: c.h - 40 });

                    makeChart(grid, 'Entropy Distribution (sorted, data-density range)', {
                        brush: 'xy',
                        draw: function (c) {
                            const ctx = c.ctx, b = area(c), W = b.right - b.left, H = b.bottom - b.top;
                            const sy = v => b.bottom - ((v - yLo) / yR) * H;

                            [[pct(0.25), '#3a5a3a', 'P25'], [pct(0.50), '#5a5a2a', 'P50'], [pct(0.75), '#5a3a2a', 'P75']].forEach(function ([pv, col, lbl]) {
                                ctx.save();
                                ctx.strokeStyle = col; ctx.lineWidth = 1; ctx.setLineDash([4, 4]);
                                ctx.beginPath(); ctx.moveTo(b.left, sy(pv)); ctx.lineTo(b.right, sy(pv)); ctx.stroke();
                                ctx.setLineDash([]);
                                ctx.fillStyle = col; ctx.font = '10px Ubuntu Mono, monospace'; ctx.textAlign = 'left';
                                ctx.fillText(lbl + ' ' + pv.toFixed(2), b.left + 4, sy(pv) - 3);
                                ctx.restore();
                            });
                            drawAxes(ctx, b.left, b.top, b.right, b.bottom);

                            ctx.fillStyle = '#888'; ctx.font = '10px Ubuntu Mono, monospace'; ctx.textAlign = 'right';
                            for (let t = 0; t <= 5; t++) {
                                const v = yLo + (yR * t) / 5;
                                ctx.fillText(v.toFixed(2), b.left - 4, sy(v) + 4);
                            }
                            ctx.fillStyle = '#aaa'; ctx.font = '11px Ubuntu Mono, monospace'; ctx.textAlign = 'center';
                            ctx.fillText('Files sorted by entropy (low → high)', b.left + W / 2, b.bottom + 18);
                            ctx.save(); ctx.translate(13, b.top + H / 2); ctx.rotate(-Math.PI / 2);
                            ctx.fillText('Shannon Entropy', 0, 0); ctx.restore();

                            drawDots(c, sorted.map((d, i) => {
                                let color = '#4a8bc2';
                                if (d.threatScore >= CRITICAL_SCORE) color = '#ff4444';
                                else if (d.threatScore >= ANOMALY_SCORE) color = '#ffaa00';
                                else if ((d.entropy || 0) > HIGH_ENTROPY) color = '#9b59b6';
                                return { x: b.left + (i / Math.max(1, sorted.length - 1)) * W, y: sy(d.entropy || 0), d: d, color: color };
                            }), 3);

                            const leg = [['#ff4444', 'Critical (≥15)'], ['#ffaa00', 'High Risk (≥8)'], ['#9b59b6', 'High Entropy (>' + HIGH_ENTROPY + ')'], ['#4a8bc2', 'Normal']];
                            let lx = b.left + 4;
                            leg.forEach(function ([col, lbl]) {
                                ctx.fillStyle = col; ctx.beginPath(); ctx.arc(lx + 5, b.top + 12, 4, 0, Math.PI * 2); ctx.fill();
                                ctx.fillStyle = '#aaa'; ctx.font = '10px Ubuntu Mono, monospace'; ctx.textAlign = 'left';
                                ctx.fillText(lbl, lx + 13, b.top + 16);
                                lx += ctx.measureText(lbl).width + 26;
                            });
                        },
                        hit: (c, x, y) => fileHit(dotAt(c, x, y), d => [['Entropy', (d.entropy || 0).toFixed(4)]]),
                        pathsIn: dotsIn,
                    });
                }
            }

            // ── Chunked AJAX scan ────────────────────────────────────────────
            var _scanCancelled = false;
            // md5 => path of the first file seen with it, for duplicate_of across batches
            var _firstPathByMd5 = new Map();
            var _lastProgressRender = 0;

            function getChunkSize() {
                var el = document.getElementById('chunkSizeInput');
                var val = el ? parseInt(el.value, 10) : 25;
                if (isNaN(val) || val < 1) {
                    val = 25;
                }
                return val;
            }


            function startChunkedScan() {
                var dirInput = document.querySelector('input[name="dir"]');
                var dir = dirInput ? dirInput.value.trim() : '';
                if (!dir) { logWarning('Enter a directory path first.', 'error'); return; }

                var chunkSize = getChunkSize();
                _scanCancelled = false;
                _firstPathByMd5 = new Map();
                _lastProgressRender = Date.now();
                _chartSelection = null;
                var allFeatures = [];

                resetWarningPanel();

                document.getElementById('ajaxProgress').style.display = 'block';
                document.getElementById('ajaxBar').style.width = '0%';
                document.getElementById('ajaxStatus').textContent = 'Phase 1: Scanning directory\u2026';
                document.getElementById('ajaxSubStatus').textContent = '';
                document.getElementById('result').innerHTML = '';
                analyzedData = [];

                postAction({ ajax_action: 'scan', dir: dir })
                    .then(function(data) {
                        if (_scanCancelled) { return; }
                        reportServerWarnings(data);
                        var readable    = data.readable    || [];
                        var notReadable = data.not_readable || [];
                        var total       = data.total || (readable.length + notReadable.length);

                        document.getElementById('ajaxStatus').textContent =
                            'Phase 2: Processing ' + total + ' files\u2026 (chunk size: ' + chunkSize + ')';

                        // Build flat chunk list
                        var chunks = [];
                        for (var i = 0; i < readable.length; i += chunkSize) {
                            chunks.push({ paths: readable.slice(i, i + chunkSize), isNotReadable: false });
                        }
                        for (var j = 0; j < notReadable.length; j += chunkSize) {
                            chunks.push({ paths: notReadable.slice(j, j + chunkSize), isNotReadable: true });
                        }

                        return processChunk(chunks, 0, allFeatures, total, chunkSize);
                    })
                    .then(function() {
                        if (_scanCancelled) { return; }
                        document.getElementById('ajaxProgress').style.display = 'none';
                        window.rawFileData = allFeatures;
                        window.lastScanFeatures = allFeatures;
                        reanalyze(allFeatures);
                    })
                    .catch(function(err) {
                        document.getElementById('ajaxProgress').style.display = 'none';
                        logWarning('AJAX scan error: ' + err.message, 'error');
                    });
            }

            // One 'process' request for a batch of paths (see postAction() for failures)
            function fetchProcessBatch(paths, isNotReadable) {
                return postAction({
                    ajax_action: 'process',
                    is_not_readable: isNotReadable ? '1' : '0',
                    paths: paths.join(','),
                    ml: (typeof ML_MODEL !== 'undefined' && ML_MODEL) ? '1' : '0', // no model: skip ML features
                });
            }

            // Batches arrive in scan order, so the first file with an MD5 is the
            // original and later ones are its duplicates
            function applyProcessResult(data, allFeatures) {
                reportServerWarnings(data);
                (data.features || []).forEach(function(f) {
                    f.pathRaw = f.path; // encoded form, sent back as-is
                    f.path = decodePath(f.path);
                    f.duplicate_of = false;
                    if (!f.is_unreadable) {
                        if (_firstPathByMd5.has(f.md5)) f.duplicate_of = _firstPathByMd5.get(f.md5);
                        else _firstPathByMd5.set(f.md5, f.path);
                    }
                    allFeatures.push(f);
                });
            }

            // A batch that fails to parse as JSON usually means exactly one
            // path in it tripped something server-side (a WAF/security rule,
            // an open_basedir restriction, etc.) that blocked the whole
            // request \u2014 not that every file in the batch is a problem.
            // Bisect the batch and retry each half, splitting again on
            // failure, down to individual files if needed \u2014 so a batch of
            // 500 with one bad file costs a handful of requests instead of
            // 500 individual ones.
            function retryProcessBisect(paths, isNotReadable, allFeatures) {
                return fetchProcessBatch(paths, isNotReadable)
                    .then(function(data) { applyProcessResult(data, allFeatures); })
                    .catch(function(err) {
                        if (!(err instanceof SyntaxError) || paths.length <= 1) {
                            if (paths.length === 1) {
                                logWarning('Skipped ' + paths[0] + ' \u2014 ' + err.message, 'error');
                            } else {
                                logWarning('Failed to process ' + paths.length + ' file(s): ' + err.message, 'error');
                            }
                            return;
                        }
                        var mid = Math.ceil(paths.length / 2);
                        var left = paths.slice(0, mid);
                        var right = paths.slice(mid);
                        return retryProcessBisect(left, isNotReadable, allFeatures)
                            .then(function() { return retryProcessBisect(right, isNotReadable, allFeatures); });
                    });
            }

            function processChunk(chunks, idx, allFeatures, totalFiles, chunkSize) {
                if (_scanCancelled || idx >= chunks.length) { return Promise.resolve(); }

                var chunk = chunks[idx];
                var done  = Math.min(idx * chunkSize, totalFiles);
                var pct   = totalFiles > 0 ? Math.round(done / totalFiles * 100) : 0;

                document.getElementById('ajaxBar').style.width = pct + '%';
                document.getElementById('ajaxSubStatus').textContent =
                    'Chunk ' + (idx + 1) + '/' + chunks.length + ' \u2014 ' + done + '/' + totalFiles + ' files (' + pct + '%)';

                return fetchProcessBatch(chunk.paths, chunk.isNotReadable)
                    .then(function(data) {
                        if (_scanCancelled) { return; }
                        applyProcessResult(data, allFeatures);
                    })
                    .catch(function(err) {
                        // A small obstacle (one bad path, one bad chunk) should
                        // never stop the entire scan \u2014 always fall through to
                        // the next chunk below, regardless of what happens here.
                        if (_scanCancelled) { return; }
                        if (err instanceof SyntaxError && chunk.paths.length > 1) {
                            logWarning(
                                'Chunk ' + (idx + 1) + '/' + chunks.length + ' returned an invalid response \u2014 retrying its ' + chunk.paths.length + ' file(s) in smaller batches',
                                'warning'
                            );
                            return retryProcessBisect(chunk.paths, chunk.isNotReadable, allFeatures);
                        }
                        // A network-level failure would fail identically on every
                        // retry, so there's nothing to gain from splitting it up.
                        logWarning(
                            'Chunk ' + (idx + 1) + '/' + chunks.length + ' failed (' + chunk.paths.length + ' file(s) skipped): ' + err.message,
                            'error'
                        );
                    })
                    .then(function() {
                        if (_scanCancelled) { return; }
                        // Show results so far every few seconds: rescoring and rendering
                        // everything after each chunk would cost more than the scan
                        if (Date.now() - _lastProgressRender > 3000) {
                            reanalyze(allFeatures);
                            _lastProgressRender = Date.now();
                        }
                        return processChunk(chunks, idx + 1, allFeatures, totalFiles, chunkSize);
                    });
            }

            function cancelChunkedScan() {
                _scanCancelled = true;
                document.getElementById('ajaxProgress').style.display = 'none';
            }
            // ────────────────────────────────────────────────────────────────

            // ── Malware Hash Registry (Team Cymru) bulk lookup ─────────────────
            // Manual, triggered by the "MHR SCAN" button after a scan has
            // completed — against every file that isn't already known-good
            // (whitelisted, filtered out server-side before this point) or
            // known-bad (locally blacklisted — no need to ask a third party
            // about a hash already identified). Deduplicates by MD5 and
            // submits in batches of at most 1000 hashes per request per the
            // API's documented limit. A hit is treated the same as a local
            // blacklist match: forced to a minimum threat score of 100 and
            // unlinked from disk.
            var _mhrQueriesRemaining = null;

            function runMhrCheckClick() {
                var features = window.lastScanFeatures;
                if (!features || features.length === 0) {
                    logWarning('Run a scan first.', 'error');
                    return;
                }
                var user = (document.getElementById('mhrUsername').value || '').trim();
                var pass = document.getElementById('mhrPassword').value || '';
                if (!user || !pass) {
                    logWarning('Enter your MHR username and password first.', 'error');
                    return;
                }
                runMhrCheck(features, user, pass);
            }

            function runMhrCheck(features, mhrUser, mhrPass) {
                if (typeof mhrEnabled === 'undefined' || !mhrEnabled) { return Promise.resolve(); }

                var seen = {};
                var hashes = [];
                features.forEach(function (f) {
                    if (f.is_unreadable || f.is_blacklisted) { return; }
                    var md5 = f.md5;
                    if (!md5 || md5 === 'N/A' || seen[md5]) { return; }
                    seen[md5] = true;
                    hashes.push(md5);
                });

                var statusEl = document.getElementById('mhrStatus');

                if (hashes.length === 0) {
                    if (statusEl) { statusEl.textContent = 'Nothing to check.'; }
                    return Promise.resolve();
                }

                var batches = [];
                for (var i = 0; i < hashes.length; i += MHR_BATCH) {
                    batches.push(hashes.slice(i, i + MHR_BATCH));
                }

                var hitMap = {};

                function runBatch(idx) {
                    if (idx >= batches.length) { return Promise.resolve(); }

                    if (statusEl) {
                        statusEl.textContent = 'Checking Malware Hash Registry… batch ' +
                            (idx + 1) + '/' + batches.length + ' (' + batches[idx].length + ' hashes)';
                    }

                    return postAction({ ajax_action: 'mhr_check', mhr_user: mhrUser, mhr_pass: mhrPass, hashes: batches[idx].join(',') })
                        .then(function (data) {
                            reportServerWarnings(data);
                            if (data && data.error) {
                                var errMsg = 'MHR error: ' + (data.msg || data.message || data.error);
                                if (statusEl) { statusEl.textContent = errMsg; }
                                logWarning(errMsg, 'error');
                                return; // misconfigured, rate-limited, bad credentials, etc. — stop rather than retry
                            }
                            if (data && typeof data.queries_remaining !== 'undefined') {
                                _mhrQueriesRemaining = data.queries_remaining;
                            }
                            (data && data.results ? data.results : []).forEach(function (r) {
                                if (r.md5 && r.antivirus_detection_rate !== null && typeof r.antivirus_detection_rate !== 'undefined') {
                                    hitMap[r.md5.toLowerCase()] = r;
                                }
                            });
                            return runBatch(idx + 1);
                        })
                        .catch(function (err) {
                            // A network-level failure (a dropped connection, a
                            // truncated response) is specific to this batch, not
                            // a config problem — skip it and keep checking the
                            // rest rather than abandoning the whole MHR scan.
                            var errMsg = 'MHR batch ' + (idx + 1) + '/' + batches.length + ' failed: ' + err.message;
                            if (statusEl) { statusEl.textContent = errMsg; }
                            logWarning(errMsg, 'error');
                            return runBatch(idx + 1);
                        });
                }

                return runBatch(0).then(function () {
                    var hitCount = Object.keys(hitMap).length;
                    if (hitCount === 0) {
                        if (statusEl) {
                            statusEl.textContent = 'No matches' +
                                (_mhrQueriesRemaining !== null ? ' — ' + _mhrQueriesRemaining + ' queries remaining' : '') + '.';
                        }
                        return;
                    }

                    var hitFiles = [];
                    features.forEach(function (f) {
                        if (!f.md5) { return; }
                        var hit = hitMap[f.md5.toLowerCase()];
                        if (hit) {
                            f.mhr_hit = true;
                            f.mhr_detection_rate = hit.antivirus_detection_rate;
                            f.mhr_last_seen = hit.last_run_date;
                            hitFiles.push(f);
                        }
                    });

                    if (statusEl) {
                        statusEl.textContent = 'Unlinking ' + hitFiles.length + ' matched file(s)…';
                    }

                    // The server re-checks each file's hash with MHR before deleting it
                    return postAction({
                        ajax_action: 'mhr_unlink', mhr_user: mhrUser, mhr_pass: mhrPass,
                        paths: hitFiles.map(function (f) { return f.pathRaw; }).join(','),
                    })
                        .then(function (data) {
                            reportServerWarnings(data);
                            var errorsByPath = {};
                            (data && data.results ? data.results : []).forEach(function (r) {
                                if (r.error) { errorsByPath[r.path] = r.error; }
                            });
                            hitFiles.forEach(function (f) {
                                if (errorsByPath[f.pathRaw]) {
                                    f.error = errorsByPath[f.pathRaw];
                                }
                            });

                            // renderTable() refreshes the data-driven part of the panel (the
                            // per-file failed-deletion list with paths, via renderWarningPanel)
                            // *before* logWarning adds the one summary line below it — so the
                            // outcome is reported exactly once, not twice in different words.
                            reanalyze(features);

                            var failCount = Object.keys(errorsByPath).length;
                            if (statusEl) { statusEl.textContent = 'Done.'; }
                            logWarning(
                                'Malware Hash Registry: ' + hitCount + ' hash match(es) — ' +
                                (hitCount - failCount) + ' unlinked' +
                                (failCount > 0 ? ', ' + failCount + ' failed to delete (see file list above)' : '') +
                                (_mhrQueriesRemaining !== null ? ' — ' + _mhrQueriesRemaining + ' queries remaining' : ''),
                                failCount > 0 ? 'error' : 'warning'
                            );
                        })
                        .catch(function (err) {
                            reanalyze(features);
                            var errMsg = 'MHR unlink request failed: ' + err.message;
                            if (statusEl) { statusEl.textContent = errMsg; }
                            logWarning(errMsg, 'error');
                        });
                });
            }
            // ────────────────────────────────────────────────────────────────

            window.onload = function () {
                var mhrPanelEl = document.getElementById('mhrPanel');
                if (mhrPanelEl && typeof mhrEnabled !== 'undefined' && mhrEnabled) {
                    mhrPanelEl.style.display = 'block';
                }

                if (typeof serverWarnings !== 'undefined' && serverWarnings.length > 0) {
                    reportServerWarnings({ warnings: serverWarnings });
                }
            };
        </script>
    </body>

</html>