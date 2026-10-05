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

$minute = 60;
$limit = (60 * $minute); // 60 minutes
set_time_limit($limit);
ini_set('memory_limit', '-1');
ini_set('max_execution_time', $limit);
ini_set('display_errors', 0);
error_reporting(E_ALL);

define('_WHITELIST_', true);
define('_BLACKLIST_', true);
define('_MHR_', true);
define('_ML_', true); // ML second opinion; false skips its feature extraction (~40% less analysis time)
// Where the ML weights come from (an http(s) URL or a local file path)
define('_ML_MODEL_URL_', 'https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/ml-model.json');

$mhrUsername = '';
$mhrPassword = '';
$GLOBALS['phpWarnings'] = array();
$GLOBALS['mlWanted'] = true; // false when the page has no usable model (see 'process')

/**
 * Summary of errorHandler
 * @param mixed $errno
 * @param mixed $errstr
 * @param mixed $errfile
 * @param mixed $errline
 * @return bool
 */
function errorHandler($errno, $errstr, $errfile, $errline) {
    if (!(error_reporting() & $errno)) {
        return false; // respect @ suppression — don't record intentionally-silenced failures
    }
    error_log($errstr . ' in ' . $errfile . ' on line ' . $errline);
    $GLOBALS['phpWarnings'][] = $errstr;
    return true;
}

set_error_handler('errorHandler');

if (!function_exists('json_encode')) {
    /**
     * json_encode() for PHP < 5.2: null, bools, numbers, strings and
     * (nested) arrays. Lists become [...], other arrays {...}. "/" is escaped
     * like the native one so "</script>" can't end an inline <script> early.
     *
     * @param mixed $value
     * @return string
     */
    function json_encode($value)
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
            if ($isList) {
                $parts[] = json_encode($item);
            } else {
                $parts[] = json_encode((string) $key) . ':' . json_encode($item);
            }
        }
        if ($isList) {
            return '[' . implode(',', $parts) . ']';
        }
        return '{' . implode(',', $parts) . '}';
    }
}

/**
 * Check if function is available
 *
 * @param callable $callback
 * @return boolean
 */
function isWorking($callback)
{
    $securityDisabled = ini_get('disable_functions');
    $securityDisabled = explode(',', $securityDisabled);

    if (in_array($callback, $securityDisabled)) {
        return false;
    }
    if (!function_exists($callback)) {
        return false;
    }
    return true;
}

if (isWorking('curl_exec')) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    // Verified TLS: the downloaded blacklist deletes files, so it must really come from GitHub
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt_array($ch, array(
        CURLOPT_HTTPHEADER => array(
            'Cache-Control: no-cache, no-store, must-revalidate',
            'Pragma: no-cache',
            'Expires: 0'
        )
    ));
}

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
 *
 * Sort array of list file by lastest modified time
 *
 * @param array  $files Array of files
 * @return array
 *
 */
function sortByLastModified($files)
{
    @array_multisort(array_map('filemtime', $files), SORT_DESC, $files);
    return $files;
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
    $entries['file_readable'] = sortByLastModified($entries['file_readable']);
    return $entries;
}

/**
 * Tokenize PHP source, normalising short open tags first. Inside "...",
 * `...` and heredocs only variables and {$...} expressions are kept: the rest
 * is literal text, which PHP 4/5.0 (and array keys in "$a[key]" on any
 * version) hand out as T_STRING tokens that would otherwise read as code.
 *
 * @param string $fileContent
 * @return array token_get_all() output minus literal string text
 */
function getFileTokens($fileContent)
{
    $fileContent = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $fileContent);
    // Short open tags ("<?if(...)", "<? echo") become "<?php " so detection doesn't
    // depend on this host's short_open_tag; "<?=", "<?php" and "<?xml" stay as they are
    $fileContent = preg_replace('/<\?(?!php|=|xml)/i', '<?php ', $fileContent);
    $tokens = @token_get_all($fileContent); // https://www.php.net/manual/en/function.token-get-all.php

    $output = array();
    $quote = null;  // closing '"' or '`', or T_END_HEREDOC, while inside a string
    $depth = 0;     // brace depth inside a {$...} expression
    foreach ($tokens as $token) {
        $id = is_array($token) ? $token[0] : 0;
        $text = is_array($token) ? $token[1] : $token;
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
        $output[] = $token;
    }
    return $output;
}

/**
 * Lowercased, trimmed, de-duplicated code token texts as a lookup set.
 * String/HTML/comment content is left out ("...`{$t}`..." would otherwise
 * yield a lone "`"), as are method/function names (->exec(), ::system(),
 * function eval()) since those aren't the global functions. A leading "\"
 * is dropped so PHP 8's fully-qualified "\system" still matches "system".
 *
 * @param array $tokens token_get_all() output
 * @return array text => true
 */
function tokenTextSet($tokens)
{
    $ignore = array(T_WHITESPACE => 1, T_COMMENT => 1);
    $content = array(T_ENCAPSED_AND_WHITESPACE => 1, T_INLINE_HTML => 1);
    $member = array(T_OBJECT_OPERATOR => 1, T_PAAMAYIM_NEKUDOTAYIM => 1, T_FUNCTION => 1);
    if (defined('T_DOC_COMMENT')) {
        $ignore[constant('T_DOC_COMMENT')] = 1;
    }
    if (defined('T_NULLSAFE_OBJECT_OPERATOR')) {
        $member[constant('T_NULLSAFE_OBJECT_OPERATOR')] = 1;
    }

    $set = array();
    $prev = 0;
    foreach ($tokens as $token) {
        if (!is_array($token)) {
            $token = array(0, $token);
        }
        if (isset($ignore[$token[0]])) {
            continue;
        }
        if (!isset($content[$token[0]]) && !($token[0] == T_STRING && isset($member[$prev]))) {
            $set[ltrim(strtolower(trim($token[1])), '\\')] = true;
        }
        $prev = $token[0];
    }
    unset($set['']);
    return $set;
}

/**
 * Return the needles (keys of the weight map) present in a token set
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
 * Detect code shapes that plain token matching can't see. Returns
 * "@"-prefixed pseudo-needles (no PHP token is "@" + letters, so they never
 * collide with real ones) plus any needle function name that was hidden in
 * a string: 'ba'.'se64_decode', "\x73ystem", 'system'('id').
 *
 * @param array  $tokens       token_get_all() output
 * @param string $content      raw file content
 * @param array  $tokenNeedles needle => weight
 * @return array
 */
function findStructuralSignals($tokens, $content, $tokenNeedles)
{
    $needleSet = array_change_key_case($tokenNeedles, CASE_LOWER);
    $inputVars = array('$_get' => 1, '$_post' => 1, '$_request' => 1, '$_cookie' => 1, '$_server' => 1, '$_files' => 1);
    $skip = array(T_WHITESPACE => 1, T_COMMENT => 1);
    if (defined('T_DOC_COMMENT')) {
        $skip[constant('T_DOC_COMMENT')] = 1;
    }

    // Significant tokens only, as (id, text); single-char tokens get id 0
    $sig = array();
    $haltBytes = -1;
    foreach ($tokens as $token) {
        if (!is_array($token)) {
            $token = array(0, $token);
        }
        if ($haltBytes >= 0) {
            $haltBytes += strlen($token[1]);
            continue;
        }
        if (isset($skip[$token[0]])) {
            continue;
        }
        if (strtolower($token[1]) == '__halt_compiler') {
            $haltBytes = 0;
        }
        $sig[] = $token;
    }

    $found = array();
    $n = count($sig);
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
        if ($id == T_STRING && ltrim(strtolower($text), '\\') == 'preg_replace' && $i + 2 < $n && $sig[$i + 1][1] == '(' && $sig[$i + 2][0] == T_CONSTANT_ENCAPSED_STRING) {
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
                // Walk back over [..][..] to the variable being indexed
                $j = $i - 1;
                while ($j >= 0 && $sig[$j][1] == ']') {
                    $depth = 0;
                    for (; $j >= 0; $j--) {
                        if ($sig[$j][1] == ']') {
                            $depth++;
                        } elseif ($sig[$j][1] == '[') {
                            $depth--;
                            if ($depth == 0) {
                                break;
                            }
                        }
                    }
                    $j--;
                }
                if ($j >= 0 && $sig[$j][0] == T_VARIABLE) {
                    $found['@dyn_call'] = true;
                    if (isset($inputVars[strtolower($sig[$j][1])])) {
                        $found['@input_call'] = true;
                    }
                }
            }
        }
    }

    // Packed payloads tend to sit on one huge line
    $maxLine = 0;
    foreach (explode("\n", $content) as $line) {
        if (strlen($line) > $maxLine) {
            $maxLine = strlen($line);
        }
    }
    // ASP/JSP/CGI shell code in a file named like PHP (no PHP in it at all):
    // nothing for the PHP checks above to see
    if (!preg_match('/<\?(?!xml)/i', $content) &&
        (preg_match('/<%.*?(Response\.Write|CreateObject|Server\.MapPath|Request\.(Form|QueryString)|WScript\.Shell|FileSystemObject|Runtime\.getRuntime|java\.io\.|<%@\s*page)/is', $content) ||
         preg_match('/^#!\S*perl|^\s*use CGI\b/m', $content))) {
        $found['@foreign_code'] = true;
    }
    if ($maxLine > 5000) {
        $found['@long_line'] = true;
    }
    if ($haltBytes > 1024) {
        $found['@halt_payload'] = true;
    }

    return array_keys($found);
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

// Hashed feature space for the ML model (a power of two; the model's weight
// count must match, see test/train-ml.js)
define('ML_BUCKETS', 2048);
// Bump whenever mlFeatures() changes what it emits: a model trained on other
// features is refused (ml-model.json carries the version it was trained on)
define('ML_FEATURE_VERSION', 1);

/**
 * Binary feature vector for the client-side ML model, as a hex bitmap of
 * ML_BUCKETS bits. Each feature is a short string (a token-type bigram, a
 * called function's name, a variable's name, a string literal's shape, a
 * bucketed file statistic) hashed into a bucket with crc32. "& mask" keeps
 * the low bits the same on 32- and 64-bit PHP.
 *
 * @param array  $tokens  getFileTokens() output
 * @param string $content raw file content
 * @param float  $entropy shannonEntropy($content)
 * @return string
 */
function mlFeatures($tokens, $content, $entropy)
{
    $skip = array(T_WHITESPACE => 1, T_COMMENT => 1);
    if (defined('T_DOC_COMMENT')) {
        $skip[constant('T_DOC_COMMENT')] = 1;
    }
    $member = array(T_OBJECT_OPERATOR => 1, T_PAAMAYIM_NEKUDOTAYIM => 1, T_FUNCTION => 1, T_NEW => 1);
    if (defined('T_NULLSAFE_OBJECT_OPERATOR')) {
        $member[constant('T_NULLSAFE_OBJECT_OPERATOR')] = 1;
    }

    $names = array();
    $sig = array();
    foreach ($tokens as $token) {
        if (!is_array($token)) {
            $token = array(0, $token);
        }
        if (!isset($skip[$token[0]])) {
            $sig[] = $token;
        }
    }

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

    $maxLine = 0;
    foreach (explode("\n", $content) as $line) {
        if (strlen($line) > $maxLine) {
            $maxLine = strlen($line);
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
 * Download the ML model (ml-model.json) and check it fits this main.php.
 * Returns the JSON text to embed in the page, or 'null' with a warning when
 * it's unavailable, malformed, or trained for different features. The text
 * is matched against a strict pattern (digits, hex and fixed keys only), so
 * nothing from the download can break out of the <script> it goes into.
 *
 * @param string $url
 * @return string
 */
function mlModelJson($url)
{
    if (preg_match('#^https?://#i', $url)) {
        $json = trim(implode("\n", urlFileArray($url)));
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
 * Try every remote download method and return array of strings from a URL.
 *
 * @param string $url
 * @return array
 */
function urlFileArray($url)
{
    $content = false;

    // 1. Try cURL if a global handle exists
    if (isset($GLOBALS['ch'])) {
        curl_setopt($GLOBALS['ch'], CURLOPT_URL, $url);
        curl_setopt($GLOBALS['ch'], CURLOPT_RETURNTRANSFER, true);

        $content = curl_exec($GLOBALS['ch']);

        // Anything but a non-empty string is a failure: a real list is never
        // empty, and PHP 4.3's file_get_contents() returns NULL, not false,
        // when it can't take the stream context
        if (!is_string($content) || $content === '') {
            $error_msg = curl_error($GLOBALS['ch']);
            trigger_error("cURL error fetching URL: $error_msg", E_USER_WARNING);
        } else {
            return explode("\n", $content);
        }
    }

    // 2. Try file_get_contents
    if (isWorking('file_get_contents')) {
        $context = stream_context_create(array(
            'http' => array(
                'ignore_errors' => true, // Handle potential errors gracefully
                'header' => implode("\r\n", array(
                    'Cache-Control: no-cache, no-store, must-revalidate',
                    'Pragma: no-cache',
                    'Expires: 0'
                )),
            ),
            'ssl' => array(
                'verify_peer' => true,
                'verify_peer_name' => true,
            ),
        ));

        $content = @file_get_contents($url, false, $context);

        if (is_string($content) && $content !== '') {
            return explode("\n", $content);
        } else {
            trigger_error("Failed to fetch URL using file_get_contents", E_USER_WARNING);
        }
    }

    // 3. Try file()
    if (isWorking('file')) {
        $content = @file($url, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        if (is_array($content) && !empty($content)) {
            return $content;
        } else {
            trigger_error("Failed to fetch URL using file()", E_USER_WARNING);
        }
    }

    // 4. No suitable method found
    trigger_error("No suitable methods found to fetch URL content", E_USER_WARNING);
    return array();
}

/**
 * Submit up to 1000 MD5/SHA1/SHA256 hashes to Team Cymru's Malware Hash
 * Registry bulk lookup API in one request.
 * https://hash.cymru.com/docs_rest
 *
 * @param array $hashes
 * @param string $username
 * @param string $password
 * @return array Decoded response — {results, queries_remaining} on success,
 *               {error, msg} on failure — mirroring the API's own shape.
 */
function mhrSubmitHashes($hashes, $username, $password)
{
    if (empty($username) || empty($password)) {
        return array('error' => 'not configured', 'msg' => 'MHR username/password not set (_MHR_ requires an account — see https://hash.cymru.com/signup)');
    }
    if (empty($hashes)) {
        return array('results' => array(), 'queries_remaining' => null);
    }
    if (!function_exists('json_decode')) {
        return array('error' => 'unsupported', 'msg' => 'MHR lookups need PHP 5.2+ (json_decode)');
    }
    if (count($hashes) > 1000) {
        $hashes = array_slice($hashes, 0, 1000); // API hard limit — see docs_rest
    }

    $url  = 'https://hash.cymru.com/v2/submitHashes';
    $body = implode("\n", $hashes);

    // 1. Try cURL if a global handle exists
    if (isset($GLOBALS['ch'])) {
        $ch = $GLOBALS['ch'];
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        curl_setopt($ch, CURLOPT_USERPWD, $username . ':' . $password);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: text/plain; charset=utf-8'));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        // hash.cymru.com's HTTP/2 endpoint intermittently drops the stream
        // mid-response ("HTTP/2 stream 0 was not closed cleanly"); HTTP/1.1
        // doesn't hit that failure mode. Bounded timeouts so a broken
        // connection fails fast into the file_get_contents fallback below
        // instead of hanging.
        curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);

        $content = curl_exec($ch);
        if ($content !== false) {
            $decoded = json_decode($content, true);
            if (is_array($decoded)) {
                return $decoded;
            }
        } else {
            trigger_error('cURL error submitting hashes to MHR: ' . curl_error($ch), E_USER_WARNING);
        }
    }

    // 2. Fallback: file_get_contents with a POST stream context
    if (isWorking('file_get_contents')) {
        $context = stream_context_create(array(
            'http' => array(
                'method'        => 'POST',
                'header'        => implode("\r\n", array(
                    'Content-Type: text/plain; charset=utf-8',
                    'Authorization: Basic ' . base64_encode($username . ':' . $password),
                )),
                'content'       => $body,
                'ignore_errors' => true,
                'timeout'       => 30,
            ),
            'ssl' => array(
                'verify_peer'      => true,
                'verify_peer_name' => true,
            ),
        ));
        $content = @file_get_contents($url, false, $context);
        if ($content !== false) {
            $decoded = json_decode($content, true);
            if (is_array($decoded)) {
                return $decoded;
            }
        }
    }

    trigger_error('Unable to reach Malware Hash Registry', E_USER_WARNING);
    return array('error' => 'request failed', 'msg' => 'Unable to reach Malware Hash Registry');
}

/**
 * Delete a file and return the specific failure reason (e.g. "unlink(...):
 * Permission denied") instead of a generic "Failed to unlink", so the reason
 * ends up attached to the file instead of being thrown away by
 * @-suppression. The captured warning is consumed (removed from
 * $phpWarnings) rather than just read, so it surfaces exactly once — via
 * this file's own `error` field — instead of also duplicating into the
 * generic warnings list every AJAX response carries.
 *
 * @param string $filePath
 * @return string|null null on success, the reason string on failure
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
 * Read a request value, undoing magic_quotes_gpc (PHP < 5.4 escapes quotes,
 * backslashes and NUL) so it arrives exactly as sent.
 *
 * @param array $source $_POST
 * @param string $key
 * @return string|null null when missing
 */
function inputValue($source, $key)
{
    if (!isset($source[$key]) || !is_string($source[$key])) {
        return null;
    }
    $value = $source[$key];
    if (function_exists('get_magic_quotes_gpc') && @get_magic_quotes_gpc()) {
        $value = stripslashes($value);
    }
    return $value;
}

/**
 * Read a POST field holding a comma-separated list. One field (unlike
 * paths[]=...) stays clear of max_input_vars no matter how many entries it
 * holds. Paths travel rawurlencode()d, so a raw comma can't occur inside an
 * entry. (NUL was used before, but hardened hosts strip or drop request values
 * containing NUL, e.g. Suhosin's default disallow_nul, which emptied every scan.)
 *
 * @param string $key
 * @return array
 */
function postList($key)
{
    $value = inputValue($_POST, $key);
    if ($value === null || $value === '') {
        return array();
    }
    return explode(',', $value);
}

/**
 * Scan a list of readable file paths and build their feature rows, applying
 * the whitelist/blacklist checks, token matching, and duplicate-of
 * detection used throughout this file's scanning.
 *
 * @param array $paths
 * @param array $whitelistMD5Sums md5 => anything (array_flip'd list)
 * @param array $blacklistMD5Sums md5 => anything (array_flip'd list)
 * @param array $tokenNeedles
 * @param array $localSeen hash => first-seen path; read and updated in place
 * @param array $newlySeen appended with "hash:path" for each entry newly
 *                         added to $localSeen during this call; pass a
 *                         throwaway array if the caller doesn't need it
 * @return array list of feature rows (see the 'path'/'size'/... shape used throughout)
 */
function scanReadablePaths($paths, $whitelistMD5Sums, $blacklistMD5Sums, $tokenNeedles, &$localSeen, &$newlySeen)
{
    $features = array();

    foreach ($paths as $filePath) {
        if (!file_exists($filePath) || !is_readable($filePath)) {
            trigger_error('Skipped ' . $filePath . ': it no longer exists or is not readable', E_USER_WARNING);
            continue;
        }

        $content = file_get_contents($filePath);
        if ($content === false) {
            $features = array_merge($features, scanUnreadablePaths(array($filePath)));
            continue;
        }

        $fileSum = md5($content);
        if (isset($whitelistMD5Sums[$fileSum])) {
            continue;
        }

        $tokens        = getFileTokens($content);
        $tokenSet      = tokenTextSet($tokens);
        $matchedTokens = array_values(array_unique(array_merge(
            compareTokens($tokenNeedles, $tokenSet),
            findStructuralSignals($tokens, $content, $tokenNeedles)
        )));
        $totalTokens   = count($tokenSet);
        $size          = strlen($content);
        $mtime         = filemtime($filePath);
        $ctime         = filectime($filePath); // stat before a blacklist unlink below
        $owner         = fileowner($filePath);
        $isBlacklisted = isset($blacklistMD5Sums[$fileSum]);
        $isHtaccess    = (pathinfo($filePath, PATHINFO_EXTENSION) == 'htaccess');
        $duplicateOf   = false;

        if (isset($localSeen[$fileSum])) {
            $duplicateOf = $localSeen[$fileSum];
        } else {
            $localSeen[$fileSum] = $filePath;
            $newlySeen[] = $fileSum . ':' . $filePath;
        }

        $entropy       = shannonEntropy($content);
        $error = null;
        if ($isBlacklisted) {
            $error = unlinkWithReason($filePath);
        }

        $features[] = array(
            'path'           => $filePath,
            'size'           => $size,
            'mtime'          => $mtime,
            'ctime'          => $ctime,
            'owner'          => $owner,
            'entropy'        => $entropy,
            'total_tokens'   => $totalTokens,
            'ml_features'    => (_ML_ && $GLOBALS['mlWanted']) ? mlFeatures($tokens, $content, $entropy) : null,
            'matched_tokens' => $matchedTokens,
            'md5'            => $fileSum,
            'is_blacklisted' => $isBlacklisted,
            'is_htaccess'    => $isHtaccess,
            'duplicate_of'   => $duplicateOf,
            'error'          => $error,
            'is_unreadable'  => false,
        );
    }

    return $features;
}

/**
 * Build feature rows for paths that could not be read.
 *
 * @param array $paths
 * @return array
 */
function scanUnreadablePaths($paths)
{
    $features = array();

    foreach ($paths as $filePath) {
        $mtime = @filemtime($filePath);
        if (!$mtime) {
            $mtime = 0;
        }

        $features[] = array(
            'path'           => $filePath,
            'size'           => null,
            'mtime'          => $mtime,
            'ctime'          => 0,
            'owner'          => null,
            'entropy'        => null,
            'total_tokens'   => null,
            'ml_features'    => null,
            'matched_tokens' => array('NOT_READABLE'),
            'md5'            => 'N/A',
            'is_blacklisted' => false,
            'is_htaccess'    => false,
            'duplicate_of'   => false,
            'error'          => null,
            'is_unreadable'  => true,
        );
    }

    return $features;
}

// Which files to scan, matched against the file name: a PHP-ish or SSI last
// extension, "php" as an inner extension ("x.php.jpg" and "x.php." run as PHP
// under Apache's AddHandler), .htaccess, and the per-directory PHP config files
$pattern = '/\.(ph[^.]+|sh[^.]+|inc|htaccess)$|\.(php[0-9]*|phtml|pht|phar)\.|^(\.user|php[0-9]*)\.ini$/i';

/**
 * Master Token Needles and Threat Weights Map
 * Maps token strings directly to their threat score weights.
 */
$tokenNeedles = array(
    // Critical RCE (Weight: 10.0)
    'eval' => 10.0,
    'exec' => 10.0,
    'shell_exec' => 10.0,
    'system' => 10.0,
    'passthru' => 10.0,
    'proc_open' => 10.0,
    'create_function' => 10.0,
    'pcntl_fork' => 10.0,
    'posix_kill' => 10.0,
    'posix_setuid' => 10.0,
    '`' => 10.0, // backtick operator = shell_exec
    '@input_call' => 10.0, // $_GET['a']($_GET['b'])
    '@preg_e' => 10.0, // preg_replace('/.../e') evaluates the replacement
    '@foreign_code' => 10.0, // ASP/JSP/CGI code in a PHP-named file

    // High Obfuscation & De-encoding (Weight: 5.0)
    'base64_decode' => 5.0,
    'gzinflate' => 5.0,
    'str_rot13' => 5.0,
    'gzuncompress' => 5.0,
    'convert_uu' => 5.0,
    'rawurldecode' => 5.0,
    'urldecode' => 5.0,
    'hex2bin' => 5.0,
    'bin2hex' => 5.0,
    'exif_read_data' => 5.0,
    'readgzfile' => 5.0,
    '$SISTEMIT_COM_ENC' => 5.0,
    '@concat_name' => 5.0, // function name hidden in a string: 'ba'.'se64_decode', "\x73ystem"
    '@halt_payload' => 5.0, // data appended after __halt_compiler()

    // Obfuscation Helpers & I/O Manipulation (Weight: 2.0)
    'assert' => 2.0,
    'htmlspecialchars_decode' => 2.0,
    'hexdec' => 2.0,
    'chr' => 2.0,
    'strrev' => 2.0,
    'goto' => 2.0,
    'extract' => 2.0,
    'parse_str' => 2.0,
    'popen' => 2.0,
    'fsockopen' => 2.0,
    'posix_setsid' => 2.0,
    'posix_setpgid' => 2.0,
    'proc_nice' => 2.0,
    'proc_close' => 2.0,
    'proc_terminate' => 2.0,
    'apache_child_terminate' => 2.0,
    'move_uploaded_file' => 2.0,
    '$_files' => 2.0,
    '$auth_pass' => 2.0,
    '$password' => 2.0,
    '$pass' => 2.0,
    'proc_get_status' => 2.0,
    'posix_mkfifo' => 2.0,
    'php_uname' => 2.0,
    '@dyn_call' => 2.0, // call through a variable/expression: $f(), $a['x'](), (...)()
    '@long_line' => 2.0, // a line over 5000 chars

    // User input (Weight: 0.5) — everywhere in legit code, only matters in combination
    '$_get' => 0.5,
    '$_post' => 0.5,
    '$_request' => 0.5,
    '$_cookie' => 0.5,
    'getallheaders' => 0.5,

    // Low / Routine Tokens (Weight: 0.1)
    'preg_replace' => 0.1, // the dangerous /e form is scored as @preg_e
    'call_user_func' => 0.1,
    'call_user_func_array' => 0.1,
    'register_shutdown_function' => 0.1,
    'register_tick_function' => 0.1,
    'implode' => 0.1,
    'strtr' => 0.1,
    'substr' => 0.1,
    'mb_substr' => 0.1,
    'str_replace' => 0.1,
    'substr_replace' => 0.1,
    'basename' => 0.1,
    'getcwd' => 0.1,
    'pathinfo' => 0.1,
    'getenv' => 0.1,
    'get_current_user' => 0.1,
    'fileowner' => 0.1,
    'filegroup' => 0.1,
    'disk_free_space' => 0.1,
    'disk_total_space' => 0.1,
    'sys_get_temp_dir' => 0.1,
    'fopen' => 0.1,
    'file_put_contents' => 0.1,
    'file_get_contents' => 0.1,
    'url_get_contents' => 0.1,
    'stream_get_meta_data' => 0.1,
    'copy' => 0.1,
    'include' => 0.1,
    'require' => 0.1,
    'include_once' => 0.1,
    'require_once' => 0.1,
    '__file__' => 0.1,
    'mail' => 0.1,
    'putenv' => 0.1,
    'curl_init' => 0.1,
    'tmpfile' => 0.1,
    'allow_url_fopen' => 0.1,
    'ini_set' => 0.1,
    'set_time_limit' => 0.1,
    'session_start' => 0.1,
    'symlink' => 0.1,
    '__halt_compiler' => 0.1,
    '__compiler_halt_offset__' => 0.1,
    'error_reporting' => 0.1,
    'get_magic_quotes_gpc' => 0.1,
    'phpinfo' => 0.1,
    'posix_getuid' => 0.1,
    'posix_geteuid' => 0.1,
    'posix_getegid' => 0.1,
    'posix_getpwuid' => 0.1,
    'posix_getgrgid' => 0.1,
    'posix_getlogin' => 0.1,
    'posix_ttyname' => 0.1,
    'get_cfg_var' => 0.1,
    'diskfreespace' => 0.1,
    'getlastmod' => 0.1,
    'getmyinode' => 0.1,
    'getmypid' => 0.1,
    'getmyuid' => 0.1,
    'getmygid' => 0.1,
    'mysql_connect' => 0.1,
    'mysqli_connect' => 0.1,
    'mysql_query' => 0.1,
    'mysqli_query' => 0.1
);

// test/run.js includes this file for its functions and needle map only
if (defined('SUSSY_LIB')) {
    return;
}

$whitelistMD5Sums = array();
$blacklistMD5Sums = array();
if (_WHITELIST_) {
    $whitelistMD5Sums = array_flip(array_map('trim', urlFileArray('https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/whitelist.txt')));
}
if (_BLACKLIST_) {
    $blacklistMD5Sums = array_flip(array_map('trim', urlFileArray('https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/blacklist.txt')));
}
/**
 * Emit a clean JSON response for an AJAX action. Folds in any PHP warnings
 * captured during this request and, as a last-resort safety net, discards
 * (and reports, rather than silently drops) any stray buffered output that
 * isn't part of the intended payload — so a single unexpected warning or
 * accidental echo can never corrupt the JSON body the client is about to
 * parse.
 *
 * @param array $data
 * @return void
 */
function ajaxRespond($data)
{
    $stray = ob_get_clean();
    $warnings = (isset($data['warnings']) && is_array($data['warnings'])) ? $data['warnings'] : array();
    $warnings = array_merge($warnings, $GLOBALS['phpWarnings']);
    if (trim($stray) !== '') {
        $warnings[] = 'Unexpected output suppressed: ' . substr(trim($stray), 0, 500);
    }
    $data['warnings'] = array_values($warnings);
    $json = json_encode($data);
    if ($json === false) {
        $json = json_encode(utf8Safe($data)); // a message quoting a non-UTF-8 file name
    }
    echo $json;
    exit;
}

/**
 * Make every string in $value valid UTF-8 for json_encode() (PHP 5.2+ returns
 * false on invalid bytes, which would empty the whole response). Invalid
 * strings are read as Latin-1. Only for text shown to the user: paths travel
 * rawurlencode()d so they survive byte for byte.
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

// ── AJAX request handler ────────────────────────────────────────────────
if (isset($_POST['ajax_action'])) {
    ob_start();
    header('Content-Type: application/json');
    // CSRF check: a browser sends a custom header cross-site only after a CORS
    // preflight this script never approves, so it proves the page sent the request
    if (!isset($_SERVER['HTTP_X_SUSSY_REQUEST'])) {
        ajaxRespond(array('error' => 'forbidden', 'msg' => 'Missing X-Sussy-Request header'));
    }
    $ajaxAction = $_POST['ajax_action'];
    // Paths travel rawurlencode()d both ways, so names that aren't valid UTF-8
    // survive JSON and come back byte for byte
    $mhrUser = inputValue($_POST, 'mhr_user');
    $mhrUser = ($mhrUser !== null && $mhrUser !== '') ? trim($mhrUser) : $mhrUsername;
    $mhrPass = inputValue($_POST, 'mhr_pass');
    $mhrPass = ($mhrPass !== null && $mhrPass !== '') ? $mhrPass : $mhrPassword;

    if ($ajaxAction == 'scan') {
        $path = inputValue($_POST, 'dir');
        if ($path === null) {
            $path = getcwd();
        }

        $result = getSortedByPattern($path, $pattern);

        $readable = $result['file_readable'];
        if (!empty($whitelistMD5Sums)) {
            $readable = array();
            foreach ($result['file_readable'] as $fp) {
                if (!isset($whitelistMD5Sums[md5_file($fp)])) {
                    $readable[] = $fp;
                }
            }
        }

        ajaxRespond(array(
            'readable'     => array_map('rawurlencode', $readable),
            'not_readable' => array_map('rawurlencode', $result['file_not_readable']),
            'total'        => count($readable) + count($result['file_not_readable']),
        ));
    }

    if ($ajaxAction == 'process') {
        $paths = array_map('rawurldecode', postList('paths'));
        if (inputValue($_POST, 'ml') === '0') {
            $GLOBALS['mlWanted'] = false; // the page has no model to score with
        }

        if (isset($_POST['is_not_readable']) && $_POST['is_not_readable'] == '1') {
            $isUnreadable = true;
        } else {
            $isUnreadable = false;
        }

        $seenHashes = postList('seen_hashes'); // "md5:encoded path" entries

        $newHashes = array();

        if ($isUnreadable) {
            $features = scanUnreadablePaths($paths);
        } else {
            $localSeen = array();
            foreach ($seenHashes as $entry) {
                $parts = explode(':', $entry, 2);
                if (count($parts) == 2) {
                    $localSeen[$parts[0]] = rawurldecode($parts[1]);
                }
            }

            $features = scanReadablePaths($paths, $whitelistMD5Sums, $blacklistMD5Sums, $tokenNeedles, $localSeen, $newHashes);
        }

        foreach ($features as $i => $row) {
            $features[$i]['path'] = rawurlencode($row['path']);
            if ($row['duplicate_of'] !== false) {
                $features[$i]['duplicate_of'] = rawurlencode($row['duplicate_of']);
            }
        }
        foreach ($newHashes as $i => $entry) {
            $parts = explode(':', $entry, 2);
            $newHashes[$i] = $parts[0] . ':' . rawurlencode($parts[1]);
        }

        ajaxRespond(array('features' => $features, 'new_hashes' => $newHashes));
    }

    if ($ajaxAction == 'mhr_check') {
        if (isset($_POST['hashes']) && is_array($_POST['hashes'])) {
            $hashes = array_values(array_unique(array_filter(array_map('strval', $_POST['hashes']))));
        } else {
            $hashes = array();
        }

        if (!_MHR_) {
            ajaxRespond(array('error' => 'not configured', 'msg' => 'MHR integration is disabled (_MHR_ is false in main.php)'));
        }

        ajaxRespond(mhrSubmitHashes($hashes, $mhrUser, $mhrPass));
    }

    if ($ajaxAction == 'mhr_unlink') {
        // The paths come from the browser, so delete only files whose current
        // hash MHR itself confirms; trusting the list would make this an
        // arbitrary-file-delete endpoint
        if (!_MHR_) {
            ajaxRespond(array('error' => 'not configured', 'msg' => 'MHR integration is disabled (_MHR_ is false in main.php)'));
        }
        $sums = array();
        foreach (array_map('rawurldecode', postList('paths')) as $filePath) {
            $sums[$filePath] = is_file($filePath) ? md5_file($filePath) : false;
        }
        $lookup = mhrSubmitHashes(array_values(array_unique(array_filter($sums))), $mhrUser, $mhrPass);
        if (isset($lookup['error'])) {
            ajaxRespond($lookup);
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

        ajaxRespond(array('results' => $results));
    }

    ajaxRespond(array('error' => 'Unknown action'));
}
// ────────────────────────────────────────────────────────────────────────
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
            <button type="button" onclick="runMhrCheckClick()" title="Submit non-blacklisted/non-whitelisted MD5s to hash.cymru.com in batches of 1000">MHR SCAN</button>
            <span id="mhrStatus" style="margin-left:10px;color:#888;"></span>
        </div>

        <?php
        // Emit token weight map so JS can replicate PHP scoring exactly
        echo '<script>const tokenWeights = ' . json_encode($tokenNeedles) . ';</script>';
        echo '<script>const mhrEnabled = ' . json_encode((bool)_MHR_) . ';</script>';
        echo '<script>const ML_MODEL = ' . (_ML_ ? mlModelJson(_ML_MODEL_URL_) : 'null') . ';</script>';
        echo '<script>const serverWarnings = ' . json_encode(array_values($GLOBALS['phpWarnings'])) . ';</script>';
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

            <label>🔍 <input type="text" id="searchInput" class="search-input" placeholder="e.g. eval or .php" oninput="applySearch()"></label>

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
            let currentThreshold = 3.5;
            let insightsVisible = false;
            let chartsVisible = false;
            let currentSearch = '';
            let searchTokensOnly = false;

            // --- Client-side threat scoring (offloaded from PHP) ---

            // Whole-file Shannon entropy (bits/byte, computed server-side) above
            // this means packed/encoded content: 98/202 test webshells vs 1/1927
            // benign files (node test/run.js).
            const HIGH_ENTROPY = 5.5;

            /**
             * Compute composite threat score for one feature row.
             * @param {Object} d       feature row from the server
             * @param {Object} weights tokenWeights map (key -> weight)
             */
            // Server-reconnaissance calls; see the recon bonus in calculateThreatScore()
            const RECON_TOKENS = ['php_uname', 'phpinfo', 'get_cfg_var', 'get_current_user', 'getmyuid', 'getmygid', 'getmypid',
                'getmyinode', 'posix_getuid', 'posix_geteuid', 'posix_getegid', 'posix_getlogin', 'disk_total_space',
                'disk_free_space', 'diskfreespace', 'getlastmod'];

            function calculateThreatScore(d, weights) {
                var score = 0.0;
                var hasCritical = false;
                var hasObfuscation = false;
                var hasUploadReq = false;
                var hasInput = false;

                var critTokens = ['eval','exec','shell_exec','system','passthru','proc_open','create_function','`','@input_call','@preg_e','@foreign_code'];
                // Full "High Obfuscation & De-encoding" (5.0) and upload/IO-request tiers —
                // kept in sync with the weight categories in $tokenNeedles.
                var obfTokens  = ['base64_decode','gzinflate','str_rot13','gzuncompress','convert_uu','rawurldecode','urldecode','hex2bin','bin2hex','exif_read_data','readgzfile','$sistemit_com_enc','@concat_name','@halt_payload'];
                var reqTokens  = ['move_uploaded_file','$_files','file_put_contents'];
                var inputTokens = ['$_get','$_post','$_request','$_cookie','getallheaders'];

                var tokens = Array.isArray(d.matched_tokens) ? d.matched_tokens.map(function (t) { return t.toLowerCase(); }) : [];

                // Obfuscation/upload-handling functions (compression, encoding, file upload
                // helpers) are everyday building blocks of legitimate code — ZIP libraries,
                // mail clients, HTTP clients, media parsers. They're only a strong signal in
                // combination with a real code-execution primitive (already captured by the
                // combo multipliers below); standing alone they get a reduced weight so a
                // large legitimate library doesn't cross the anomaly bar on that basis alone.
                for (var c = 0; c < tokens.length; c++) {
                    if (critTokens.indexOf(tokens[c]) !== -1) { hasCritical = true; }
                    if (inputTokens.indexOf(tokens[c]) !== -1) { hasInput = true; }
                }
                var nonCriticalDampen = hasCritical ? 1.0 : 0.3;

                for (var i = 0; i < tokens.length; i++) {
                    var token = tokens[i];
                    var w = (weights && typeof weights[token] !== 'undefined') ? parseFloat(weights[token]) : 1.0;
                    var isObf = obfTokens.indexOf(token) !== -1;
                    var isReq = reqTokens.indexOf(token) !== -1;
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
                    if (RECON_TOKENS.indexOf(tokens[r]) !== -1) recon++;
                }
                if (recon >= 2) score += 6.0;

                return Math.round(score * 100) / 100;
            }

            // Tiny ML model: logistic regression over the hashed token features
            // from mlFeatures() in PHP (one bit per bucket), int8 weights as hex.
            // Trained and cross-validated by node test/train-ml.js --write, which
            // writes ml-model.json; the server embeds it in the page as ML_MODEL
            // (null when unavailable or disabled).
            // Score at or above which the model alone flags a file (a ranking
            // score from training, not a calibrated probability)
            const ML_THRESHOLD = 0.9;
            // The ML score adds threat points: none at or below ML_FLOOR, rising
            // linearly to 8 (the anomaly / HIGH RISK bar) at ML_THRESHOLD and 10 at 1.0.
            // 0.6 on node test/run.js: lower adds false positives, higher loses catches
            // (node test/train-ml.js reports the same sweep on held-out scores)
            const ML_FLOOR = 0.6;

            // floor: ML_FLOOR unless given (test/train-ml.js sweeps it)
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

            function analyzeData(rawData, threshold) {
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
                            isAnomaly: true,
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
                    // positives in node test/run.js): the weighted threatScore
                    // already covers "many suspicious tokens". The residual (more
                    // matched tokens than the file's size predicts) dropped out once
                    // the recon bonus scored what it was catching: its only unique
                    // webshell catches were recon-heavy shells, for 7 false positives.
                    //
                    // Entropy only matters on the high side; a near-empty stub
                    // isn't an outlier worth reviewing.
                    const otherTriggers = (zEntropy > threshold) ||
                        (Math.abs(zMtime) > threshold) ||
                        (Math.abs(zCtime) > threshold) ||
                        rareOwner ||
                        d.is_blacklisted ||
                        d.mhr_hit === true;
                    // ML points can lift a file over the bar, never pull one under it;
                    // mlOnly marks files flagged only because of them
                    const ruleAnomaly = ruleScore >= 8.0 || otherTriggers;
                    const isAnomaly = threatScore >= 8.0 || otherTriggers;
                    const mlOnly = isAnomaly && !ruleAnomaly;

                    return {
                        ...d,
                        zScores: { size: zSize, mtime: zMtime, tokens: zTokens, susp: zSusp, entropy: zEntropy, ctime: zCtime },
                        residual: residual,
                        rareOwner: rareOwner,
                        isAnomaly: isAnomaly,
                        mlScore: ml,
                        mlPoints: mlPts,
                        mlOnly: mlOnly,
                        ruleScore: ruleScore,
                        threatScore: threatScore,
                        date: d.mtime ? formatDate(d.mtime) : 'N/A',
                        suspCount: suspCount
                    };
                });
            }

            // --- End client-side threat scoring ---

            function shortenUnlinkError(msg) {
                if (!msg) return msg;
                // The file path is already shown right next to this message
                // (the row's own file link, or the <code> path beside it in
                // the warning panel) — repeating it inside "unlink(/long/
                // path): reason" just pushes the actual reason off-screen for
                // anything with a longish path. Keep only the reason.
                return msg.replace(/^unlink\([^)]*\):\s*/, '');
            }

            // Every AJAX call goes through here: the custom header is the server's
            // CSRF check (another site can't send it)
            function postAction(body) {
                return fetch('', { method: 'POST', body: body, headers: { 'X-Sussy-Request': '1' } });
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

            function passesTableFilters(d) {
                if (currentSearch === '__BLACKLIST__') return d.is_blacklisted === true;
                if (currentFilterMode === 'anomalies' && !d.isAnomaly) return false;
                if (currentFilterMode === 'critical' && d.threatScore < 10.0 && !d.is_blacklisted) return false;
                if (currentFilterMode === 'obfuscated' && (d.entropy <= HIGH_ENTROPY || d.is_unreadable)) return false;

                if (!currentSearch.trim()) return true;

                const searchLower = currentSearch.toLowerCase();
                const pathMatch = d.path.toLowerCase().includes(searchLower);
                if (searchTokensOnly) {
                    if (d.matched_tokens && d.matched_tokens.length) {
                        return d.matched_tokens.some(t => t.toLowerCase().includes(searchLower));
                    }
                    return false;
                } else {
                    if (pathMatch) return true;
                    if (d.matched_tokens && d.matched_tokens.length) {
                        return d.matched_tokens.some(t => t.toLowerCase().includes(searchLower));
                    }
                    return false;
                }
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
                _eventLog.push({ message: message, level: level || 'warning', time: new Date() });
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
                    data.warnings.forEach(function (w) { logWarning(w, 'warning'); });
                }
            }

            function renderWarningPanel(data) {
                _lastRenderedData = data || _lastRenderedData;
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

            function renderTable(data) {
                renderWarningPanel(data);
                let filtered = data.filter(d => shouldShowFile(d));

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
                            badge = '<span style="background:#8b0000;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold;font-size:11px;">NOT READABLE</span> ';
                        } else if (d.is_blacklisted) {
                            color = '#f72f2f';
                            badge = '<span style="background:#cc0000;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold;font-size:11px;">BLACKLIST</span> ';
                            if (d.error) status = escapeHtml(shortenUnlinkError(d.error));
                        } else if (d.mhr_hit) {
                            color = '#f72f2f';
                            badge = `<span style="background:#cc0000;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold;font-size:11px;">MHR HIT (${d.mhr_detection_rate}%)</span> `;
                            status = escapeHtml(d.error ? shortenUnlinkError(d.error) : ('last seen ' + (d.mhr_last_seen || 'unknown')));
                        } else if (d.threatScore >= 15.0) {
                            color = '#dddbdb';
                            badge = `<span style="background:#990000;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold;font-size:11px;">CRITICAL (${d.threatScore.toFixed(1)})</span> `;
                        } else if (d.threatScore >= 8.0) {
                            color = '#dddbdb';
                            badge = `<span style="background:#b37700;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold;font-size:11px;">HIGH RISK (${d.threatScore.toFixed(1)})</span> `;
                        } else if (d.is_htaccess) {
                            color = '#66ccff';
                            badge = '<span style="background:#005580;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold;font-size:11px;">HTACCESS</span> ';
                        } else if (d.duplicate_of !== false) {
                            badge = '<span style="background:#444;color:#aaa;padding:2px 6px;border-radius:3px;font-size:11px;">DUPLICATE</span> ';
                            status = escapeHtml(d.duplicate_of);
                        }

                        if (d.mlPoints > 0) {
                            const why = `ML model ${Math.round(d.mlScore * 100)}%: +${d.mlPoints.toFixed(1)} of the threat score` +
                                (d.mlOnly ? '. Flagged only because of it' : '');
                            badge += `<span style="background:#6a3d9a;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold;font-size:11px;" title="${why}">ML +${d.mlPoints.toFixed(1)}</span> `;
                        }

                        if (!status && d.matched_tokens && d.matched_tokens.length > 0) {
                            let tokens = d.matched_tokens.map(t => {
                                const essential = ['eval', 'exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'assert', 'create_function', '`', '@input_call', '@preg_e', '@concat_name', '@halt_payload', 'base64_decode', 'str_rot13', 'bin2hex', 'hex2bin', 'gzinflate', 'gzuncompress', '$_files', '$auth_pass', '$password', '$pass', '$SISTEMIT_COM_ENC'];
                                if (essential.includes(t.toLowerCase())) return '<span class="token-highlight">' + escapeHtml(t) + '</span>';
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
                        analyzedData = analyzeData(rawFileData, currentThreshold);
                        renderTable(analyzedData);
                        if (insightsVisible) renderInsights(analyzedData);
                    }
                }
            }

            function applySearch() {
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
                const criticalCount = data.filter(d => d.threatScore >= 10.0 || d.is_blacklisted).length;

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
                            <td><strong style="color:${d.threatScore >= 10 ? '#ff4444' : '#ffaa00'}">${d.threatScore.toFixed(1)}</strong></td>
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
            let _chartRedrawQueued = false;
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
                if (_chartRedrawQueued) return;
                _chartRedrawQueued = true;
                requestAnimationFrame(function () {
                    _chartRedrawQueued = false;
                    _charts.forEach(c => c.draw());
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
                        c.draw();
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
                g.c.draw();
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
                dots.forEach(p => (shouldShowFile(p.d) ? shown : faded).push(p));
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

                // 1. THREAT MATRIX: suspicious-token ratio vs composite threat score
                {
                    const X_SPLIT = 0.15, Y_SPLIT = 8.0;
                    const pts = valid.map(d => ({ d: d, ratio: d.total_tokens > 0 ? (d.suspCount || 0) / d.total_tokens : 0, score: d.threatScore || 0 }));
                    let maxRatio = 0.01, maxScore = 1;
                    pts.forEach(p => { if (p.ratio > maxRatio) maxRatio = p.ratio; if (p.score > maxScore) maxScore = p.score; });
                    const fit = () => ({ xLo: 0, xHi: maxRatio * 1.15 + 0.001, yLo: 0, yHi: maxScore * 1.12 + 0.5 });
                    let view = fit();
                    const area = c => ({ left: 70, top: 30, right: c.w - 30, bottom: c.h - 45 });
                    const ratioOf = d => d.total_tokens > 0 ? (d.suspCount || 0) / d.total_tokens : 0;

                    makeChart(grid, 'Threat Matrix: Token Suspicion Ratio vs Threat Score', {
                        brush: 'xy',
                        draw: function (c) {
                            const ctx = c.ctx, b = area(c), W = b.right - b.left, H = b.bottom - b.top;
                            const xR = view.xHi - view.xLo || 1, yR = view.yHi - view.yLo || 1;
                            const sx = v => b.left + ((v - view.xLo) / xR) * W;
                            const sy = v => b.bottom - ((v - view.yLo) / yR) * H;
                            drawAxes(ctx, b.left, b.top, b.right, b.bottom);

                            // quadrant dividers and labels
                            const qx = sx(X_SPLIT), qy = sy(Y_SPLIT);
                            ctx.save(); ctx.strokeStyle = '#555'; ctx.lineWidth = 1; ctx.setLineDash([5, 4]);
                            ctx.beginPath();
                            if (qx > b.left && qx < b.right) { ctx.moveTo(qx, b.top); ctx.lineTo(qx, b.bottom); }
                            if (qy > b.top && qy < b.bottom) { ctx.moveTo(b.left, qy); ctx.lineTo(b.right, qy); }
                            ctx.stroke(); ctx.restore();
                            ctx.font = '10px Ubuntu Mono, monospace';
                            ctx.textAlign = 'right'; ctx.fillStyle = '#ff4444'; ctx.fillText('OBFUSCATED WEBSHELL', b.right - 4, b.top + 14);
                            ctx.textAlign = 'left';  ctx.fillStyle = '#ffaa00'; ctx.fillText('RCE SCRIPT', b.left + 4, b.top + 14);
                            ctx.textAlign = 'right'; ctx.fillStyle = '#4a8bc2'; ctx.fillText('DENSE NORMAL', b.right - 4, b.bottom - 6);
                            ctx.textAlign = 'left';  ctx.fillStyle = '#777';    ctx.fillText('BENIGN', b.left + 4, b.bottom - 6);

                            // ticks
                            ctx.fillStyle = '#888'; ctx.font = '10px Ubuntu Mono, monospace';
                            for (let t = 0; t <= 5; t++) {
                                const vy = view.yLo + (yR * t) / 5, vx = view.xLo + (xR * t) / 5;
                                ctx.textAlign = 'right';  ctx.fillText(vy.toFixed(1), b.left - 4, sy(vy) + 4);
                                ctx.textAlign = 'center'; ctx.fillText((vx * 100).toFixed(1) + '%', sx(vx), b.bottom + 14);
                            }

                            // axis labels
                            ctx.fillStyle = '#aaa'; ctx.font = '11px Ubuntu Mono, monospace'; ctx.textAlign = 'center';
                            ctx.fillText('Suspicious Token Ratio (wheel: zoom · Shift+drag: pan · double-click: reset)', b.left + W / 2, b.bottom + 30);
                            ctx.save(); ctx.translate(14, b.top + H / 2); ctx.rotate(-Math.PI / 2);
                            ctx.fillText('Threat Score', 0, 0); ctx.restore();

                            const dots = [];
                            pts.forEach(p => {
                                const x = sx(p.ratio), y = sy(p.score);
                                if (x < b.left || x > b.right || y < b.top || y > b.bottom) return;
                                let color = '#555';
                                if (p.score >= Y_SPLIT && p.ratio >= X_SPLIT) color = '#ff4444';
                                else if (p.score >= Y_SPLIT) color = '#ffaa00';
                                else if (p.ratio >= X_SPLIT) color = '#4a8bc2';
                                dots.push({ x: x, y: y, d: p.d, color: color });
                            });
                            drawDots(c, dots, 3.5);
                        },
                        hit: (c, x, y) => fileHit(dotAt(c, x, y), d => [
                            ['Token Ratio', (ratioOf(d) * 100).toFixed(1) + '%'],
                            ['Matched / Total', (d.suspCount || 0) + ' / ' + d.total_tokens],
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
                                    const shown = k.files.filter(d => shouldShowFile(d));
                                    const hAll = (k.files.length / maxCount) * H, hShown = (shown.length / maxCount) * H;
                                    ctx.fillStyle = '#3a3a3a';
                                    ctx.fillRect(x, b.bottom - hAll, w, hAll);
                                    const top = shown.reduce((m, d) => Math.max(m, d.threatScore || 0), 0);
                                    ctx.fillStyle = top >= 10.0 ? '#ff4444' : (top >= 5.0 ? '#ffaa00' : '#4a8bc2');
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
                    makeChart(grid, 'Top Composite Threat Scores', {
                        draw: function (c) {
                            const ctx = c.ctx, b = area(c);
                            const top = valid.filter(d => passesTableFilters(d))
                                .sort((a, z) => (z.threatScore || 0) - (a.threatScore || 0)).slice(0, 12);
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
                                ctx.fillStyle = score >= 10.0 ? '#ff4444' : (score >= 5.0 ? '#ffaa00' : '#4a8bc2');
                                ctx.fillRect(b.left, y, w, h);
                                const name = String(d.path || '').split('/').pop() || d.path;
                                drawLabel(ctx, name.length > 26 ? name.slice(0, 23) + '...' : name, b.left - 8, y + h / 2 + 4, 'right');
                                drawLabel(ctx, score.toFixed(1), Math.min(b.right - 4, b.left + w + 6), y + h / 2 + 4, 'left');
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
                                if (d.threatScore >= 15) color = '#ff4444';
                                else if (d.threatScore >= 8) color = '#ffaa00';
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
            var _seenHashes = [];

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
                _seenHashes = [];
                _chartSelection = null;
                var allFeatures = [];

                resetWarningPanel();

                document.getElementById('ajaxProgress').style.display = 'block';
                document.getElementById('ajaxBar').style.width = '0%';
                document.getElementById('ajaxStatus').textContent = 'Phase 1: Scanning directory\u2026';
                document.getElementById('ajaxSubStatus').textContent = '';
                document.getElementById('result').innerHTML = '';
                analyzedData = [];

                var body = new URLSearchParams();
                body.set('ajax_action', 'scan');
                body.set('dir', dir);

                postAction(body)
                    .then(function(r) { return r.json(); })
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
                        currentThreshold = parseFloat(document.getElementById('zThreshold').value) || 3.5;
                        analyzedData = analyzeData(allFeatures, currentThreshold);
                        renderTable(analyzedData);
                    })
                    .catch(function(err) {
                        document.getElementById('ajaxProgress').style.display = 'none';
                        logWarning('AJAX scan error: ' + err.message, 'error');
                    });
            }

            // One 'process' request for a batch of paths \u2014 returns the parsed
            // JSON, or rejects (with a SyntaxError specifically when the body
            // wasn't valid JSON at all, e.g. a hosting-level security rule
            // blocked the request and returned an HTML page instead).
            function fetchProcessBatch(paths, isNotReadable) {
                var body = new URLSearchParams();
                body.set('ajax_action', 'process');
                body.set('is_not_readable', isNotReadable ? '1' : '0');
                body.set('paths', paths.join(','));
                body.set('seen_hashes', _seenHashes.join(','));
                body.set('ml', (typeof ML_MODEL !== 'undefined' && ML_MODEL) ? '1' : '0'); // no model: skip ML features
                return postAction(body).then(function(r) { return r.json(); });
            }

            function applyProcessResult(data, allFeatures) {
                reportServerWarnings(data);
                var feats = data.features || [];
                feats.forEach(function(f) {
                    f.pathRaw = f.path; // encoded form, sent back as-is
                    f.path = decodePath(f.path);
                    if (f.duplicate_of !== false) f.duplicate_of = decodePath(f.duplicate_of);
                    allFeatures.push(f);
                });
                if (data.new_hashes) {
                    data.new_hashes.forEach(function(h) { _seenHashes.push(h); });
                }
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
                        // Incremental render every 3 chunks so user sees progress
                        if ((idx + 1) % 3 === 0 || idx + 1 === chunks.length) {
                            currentThreshold = parseFloat(document.getElementById('zThreshold').value) || 3.5;
                            analyzedData = analyzeData(allFeatures, currentThreshold);
                            renderTable(analyzedData);
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
                for (var i = 0; i < hashes.length; i += 1000) {
                    batches.push(hashes.slice(i, i + 1000));
                }

                var hitMap = {};

                function runBatch(idx) {
                    if (idx >= batches.length) { return Promise.resolve(); }

                    if (statusEl) {
                        statusEl.textContent = 'Checking Malware Hash Registry… batch ' +
                            (idx + 1) + '/' + batches.length + ' (' + batches[idx].length + ' hashes)';
                    }

                    var body = new URLSearchParams();
                    body.set('ajax_action', 'mhr_check');
                    body.set('mhr_user', mhrUser);
                    body.set('mhr_pass', mhrPass);
                    batches[idx].forEach(function (h) { body.append('hashes[]', h); });

                    return postAction(body)
                        .then(function (r) { return r.json(); })
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

                    var body = new URLSearchParams();
                    body.set('ajax_action', 'mhr_unlink');
                    body.set('mhr_user', mhrUser); // the server re-checks each file's hash with MHR before deleting
                    body.set('mhr_pass', mhrPass);
                    body.set('paths', hitFiles.map(function (f) { return f.pathRaw; }).join(','));

                    return postAction(body)
                        .then(function (r) { return r.json(); })
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
                            currentThreshold = parseFloat(document.getElementById('zThreshold').value) || 3.5;
                            analyzedData = analyzeData(features, currentThreshold);
                            renderTable(analyzedData);

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
                            currentThreshold = parseFloat(document.getElementById('zThreshold').value) || 3.5;
                            analyzedData = analyzeData(features, currentThreshold);
                            renderTable(analyzedData);
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