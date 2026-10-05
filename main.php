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

$mhrUsername = '';
$mhrPassword = '';
$GLOBALS['phpWarnings'] = array();

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
 * Read a POST field holding a NUL-separated list. One field (unlike
 * paths[]=...) stays clear of max_input_vars no matter how many entries it
 * holds. Paths travel rawurlencode()d, so NUL can't occur inside an entry.
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
    return explode("\0", $value);
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
            'ml_features'    => _ML_ ? mlFeatures($tokens, $content, $entropy) : null,
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
            <div id="chartsGrid" class="charts-grid"></div>
        </div>

        <!-- Tooltip for charts -->
        <div id="chart-tooltip"></div>

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
            let _timelineFilter = null; // {minTime, maxTime} or null

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

                return Math.round(score * 100) / 100;
            }

            // Tiny ML model: logistic regression over the hashed token features
            // from mlFeatures() in PHP (one bit per bucket), int8 weights as hex.
            // Trained and cross-validated by node test/train-ml.js --write.
            const ML_MODEL = {"scale":0.00936201,"bias":0.0182935,"weights":"0dfeffff160006f802f90bfe010108fe07fc04ff07fa0ff705fe2c0003fefd00f3f9100b0afe06fc00030102fefffef00efac8c8021e500613f5cb07f3faff091101ed1105f9080100fd01effbfa0b06fde4fefefcffd5fe02061204f903f8f601fcfffaf300fc11fbfefdff0304fef30b1c2efaf8fcfc210ce7000003fbfc0023fc02171a0000121afffdf2fbfcff00000b0304ff02cb00fe0202fffefdf509fdf5ff08c100fce8fef3010400fdf9f100f40ff0fafe21f9fbd60405fefbfdc6e5eef902fd02f9ff06fef6fd050000fe04fd7c0800040bff0401f5fbfdfc01000403fcfefec2fcfef4fbf914f90023dc0200f801f9fd01ecf0fefffdf9fffaf9f801fdfffb01fcff010d080005fef5fdfafe0d00fe0002fefe022d0b09fb270efd010ffb04ecfffcff12fbfb1300070dfffc0403000e00fb04f513fdfffbfdfefee01904f90903fedf12f409fff1fc020104fd00f9f409edff20ff0de8fa1003fefef6f9feff0202ff00fdf60bfcfa08feff03ff0805fe0e01e9f6fefffffe21ffecfd010a0003fef45afffefcf00700ecff4a02fdfb0afc013f12030f070738fefc05feff0ffffafc0210021420fdffff0e01031ef4fdfe00f804fc03f61a120bfef6f900f900150060f90005fff8fd11fd1cfef509f2fefbfffb0401fb04f50701f9fdfe02edfeebfbfd04fefffe01fefd00fffbeefe05fdc30d01eae7030702ff02040d3000fdf1ff05fe0000fb120312faf4f5fe2bfffbfefe1904fcf9fbfdfe1102fbfc021701f8f6fefafffe5bf5ff01fffc06030008f1fdfef002f1fefafbfee7fdfe02fdffe00201fcff2bf7ef0302010cfd1af706f401f4dffef2ff00fffe0203faf8f0f305fff8ff02fcfbfdfff906ffff0af701fff800fef8ff00fe06fafdfe0001fdfefcff04fd41fcffe2f6fafd00fcfe7f00fd04fefffcfe09fdf9fc21fbfefdfcfffcffec0b1c0bfe00fdff0603fefefffd0be1f6ff0b0633fefe0bfefafc04ef04010507fd0201fe06fdff02fdfafe043b12040a0011fd00fefe02260005ff02fdf6fc05f804fdfc04fafefbf7fb00de00f5fc0207f9fefdfdeff900f81300fcfed4fb06fe0012f1f900000601fef205ff14faf53604fbe2fefd0b01fef914f9060afc04f2f9fb0c0401f700fd12010b0000fefd9dfdfd04fc180df7fc03090503fb000cfefaf4e6fd02fefde8fefc0a05fd09fffd00fdfefd03f3fe0a06fe00fcfff6fefee902fffb13fe00fefdfeff1400eefcfcfdfbfd02fffffe0fea00a80410f106f9090410e800fdfafe00051e2004f6e2f0fefcfd0efafc00fafefffff2fa00feec01fffefbf4170301f9d0fff9fe070a0efffdff03fe0900ff0c06fc0119fe00fcfff60bfefe03fe09070300fefe0107fe07fdfbfbfbfbfbf2fe010717fff9ff0500f800f3fe1afcf4fa0301fe00f4ee0ed800fc01f90402fd3e00031df9f112fefb0111dc12e60f05ffee0901f5fffbfef2c5fdfdfdfdfb011ffdfe00ff0324021cfd02fe02f71709fffd1aff001601feff1901fefffd41f7ffe60bfeebf801100904200204fdf4f9fd111b0e140001f8fffefdfdfcffff02f90a039f03fd2b07fd020012f202fa03fffffcfff8f8f2fff20800fd03f7fc0a04fffafcfcfc03ff03050bfcfcfdff05110bff031100fdf8f9ddfeff03f7ffff2301fe051bfb00fcff03fb19fafdfaff0429040ef3ff121f2515fbfcfd0115fd091402feff06fe06dbfcfcfcfbe3fa000100fffc0a0800fe021afe13fe2800fdf700f9f903e902fc0003effc02fefd0105fcfe1afe08fefc20dc070302f60000dd01e306010efff60704fd00ff1b0c05ff07ff03fe00fe0903fd000af6001402ecf0f9ffeb01fffdbf00f10ef6fef2dfe1fcecfffa01ff13f704fdfdf609051607f52307f932fefe0cff2f2bd9e9fcfbf20aff071005fefbfd01fefdfed30200fa0301fe01f6f61c09fe200f00ff00fd15fff910fefdfff1fed4fdfbff00081615fcfef20a0001fffcfe030110fd00ff000bfee7fae5fffafcf700ecf8ff09f902fcfe001dfff3fc01f3fdf507ff05061111f506fbf70110fffff8fef8ffe10ffc00c5f7ff0002fbf2fbf9fe1808fcfeffd203f9010b0004fffefaf5f416d501ff14ff14fc01fd00d3fefa0503090222eb00ff03030bfffa0102ff00fa00fffcfcfcff01ede7fd02fd0410fcff00fd00fffdfc10f9fbfcf4f10002fefe0900ff0101ff01f3fee0f8fbeefb02fe0103fbfae30401bb010700fd03ff12ff2902030302fe21ffff050010fb08f8111105030bfe10fefcfefffefdf600fd0c08f8e628030a03f400f9f1f9f90809fdffe9fd01fdfaf6fdb3f8250806fafe02051ff4edfefea1fefdff02000304ffff03fefa00fefd060dff0dfdfe09fe210301f94e90fe000b0bfe07fbfcf9fff615fdfc010301fdfafb00f3fe02fefffc04f302fb01fefc09f9d811fff1fb07fffb00fe0009fefa07feef1500fafcfde503ff06faf8fc02fc14fffefe000106fffe02e901fd00fafffbfdeaf5fe05fffffdfc1005f6fafb0501fffbffed08000e01fc060301fe01fc001cfa040700fbe4fd020cfcfefe08f509fbfd0406001aff02ecfe0e0100f801fd000114fa00f2d80c000bfdffe7fb06f8ffee0701fff8fe2af908fcf60dff060214fd02fdfc05170409ff0003fbc5fd13ff02fcf908fefff4fefe01fd06fe04db0904fe00fffffffe00e8fb03fdfff602fb2315fe05f8fe04fdfaf6fefe03fe00fd0ffdfe02f9fffd22fe0cf83f13ffff00e602e0feffdb080016f7fffafced01fdf0f6ebfdf708f5fff403f81d0e05fefdfefb06fafe08fefe04fbfbc9f8030002f9f2fc0dfd03ff08fffc0cfbeefeff06f8edf60600fefd0205191725f0fafcfe0004fa04fc"};
            // Score at or above which the model alone flags a file (a ranking
            // score from training, not a calibrated probability)
            const ML_THRESHOLD = 0.9;
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
                model = model || ML_MODEL;
                if (!hex || !model.weights) return null;
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
                            mlOnly: false,
                            threatScore: 0,
                            date: formatDate(d.mtime),
                            suspCount: 0
                        };
                    }

                    let threatScore = calculateThreatScore(d, weights);

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
                    // already covers "many suspicious tokens".
                    //
                    // Entropy only matters on the high side; a near-empty stub
                    // isn't an outlier worth reviewing.
                    const ruleAnomaly = (threatScore >= 8.0) ||
                        (zEntropy > threshold) ||
                        (Math.abs(zMtime) > threshold) ||
                        (Math.abs(zCtime) > threshold) ||
                        rareOwner ||
                        (residual > 5) ||
                        d.is_blacklisted ||
                        d.mhr_hit === true;
                    // The ML model is a second opinion: it can flag a file the
                    // rules miss (mlOnly), never clear one they flag. It was
                    // trained on PHP, so .htaccess files aren't scored.
                    const ml = d.is_htaccess ? null : mlScore(d.ml_features);
                    const mlOnly = !ruleAnomaly && ml !== null && ml >= ML_THRESHOLD;
                    const isAnomaly = ruleAnomaly || mlOnly;

                    return {
                        ...d,
                        zScores: { size: zSize, mtime: zMtime, tokens: zTokens, susp: zSusp, entropy: zEntropy, ctime: zCtime },
                        residual: residual,
                        rareOwner: rareOwner,
                        isAnomaly: isAnomaly,
                        mlScore: ml,
                        mlOnly: mlOnly,
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

            function shouldShowFile(d) {
                if (currentFilterMode === 'anomalies' && !d.isAnomaly) return false;
                if (currentFilterMode === 'critical' && d.threatScore < 10.0 && !d.is_blacklisted) return false;
                if (currentFilterMode === 'obfuscated' && (d.entropy <= HIGH_ENTROPY || d.is_unreadable)) return false;

                if (_timelineFilter) {
                    if (!d.mtime || d.mtime < _timelineFilter.minTime || d.mtime > _timelineFilter.maxTime) return false;
                }

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
                        } else if (d.mlOnly) {
                            badge = `<span style="background:#6a3d9a;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold;font-size:11px;" title="flagged by the ML model only">ML (${Math.round(d.mlScore * 100)}%)</span> `;
                        } else if (d.is_htaccess) {
                            color = '#66ccff';
                            badge = '<span style="background:#005580;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold;font-size:11px;">HTACCESS</span> ';
                        } else if (d.duplicate_of !== false) {
                            badge = '<span style="background:#444;color:#aaa;padding:2px 6px;border-radius:3px;font-size:11px;">DUPLICATE</span> ';
                            status = escapeHtml(d.duplicate_of);
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
                            verbosity = `${d.date} | Size: ${sizeKB} KB | Tokens: ${d.total_tokens || 0} | Suspicious: ${d.suspCount} | Entropy: ${entStr} | Score: ${d.threatScore.toFixed(1)}${d.mlScore !== null ? ' | ML: ' + Math.round(d.mlScore * 100) + '%' : ''} | Z‑Susp: ${d.zScores.susp.toFixed(1)} | Z‑Ctime: ${d.zScores.ctime.toFixed(1)} | Owner: ${d.owner}${d.rareOwner ? ' (RARE)' : ''}`;
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

                        html += `<tr>
                            <td style="color:${color}; font-size:13px;">
                                ${mainLine}
                                <br><span class="verbosity">${verbosity}</span>
                            </td>
                        </tr>`;
                    });
                }
                document.getElementById('result').innerHTML = html;
            }

            function copyResults() {
                let text = analyzedData
                    .filter(d => shouldShowFile(d))
                    .map(d => {
                        let line = d.path;
                        if (d.is_unreadable) line += ' (NOT_READABLE)';
                        else if (d.is_blacklisted) line += ' (BLACKLIST)';
                        else if (d.mhr_hit) line += ' (MHR HIT ' + d.mhr_detection_rate + '%)';
                        else if (d.mlOnly) line += ' (ML ' + Math.round(d.mlScore * 100) + '%)';
                        else if (d.is_htaccess) line += ' (HTACCESS)';
                        else if (d.duplicate_of !== false) line += ' (' + d.duplicate_of + ')';
                        else if (d.matched_tokens && d.matched_tokens.length > 0) {
                            line += ' (' + d.matched_tokens.join(', ') + ')';
                        }
                        if (!d.is_unreadable && d.size !== null) {
                            const sizeKB = (d.size / 1024).toFixed(1);
                            line += ` | ${d.date} | Size: ${sizeKB} KB | ThreatScore: ${d.threatScore.toFixed(1)}${d.mlScore !== null ? ' | ML: ' + Math.round(d.mlScore * 100) + '%' : ''} | Tokens: ${d.total_tokens} | Suspicious: ${d.suspCount} | Z-Susp: ${d.zScores.susp.toFixed(1)}`;
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
                        if (chartsVisible) renderCharts(analyzedData);
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
                _timelineFilter = null;
                renderTable(analyzedData);
            }

            function filterByTimeline(minTime, maxTime) {
                _timelineFilter = { minTime: minTime, maxTime: maxTime };
                currentSort = 'mtime';
                currentSearch = '';
                searchTokensOnly = false;
                currentFilterMode = 'all';
                document.getElementById('searchInput').value = '';
                document.getElementById('searchTokensOnly').checked = false;
                document.getElementById('severityFilter').value = 'all';
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
                _timelineFilter = null;
                renderTable(analyzedData);
            }

            const originalShouldShow = shouldShowFile;
            shouldShowFile = function(d) {
                if (currentSearch === '__BLACKLIST__') {
                    return d.is_blacklisted === true;
                }
                return originalShouldShow(d);
            };

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

            function renderCharts(data) {
                const grid = document.getElementById('chartsGrid');
                grid.innerHTML = '';

                if (!data || data.length < 2) {
                    grid.innerHTML = '<div class="dashboard-empty">Not enough data to render charts.</div>';
                    return;
                }

                const valid = data.filter(d => !d.is_unreadable && d.size !== null && d.mtime !== null);

                if (valid.length < 2) {
                    grid.innerHTML = '<div class="dashboard-empty">Not enough readable files to render charts.</div>';
                    return;
                }

                const tooltip = document.getElementById('chart-tooltip');

                function makeBox(title) {
                    const box = document.createElement('div');
                    box.className = 'chart-box';

                    const titleEl = document.createElement('div');
                    titleEl.style.textAlign = 'center';
                    titleEl.style.color = '#ccc';
                    titleEl.style.marginBottom = '8px';
                    titleEl.style.fontWeight = 'bold';
                    titleEl.textContent = title;
                    box.appendChild(titleEl);

                    const canvas = document.createElement('canvas');
                    canvas.width = 900;
                    canvas.height = 300;
                    box.appendChild(canvas);
                    grid.appendChild(box);

                    return canvas.getContext('2d');
                }

                function clear(ctx) {
                    ctx.clearRect(0, 0, ctx.canvas.width, ctx.canvas.height);
                    ctx.fillStyle = '#2a2a2a';
                    ctx.fillRect(0, 0, ctx.canvas.width, ctx.canvas.height);
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

                // 1. QUADRANT THREAT MATRIX: Token Suspicion Ratio vs Composite Threat Score
                {
                    const ctx = makeBox('Threat Matrix: Token Suspicion Ratio vs Threat Score');
                    const canvas = ctx.canvas;
                    const left = 70, top = 30, right = 860, bottom = 255;
                    const W = right - left, H = bottom - top;

                    // raw data points
                    const pts = valid.map(d => ({
                        ratio: d.total_tokens > 0 ? (d.suspCount || 0) / d.total_tokens : 0,
                        score: d.threatScore || 0,
                        data: d
                    }));

                    // auto-fit initial axes to actual data range
                    const xThresh = 0.15, yThresh = 8.0;
                    let rawMaxRatio = 0.01, rawMaxScore = 1;
                    pts.forEach(p => {
                        if (p.ratio > rawMaxRatio) rawMaxRatio = p.ratio;
                        if (p.score > rawMaxScore) rawMaxScore = p.score;
                    });
                    let view = {
                        xLo: 0, xHi: rawMaxRatio * 1.15 + 0.001,
                        yLo: 0, yHi: rawMaxScore * 1.12 + 0.5
                    };

                    const hitPoints = [];

                    function drawThreatMatrix() {
                        clear(ctx);
                        const xRange = view.xHi - view.xLo || 1;
                        const yRange = view.yHi - view.yLo || 1;

                        drawAxes(ctx, left, top, right, bottom);

                        // quadrant dividers
                        const qx = left + ((xThresh - view.xLo) / xRange) * W;
                        const qy = bottom - ((yThresh - view.yLo) / yRange) * H;
                        ctx.save(); ctx.strokeStyle = '#555'; ctx.lineWidth = 1; ctx.setLineDash([5,4]);
                        ctx.beginPath();
                        if (qx > left && qx < right) { ctx.moveTo(qx, top); ctx.lineTo(qx, bottom); }
                        if (qy > top && qy < bottom) { ctx.moveTo(left, qy); ctx.lineTo(right, qy); }
                        ctx.stroke(); ctx.setLineDash([]); ctx.restore();

                        // quadrant labels
                        ctx.font = '10px Ubuntu Mono, monospace';
                        ctx.textAlign = 'right';  ctx.fillStyle = '#ff4444'; ctx.fillText('OBFUSCATED WEBSHELL', right-4, top+14);
                        ctx.textAlign = 'left';   ctx.fillStyle = '#ffaa00'; ctx.fillText('RCE SCRIPT', left+4, top+14);
                        ctx.textAlign = 'right';  ctx.fillStyle = '#4a8bc2'; ctx.fillText('DENSE NORMAL', right-4, bottom-6);
                        ctx.textAlign = 'left';   ctx.fillStyle = '#777';    ctx.fillText('BENIGN', left+4, bottom-6);

                        // Y ticks
                        ctx.fillStyle = '#888'; ctx.font = '10px Ubuntu Mono, monospace'; ctx.textAlign = 'right';
                        for (let t = 0; t <= 5; t++) {
                            const v = view.yLo + (yRange * t) / 5;
                            const y = bottom - ((v - view.yLo) / yRange) * H;
                            ctx.fillText(v.toFixed(1), left-4, y+4);
                            ctx.save(); ctx.strokeStyle='#333'; ctx.lineWidth=1;
                            ctx.beginPath(); ctx.moveTo(left-3,y); ctx.lineTo(left,y); ctx.stroke(); ctx.restore();
                        }

                        // X ticks
                        ctx.textAlign = 'center';
                        for (let t = 0; t <= 5; t++) {
                            const v = view.xLo + (xRange * t) / 5;
                            const x = left + ((v - view.xLo) / xRange) * W;
                            ctx.fillText((v * 100).toFixed(1) + '%', x, bottom+14);
                            ctx.save(); ctx.strokeStyle='#333'; ctx.lineWidth=1;
                            ctx.beginPath(); ctx.moveTo(x,bottom); ctx.lineTo(x,bottom+3); ctx.stroke(); ctx.restore();
                        }

                        // axis labels
                        ctx.fillStyle = '#aaa'; ctx.font = '11px Ubuntu Mono, monospace'; ctx.textAlign = 'center';
                        ctx.fillText('Suspicious Token Ratio — scroll to zoom, drag to pan, dblclick to reset', left+W/2, bottom+28);
                        ctx.save(); ctx.translate(14, top+H/2); ctx.rotate(-Math.PI/2);
                        ctx.fillText('Threat Score', 0, 0); ctx.restore();

                        // dots
                        hitPoints.length = 0;
                        pts.forEach(p => {
                            const px = left + ((p.ratio - view.xLo) / xRange) * W;
                            const py = bottom - ((p.score - view.yLo) / yRange) * H;
                            if (px < left || px > right || py < top || py > bottom) return;
                            let color;
                            if (p.score >= yThresh && p.ratio >= xThresh) color = '#ff4444';
                            else if (p.score >= yThresh)                  color = '#ffaa00';
                            else if (p.ratio >= xThresh)                  color = '#4a8bc2';
                            else                                           color = '#555';
                            ctx.fillStyle = color;
                            ctx.beginPath(); ctx.arc(px, py, 3.5, 0, Math.PI*2); ctx.fill();
                            hitPoints.push({ x: px, y: py, data: p.data, ratio: p.ratio });
                        });
                    }

                    drawThreatMatrix();

                    // wheel zoom around cursor
                    canvas.addEventListener('wheel', function(e) {
                        e.preventDefault();
                        const rect = canvas.getBoundingClientRect();
                        const mx = (e.clientX - rect.left) * (canvas.width / rect.width);
                        const my = (e.clientY - rect.top) * (canvas.height / rect.height);
                        const fx = Math.max(0, Math.min(1, (mx - left) / W));
                        const fy = Math.max(0, Math.min(1, (my - top) / H));
                        const f = e.deltaY > 0 ? 1.08 : 0.925;
                        const xR = view.xHi - view.xLo, yR = view.yHi - view.yLo;
                        const pivX = view.xLo + fx * xR, pivY = view.yHi - fy * yR;
                        view.xLo = Math.max(0, pivX - fx * xR * f);
                        view.xHi = pivX + (1 - fx) * xR * f;
                        view.yLo = Math.max(0, pivY - (1 - fy) * yR * f);
                        view.yHi = pivY + fy * yR * f;
                        drawThreatMatrix();
                    }, { passive: false });

                    // drag pan
                    let tmDrag = false, tmLX = 0, tmLY = 0;
                    canvas.addEventListener('mousedown', function(e) {
                        if (e.button !== 0) return;
                        tmDrag = true; tmLX = e.clientX; tmLY = e.clientY;
                        canvas.style.cursor = 'grabbing'; e.preventDefault();
                    });
                    document.addEventListener('mousemove', function(e) {
                        if (!tmDrag) return;
                        const rect = canvas.getBoundingClientRect();
                        const dx = (e.clientX - tmLX) / rect.width  * (view.xHi - view.xLo) * (canvas.width  / W);
                        const dy = (e.clientY - tmLY) / rect.height * (view.yHi - view.yLo) * (canvas.height / H);
                        view.xLo -= dx; view.xHi -= dx;
                        view.yLo += dy; view.yHi += dy;
                        if (view.xLo < 0) { view.xHi -= view.xLo; view.xLo = 0; }
                        if (view.yLo < 0) { view.yHi -= view.yLo; view.yLo = 0; }
                        tmLX = e.clientX; tmLY = e.clientY;
                        drawThreatMatrix();
                    });
                    document.addEventListener('mouseup', function() {
                        if (tmDrag) { tmDrag = false; canvas.style.cursor = 'crosshair'; }
                    });

                    // hover tooltip
                    canvas.addEventListener('mousemove', function(e) {
                        if (tmDrag) return;
                        const rect = canvas.getBoundingClientRect();
                        const mx = (e.clientX - rect.left) * (canvas.width / rect.width);
                        const my = (e.clientY - rect.top)  * (canvas.height / rect.height);
                        let hit = null;
                        for (let j = 0; j < hitPoints.length; j++) {
                            const hp = hitPoints[j];
                            if ((hp.x-mx)**2 + (hp.y-my)**2 < 100) { hit = hp; break; }
                        }
                        if (hit) {
                            const d = hit.data;
                            tooltip.innerHTML =
                                '<div><span class="label">File:</span> <span class="value">' + escapeHtml(d.path) + '</span></div>' +
                                '<div><span class="label">Threat Score:</span> <span class="value">' + d.threatScore.toFixed(1) + '</span></div>' +
                                '<div><span class="label">Token Ratio:</span> <span class="value">' + (hit.ratio*100).toFixed(1) + '%</span></div>' +
                                '<div><span class="label">Matched / Total:</span> <span class="value">' + (d.suspCount||0) + ' / ' + d.total_tokens + '</span></div>' +
                                '<div><span class="label">Matched:</span> <span class="value">' + escapeHtml((d.matched_tokens||[]).join(', ')) + '</span></div>';
                            tooltip.style.display = 'block';
                            positionTooltip(e, tooltip);
                            canvas.style.cursor = 'pointer';
                        } else {
                            tooltip.style.display = 'none';
                            canvas.style.cursor = 'crosshair';
                        }
                    });
                    canvas.addEventListener('click', function(e) {
                        if (tmDrag) return;
                        const rect = canvas.getBoundingClientRect();
                        const mx = (e.clientX - rect.left) * (canvas.width / rect.width);
                        const my = (e.clientY - rect.top)  * (canvas.height / rect.height);
                        for (let j = 0; j < hitPoints.length; j++) {
                            const hp = hitPoints[j];
                            if ((hp.x-mx)**2 + (hp.y-my)**2 < 100) { filterByPath(hp.data.path); break; }
                        }
                    });
                    // double-click resets to auto-fit
                    canvas.addEventListener('dblclick', function() {
                        view = { xLo:0, xHi:rawMaxRatio*1.15+0.001, yLo:0, yHi:rawMaxScore*1.12+0.5 };
                        drawThreatMatrix();
                    });
                }

                // 2. TIMELINE HISTOGRAM: File Modifications over Time
                {
                    const ctx = makeBox('Incident Timeline: File Modifications over Time');
                    clear(ctx);
                    const left = 60, top = 25, right = 870, bottom = 250;
                    drawAxes(ctx, left, top, right, bottom);

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
                        const targetBuckets = 20;
                        const idealSize = span / targetBuckets;
                        let bucketSize = NICE_BUCKETS[NICE_BUCKETS.length - 1];
                        for (const candidate of NICE_BUCKETS) {
                            if (candidate >= idealSize) { bucketSize = candidate; break; }
                        }

                        // Align the first bucket to a clean boundary (e.g. day buckets
                        // start at UTC midnight) rather than the raw earliest timestamp.
                        const startT = Math.floor(minT / bucketSize) * bucketSize;
                        const numBuckets = Math.max(1, Math.ceil((maxT - startT + 1) / bucketSize));
                        const buckets = [];
                        for (let i = 0; i < numBuckets; i++) {
                            buckets.push({ count: 0, maxThreat: 0, files: [] });
                        }

                        valid.forEach(d => {
                            if (!d.mtime) return;
                            let idx = Math.floor((d.mtime - startT) / bucketSize);
                            if (idx >= numBuckets) idx = numBuckets - 1;
                            if (idx < 0) idx = 0;
                            buckets[idx].count++;
                            if (d.threatScore > buckets[idx].maxThreat) buckets[idx].maxThreat = d.threatScore;
                            buckets[idx].files.push(d);
                        });

                        const maxBucketCount = Math.max(1, ...buckets.map(b => b.count));
                        const barW = (right - left) / numBuckets - 3;
                        const hitBars = [];

                        buckets.forEach((b, i) => {
                            const bx = left + i * ((right - left) / numBuckets) + 1;
                            const barH = (b.count / maxBucketCount) * (bottom - top);
                            const by = bottom - barH;

                            let color = '#4a8bc2';
                            if (b.maxThreat >= 10.0) color = '#ff4444';
                            else if (b.maxThreat >= 5.0) color = '#ffaa00';

                            ctx.fillStyle = color;
                            ctx.fillRect(bx, by, barW, barH);

                            hitBars.push({ x: bx, y: by, w: barW, h: barH, bucket: b, time: startT + i * bucketSize });
                        });

                        const canvas = ctx.canvas;
                        canvas.addEventListener('mousemove', function(e) {
                            const rect = canvas.getBoundingClientRect();
                            const mx = (e.clientX - rect.left) * (canvas.width / rect.width);
                            const my = (e.clientY - rect.top) * (canvas.height / rect.height);
                            let found = false;
                            for (let hb of hitBars) {
                                if (mx >= hb.x && mx <= hb.x + hb.w && my >= hb.y && my <= bottom) {
                                    const info = `
                                        <div><span class="label">Timeframe:</span> <span class="value">${formatDate(hb.time)}</span></div>
                                        <div><span class="label">Files Modified:</span> <span class="value">${hb.bucket.count}</span></div>
                                        <div><span class="label">Max Threat Score:</span> <span class="value">${hb.bucket.maxThreat.toFixed(1)}</span></div>
                                    `;
                                    tooltip.innerHTML = info;
                                    tooltip.style.display = 'block';
                                    positionTooltip(e, tooltip);
                                    canvas.style.cursor = 'pointer';
                                    found = true;
                                    break;
                                }
                            }
                            if (!found) {
                                tooltip.style.display = 'none';
                                canvas.style.cursor = 'crosshair';
                            }
                        });

                        canvas.addEventListener('click', function(e) {
                            var rect = canvas.getBoundingClientRect();
                            var mx = (e.clientX - rect.left) * (canvas.width / rect.width);
                            var my = (e.clientY - rect.top) * (canvas.height / rect.height);
                            for (var hb_i = 0; hb_i < hitBars.length; hb_i++) {
                                var hb = hitBars[hb_i];
                                if (mx >= hb.x && mx <= hb.x + hb.w && my >= hb.y && my <= bottom) {
                                    filterByTimeline(hb.time, hb.time + bucketSize);
                                    break;
                                }
                            }
                        });

                        drawLabel(ctx, formatDate(minT), left, bottom + 35, 'left');
                        drawLabel(ctx, formatDate(maxT), right, bottom + 35, 'right');
                        drawLabel(ctx, 'File Count', 8, top + 10, 'left');
                    }
                }

                // 3. TOP THREAT SCORES BAR CHART
                {
                    const ctx = makeBox('Top Composite Threat Scores');
                    clear(ctx);

                    const selected = valid.slice().sort((a, b) => (b.threatScore || 0) - (a.threatScore || 0)).slice(0, 12);
                    const left = 200, top = 20, right = 870, bottom = 270;
                    const rowH = (bottom - top) / Math.max(1, selected.length);
                    const maxScore = Math.max(10.0, ...selected.map(d => d.threatScore || 0));

                    const barHitAreas = [];

                    selected.forEach((d, i) => {
                        const score = d.threatScore || 0;
                        const y = top + i * rowH + 3;
                        const w = (score / maxScore) * (right - left);

                        ctx.fillStyle = score >= 10.0 ? '#ff4444' : (score >= 5.0 ? '#ffaa00' : '#4a8bc2');
                        ctx.fillRect(left, y, w, Math.max(8, rowH - 6));

                        const name = String(d.path || '').split('/').pop() || d.path;
                        drawLabel(ctx, name.length > 26 ? name.slice(0, 23) + '...' : name, left - 8, y + rowH / 2 + 4, 'right');
                        drawLabel(ctx, score.toFixed(1), Math.min(right - 4, left + w + 6), y + rowH / 2 + 4, 'left');

                        barHitAreas.push({ x: left, y: y, w: w, h: Math.max(8, rowH - 6), data: d });
                    });

                    const canvas = ctx.canvas;
                    canvas.addEventListener('click', function(e) {
                        const rect = canvas.getBoundingClientRect();
                        const mx = (e.clientX - rect.left) * (canvas.width / rect.width);
                        const my = (e.clientY - rect.top) * (canvas.height / rect.height);
                        for (let bar of barHitAreas) {
                            if (mx >= bar.x && mx <= bar.x + bar.w && my >= bar.y && my <= bar.y + bar.h) {
                                filterByPath(bar.data.path);
                                break;
                            }
                        }
                    });
                    canvas.addEventListener('mousemove', function(e) {
                        const rect = canvas.getBoundingClientRect();
                        const mx = (e.clientX - rect.left) * (canvas.width / rect.width);
                        const my = (e.clientY - rect.top) * (canvas.height / rect.height);
                        let found = false;
                        for (let bar of barHitAreas) {
                            if (mx >= bar.x && mx <= bar.x + bar.w && my >= bar.y && my <= bar.y + bar.h) {
                                const d = bar.data;
                                const info = `
                                    <div><span class="label">File:</span> <span class="value">${escapeHtml(d.path)}</span></div>
                                    <div><span class="label">Threat Score:</span> <span class="value">${d.threatScore.toFixed(1)}</span></div>
                                    <div><span class="label">Matched Tokens:</span> <span class="value">${escapeHtml((d.matched_tokens || []).join(', '))}</span></div>
                                    <div><span class="label">MD5:</span> <span class="value mono">${escapeHtml(d.md5)}</span></div>
                                `;
                                tooltip.innerHTML = info;
                                tooltip.style.display = 'block';
                                positionTooltip(e, tooltip);
                                canvas.style.cursor = 'pointer';
                                found = true;
                                break;
                            }
                        }
                        if (!found) {
                            tooltip.style.display = 'none';
                            canvas.style.cursor = 'crosshair';
                        }
                    });
                }

                // 4. ENTROPY DISTRIBUTION — sorted scatter, Y range follows data density (no blank space)
                {
                    const ctx = makeBox('Entropy Distribution (sorted, data-density range)');
                    clear(ctx);

                    // Sort by entropy ascending
                    const eData = valid.slice().sort((a, b) => (a.entropy || 0) - (b.entropy || 0));
                    const entVals = eData.map(d => d.entropy || 0);
                    const eMin = entVals[0] || 0;
                    const eMax = entVals[entVals.length - 1] || 1;
                    const ePad = Math.max(0.05, (eMax - eMin) * 0.06);
                    const yLo = Math.max(0, eMin - ePad);
                    const yHi = eMax + ePad;
                    const eRange = yHi - yLo || 1;

                    const left = 55, top = 25, right = 870, bottom = 260;
                    const W = right - left, H = bottom - top;

                    // Percentile gridlines (25 / 50 / 75)
                    const p25 = entVals[Math.floor(entVals.length * 0.25)] || 0;
                    const p50 = entVals[Math.floor(entVals.length * 0.50)] || 0;
                    const p75 = entVals[Math.floor(entVals.length * 0.75)] || 0;
                    [[p25,'#3a5a3a','P25'],[p50,'#5a5a2a','P50'],[p75,'#5a3a2a','P75']].forEach(function([pv, col, lbl]) {
                        const py = bottom - ((pv - yLo) / eRange) * H;
                        ctx.save();
                        ctx.strokeStyle = col;
                        ctx.lineWidth = 1;
                        ctx.setLineDash([4, 4]);
                        ctx.beginPath(); ctx.moveTo(left, py); ctx.lineTo(right, py); ctx.stroke();
                        ctx.setLineDash([]);
                        ctx.fillStyle = col;
                        ctx.font = '10px Ubuntu Mono, monospace';
                        ctx.textAlign = 'left';
                        ctx.fillText(lbl + ' ' + pv.toFixed(2), left + 4, py - 3);
                        ctx.restore();
                    });

                    drawAxes(ctx, left, top, right, bottom);

                    // Y-axis ticks (5 steps across actual data range)
                    ctx.fillStyle = '#888'; ctx.font = '10px Ubuntu Mono, monospace'; ctx.textAlign = 'right';
                    for (let t = 0; t <= 5; t++) {
                        const v = yLo + (eRange * t) / 5;
                        const y = bottom - ((v - yLo) / eRange) * H;
                        ctx.fillText(v.toFixed(2), left - 4, y + 4);
                        ctx.save(); ctx.strokeStyle = '#333'; ctx.lineWidth = 1;
                        ctx.beginPath(); ctx.moveTo(left - 3, y); ctx.lineTo(left, y); ctx.stroke();
                        ctx.restore();
                    }

                    // X-axis label
                    ctx.fillStyle = '#aaa'; ctx.font = '11px Ubuntu Mono, monospace'; ctx.textAlign = 'center';
                    ctx.fillText('Files sorted by entropy (low → high)', left + W / 2, bottom + 18);
                    ctx.save(); ctx.translate(13, top + H / 2); ctx.rotate(-Math.PI / 2);
                    ctx.fillText('Shannon Entropy', 0, 0); ctx.restore();

                    // Plot dots
                    const eHits = [];
                    eData.forEach(function(d, i) {
                        const px = left + (i / Math.max(1, eData.length - 1)) * W;
                        const py = bottom - ((( d.entropy || 0) - yLo) / eRange) * H;
                        let col;
                        if (d.threatScore >= 15) col = '#ff4444';
                        else if (d.threatScore >= 8)  col = '#ffaa00';
                        else if ((d.entropy || 0) > HIGH_ENTROPY) col = '#9b59b6';
                        else col = '#4a8bc2';
                        ctx.fillStyle = col;
                        ctx.beginPath(); ctx.arc(px, py, 3, 0, Math.PI * 2); ctx.fill();
                        eHits.push({ x: px, y: py, data: d });
                    });

                    // Legend
                    const leg = [['#ff4444','Critical (≥15)'],['#ffaa00','High Risk (≥8)'],['#9b59b6','High Entropy (>' + HIGH_ENTROPY + ')'],['#4a8bc2','Normal']];
                    let lx = left + 4;
                    leg.forEach(function([c, lbl]) {
                        ctx.fillStyle = c; ctx.beginPath(); ctx.arc(lx + 5, top + 12, 4, 0, Math.PI * 2); ctx.fill();
                        ctx.fillStyle = '#aaa'; ctx.font = '10px Ubuntu Mono, monospace'; ctx.textAlign = 'left';
                        ctx.fillText(lbl, lx + 13, top + 16);
                        lx += ctx.measureText(lbl).width + 26;
                    });

                    const canvas = ctx.canvas;
                    canvas.addEventListener('mousemove', function(e) {
                        const rect = canvas.getBoundingClientRect();
                        const mx = (e.clientX - rect.left) * (canvas.width / rect.width);
                        const my = (e.clientY - rect.top) * (canvas.height / rect.height);
                        let hit = null;
                        for (let h of eHits) {
                            const dx = h.x - mx, dy = h.y - my;
                            if (dx*dx + dy*dy < 100) { hit = h; break; }
                        }
                        if (hit) {
                            const d = hit.data;
                            tooltip.innerHTML =
                                '<div><span class="label">File:</span> <span class="value">' + escapeHtml(d.path) + '</span></div>' +
                                '<div><span class="label">Entropy:</span> <span class="value">' + (d.entropy||0).toFixed(4) + '</span></div>' +
                                '<div><span class="label">Threat Score:</span> <span class="value">' + d.threatScore.toFixed(1) + '</span></div>' +
                                '<div><span class="label">Matched Tokens:</span> <span class="value">' + escapeHtml((d.matched_tokens||[]).join(', ')) + '</span></div>';
                            tooltip.style.display = 'block';
                            positionTooltip(e, tooltip);
                            canvas.style.cursor = 'pointer';
                        } else {
                            tooltip.style.display = 'none';
                            canvas.style.cursor = 'crosshair';
                        }
                    });
                    canvas.addEventListener('click', function(e) {
                        const rect = canvas.getBoundingClientRect();
                        const mx = (e.clientX - rect.left) * (canvas.width / rect.width);
                        const my = (e.clientY - rect.top) * (canvas.height / rect.height);
                        for (let h of eHits) {
                            const dx = h.x - mx, dy = h.y - my;
                            if (dx*dx + dy*dy < 100) { filterByPath(h.data.path); break; }
                        }
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
                body.set('paths', paths.join('\0'));
                body.set('seen_hashes', _seenHashes.join('\0'));
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
                    body.set('paths', hitFiles.map(function (f) { return f.pathRaw; }).join('\0'));

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