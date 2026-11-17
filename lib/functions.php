<?php
/*
 *  Jirafeau, your web file repository
 *  Copyright (C) 2008  Julien "axolotl" BERNARD <axolotl@magieeternelle.org>
 *  Copyright (C) 2015  Jerome Jutteau <jerome@jutteau.fr>
 *  Copyright (C) 2024  Jirafeau project <https://gitlab.com/jirafeau> (see AUTHORS.md)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

if (!defined('JIRAFEAU_DELETE_CODE_LENGTH')) {
    define('JIRAFEAU_DELETE_CODE_LENGTH', 32);
}
if (!defined('JIRAFEAU_ASYNC_CODE_LENGTH')) {
    define('JIRAFEAU_ASYNC_CODE_LENGTH', 16);
}

/**
 * Transform a string in a path by separating each letters by a '/'.
 * @return path finishing with a '/'
 */
function s2p($s)
{
    $block_size = 8;
    $p = '';
    for ($i = 0; $i < strlen($s); $i++) {
        $p .= $s[$i];
        if (($i + 1) % $block_size == 0) {
            $p .= '/';
        }
    }
    if (strlen($s) % $block_size != 0) {
        $p .= '/';
    }
    return $p;
}

/**
 * Convert base 16 to base 64
 * @returns A string based on 64 characters (0-9, a-z, A-Z, "-" and "_")
 */
function base_16_to_64($num)
{
    $m = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_';
    $hex2bin = array('0000',  # 0
                      '0001',  # 1
                      '0010',  # 2
                      '0011',  # 3
                      '0100',  # 4
                      '0101',  # 5
                      '0110',  # 6
                      '0111',  # 7
                      '1000',  # 8
                      '1001',  # 9
                      '1010',  # a
                      '1011',  # b
                      '1100',  # c
                      '1101',  # d
                      '1110',  # e
                      '1111'); # f
    $o = '';
    $b = '';
    $i = 0;
    # Convert long hex string to bin.
    $size = strlen($num);
    for ($i = 0; $i < $size; $i++) {
        $b .= $hex2bin[hexdec($num[$i])];
    }
    # Convert long bin to base 64.
    $size *= 4;
    for ($i = $size - 6; $i >= 0; $i -= 6) {
        $o = $m[bindec(substr($b, $i, 6))] . $o;
    }
    # Some few bits remaining ?
    if ($i < 0 && $i > -6) {
        $o = $m[bindec(substr($b, 0, $i + 6))] . $o;
    }
    return $o;
}

/**
  * Generate a cryptographically secure random hex code.
  * @param $l code length
  * @return  random code.
  */
function jirafeau_gen_random($l)
{
    if ($l <= 0) {
        return '0';
    }

    $bytes = random_bytes((int) ceil($l / 2));
    return substr(bin2hex($bytes), 0, $l);
}

function jirafeau_gen_download_pass($length, $allowed_chars)
{
    if ($length <= 0 || !is_string($allowed_chars) || $allowed_chars === '') {
        return false;
    }
    $max = strlen($allowed_chars) - 1;
    $pass = '';
    for ($i = 0; $i < $length; $i++) {
        $pass .= $allowed_chars[random_int(0, $max)];
    }

    return $pass;
}

function is_ssl()
{
    if (isset($_SERVER['HTTPS'])) {
        if ('on' == strtolower($_SERVER['HTTPS']) ||
             '1' == $_SERVER['HTTPS']) {
            return true;
        }
    } elseif (isset($_SERVER['SERVER_PORT']) && ('443' == $_SERVER['SERVER_PORT'])) {
        return true;
    }

    // Trust X-Forwarded-Proto only when the direct peer is a configured proxy.
    global $cfg;
    if (is_array($cfg)
        && !empty($cfg['proxy_ip'])
        && isset($_SERVER['REMOTE_ADDR'])
        && isset($_SERVER['HTTP_X_FORWARDED_PROTO'])
        && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
        foreach ($cfg['proxy_ip'] as $proxy_ip) {
            if ($_SERVER['REMOTE_ADDR'] === $proxy_ip) {
                return true;
            }
        }
    }
    return false;
}

/**
 * Configure session cookie flags before session_start().
 */
function jirafeau_configure_session()
{
    if (PHP_SAPI === 'cli' || session_status() !== PHP_SESSION_NONE) {
        return;
    }
    session_set_cookie_params(array(
        'lifetime' => 0,
        'path' => '/',
        'secure' => is_ssl(),
        'httponly' => true,
        'samesite' => 'Lax',
    ));
}

/**
 * Send baseline security headers for HTML or file responses.
 */
function jirafeau_send_security_headers($html = true)
{
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: SAMEORIGIN');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
    if ($html) {
        // Inline scripts/handlers are still used by the UI; tighten when templates allow.
        header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'self'; base-uri 'self'; form-action 'self'");
    }
    if (is_ssl()) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

/**
 * Prevent Content-Disposition / path tricks in download filenames.
 */
function jirafeau_sanitize_filename_for_header($filename)
{
    $filename = str_replace(array("\r", "\n", '"', "\0"), '', (string) $filename);
    // Normalize separators then keep only the final path component.
    $filename = str_replace(array('\\', '/'), DIRECTORY_SEPARATOR, $filename);
    $filename = basename($filename);
    if ($filename === '' || $filename === '.' || $filename === '..') {
        $filename = 'download';
    }
    return $filename;
}

function jirafeau_content_disposition_header($filename, $attachment = true)
{
    $safe = jirafeau_sanitize_filename_for_header($filename);
    $type = $attachment ? 'attachment' : 'inline';
    $encoded = rawurlencode($safe);
    header('Content-Disposition: ' . $type . '; filename="' . $safe . '"; filename*=UTF-8\'\'' . $encoded);
}

/**
 * Reject header-injection attempts in Content-Type values from clients.
 */
function jirafeau_sanitize_mime_type($mime)
{
    $mime = trim((string) $mime);
    if (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9!#$&\-\^_+.]*\/[a-zA-Z0-9][a-zA-Z0-9!#$&\-\^_+.]*$/', $mime)) {
        return 'application/octet-stream';
    }
    return $mime;
}

function jirafeau_is_valid_style_name($style)
{
    return is_string($style) && preg_match('/^[a-zA-Z0-9_-]+$/', $style);
}

function jirafeau_is_valid_async_ref($ref)
{
    return is_string($ref) && preg_match('/^[0-9a-f]{8,64}$/', $ref);
}

/**
 * Hash an admin password with a modern password_hash algorithm.
 */
function jirafeau_hash_admin_password($password)
{
    return password_hash($password, PASSWORD_DEFAULT);
}

/**
 * Verify admin password. Supports password_hash and legacy unsalted SHA-256 hex.
 */
function jirafeau_verify_admin_password($password, $stored)
{
    if (!is_string($password) || !is_string($stored) || $stored === '') {
        return false;
    }
    if (isset($stored[0]) && $stored[0] === '$') {
        return password_verify($password, $stored);
    }
    if (strlen($stored) === 64 && ctype_xdigit($stored)) {
        return hash_equals(strtolower($stored), hash('sha256', $password));
    }
    return false;
}

function jirafeau_admin_password_needs_rehash($stored)
{
    if (!is_string($stored) || $stored === '') {
        return false;
    }
    if (isset($stored[0]) && $stored[0] === '$') {
        return password_needs_rehash($stored, PASSWORD_DEFAULT);
    }
    // Legacy SHA-256 storage must be upgraded after a successful login.
    return true;
}

/**
 * Store a download password. New entries use password_hash; verification stays backward compatible.
 */
function jirafeau_store_download_password($key)
{
    if ($key === null || $key === '') {
        return '';
    }
    return '[PASSWORD]' . password_hash($key, PASSWORD_DEFAULT);
}

/**
 * Verify a download password against stored link metadata.
 */
function jirafeau_verify_download_password($provided, $stored)
{
    if ($stored === null || $stored === '') {
        return true;
    }
    if (!is_string($provided)) {
        return false;
    }
    if (strpos($stored, '[PASSWORD]') === 0) {
        return password_verify($provided, substr($stored, 10));
    }
    if (strpos($stored, '[SHA256]') === 0) {
        return hash_equals(substr($stored, 8), hash('sha256', $provided));
    }
    // Legacy bare MD5 hashes.
    return hash_equals($stored, md5($provided));
}

function jirafeau_human_size($octets)
{
    $u = array('B', 'KB', 'MB', 'GB', 'TB');
    $o = max($octets, 0);
    $p = min(floor(($o ? log($o) : 0) / log(1024)), count($u) - 1);
    $o /= pow(1024, $p);
    return round($o, 1) . $u[$p];
}

// Convert UTC timestamp to a datetime field
function jirafeau_get_datetimefield($timestamp)
{
    $ts = date_create('@' . $timestamp);
    $content = '<span class="datetime" data-datetime="' . date_format($ts, 'Y-m-d H:i') . '">'
        . date_format($ts, 'Y-m-d H:i') . ' (GMT)</span>';

    return $content;
}

function jirafeau_fatal_error($errorText, $cfg = array())
{
    echo '<div class="error"><h2>Error</h2><p>' . $errorText . '</p></div>';
    require(JIRAFEAU_ROOT . 'lib/template/footer.php');
    exit;
}

function jirafeau_clean_rm_link($link)
{
    $p = s2p("$link");
    if (file_exists(VAR_LINKS . $p . $link)) {
        unlink(VAR_LINKS . $p . $link);
    }
    if (file_exists(VAR_LINKS . $p . $link . '_download')) {
        unlink(VAR_LINKS . $p . $link . '_download');
    }
    $parse = VAR_LINKS . $p;
    $scan = array();
    while (file_exists($parse)
           && ($scan = scandir($parse))
           && count($scan) == 2 // '.' and '..' folders => empty.
           && basename($parse) != basename(VAR_LINKS)) {
        rmdir($parse);
        $parse = substr($parse, 0, strlen($parse) - strlen(basename($parse)) - 1);
    }
}

function jirafeau_clean_rm_file($hash)
{
    // Force refcount to zero under the stable per-hash lock (never unlink .lock).
    $fp = jirafeau_file_refcount_lock($hash);
    if ($fp === false) {
        return;
    }
    try {
        $p = s2p("$hash");
        $f = VAR_FILES . $p . $hash;
        if (is_file($f)) {
            @unlink($f);
        }
        $count_file = jirafeau_file_count_path($hash);
        if (is_file($count_file)) {
            @unlink($count_file);
        }
    } finally {
        flock($fp, LOCK_UN);
        fclose($fp);
    }
}

/**
 * transforms a php.ini string representing a value in an integer
 * @param $value the value from php.ini
 * @returns an integer for this value
 */
function jirafeau_ini_to_bytes($value)
{
    $modifier = substr($value, -1);
    $bytes = substr($value, 0, -1);
    switch (strtoupper($modifier)) {
        default:
            return intval($value);
            break;
        case 'P':
            $bytes *= 1024;
            // no break
        case 'T':
            $bytes *= 1024;
            // no break
        case 'G':
            $bytes *= 1024;
            // no break
        case 'M':
            $bytes *= 1024;
            // no break
        case 'K':
            $bytes *= 1024;
    }
    return $bytes;
}

/**
 * returns the configured disallowed extensions, lower-cased and without
 * a leading dot
 * @param $cfg jirafeau config
 * @returns array of normalized extensions
 */
function jirafeau_disallowed_extensions($cfg)
{
    if (empty($cfg['disallowed_extensions'])) {
        return array();
    }

    // tolerate a leading dot in the config, e.g. '.jpg' instead of 'jpg'
    $extensions = array();
    foreach ($cfg['disallowed_extensions'] as $extension) {
        $extension = ltrim(strtolower(trim($extension)), '.');
        if ($extension !== '') {
            $extensions[] = $extension;
        }
    }

    return $extensions;
}

/**
 * checks if a file name's extension is allowed to be uploaded
 * @param $cfg jirafeau config
 * @param $filename the name of the file being uploaded
 * @returns true if the extension is allowed
 */
function jirafeau_is_extension_allowed($cfg, $filename)
{
    $extensions = jirafeau_disallowed_extensions($cfg);
    if (empty($extensions)) {
        return true;
    }

    // trailing dots and whitespace are dropped on storage or by the client OS
    $filename = strtolower(rtrim($filename, " \t\n\r\0\v."));

    // suffix match so that compound extensions such as 'tar.gz' work too;
    // 'gz' still covers 'archive.tar.gz'
    foreach ($extensions as $extension) {
        $suffix = '.' . $extension;
        if (substr($filename, -strlen($suffix)) === $suffix) {
            return false;
        }
    }

    return true;
}

/**
 * gets the maximum upload size according to php.ini
 * @returns the maximum upload size in bytes
 */
function jirafeau_get_max_upload_size_bytes()
{
    return min(
        jirafeau_ini_to_bytes(ini_get('post_max_size')),
        jirafeau_ini_to_bytes(ini_get('upload_max_filesize'))
    );
}

/**
 * gets the maximum upload size according to php.ini
 * @returns the maximum upload size string
 */
function jirafeau_get_max_upload_size()
{
    return jirafeau_human_size(jirafeau_get_max_upload_size_bytes());
}

/**
 * get the maximal upload size for a data chunk in async uploads
 * @param max_upload_chunk_size_bytes
 */
function jirafeau_get_max_upload_chunk_size_bytes($max_upload_chunk_size_bytes = 0)
{
    if ($max_upload_chunk_size_bytes == 0) {
        $size = jirafeau_get_max_upload_size_bytes();
        // Jirafeau must choose an arbitrary number as PHP config does not give any limit nor $max_upload_chunk_size_bytes
        if ($size == 0) {
            return 10000000; // 10MB
        }
        return $size;
    }
    $size = min(
        jirafeau_get_max_upload_size_bytes(),
        $max_upload_chunk_size_bytes
    );
    if ($size == 0) {
        return $max_upload_chunk_size_bytes;
    }
    return $size;
}

/**
 * gets a string explaining the error
 * @param $code the error code
 * @returns a string explaining the error
 */
function jirafeau_upload_errstr($code)
{
    switch ($code) {
        case UPLOAD_ERR_INI_SIZE:
        case UPLOAD_ERR_FORM_SIZE:
            return t('Your file exceeds the maximum authorized file size. ');

        case UPLOAD_ERR_PARTIAL:
        case UPLOAD_ERR_NO_FILE:
            return
                t('Your file was not uploaded correctly. You may succeed in retrying. ');

        case UPLOAD_ERR_NO_TMP_DIR:
        case UPLOAD_ERR_CANT_WRITE:
        case UPLOAD_ERR_EXTENSION:
            return t('Internal error. You may not succeed in retrying. ');
    }
    return t('Unknown error. ');
}

/** Remove link and it's file
 * @param $link the link's name (hash)
 */

function jirafeau_delete_link($link)
{
    $l = jirafeau_get_link($link);
    if (!count($l)) {
        return;
    }

    jirafeau_clean_rm_link($link);
    jirafeau_file_refcount_adjust($l['hash'], -1);
}

/**
 * Stable flock target for a stored payload. Never unlinked by refcount ops so
 * concurrent processes always serialize on the same inode (Linux unlink race).
 */
function jirafeau_file_lock_path($hash)
{
    return VAR_FILES . s2p($hash) . $hash . '.lock';
}

/**
 * Reference-counter path (may be created/removed under the stable lock).
 */
function jirafeau_file_count_path($hash)
{
    return VAR_FILES . s2p($hash) . $hash . '_count';
}

/**
 * Open and exclusively lock the stable per-hash lock file.
 * @return resource|false
 */
function jirafeau_file_refcount_lock($hash)
{
    if (!is_string($hash) || $hash === '') {
        return false;
    }
    $lock_file = jirafeau_file_lock_path($hash);
    $dir = dirname($lock_file);
    if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
        return false;
    }
    $fp = @fopen($lock_file, 'c+');
    if ($fp === false) {
        return false;
    }
    if (!flock($fp, LOCK_EX)) {
        fclose($fp);
        return false;
    }
    return $fp;
}

/**
 * Read refcount from the _count file (caller must hold the stable lock).
 */
function jirafeau_file_refcount_read_unlocked($hash)
{
    $count_file = jirafeau_file_count_path($hash);
    if (!is_file($count_file)) {
        return 0;
    }
    $raw = @file_get_contents($count_file);
    return ($raw === false || trim((string) $raw) === '') ? 0 : (int) trim($raw);
}

/**
 * Write/remove the _count file (caller must hold the stable lock).
 * Counter 0 removes _count; the .lock file is left in place.
 */
function jirafeau_file_refcount_write_unlocked($hash, $counter)
{
    $count_file = jirafeau_file_count_path($hash);
    if ($counter > 0) {
        $dir = dirname($count_file);
        if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
            return false;
        }
        return @file_put_contents($count_file, (string) $counter) !== false;
    }
    if (is_file($count_file)) {
        @unlink($count_file);
    }
    return true;
}

/**
 * Atomically adjust a stored file reference counter under the stable lock.
 * When the counter reaches 0, the payload (and _count) are removed while the
 * lock is still held. The .lock file is never unlinked.
 *
 * @return int|false new counter value, or false on lock/IO failure
 */
function jirafeau_file_refcount_adjust($hash, $delta)
{
    $fp = jirafeau_file_refcount_lock($hash);
    if ($fp === false) {
        return false;
    }
    try {
        $p = s2p($hash);
        $payload = VAR_FILES . $p . $hash;
        $counter = jirafeau_file_refcount_read_unlocked($hash);
        $counter += (int) $delta;
        if ($counter < 0) {
            $counter = 0;
        }
        if ($counter > 0) {
            if (!jirafeau_file_refcount_write_unlocked($hash, $counter)) {
                return false;
            }
        } else {
            // Keep LOCK_EX until payload/_count are gone to close the TOCTOU window.
            if (is_file($payload)) {
                @unlink($payload);
            }
            jirafeau_file_refcount_write_unlocked($hash, 0);
        }
        return $counter;
    } finally {
        flock($fp, LOCK_UN);
        fclose($fp);
    }
}

/**
 * Under one exclusive lock: ensure the payload exists (install from $src_path if
 * needed) and increment the reference counter. Prevents "counter without file"
 * races with concurrent deletes.
 *
 * @param string $hash content hash / storage id
 * @param string $src_path temporary source file
 * @param string $install_mode move_uploaded_file|rename|symlink|copy
 * @return int|false new counter value
 */
function jirafeau_file_commit_payload($hash, $src_path, $install_mode = 'rename')
{
    $fp = jirafeau_file_refcount_lock($hash);
    if ($fp === false) {
        return false;
    }
    $p = s2p($hash);
    $payload = VAR_FILES . $p . $hash;
    $installed = false;
    try {
        if (!is_file($payload)) {
            if (!is_string($src_path) || !is_file($src_path)) {
                return false;
            }
            $dir = dirname($payload);
            if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
                return false;
            }
            switch ($install_mode) {
                case 'move_uploaded_file':
                    $installed = @move_uploaded_file($src_path, $payload);
                    break;
                case 'symlink':
                    $installed = @symlink($src_path, $payload);
                    break;
                case 'copy':
                    $installed = @copy($src_path, $payload);
                    if ($installed) {
                        @unlink($src_path);
                    }
                    break;
                case 'rename':
                default:
                    $installed = @rename($src_path, $payload);
                    break;
            }
            if (!$installed || !is_file($payload)) {
                return false;
            }
        } else {
            // Deduplicated hit: drop the spare source while still locked.
            if (is_string($src_path) && is_file($src_path)) {
                $src_real = @realpath($src_path);
                $dst_real = @realpath($payload);
                if ($src_real === false || $dst_real === false || $src_real !== $dst_real) {
                    @unlink($src_path);
                }
            }
        }
        if (!is_file($payload)) {
            return false;
        }
        $counter = jirafeau_file_refcount_read_unlocked($hash) + 1;
        if (!jirafeau_file_refcount_write_unlocked($hash, $counter)) {
            return false;
        }
        return $counter;
    } finally {
        flock($fp, LOCK_UN);
        fclose($fp);
    }
}

/**
 * Delete a file and it's links.
 */
function jirafeau_delete_file($hash)
{
    $count = 0;
    /* Get all links files. */
    $stack = array(VAR_LINKS);
    while (($d = array_shift($stack)) && $d != null) {
        $dir = scandir($d);

        foreach ($dir as $node) {
            if (strcmp($node, '.') == 0 || strcmp($node, '..') == 0 ||
                preg_match('/\.tmp/i', "$node")) {
                continue;
            }

            if (is_dir($d . $node)) {
                /* Push new found directory. */
                $stack[] = $d . $node . '/';
            } elseif (is_file($d . $node)) {
                /* Read link informations. */
                $l = jirafeau_get_link(basename($node));
                if (!count($l)) {
                    continue;
                }
                if ($l['hash'] == $hash) {
                    $count++;
                    jirafeau_delete_link($node);
                }
            }
        }
    }
    jirafeau_clean_rm_file($hash);
    return $count;
}


/** hash file's content
 * @param $method hash method, see 'file_hash' option. Valid methods are 'md5', 'md5_outside' or 'random'
 * @param $file_path file to hash
 * @returns hash string
 */
function jirafeau_hash_file($method, $file_path)
{
    switch ($method) {
        case 'md5_outside':
            return jirafeau_md5_outside($file_path);
        case 'md5':
            return md5_file($file_path);
        case 'random':
            return jirafeau_gen_random(32);
    }
    return md5_file($file_path);
}

/** hash part of file: start, end and size.
 * This is a partial file hash, faster but weaker.
 * @param $file_path file to hash
 * @returns hash string
 */
function jirafeau_md5_outside($file_path)
{
    $out = false;
    $handle = fopen($file_path, 'r');
    if ($handle === false) {
        return false;
    }
    $size = filesize($file_path);
    if ($size === false) {
        goto err;
    }
    $first = fread($handle, 64);
    if ($first === false) {
        goto err;
    }
    if (fseek($handle, $size < 64 ? 0 : $size - 64) == -1) {
        goto err;
    }
    $last = fread($handle, 64);
    if ($last === false) {
        goto err;
    }
    $out = md5($first . $last . $size);
    err:
    fclose($handle);
    return $out;
}

/**
 * handles an uploaded file
 * @param $file the file struct given by $_FILE[]
 * @param $one_time_download is the file a one time download ?
 * @param $key if not empty, protect the file with this key
 * @param $time the time of validity of the file
 * @param $ip uploader's ip
 * @param $crypt boolean asking to crypt or not
 * @param $link_name_length size of the link name
 * @returns an array containing some information
 *   'error' => information on possible errors
 *   'link' => the link name of the uploaded file
 *   'delete_link' => the link code to delete file
 */
function jirafeau_upload($file, $one_time_download, $key, $time, $ip, $crypt, $link_name_length, $file_hash_method)
{
    if (empty($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
        return (array(
                 'error' =>
                   array('has_error' => true,
                          'why' => jirafeau_upload_errstr($file['error'])),
                 'link' => '',
                 'delete_link' => ''));
    }
    return jirafeau_add_file($file, $one_time_download, $key, $time, $ip, $crypt, $link_name_length, $file_hash_method);
}

/**
 *
 * @param bool $crypt_module_enabled
 * @param string $file_path
 * @return array [bool, string]
 */
function jirafeau_handle_add_file_encryption($crypt_module_enabled, $file_path)
{
    /* Crypt file if option is enabled. */
    $crypted = false;
    $crypt_key = '';
    if ($crypt_module_enabled == true && !(extension_loaded('sodium') == true)) {
        error_log("PHP extension sodium not loaded, won't encrypt in Jirafeau");
    }
    if ($crypt_module_enabled == true && extension_loaded('sodium') == true) {
        $crypt_key = jirafeau_encrypt_file($file_path, $file_path.'.crypt');
        if (strlen($crypt_key) > 0) {
            if (rename($file_path.'.crypt', $file_path) === true) {
                $crypted = true;
            }
        }
    }

    return [$crypted, $crypt_key];
}

/**
 * adds an uploaded or copy/linked local file
 * @param $file the file struct given by $_FILE[]
 * @param $one_time_download is the file a one time download ?
 * @param $key if not empty, protect the file with this key
 * @param $time the time of validity of the file
 * @param $ip uploader's ip
 * @param $crypt boolean asking to crypt or not
 * @param $link_name_length size of the link name
 * @param $is_upload, determines if the file is uploaded or local - it controls which file-functions are used
 * @return array  an array containing some information
 *   'error' => information on possible errors
 *   'link' => the link name of the uploaded file
 *   'delete_link' => the link code to delete file
 */
function jirafeau_add_file($file, $one_time_download, $key, $time, $ip, $crypt, $link_name_length, $file_hash_method, $is_upload = true)
{
    /* array representing no error */
    $noerr = array('has_error' => false, 'why' => '');

    $crypted = false;
    $crypt_key = '';
    list($crypted, $crypt_key) = jirafeau_handle_add_file_encryption($crypt, $file['tmp_name']);

    /* file information */
    $hash = jirafeau_hash_file($file_hash_method, $file['tmp_name']);
    $name = str_replace(NL, '', trim($file['name']));
    $mime_type = jirafeau_sanitize_mime_type($file['type']);
    $size = $file['size'];

    /* Dedup + install + refcount under one lock (avoids counter without payload). */
    $install_mode = $is_upload ? 'move_uploaded_file' : 'symlink';
    if (jirafeau_file_commit_payload($hash, $file['tmp_name'], $install_mode) === false) {
        return (array(
                 'error' =>
                   array('has_error' => true,
                          'why' => t('INTERNAL_ERROR_DEL')),
                 'link' => '',
                 'delete_link' => ''));
    }

    /* Create delete code. */
    $delete_link_code = jirafeau_gen_random(JIRAFEAU_DELETE_CODE_LENGTH);

    /* hash password or empty. */
    $password = jirafeau_store_download_password($key);

    /* create link file */
    $link_tmp_name =  VAR_LINKS . $hash . rand(0, 10000) . '.tmp';
    $handle = fopen($link_tmp_name, 'w');
    fwrite(
        $handle,
        $name . NL. $mime_type . NL. $size . NL. $password . NL. $time .
            NL . $hash. NL . ($one_time_download ? 'O' : 'R') . NL . time() .
            NL . $ip . NL. $delete_link_code . NL . ($crypted ? 'C2' : 'O')
    );
    fclose($handle);
    $hash_link = substr(base_16_to_64(md5_file($link_tmp_name)), 0, $link_name_length);
    $l = s2p("$hash_link");
    if (!@mkdir(VAR_LINKS . $l, 0755, true) ||
        !rename($link_tmp_name, VAR_LINKS . $l . $hash_link)) {
        if (file_exists($link_tmp_name)) {
            unlink($link_tmp_name);
        }

        jirafeau_file_refcount_adjust($hash, -1);
        return array(
                 'error' =>
                   array('has_error' => true,
                          'why' => t('Internal error during file creation. ')),
                 'link' => '',
                 'delete_link' => '');
    }
    return array( 'error' => $noerr,
                  'link' => $hash_link,
                  'delete_link' => $delete_link_code,
                  'crypt_key' => $crypt_key);
}

function jirafeau_admin_list_table($name, $file_hash, $link_hash, $visitor_function = null)
{
    echo '<fieldset><legend>';
    if (!empty($name)) {
        echo t('FILENAME') . ": " . jirafeau_escape($name);
    }
    if (!empty($file_hash)) {
        echo t('FILE') . ": " . jirafeau_escape($file_hash);
    }
    if (!empty($link_hash)) {
        echo t('LINK') . ": " . jirafeau_escape($link_hash);
    }
    if (empty($name) && empty($file_hash) && empty($link_hash)) {
        echo t('LS_FILES');
    }
    echo '</legend>';
    echo '<table>';
    echo '<tr>';
    echo '<th></th>';
    echo '<th>' . t('ACTION') . '</th>';
    echo '</tr>';
    if ($visitor_function != null) {
        $visitor_function($name, $file_hash, $link_hash);
    }
    echo '</table></fieldset>';
}

/**
 * Tells if a mime-type is viewable in a browser
 * @param $mime the mime type
 * @returns a boolean telling if a mime type is viewable
 */
function jirafeau_is_viewable($mime)
{
    if (!empty($mime)) {
        $viewable = array('image', 'video', 'audio');
        $decomposed = explode('/', $mime);
        if (in_array($decomposed[0], $viewable) && stripos($mime, 'image/svg+xml') === false && strpos($mime, ',') === false) {
            return true;
        }
        $viewable = array('text/plain');
        if (in_array($mime, $viewable)) {
            return true;
        }
    }
    return false;
}

// Error handling functions.
//! Global array that contains all registered errors.
$error_list = array();

/**
 * Adds an error to the list of errors.
 * @param $title the error's title
 * @param $description is a human-friendly description of the problem.
 */
function add_error($title, $description)
{
    global $error_list;
    $error_list[] = '<p>' . $title. '<br />' . $description. '</p>';
}

/**
 * Informs whether any error has been registered yet.
 * @return true if there are errors.
 */
function has_error()
{
    global $error_list;
    return !empty($error_list);
}

/**
 * Displays all the errors.
 */
function show_errors()
{
    if (has_error()) {
        global $error_list;
        echo '<div class="error">';
        foreach ($error_list as $error) {
            echo $error;
        }
        echo '</div>';
    }
}

function check_errors($cfg)
{
    if (!($cfg['installation_done'] === true)) {
        if (file_exists(JIRAFEAU_ROOT . 'install.php')) {
            header('Location: install.php');
            exit;
        } else {
            add_error(t('INSTALL_FILE_NOT_FOUND_TITLE'), t('INSTALL_FILE_NOT_FOUND_DESC'));
        }
    }

    if (!is_writable(VAR_FILES)) {
        add_error(t('FILE_DIR_W'), VAR_FILES);
    }

    if (!is_writable(VAR_LINKS)) {
        add_error(t('LINK_DIR_W'), VAR_LINKS);
    }

    if (!is_writable(VAR_ASYNC)) {
        add_error(t('ASYNC_DIR_W'), VAR_ASYNC);
    }

    if ($cfg['enable_crypt'] && $cfg['litespeed_workaround']) {
        add_error(t('INCOMPATIBLE_OPTIONS_W'), 'enable_crypt=true<br>litespeed_workaround=true');
    }

    if ($cfg['one_time_download'] && $cfg['litespeed_workaround']) {
        add_error(t('INCOMPATIBLE_OPTIONS_W'), 'one_time_download=true<br>litespeed_workaround=true');
    }
}

/**
 * Parse link metadata from a link file path (active or claimed).
 */
function jirafeau_get_link_from_path($path)
{
    $out = array();
    if (!is_string($path) || !is_file($path)) {
        return $out;
    }
    $c = @file($path);
    if ($c === false || count($c) < 11) {
        return $out;
    }
    $out['file_name'] = trim($c[0]);
    $out['mime_type'] = trim($c[1]);
    $out['file_size'] = trim($c[2]);
    $out['key'] = trim($c[3], NL);
    $out['time'] = trim($c[4]);
    $out['hash'] = trim($c[5]);
    $out['onetime'] = trim($c[6]);
    $out['upload_date'] = trim($c[7]);
    $out['ip'] = trim($c[8]);
    $out['link_code'] = trim($c[9]);
    $out['crypted'] = trim($c[10]) == 'C2';
    $out['crypted_legacy'] = trim($c[10]) == 'C';

    return $out;
}

/**
 * Read link information
 * @return array containing information.
 */
function jirafeau_get_link($hash)
{
    $out = array();
    if (!is_string($hash) || !preg_match('/^[0-9a-zA-Z_-]+$/', $hash)) {
        return $out;
    }
    return jirafeau_get_link_from_path(VAR_LINKS . s2p("$hash") . $hash);
}

/**
 * Extract original link id from a claimed one-time filename, or false.
 */
function jirafeau_claimed_link_name($basename)
{
    if (!is_string($basename)) {
        return false;
    }
    if (preg_match('/^([0-9a-zA-Z_-]+)\.claimed-[0-9a-f]+$/', $basename, $m)) {
        return $m[1];
    }
    return false;
}

/**
 * List files in admin interface.
 */
function jirafeau_admin_list($name, $file_hash, $link_hash)
{
    $function = function ($name, $file_hash, $link_hash) {
        /* Get all links files. */
        $stack = array(VAR_LINKS);
        while (($d = array_shift($stack)) && $d != null) {
            $dir = scandir($d);
            foreach ($dir as $node) {
                if (strcmp($node, '.') == 0 || strcmp($node, '..') == 0 ||
                    preg_match('/\.tmp/i', "$node")) {
                    continue;
                }
                if (is_dir($d . $node)) {
                    /* Push new found directory. */
                    $stack[] = $d . $node . '/';
                } elseif (is_file($d . $node)) {
                    /* Read link information. */
                    $l = jirafeau_get_link($node);
                    if (!count($l)) {
                        continue;
                    }

                    /* Filter. */
                    if (!empty($name) && !@preg_match('/' . preg_quote($name, '/') . '/i', $l['file_name'])) {
                        continue;
                    }
                    if (!empty($file_hash) && $file_hash != $l['hash']) {
                        continue;
                    }
                    if (!empty($link_hash) && $link_hash != $node) {
                        continue;
                    }

                    /* Get download statistics */
                    $ld = jirafeau_get_download_stats($node);
                    /* Print link information. */
                    echo '<tr>';
                    echo '<td><strong>';

                    if (!$l['crypted'] && !$l['crypted_legacy']) {
                        echo'<a href="f.php?h='. jirafeau_escape($node) .'" title="' .
                        t('DL_PAGE') . '">' . jirafeau_escape($l['file_name']) . '</a>';
                    } else {
                        echo jirafeau_escape($l['file_name']);
                    }

                    echo '</strong><br/>';

                    echo t('TYPE') . ': ' . jirafeau_escape($l['mime_type']) . '<br/>';
                    echo t('SIZE') . ': ' . jirafeau_human_size($l['file_size']) . '<br>';
                    echo t('EXPIRE') . ': ' . ($l['time'] == -1 ? '∞' : jirafeau_get_datetimefield($l['time'])) . '<br/>';
                    echo t('ONETIME') . ': ' . ($l['onetime'] == 'O' ? t('YES') : t('NO')) . '<br/>';
                    echo t('ENCRYPTED') . ': ' . (($l['crypted'] || $l['crypted_legacy']) ? t('YES') : t('NO')) . '<br/>';
                    echo t('UPLOAD_DATE') . ': ' . jirafeau_get_datetimefield($l['upload_date']) . '<br/>';
                    if (strlen($l['ip']) > 0) {
                        echo t('ORIGIN') . ': ' . $l['ip'] . '<br/>';
                    }
                    echo t('DOWNLOAD_COUNT') . ': ' . $ld['count'] . '<br/>';
                    if ($ld['count'] > 0) {
                        echo t('DOWNLOAD_DATE') . ': ' . jirafeau_get_datetimefield($ld['date']) . '<br/>';
                        echo t('DOWNLOAD_IP') . ': ' . $ld['ip'] . '<br/>';
                    }
                    echo '</td><td>';

                    if (!$l['crypted'] && !$l['crypted_legacy']) {
                        echo '<form method="post">' .
                        '<input type = "hidden" name = "action" value = "download"/>' .
                        '<input type = "hidden" name = "link" value = "' . $node . '"/>' .
                        jirafeau_admin_csrf_field() .
                        '<input type = "submit" value = "' . t('DL') . '" />' .
                        '</form>';
                    }

                    echo '<form method="post">' .
                    '<input type = "hidden" name = "action" value = "delete_link"/>' .
                    '<input type = "hidden" name = "link" value = "' . $node . '"/>' .
                    jirafeau_admin_csrf_field() .
                    '<input type = "submit" value = "' . t('DEL_LINK') . '" />' .
                    '</form>' .
                    '<form method="post">' .
                    '<input type = "hidden" name = "action" value = "delete_file"/>' .
                    '<input type = "hidden" name = "hash" value = "' . $l['hash'] . '"/>' .
                    jirafeau_admin_csrf_field() .
                    '<input type = "submit" value = "' . t('DEL_FILE_LINKS') . '" />' .
                    '</form>' .
                    '</td>';
                    echo '</tr>';
                }
            }
        }
    };

    jirafeau_admin_list_table($name, $file_hash, $link_hash, $function);
}

/**
 * Clean expired files.
 * @return number of cleaned files.
 */
function jirafeau_admin_clean()
{
    $count = 0;
    /* Get all links files. */
    $stack = array(VAR_LINKS);
    while (($d = array_shift($stack)) && $d != null) {
        $dir = scandir($d);

        foreach ($dir as $node) {
            if (strcmp($node, '.') == 0 || strcmp($node, '..') == 0 ||
                preg_match('/\.tmp$/i', "$node")) {
                continue;
            }

            if (is_dir($d . $node)) {
                /* Push new found directory. */
                $stack[] = $d . $node . '/';
            } elseif (is_file($d . $node)) {
                $full = $d . $node;
                /* Crash mid-finalize: decrement not yet done (no .done suffix). */
                if (preg_match('/\.finishing-[0-9a-f]+\.done$/', $node)) {
                    @unlink($full);
                    jirafeau_cleanup_link_dirs($d);
                    $count++;
                    continue;
                }
                if (preg_match('/\.finishing-[0-9a-f]+$/', $node)) {
                    $mtime = @filemtime($full);
                    if ($mtime !== false && (time() - $mtime) > 3600) {
                        $l = jirafeau_get_link_from_path($full);
                        jirafeau_finalize_onetime_claim($full, $l);
                        $count++;
                    }
                    continue;
                }
                /* Recover interrupted one-time downloads left as .claimed-* orphans.
                 * mtime is stamped at claim time (not original link age). */
                if (jirafeau_claimed_link_name($node) !== false) {
                    $mtime = @filemtime($full);
                    // 24h keeps long downloads safe; shutdown handlers clean sooner.
                    if ($mtime !== false && (time() - $mtime) > 86400) {
                        $l = jirafeau_get_link_from_path($full);
                        if (count($l)) {
                            jirafeau_finalize_onetime_claim($full, $l);
                        } else {
                            @unlink($full);
                        }
                        $count++;
                    }
                    continue;
                }

                /* Read link information. */
                $l = jirafeau_get_link(basename($node));
                if (!count($l)) {
                    continue;
                }
                $p = s2p($l['hash']);
                if (empty($l['time']) || // invalid
                    $l['time'] > 0 && $l['time'] < time() || // expired
                    !file_exists(VAR_FILES . $p . $l['hash']) || // invalid
                    !file_exists(VAR_FILES . $p . $l['hash'] . '_count')) { // invalid
                    jirafeau_delete_link($node);
                    $count++;
                }
            }
        }
    }
    return $count;
}

/**
 * Reconcile stored file refcounts against live links.
 *
 * OFFLINE / QUIESCENT MAINTENANCE ONLY. Never call from the regular cleaner while
 * uploads may be in flight: commit_payload can create a payload+counter before the
 * link is published, and this scan would treat that as an orphan and delete it.
 *
 * Recovers safe leaks from finalize crashes after `.done` and before decrement when
 * no writers are active. Live references: normal links, `.claimed-*`, `.finishing-*`.
 * `.finishing-*.done` is not counted (logical finalize already published).
 *
 * @return int number of hashes whose counter was reduced
 */
function jirafeau_admin_reconcile_file_refcounts()
{
    $live = array();
    $stack = array(VAR_LINKS);
    while (($d = array_shift($stack)) && $d != null) {
        $dir = @scandir($d);
        if ($dir === false) {
            continue;
        }
        foreach ($dir as $node) {
            if ($node === '.' || $node === '..') {
                continue;
            }
            $full = $d . $node;
            if (is_dir($full)) {
                $stack[] = $full . '/';
                continue;
            }
            if (!is_file($full)) {
                continue;
            }
            // .done markers are not live refs (decrement may be pending or done).
            if (preg_match('/\.finishing-[0-9a-f]+\.done$/', $node)) {
                continue;
            }
            $l = jirafeau_get_link_from_path($full);
            if (!count($l) || empty($l['hash'])) {
                continue;
            }
            $h = $l['hash'];
            if (!isset($live[$h])) {
                $live[$h] = 0;
            }
            $live[$h]++;
        }
    }

    $fixed = 0;
    $fstack = array(VAR_FILES);
    while (($d = array_shift($fstack)) && $d != null) {
        $dir = @scandir($d);
        if ($dir === false) {
            continue;
        }
        foreach ($dir as $node) {
            if ($node === '.' || $node === '..') {
                continue;
            }
            $full = $d . $node;
            if (is_dir($full)) {
                $fstack[] = $full . '/';
                continue;
            }
            if (!is_file($full)) {
                continue;
            }
            // Payload files only (skip _count and stable .lock).
            if (substr($node, -6) === '_count' || substr($node, -5) === '.lock') {
                continue;
            }
            if (!preg_match('/^[0-9a-f]+$/i', $node)) {
                continue;
            }
            $hash = $node;
            $expected = isset($live[$hash]) ? (int) $live[$hash] : 0;
            $fp = jirafeau_file_refcount_lock($hash);
            if ($fp === false) {
                continue;
            }
            try {
                $current = jirafeau_file_refcount_read_unlocked($hash);
                // Also treat a payload with no _count as needing alignment.
                if (!is_file(VAR_FILES . s2p($hash) . $hash) && $current === 0) {
                    continue;
                }
                if ($current <= $expected) {
                    continue;
                }
                $delta = $expected - $current;
                // Apply directly while we already hold the lock.
                $counter = $current + $delta;
                if ($counter < 0) {
                    $counter = 0;
                }
                $payload = VAR_FILES . s2p($hash) . $hash;
                if ($counter > 0) {
                    jirafeau_file_refcount_write_unlocked($hash, $counter);
                } else {
                    if (is_file($payload)) {
                        @unlink($payload);
                    }
                    jirafeau_file_refcount_write_unlocked($hash, 0);
                }
                $fixed++;
            } finally {
                flock($fp, LOCK_UN);
                fclose($fp);
            }
        }
    }
    return $fixed;
}


/**
 * Clean old async transfers.
 * @return number of cleaned files.
 */
function jirafeau_admin_clean_async()
{
    $count = 0;
    /* Get all links files. */
    $stack = array(VAR_ASYNC);
    while (($d = array_shift($stack)) && $d != null) {
        $dir = scandir($d);

        foreach ($dir as $node) {
            if (strcmp($node, '.') == 0 || strcmp($node, '..') == 0 ||
                preg_match('/\.tmp/i', "$node")) {
                continue;
            }

            if (is_dir($d . $node)) {
                /* Push new found directory. */
                $stack[] = $d . $node . '/';
            } elseif (is_file($d . $node)) {
                /* Stray locks left without a transfer meta file. */
                if (preg_match('/^([0-9a-f]{8,64})\.lock$/', $node, $m)) {
                    if (!is_file(jirafeau_async_meta_path($m[1]))) {
                        @unlink($d . $node);
                        $count++;
                    }
                    continue;
                }
                if (preg_match('/_data$/', $node) || preg_match('/\.lock$/', $node)) {
                    continue;
                }
                /* Read async information. */
                $a = jirafeau_get_async_ref(basename($node));
                if (!count($a)) {
                    continue;
                }
                /* Delete transfers older than 1 hour. */
                if (time() - $a['last_edited'] > 3600) {
                    jirafeau_async_delete(basename($node));
                    $count++;
                }
            }
        }
    }
    return $count;
}

/**
 * Better strval function for debug purposes
 */
function jirafeau_strval($value)
{
    if (gettype($value) == "boolean") {
        return $value ? 'true' : 'false';
    }
    return strval($value);
}

/**
 * Show file/folder permissions
 */
function jirafeau_fileperms($path)
{
    $out = substr(sprintf("%o", @fileperms($path)), -4) . ", ";
    $out .= "read " . (is_readable($path) ? "OK" : "KO") . ", ";
    $out .= "write " . (is_writable($path) ? "OK" : "KO");
    return $out;
}

/**
 * Show some useful informations for bug reporting.
 */
function jirafeau_admin_bug_report($cfg)
{
    $out = "<fieldset><legend>" . t('REPORTING_AN_ISSUE') . "</legend>";
    $out .= "If you have a problem related to Jirafeau, please <a href='" . JIRAFEAU_WEBSITE . "/-/issues'>open an issue</a>, explain your problem in english and copy-paste the following content:<br/><br/><code>";

    $out .= "# Jirafeau<br/>";
    $out .= "- version: " . JIRAFEAU_VERSION . "<br/>";
    $jirafeau_options = [
        'debug',
        'debug_enforce_classic_upload',
        'file_hash',
        'litespeed_workaround',
        'store_uploader_ip',
        'installation_done',
        'enable_crypt',
        'preview',
        'maximal_upload_size',
        'store_uploader_ip',
        'max_upload_chunk_size_bytes'
    ];
    foreach ($jirafeau_options as &$o) {
        $v = $cfg[$o];
        $out .= "- $o: " . jirafeau_strval($v) . " (" . gettype($v) . ")<br/>";
    }
    $out .= "<br/>";

    $out .= "# PHP options<br/>";
    $out .= "- php version: " . phpversion() . "<br/>";
    $out .= "- sodium version: " . phpversion('sodium') . "<br/>";
    $out .= "- mcrypt version: " . phpversion('mcrypt') . "<br/>";
    $php_options =  [
        'post_max_size',
        'upload_max_filesize',
        'safe_mode',
        'max_execution_time',
        'max_input_time'
    ];
    foreach ($php_options as &$o) {
        $v = ini_get($o);
        $out .= "- $o: " . jirafeau_strval($v) . " (" . gettype($v). ")<br/>";
    }
    $out .= "- can set_time_limit: " . (set_time_limit(0) ? "yes" : "no") . "<br/>";
    $out .= "<br/>";

    $out .= "# File permissions<br/>";
    $out .= "- 'var' folder permissions: " . jirafeau_fileperms($cfg['var_root']) . "<br/>";
    $out .= "- 'file' folder permissions: " . jirafeau_fileperms(VAR_FILES) . "<br/>";
    $out .= "- 'links' folder permissions: " . jirafeau_fileperms(VAR_LINKS) . "<br/>";
    $out .= "- 'async' folder permissions: " . jirafeau_fileperms(VAR_ASYNC) . "<br/>";
    $out .= "<br/>";

    $out .= "# Server details<br/>";
    $out .= "- server software: " . $_SERVER["SERVER_SOFTWARE"] . "<br/>";
    $out .= "<br/>";

    $out .= "# OS details<br/>";
    $out .= "- OS: " . php_uname() . "<br/>";
    $out .= "- Docker: " . (is_file('/.dockerenv') ? 'yes' : 'no') . "<br/>";
    $out .= "<br/>";

    $out .= "# Browser details<br/>";
    $out .= "<script type='text/javascript' lang='Javascript'>
        // @license magnet:?xt=urn:btih:0b31508aeb0634b347b8270c7bee4d411b5d4109&dn=agpl-3.0.txt AGPL-v3-or-Later
        document.write('- html5 support: ' + (check_html5_file_api() ? 'yes' : 'no') + '<br/>');
        document.write('- user agent: ' + navigator.userAgent + '<br/>');
        // @license-end
        </script>";
    $out .= "<br/>";

    $out .= "# Memory<br/>";
    $out .= "- memory_get_peak_usage: " . jirafeau_human_size(memory_get_peak_usage()) . "<br/>";

    $out .= "</code></fieldset>";
    return $out;
}

/**
 * Read async transfer information
 * @return array containing information.
 */
function jirafeau_get_async_ref($ref)
{
    $out = array();
    $refinfos = VAR_ASYNC . s2p("$ref") . "$ref";

    if (!is_file($refinfos)) {
        return $out;
    }

    if (filesize($refinfos) == 0) {
        return $out;
    }

    $c = file($refinfos);

    if(empty($c)) {
        return $out;
    }

    $out['file_name'] = trim($c[0]);
    $out['mime_type'] = trim($c[1]);
    $out['key'] = trim($c[2], NL);
    $out['time'] = trim($c[3]);
    $out['onetime'] = trim($c[4]);
    $out['ip'] = trim($c[5]);
    $out['last_edited'] = trim($c[6]);
    $out['next_code'] = trim($c[7]);
    return $out;
}

/**
 * Path of the per-transfer async metadata file.
 */
function jirafeau_async_meta_path($ref)
{
    return VAR_ASYNC . s2p($ref) . $ref;
}

/**
 * Path of the per-transfer async lock file.
 */
function jirafeau_async_lock_path($ref)
{
    return VAR_ASYNC . s2p($ref) . $ref . '.lock';
}

/**
 * Acquire the exclusive async lock for an *existing* transfer.
 * Never creates directories for unknown references (avoids disk fill via invented refs).
 * @return resource|false
 */
function jirafeau_async_acquire_lock($ref)
{
    if (!jirafeau_is_valid_async_ref($ref)) {
        return false;
    }
    $meta = jirafeau_async_meta_path($ref);
    $lock_path = jirafeau_async_lock_path($ref);
    $dir = dirname($lock_path);
    // Transfer must already exist; do not mkdir for speculative refs.
    if (!is_file($meta) || !is_dir($dir)) {
        return false;
    }
    $lock = @fopen($lock_path, 'c');
    if ($lock === false) {
        return false;
    }
    if (!flock($lock, LOCK_EX)) {
        fclose($lock);
        return false;
    }
    // Re-check under lock: transfer may have been deleted concurrently.
    if (!is_file($meta)) {
        flock($lock, LOCK_UN);
        fclose($lock);
        @unlink($lock_path);
        return false;
    }
    return $lock;
}

function jirafeau_async_release_lock($lock)
{
    if ($lock) {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

/**
 * Delete async transfer information.
 * Pass an already-held lock resource to avoid re-locking (and deadlocks) from push/end.
 */
function jirafeau_async_delete($ref, $held_lock = null)
{
    if (!jirafeau_is_valid_async_ref($ref)) {
        return;
    }
    $own_lock = false;
    $lock = $held_lock;
    if ($lock === null) {
        $lock = jirafeau_async_acquire_lock($ref);
        if ($lock === false) {
            return;
        }
        $own_lock = true;
    }
    $p = s2p("$ref");
    $lock_path = jirafeau_async_lock_path($ref);
    try {
        if (file_exists(VAR_ASYNC . $p . $ref)) {
            unlink(VAR_ASYNC . $p . $ref);
        }
        if (file_exists(VAR_ASYNC . $p . $ref . '_data')) {
            unlink(VAR_ASYNC . $p . $ref . '_data');
        }
        if (file_exists(VAR_ASYNC . $p . $ref . '.crypt')) {
            @unlink(VAR_ASYNC . $p . $ref . '.crypt');
        }
    } finally {
        if ($own_lock) {
            jirafeau_async_release_lock($lock);
            @unlink($lock_path);
        }
    }
    $parse = VAR_ASYNC . $p;
    $scan = array();
    while (file_exists($parse)
           && ($scan = scandir($parse))
           && count($scan) == 2 // '.' and '..' folders => empty.
           && basename($parse) != basename(VAR_ASYNC)) {
        rmdir($parse);
        $parse = substr($parse, 0, strlen($parse) - strlen(basename($parse)) - 1);
    }
}

/**
  * Init a new asynchronous upload.
  * @param $filename Name of the file to send
  * @param $one_time One time upload parameter
  * @param $key eventual password (or blank)
  * @param $time time limit
  * @param $ip ip address of the client
  * @return a string containing a temporary reference followed by a code or a string starting with 'Error'
  */
function jirafeau_async_init($filename, $type, $one_time, $key, $time, $ip)
{
    /* Create temporary folder. */
    $ref = '';
    $p = '';
    $code = jirafeau_gen_random(JIRAFEAU_ASYNC_CODE_LENGTH);
    do {
        $ref = jirafeau_gen_random(JIRAFEAU_ASYNC_REF_LENGTH);
        $p = VAR_ASYNC . s2p($ref);
    } while (file_exists($p));
    @mkdir($p, 0755, true);
    if (!file_exists($p)) {
        return 'Error: cannot create async folder.';
    }

    /* touch empty data file */
    $w_path = $p . $ref . '_data';
    touch($w_path);

    /* hashed download password or empty */
    $password = jirafeau_store_download_password($key);

    /* Store information. */
    $p .= $ref;
    $handle = fopen($p, 'w');
    fwrite(
        $handle,
        str_replace(NL, '', trim($filename)) . NL .
            jirafeau_sanitize_mime_type(str_replace(NL, '', trim($type))) . NL . $password . NL .
            $time . NL . ($one_time ? 'O' : 'R') . NL . $ip . NL .
            time() . NL . $code . NL
    );
    fclose($handle);

    return $ref . NL . $code ;
}

/**
  * Append a piece of file on the asynchronous upload.
  * @param $ref asynchronous upload reference
  * @param $file piece of data
  * @param $code client code for this operation
  * @param $max_file_size maximum allowed file size
  * @return a string containing a next code to use or a string starting with 'Error'
  */
function jirafeau_async_push($ref, $data, $code, $max_file_size)
{
    if (!jirafeau_is_valid_async_ref($ref)) {
        return "Error: cannot find transfer";
    }
    if (!is_file(jirafeau_async_meta_path($ref))) {
        return "Error: cannot find transfer";
    }

    $p = s2p($ref);
    $lock = jirafeau_async_acquire_lock($ref);
    if ($lock === false) {
        return is_file(jirafeau_async_meta_path($ref))
            ? "Error: transfer busy"
            : "Error: cannot find transfer";
    }

    try {
        /* Re-read async infos under lock. */
        $a = jirafeau_get_async_ref($ref);

        /* Check some errors. */
        if (count($a) == 0) {
            return "Error: cannot find transfer";
        }
        if (!is_string($code) || !hash_equals((string) $a['next_code'], (string) $code)) {
            return "Error: bad transfer code";
        }
        if ($data['error'] != UPLOAD_ERR_OK) {
            // Do not leak internal upload array details to clients.
            return "Error: upload error";
        }
        if (empty($data['tmp_name'])) {
            return "Error: missing tmp_name";
        }
        if (!is_uploaded_file($data['tmp_name'])) {
            return "Error: tmp_name may not be uploaded";
        }

        /* File path. */
        $r_path = $data['tmp_name'];
        $w_path = VAR_ASYNC . $p . $ref . '_data';

        /* Check that file size is not above upload limit. */
        if ($max_file_size > 0 &&
            filesize($r_path) + filesize($w_path) > $max_file_size * 1024 * 1024) {
            jirafeau_async_delete($ref, $lock);
            return "Error: file size is above upload limit";
        }

        /* Concatenate data. */
        $r = fopen($r_path, 'r');
        $w = fopen($w_path, 'a');
        while (!feof($r)) {
            if (fwrite($w, fread($r, 1024)) === false) {
                fclose($r);
                fclose($w);
                jirafeau_async_delete($ref, $lock);
                return "Error: cannot write file";
            }
        }
        fclose($r);
        fclose($w);
        unlink($r_path);

        /* Update async file. */
        $next = jirafeau_gen_random(JIRAFEAU_ASYNC_CODE_LENGTH);
        $handle = fopen(VAR_ASYNC . $p . $ref, 'w');
        fwrite(
            $handle,
            $a['file_name'] . NL. $a['mime_type'] . NL. $a['key'] . NL .
                $a['time'] . NL . $a['onetime'] . NL . $a['ip'] . NL .
                time() . NL . $next . NL
        );
        fclose($handle);
        return $next;
    } finally {
        jirafeau_async_release_lock($lock);
    }
}

/**
  * Finalize an asynchronous upload.
  * @param $ref asynchronous upload reference
  * @param $code client code for this operation
  * @param $crypt boolean asking to crypt or not
  * @param $link_name_length link name length
  * @return a string containing the download reference followed by a delete code or a string starting with 'Error'
  */
function jirafeau_async_end($ref, $code, $crypt, $link_name_length, $file_hash_method)
{
    if (!jirafeau_is_valid_async_ref($ref)) {
        return "Error: bad code for ending transfer";
    }
    if (!is_file(jirafeau_async_meta_path($ref))) {
        return "Error: bad code for ending transfer";
    }

    $lock = jirafeau_async_acquire_lock($ref);
    if ($lock === false) {
        return is_file(jirafeau_async_meta_path($ref))
            ? "Error: transfer busy"
            : "Error: bad code for ending transfer";
    }

    try {
        /* Re-read under the same lock used by push. */
        $a = jirafeau_get_async_ref($ref);
        if (count($a) == 0
            || !is_string($code)
            || !hash_equals((string) $a['next_code'], (string) $code)) {
            return "Error: bad code for ending transfer";
        }

        /* Generate link infos. */
        $p = VAR_ASYNC . s2p($ref) . $ref . "_data";
        if (!file_exists($p)) {
            return "Error: referenced file does not exist";
        }

        /* Store filesize before encrypting the file */
        /* Otherwise we would send the size of the encrypted file and the data of the unencrypted file */
        /* This would break some browsers */
        $size = filesize($p);

        $crypted = false;
        $crypt_key = '';
        if ($crypt == true && extension_loaded('sodium') == true) {
            $crypt_key = jirafeau_encrypt_file($p, $p.'.crypt');
            if (strlen($crypt_key) > 0) {
                if (rename($p.'.crypt', $p) === true) {
                    $crypted = true;
                }
            }
        }

        $hash = jirafeau_hash_file($file_hash_method, $p);
        $delete_link_code = jirafeau_gen_random(JIRAFEAU_DELETE_CODE_LENGTH);

        /* Install/dedup payload and bump refcount under one lock. */
        if (jirafeau_file_commit_payload($hash, $p, 'rename') === false) {
            return "Error: cannot update file reference counter";
        }

        /* Create link. */
        $link_tmp_name =  VAR_LINKS . $hash . rand(0, 10000) . '.tmp';
        $handle = fopen($link_tmp_name, 'w');
        fwrite(
            $handle,
            $a['file_name'] . NL . $a['mime_type'] . NL . $size . NL .
                $a['key'] . NL . $a['time'] . NL . $hash . NL . $a['onetime'] . NL .
                time() . NL . $a['ip'] . NL . $delete_link_code . NL . ($crypted ? 'C2' : 'O')
        );
        fclose($handle);
        $hash_link = substr(base_16_to_64(md5_file($link_tmp_name)), 0, $link_name_length);
        $l = s2p("$hash_link");
        if (!@mkdir(VAR_LINKS . $l, 0755, true)) {
            jirafeau_file_refcount_adjust($hash, -1);
            return "Error: cannot create folder in LINKS";
        }
        if (!rename($link_tmp_name, VAR_LINKS . $l . $hash_link)) {
            jirafeau_file_refcount_adjust($hash, -1);
            return "Error: cannot rename file in LINKS";
        }

        /* Clean async upload under the held lock. */
        jirafeau_async_delete($ref, $lock);
        return $hash_link . NL . $delete_link_code . NL . urlencode($crypt_key);
    } finally {
        jirafeau_async_release_lock($lock);
        @unlink(jirafeau_async_lock_path($ref));
    }
}

function jirafeau_crypt_create_iv($base, $size)
{
    $iv = '';
    while (strlen($iv) < $size) {
        $iv = $iv . $base;
    }
    $iv = substr($iv, 0, $size);
    return $iv;
}

/**
 * Crypt file using Sodium and returns decrypt key.
 * @param $fp_src file path to the file to crypt.
 * @param $fp_dst file path to the file to write crypted file (must not be the same).
 * @return key used to encrypt the file
 */
function jirafeau_encrypt_file($fp_src, $fp_dst)
{
    $fs = filesize($fp_src);
    if ($fs === false || $fs == 0 || extension_loaded('sodium') == false || $fp_src == $fp_dst) {
        return '';
    }

    /* Generate key. */
    $crypt_key = bin2hex(random_bytes(SODIUM_CRYPTO_STREAM_XCHACHA20_KEYBYTES / 2));
    /* Init module. */
    [$crypt_state, $crypt_header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($crypt_key);
    /* Crypt file. */
    $r = fopen($fp_src, 'rb');
    $w = fopen($fp_dst, 'wb');
    fwrite($w, $crypt_header);

    for ($i = 0; $i < $fs; $i += JIRAFEAU_SODIUM_CHUNKSIZE) {
        $to_enc = fread($r, JIRAFEAU_SODIUM_CHUNKSIZE);
        $enc = sodium_crypto_secretstream_xchacha20poly1305_push($crypt_state, $to_enc);

        if (fwrite($w, $enc) === false) {
            return '';
        }
    }

    fclose($r);
    fclose($w);

    /* Cleanup. */
    sodium_memzero($crypt_state);

    return $crypt_key;
}

/**
 * Decrypt file using Sodium.
 * @param $fp_src file path to the file to decrypt.
 * @param $fp_dst file path to the file to write decrypted file (must not be the same).
 * @param $k decryption key
 * @return true if decryption succeeded, false otherwise
 */
function jirafeau_decrypt_file($fp_src, $fp_dst, $k)
{
    $fs = filesize($fp_src);
    if ($fs === false || $fs == 0 || extension_loaded('sodium') == false || $fp_src == $fp_dst) {
        return false;
    }

    /* Decrypt file. */
    $r = fopen($fp_src, 'rb');
    $w = fopen($fp_dst, 'wb');

    $crypt_header = fread($r, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);

    /* Init module. */
    $crypt_state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($crypt_header, $k);

    /* Decrypt file. */

    for ($i = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES; $i < $fs; $i += JIRAFEAU_SODIUM_CHUNKSIZE + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES) {
        $to_dec = fread($r, JIRAFEAU_SODIUM_CHUNKSIZE + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
        [$dec, $crypt_tag] = sodium_crypto_secretstream_xchacha20poly1305_pull($crypt_state, $to_dec);

        if (fwrite($w, $dec) === false) {
            return false;
        }
    }

    fclose($r);
    fclose($w);

    /* Cleanup. */
    sodium_memzero($crypt_state);

    return true;
}

/**
 * Decrypt file using mcrypt.
 * @param $fp_src file path to the file to decrypt.
 * @param $fp_dst file path to the file to write decrypted file (could be the same).
 * @param $k string composed of the key and the iv separated by a point ('.')
 * @return true if decryption succeeded, false otherwise
 */
function jirafeau_decrypt_file_legacy($fp_src, $fp_dst, $k)
{
    $fs = filesize($fp_src);
    if ($fs === false || $fs == 0 || extension_loaded('mcrypt') == false) {
        return false;
    }

    /* Init module */
    $m = mcrypt_module_open('rijndael-256', '', 'ofb', '');
    /* Extract key and iv. */
    $crypt_key = $k;
    $hash_key = md5($crypt_key);
    $iv = jirafeau_crypt_create_iv($hash_key, mcrypt_enc_get_iv_size($m));
    /* Init module. */
    mcrypt_generic_init($m, $hash_key, $iv);
    /* Decrypt file. */
    $r = fopen($fp_src, 'r');
    $w = fopen($fp_dst, 'c');
    while (!feof($r)) {
        $dec = mdecrypt_generic($m, fread($r, 1024));
        if (fwrite($w, $dec) === false) {
            return false;
        }
    }
    fclose($r);
    fclose($w);
    /* Cleanup. */
    mcrypt_generic_deinit($m);
    mcrypt_module_close($m);
    return true;
}

/**
 * Check if Jirafeau is password protected for visitors.
 * @return true if Jirafeau is password protected, false otherwise.
 */
function jirafeau_has_upload_password($cfg)
{
    return count($cfg['upload_password']) > 0;
}

/**
 * Challenge password for a visitor.
 * @param $password password to be challenged
 * @return true if password is valid, false otherwise.
 */
function jirafeau_challenge_upload_password($cfg, $password)
{
    if (!jirafeau_has_upload_password($cfg)) {
        return false;
    }
    if (!is_string($password)) {
        return false;
    }
    foreach ($cfg['upload_password'] as $p) {
        if (is_string($p) && hash_equals($p, $password)) {
            return true;
        }
    }
    return false;
}

/**
 * Test if the given IP is whitelisted by the given list.
 *
 * @param $allowedIpList array of allowed IPs
 * @param $challengedIp IP to be challenged
 * @return true if IP is authorized, false otherwise.
 */
function jirafeau_challenge_ip($allowedIpList, $challengedIp)
{
    foreach ($allowedIpList as $i) {
        if ($i == $challengedIp) {
            return true;
        }
        // CIDR test for IPv4 only.
        if (strpos($i, '/') !== false) {
            list($subnet, $mask) = explode('/', $i);
            if ((ip2long($challengedIp) & ~((1 << (32 - $mask)) - 1)) == ip2long($subnet)) {
                return true;
            }
        }
    }
    return false;
}

/**
 * Check if Jirafeau has a restriction on the IP address for uploading.
 * @return true if uploading is IP restricted, false otherwise.
 */
function jirafeau_upload_has_ip_restriction($cfg)
{
    return count($cfg['upload_ip']) > 0;
}

/**
 * Test if visitor's IP is authorized to upload at all.
 *
 * @param $cfg configuration
 * @param $challengedIp IP to be challenged
 * @return true if IP is authorized, false otherwise.
 */
function jirafeau_challenge_upload_ip($cfg, $challengedIp)
{
    // If no IP address have been listed, allow upload from any IP
    if (!jirafeau_upload_has_ip_restriction($cfg)) {
        return true;
    }
    return jirafeau_challenge_ip($cfg['upload_ip'], $challengedIp);
}

/**
 * Test if visitor's IP is authorized to upload without a password.
 *
 * @param $cfg configuration
 * @param $challengedIp IP to be challenged
 * @return true if IP is authorized, false otherwise.
 */
function jirafeau_challenge_upload_ip_without_password($cfg, $challengedIp)
{
    return jirafeau_challenge_ip($cfg['upload_ip_nopassword'], $challengedIp);
}

/**
 * Test if visitor's IP is authorized or password is supplied and authorized
 * @param $ip IP to be challenged
 * @param $password password to be challenged
 * @return true if access is valid, false otherwise.
 */
function jirafeau_challenge_upload($cfg, $ip, $password)
{
    return jirafeau_challenge_upload_ip_without_password($cfg, $ip) ||
            (!jirafeau_has_upload_password($cfg) && !jirafeau_upload_has_ip_restriction($cfg)) ||
            (jirafeau_challenge_upload_password($cfg, $password) && jirafeau_challenge_upload_ip($cfg, $ip));
}

/**
 * Check if Jirafeau has a restriction on the IP address for accessing the admin interface.
 * @return true if admin interface is IP restricted, false otherwise.
 */
function jirafeau_admin_has_ip_restriction($cfg)
{
    return count($cfg['admin_ip']) > 0;
}

/**
 * Test if visitor's IP is authorized to access the admin interface.
 *
 * @param $cfg configuration
 * @param $challengedIp IP to be challenged
 * @return true if IP is authorized, false otherwise.
 */
function jirafeau_challenge_admin_ip($cfg, $challengedIp)
{
    // If no IP address have been listed, allow upload from any IP
    if (!jirafeau_admin_has_ip_restriction($cfg)) {
        return true;
    }
    return jirafeau_challenge_ip($cfg['admin_ip'], $challengedIp);
}

/** Tell if we have some HTTP headers generated by a proxy */
function has_http_forwarded()
{
    return
        !empty($_SERVER['HTTP_X_FORWARDED_FOR']) ||
        !empty($_SERVER['http_X_forwarded_for']);
}

/**
 * Generate IP list from HTTP headers generated by a proxy
 * @return  array of IP strings
 */
function get_ip_list_http_forwarded()
{
    $ip_list = array();
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $l = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        if ($l === false) {
            return array();
        }
        foreach ($l as $ip) {
            array_push($ip_list, preg_replace('/\s+/', '', $ip));
        }
    }
    if (!empty($_SERVER['http_X_forwarded_for'])) {
        $l = explode(',', $_SERVER['http_X_forwarded_for']);
        foreach ($l as $ip) {
            // Separate IP from port
            $ipa = explode(':', $ip);
            if ($ipa === false) {
                continue;
            }
            $ip = $ipa[0];
            array_push($ip_list, preg_replace('/\s+/', '', $ip));
        }
    }
    return $ip_list;
}

/**
 * Get the ip address of the client from REMOTE_ADDR
 * or from HTTP_X_FORWARDED_FOR if behind a proxy
 * @returns the client ip address
 */
function get_ip_address($cfg)
{
    $remote = $_SERVER['REMOTE_ADDR'];
    if (count($cfg['proxy_ip']) == 0 || !has_http_forwarded()) {
        return $remote;
    }

    $ip_list = get_ip_list_http_forwarded();
    if (count($ip_list) == 0) {
        return $remote;
    }

    foreach ($cfg['proxy_ip'] as $proxy_ip) {
        if ($remote != $proxy_ip) {
            continue;
        }
        // Take the last IP (the one which has been set by the defined proxy).
        return end($ip_list);
    }
    return $remote;
}

/**
 * Convert hexadecimal string to base64
 */
function hex_to_base64($hex)
{
    $b = '';
    foreach (str_split($hex, 2) as $pair) {
        $b .= chr(hexdec($pair));
    }
    return base64_encode($b);
}

/**
 * Replace markers in templates.
 *
 * Available markers have the scheme "###MARKERNAME###".
 *
 * @param $content string Template text with markers
 * @param $htmllinebreaks boolean Convert linebreaks to BR-Tags
 * @return Template with replaced markers
 */
function jirafeau_replace_markers($content, $htmllinebreaks = false)
{
    $patterns = array(
        '/###ORGANISATION###/',
        '/###CONTACTPERSON###/',
        '/###WEBROOT###/'
    );
    $replacements = array(
        $GLOBALS['cfg']['organisation'],
        $GLOBALS['cfg']['contactperson'],
        $GLOBALS['cfg']['web_root']
    );
    $content = preg_replace($patterns, $replacements, $content);

    if (true === $htmllinebreaks) {
        $content = nl2br($content);
    }

    return $content;
}

function jirafeau_escape($string)
{
    return htmlspecialchars($string, ENT_QUOTES);
}

function jirafeau_admin_session_start()
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_regenerate_id(true);
    }
    $_SESSION['admin_auth'] = true;
    $_SESSION['admin_csrf'] = bin2hex(random_bytes(32));
}

function jirafeau_session_end()
{
    $_SESSION = array();
    if (session_status() === PHP_SESSION_ACTIVE) {
        // header.php may already have flushed HTML (e.g. wrong upload password on index).
        if (!headers_sent()) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                time() - 42000,
                $params['path'],
                $params['domain'] ?? '',
                !empty($params['secure']),
                !empty($params['httponly'])
            );
        }
        session_destroy();
    }
}

function jirafeau_admin_is_authenticated()
{
    return isset($_SESSION['admin_auth']) && $_SESSION['admin_auth'] === true;
}

function jirafeau_admin_csrf_valid()
{
    return isset($_SESSION['admin_csrf'])
        && isset($_POST['admin_csrf'])
        && is_string($_POST['admin_csrf'])
        && hash_equals($_SESSION['admin_csrf'], $_POST['admin_csrf']);
}

/**
 * Backward-compatible name: authenticated admin with a valid CSRF token on POST.
 */
function jirafeau_admin_session_logged()
{
    return jirafeau_admin_is_authenticated() && jirafeau_admin_csrf_valid();
}

function jirafeau_admin_csrf_field()
{
    if (!isset($_SESSION['admin_csrf'])) {
        $_SESSION['admin_csrf'] = bin2hex(random_bytes(32));
    }
    return "<input type='hidden' name='admin_csrf' value='" . jirafeau_escape($_SESSION['admin_csrf']) . "'/>";
}

function jirafeau_admin_require_csrf_or_exit()
{
    if (!jirafeau_admin_csrf_valid()) {
        http_response_code(403);
        require(JIRAFEAU_ROOT . 'lib/template/header.php');
        jirafeau_show_page_error('BAD_PSW', 'BAD_PSW_BODY', $GLOBALS['cfg'], 'denied', false);
        require(JIRAFEAU_ROOT . 'lib/template/footer.php');
        exit;
    }
}

function jirafeau_user_session_start()
{
    $_SESSION['user_auth'] = true;
}

function jirafeau_user_session_logged()
{
    return isset($_SESSION['user_auth']) &&
        $_SESSION['user_auth'] === true;
}

function jirafeau_dir_size($dir)
{
    $size = 0;
    foreach (glob(rtrim($dir, '/').'/*', GLOB_NOSORT) as $entry) {
        $size += is_file($entry) ? filesize($entry) : jirafeau_dir_size($entry);
    }
    return $size;
}

/**
 * Parse a CSV environment value into a string array.
 * Empty / whitespace-only values become an empty array (not array('')).
 *
 * @param mixed $value getenv() result or raw string
 * @return array|null null when the variable was unset (false)
 */
function jirafeau_parse_csv_env($value)
{
    if ($value === false) {
        return null;
    }
    if (!is_string($value) || trim($value) === '') {
        return array();
    }
    $parts = array_map('trim', explode(',', $value));
    return array_values(array_filter($parts, function ($part) {
        return $part !== '';
    }));
}

/**
 * Atomically claim a one-time download link before streaming.
 * Refreshes mtime so cleaners use the claim time, not the original link age.
 * @return string|false claimed path on success, false if already consumed
 */
function jirafeau_try_claim_onetime_link($link_name)
{
    if (!is_string($link_name) || !preg_match('/^[0-9a-zA-Z_-]+$/', $link_name)) {
        return false;
    }
    $path = VAR_LINKS . s2p($link_name) . $link_name;
    if (!is_file($path)) {
        return false;
    }
    $claimed = $path . '.claimed-' . jirafeau_gen_random(8);
    if (!@rename($path, $claimed)) {
        return false;
    }
    // rename() preserves mtime on many systems; stamp the reservation now.
    @touch($claimed);
    return $claimed;
}

/**
 * Remove empty parent directories under VAR_LINKS after claim finalization.
 */
function jirafeau_cleanup_link_dirs($start_dir)
{
    $parse = $start_dir;
    while (is_dir($parse)
           && ($scan = @scandir($parse))
           && is_array($scan)
           && count($scan) == 2
           && basename($parse) != basename(VAR_LINKS)) {
        @rmdir($parse);
        $parse = dirname($parse);
    }
}

/**
 * Finalize a claimed one-time link exactly once across processes.
 *
 * Order matters for crash safety:
 * 1) claimed → finishing (exclusive winner)
 * 2) finishing → finishing.done (publish "do not decrement again")
 * 3) decrement refcount
 * 4) unlink .done
 *
 * If we crash after (2) and before (3), cleaners only unlink .done (refcount leak,
 * file retained). Never decrement twice.
 *
 * @return bool true when this caller performed finalization
 */
function jirafeau_finalize_onetime_claim($claimed_path, $link)
{
    if (!is_string($claimed_path) || $claimed_path === '') {
        return false;
    }
    $basename = basename($claimed_path);
    // Already marked done: cleaner/resume must never decrement again.
    if (preg_match('/\.finishing-[0-9a-f]+\.done$/', $basename)) {
        @unlink($claimed_path);
        jirafeau_cleanup_link_dirs(dirname($claimed_path));
        return false;
    }

    $finishing = $claimed_path;
    if (jirafeau_claimed_link_name($basename) !== false) {
        if (!is_file($claimed_path)) {
            return false;
        }
        $finishing = $claimed_path . '.finishing-' . jirafeau_gen_random(4);
        if (!@rename($claimed_path, $finishing)) {
            return false;
        }
    } elseif (!preg_match('/\.finishing-[0-9a-f]+$/', $basename) || !is_file($claimed_path)) {
        return false;
    }

    $done = $finishing . '.done';
    // Mark completion BEFORE decrement so crash recovery cannot double-decrement.
    if (!@rename($finishing, $done)) {
        // Another worker may have won; if .done exists, treat as already handled.
        if (is_file($done)) {
            return false;
        }
        return false;
    }

    if (is_array($link) && !empty($link['hash'])) {
        jirafeau_file_refcount_adjust($link['hash'], -1);
    }
    @unlink($done);
    jirafeau_cleanup_link_dirs(dirname($claimed_path));
    return true;
}

/**
 * Auth throttle state file for a scope + client key.
 */
function jirafeau_auth_throttle_file($scope, $client_key)
{
    $base = defined('VAR_FILES') ? dirname(rtrim(VAR_FILES, '/\\')) : sys_get_temp_dir();
    $dir = $base . DIRECTORY_SEPARATOR . 'auth_throttle';
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    return $dir . DIRECTORY_SEPARATOR . hash('sha256', $scope . '|' . $client_key);
}

/**
 * Resolve the client identity used for auth throttling (honours trusted proxy_ip).
 */
function jirafeau_auth_client_key($cfg = null)
{
    if (is_array($cfg)) {
        return (string) get_ip_address($cfg);
    }
    global $cfg;
    if (is_array($cfg)) {
        return (string) get_ip_address($cfg);
    }
    return isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : 'unknown';
}

/**
 * Whether authentication attempts are temporarily refused for this client.
 * Check this BEFORE verifying a password.
 */
function jirafeau_auth_is_blocked($scope, $cfg = null, $max_attempts = 5, $lockout_seconds = 300)
{
    $file = jirafeau_auth_throttle_file($scope, jirafeau_auth_client_key($cfg));
    if (!is_file($file)) {
        return false;
    }
    $fp = @fopen($file, 'c+');
    if (!$fp || !flock($fp, LOCK_SH)) {
        if ($fp) {
            fclose($fp);
        }
        return false;
    }
    $raw = stream_get_contents($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    $data = @json_decode((string) $raw, true);
    if (!is_array($data) || empty($data['blocked_until'])) {
        return false;
    }
    return time() < (int) $data['blocked_until'];
}

/**
 * Record a failed authentication attempt. Does not sleep; may set a lockout window.
 *
 * @return array{attempts:int,blocked:bool,blocked_until:int}
 */
function jirafeau_auth_register_failure($scope, $cfg = null, $max_attempts = 5, $lockout_seconds = 300, $window_seconds = 900)
{
    $file = jirafeau_auth_throttle_file($scope, jirafeau_auth_client_key($cfg));
    $now = time();
    $result = array('attempts' => 1, 'blocked' => false, 'blocked_until' => 0);
    $fp = @fopen($file, 'c+');
    if (!$fp || !flock($fp, LOCK_EX)) {
        if ($fp) {
            fclose($fp);
        }
        return $result;
    }
    $raw = stream_get_contents($fp);
    $data = @json_decode((string) $raw, true);
    if (!is_array($data)) {
        $data = array('failures' => array(), 'blocked_until' => 0);
    }
    $failures = array();
    if (!empty($data['failures']) && is_array($data['failures'])) {
        foreach ($data['failures'] as $t) {
            if (($now - (int) $t) < $window_seconds) {
                $failures[] = (int) $t;
            }
        }
    }
    $failures[] = $now;
    $blocked_until = !empty($data['blocked_until']) ? (int) $data['blocked_until'] : 0;
    if (count($failures) >= $max_attempts) {
        $blocked_until = max($blocked_until, $now + $lockout_seconds);
        $failures = array();
    }
    $payload = json_encode(array(
        'failures' => $failures,
        'blocked_until' => $blocked_until,
    ));
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, $payload);
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    return array(
        'attempts' => count($failures),
        'blocked' => $now < $blocked_until,
        'blocked_until' => $blocked_until,
    );
}

/**
 * Clear throttle state after a successful authentication.
 */
function jirafeau_auth_clear_failures($scope, $cfg = null)
{
    $file = jirafeau_auth_throttle_file($scope, jirafeau_auth_client_key($cfg));
    if (is_file($file)) {
        @unlink($file);
    }
}

function jirafeau_export_cfg($cfg)
{
    $content = '<?php' . NL;
    $content .= '/* This file was generated by the install process. ' .
               'You can edit it. Please see config.original.php to understand the ' .
               'configuration items. */' . NL;
    $content .= '$cfg = ' . var_export($cfg, true) . ';';

    $cfg_path = defined('JIRAFEAU_CFG')
        ? JIRAFEAU_CFG
        : (defined('JIRAFEAU_ROOT') ? JIRAFEAU_ROOT . 'lib/config.local.php' : 'lib/config.local.php');
    $fileWrite = file_put_contents($cfg_path, $content);

    if (false === $fileWrite) {
        jirafeau_fatal_error(t('Can not write local configuration file'));
    }
}

function jirafeau_mkdir($path)
{
    return !(!file_exists($path) && !@mkdir($path, 0755));
}

/**
 * Returns true whether the path is writable or we manage to make it
 * so, which essentially is the same thing.
 * @param $path is the file or directory to be tested.
 * @return true if $path is writable.
 */
function jirafeau_is_writable($path)
{
    /* "@" gets rid of error messages. */
    return is_writable($path) || @chmod($path, 0777);
}

function jirafeau_check_var_dir($path)
{
    $mkdir_str1 = t('CANNOT_CREATE_DIR') . ':';
    $mkdir_str2 = t('MANUAL_CREATE');
    $write_str1 = t('DIR_NOT_W') . ':';
    $write_str2 = t('You should give the write permission to the web server on ' .
                    'this directory.');
    $solution_str = t('HERE_SOLUTION') . ':';

    if (!jirafeau_mkdir($path) || !jirafeau_is_writable($path)) {
        return array('has_error' => true,
                      'why' => $mkdir_str1 . '<br /><code>' .
                               $path . '</code><br />' . $solution_str .
                               '<br />' . $mkdir_str2);
    }

    foreach (array('files', 'links', 'async') as $subdir) {
        $subpath = $path.$subdir;

        if (!jirafeau_mkdir($subpath) || !jirafeau_is_writable($subpath)) {
            return array('has_error' => true,
                          'why' => $mkdir_str1 . '<br /><code>' .
                                   $subpath . '</code><br />' . $solution_str .
                                   '<br />' . $mkdir_str2);
        }
    }

    return array('has_error' => false, 'why' => '');
}

function jirafeau_add_ending_slash($path)
{
    return $path . ((substr($path, -1) == '/') ? '' : '/');
}

function jirafeau_default_web_root()
{
    $url_scheme = (isset($_SERVER['HTTPS'])) ? 'https://' : 'http://';
    return $url_scheme . $_SERVER['HTTP_HOST'] . str_replace('install.php', '', $_SERVER['REQUEST_URI']);
}

function jirafeau_get_download_stats($hash)
{
    $filename = VAR_LINKS . s2p("$hash") . $hash . '_download';

    if (!file_exists($filename)) {
        return array('count' => 0);
    }

    $c = file($filename);
    $data['count'] = trim($c[0]);
    $data['date'] = trim($c[1]);
    $data['ip'] = trim($c[2]);

    return $data;
}

function jirafeau_write_download_stats($hash, $ip)
{
    $data = jirafeau_get_download_stats($hash);
    $count = $data['count'];
    $count++;

    $filename = VAR_LINKS . s2p("$hash") . $hash . '_download';

    $handle = fopen($filename, 'w');
    fwrite($handle, $count . NL . time() . NL . $ip);
    fclose($handle);
}

function jirafeau_create_upload_finished_box($preview = true, $download_pass = null)
{
    ?>

    <div id="upload_finished">
    <p><?php echo t('FILE_UP') ?></p>

    <div id="upload_finished_download_page">
    <p>
        <a id="upload_link" href=""><?php echo t('DL_PAGE') ?></a>
        <a id="upload_link_email" href=""><img id="upload_image_email"/></a>
    </p><p>
        <code id=upload_link_text></code>
        <button id="upload_link_button">&#128203;</button>
    </p>
    </div>

    <?php if (!is_null($download_pass)) { ?>
    <div id="show_password">
    <p><?php echo t('PSW') ?></p>

    <div id="download_password">
    <p>
        <?php echo '<input id="output_key" value="' . $download_pass . '" readonly/>'?>
        <button id="password_copy_button">&#128203;</button>
    </p>
    </div>
    </div>
    <?php
    }?>


    <?php
    if ($preview == true) { ?>
    <div id="upload_finished_preview">
    <p>
        <a id="preview_link" href=""><?php echo t('VIEW_LINK') ?></a>
    </p><p>
        <code id=preview_link_text></code>
        <button id="preview_link_button">&#128203;</button>
    </p>
    </div>
    <?php
    }
    ?>

    <div id="upload_direct_download">
    <p>
        <a id="direct_link" href=""><?php echo t('DIRECT_DL') ?></a>
    </p><p>
        <code id=direct_link_text></code>
        <button id="direct_link_button">&#128203;</button>
    </p>
    </div>

    <div id="upload_delete">
    <p>
        <a id="delete_link" href=""><?php echo t('DELETE_LINK') ?></a>
    </p><p>
        <code id=delete_link_text></code>
        <button id="delete_link_button">&#128203;</button>
    </p>
    </div>

    <div id="upload_validity">
    <p><?php echo t('VALID_UNTIL'); ?>:</p>
    <p id="date"></p>
    </div>
</div>
<?php
}

function jirafeau_get_expiration_time_options()
{
    return array(
        array(
            'value' => 'minute',
            'label' => '1_MIN'
        ),
        array(
            'value' => 'hour',
            'label' => '1_H'
        ),
        array(
            'value' => 'day',
            'label' => '1_D'
        ),
        array(
            'value' => 'week',
            'label' => '1_W'
        ),
        array(
            'value' => 'fortnight',
            'label' => '2_W'
        ),
        array(
            'value' => 'month',
            'label' => '1_M'
        ),
        array(
            'value' => 'quarter',
            'label' => '1_Q'
        ),
        array(
            'value' => 'year',
            'label' => '1_Y'
        ),
        array(
            'value' => 'none',
            'label' => 'NONE'
        )
        );
}

/**
 *
 * creates the time selection field
 * @param mixed $cfg
 * @return void
 */
function jirafeau_create_selection_array($cfg)
{
    echo '<select name="time" id="select_time">';

    $expirationTimeOptions = jirafeau_get_expiration_time_options();

    foreach ($expirationTimeOptions as $expirationTimeOption) {
        $selected = ($expirationTimeOption['value'] === $cfg['availability_default']) ? 'selected="selected"' : '';
        if (true === $cfg['availabilities'][$expirationTimeOption['value']]) {
            echo '<option value="' . $expirationTimeOption['value'] . '" ' .
            $selected . '>' . t($expirationTimeOption['label']) . '</option>';
        }
    }

    echo '</select>';
}

function jirafeau_datestr_to_int($time_str)
{
    $time = time();
    switch ($time_str) {
        case 'minute':
            $time += JIRAFEAU_MINUTE;
            break;
        case 'hour':
            $time += JIRAFEAU_HOUR;
            break;
        case 'day':
            $time += JIRAFEAU_DAY;
            break;
        case 'week':
            $time += JIRAFEAU_WEEK;
            break;
        case 'fortnight':
            $time += JIRAFEAU_FORTNIGHT;
            break;
        case 'month':
            $time += JIRAFEAU_MONTH;
            break;
        case 'quarter':
            $time += JIRAFEAU_QUARTER;
            break;
        case 'year':
            $time += JIRAFEAU_YEAR;
            break;
        default:
            $time = JIRAFEAU_INFINITY;
            break;
    }
    return $time;
}




/**
 * links or copy a local file
 * TODO: boolean in config for linking
 * @param string $filepath
 * @param $one_time_download is the file a one time download?
 * @param $key if not empty, protect the file with this key
 * @param $time the time of validity of the file
 * @param $ip uploader's ip
 * @param $crypt boolean asking to crypt or not
 * @param $link_name_length size of the link name
 * @returns an array containing some information
 *   'error' => information on possible errors
 *   'link' => the link name of the uploaded file
 *   'delete_link' => the link code to delete file
 */
function jirafeau_copy_local_file($local_file_path, $one_time_download, $key, $time, $ip, $crypt, $link_name_length, $file_hash_method)
{
    if (!file_exists($local_file_path)) {
        return (array(
            'error' =>
              array('has_error' => true,
                     'why' => t('INTERNAL_ERROR_FILE_NOT_EXIST')),
            'link' => '',
            'delete_link' => ''));
    }
    if (
        // sanity check if file can be opened
        $file = fopen($local_file_path, 'r')
    ) {
        // close file pointer - it's not needed here
        fclose($file);
        $time_in_int = jirafeau_datestr_to_int($time);
        return jirafeau_add_file(
            jirafeau_create_file_array($local_file_path),
            $one_time_download,
            $key,
            $time_in_int,
            $ip,
            $crypt,
            $link_name_length,
            $file_hash_method,
            false
        );
    } else {
        return (array(
            'error' =>
              array('has_error' => true,
                     'why' => t('INTERNAL_ERROR_FP_OPEN_LOCAL')),
            'link' => '',
            'delete_link' => ''));
    }
}


function jirafeau_create_file_array($file_path)
{
    return [
        'type' => mime_content_type($file_path),
        'tmp_name' => $file_path,
        'name' => basename($file_path),
        'size' => filesize($file_path),
    ];
}
