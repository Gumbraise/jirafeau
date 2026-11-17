<?php
/**
 * Lightweight security regression tests for Jirafeau.
 * Run: php tests/security/run.php
 */

define('JIRAFEAU_ROOT', dirname(__DIR__, 2) . DIRECTORY_SEPARATOR);

$failures = 0;
$passed = 0;

function expect_true($cond, $message)
{
    global $failures, $passed;
    if ($cond) {
        echo "[PASS] $message\n";
        $passed++;
    } else {
        echo "[FAIL] $message\n";
        $failures++;
    }
}

function expect_eq($actual, $expected, $message)
{
    expect_true($actual === $expected, $message . ' (got ' . var_export($actual, true) . ')');
}

$cfg = array(
    'web_root' => 'http://localhost/',
    'var_root' => sys_get_temp_dir() . '/jirafeau-sec-tests-' . getmypid() . '/',
    'style' => 'courgette',
    'dark_style' => 'dark-courgette',
    'debug' => false,
    'proxy_ip' => array(),
    'installation_done' => true,
);
@mkdir($cfg['var_root'], 0700, true);
@mkdir($cfg['var_root'] . 'files/', 0700, true);
@mkdir($cfg['var_root'] . 'links/', 0700, true);
@mkdir($cfg['var_root'] . 'async/', 0700, true);

require JIRAFEAU_ROOT . 'lib/config.original.php';
$cfg['var_root'] = sys_get_temp_dir() . '/jirafeau-sec-tests-' . getmypid() . '/';
$cfg['web_root'] = 'http://localhost/';
$cfg['style'] = 'courgette';
$cfg['dark_style'] = 'dark-courgette';
$cfg['debug'] = false;
$cfg['proxy_ip'] = array();
$cfg['installation_done'] = true;

if (!defined('VAR_FILES')) {
    define('VAR_FILES', $cfg['var_root'] . 'files/');
    define('VAR_LINKS', $cfg['var_root'] . 'links/');
    define('VAR_ASYNC', $cfg['var_root'] . 'async/');
}
if (!defined('NL')) {
    define('NL', "\n");
}
if (!defined('JIRAFEAU_INFINITY')) {
    define('JIRAFEAU_INFINITY', -1);
}
if (!defined('JIRAFEAU_SODIUM_CHUNKSIZE')) {
    define('JIRAFEAU_SODIUM_CHUNKSIZE', 1024);
}
if (!defined('JIRAFEAU_CFG')) {
    define('JIRAFEAU_CFG', $cfg['var_root'] . 'config.local.php');
}

require JIRAFEAU_ROOT . 'lib/functions.php';

echo "== CSPRNG / tokens ==\n";
$a = jirafeau_gen_random(32);
$b = jirafeau_gen_random(32);
expect_true(preg_match('/^[0-9a-f]{32}$/', $a) === 1, 'gen_random returns hex of requested length');
expect_true($a !== $b, 'gen_random produces distinct values');
expect_true(JIRAFEAU_DELETE_CODE_LENGTH >= 32, 'delete code length is at least 32 hex chars');
expect_true(JIRAFEAU_ASYNC_CODE_LENGTH >= 16, 'async code length is at least 16 hex chars');
expect_eq(strlen(jirafeau_gen_random(JIRAFEAU_DELETE_CODE_LENGTH)), JIRAFEAU_DELETE_CODE_LENGTH, 'generated delete code matches configured length');

$pass = jirafeau_gen_download_pass(12, 'abcdef');
expect_true(is_string($pass) && strlen($pass) === 12, 'gen_download_pass length');
expect_true(preg_match('/^[abcdef]{12}$/', $pass) === 1, 'gen_download_pass charset');

echo "== Filename / MIME sanitization ==\n";
$injected = jirafeau_sanitize_filename_for_header("report\"\r\nX-Injected: 1.pdf");
expect_true(strpos($injected, "\r") === false && strpos($injected, "\n") === false && strpos($injected, '"') === false, 'strips CR/LF and quotes from filenames');
expect_eq($injected, 'reportX-Injected: 1.pdf', 'keeps printable filename body without header breaks');
expect_eq(
    jirafeau_sanitize_filename_for_header('../etc/passwd'),
    'passwd',
    'basename prevents path traversal in Content-Disposition'
);
expect_eq(
    jirafeau_sanitize_mime_type("text/html\r\nX-Injected: 1"),
    'application/octet-stream',
    'rejects MIME with header injection'
);
expect_eq(
    jirafeau_sanitize_mime_type('image/png'),
    'image/png',
    'accepts legitimate MIME'
);

echo "== Style / async ref validation ==\n";
expect_true(jirafeau_is_valid_style_name('mygift'), 'valid style name');
expect_true(!jirafeau_is_valid_style_name('../etc'), 'rejects path style');
expect_true(jirafeau_is_valid_async_ref(str_repeat('a', 32)), 'valid async ref');
expect_true(!jirafeau_is_valid_async_ref('../x'), 'rejects path async ref');
expect_true(!jirafeau_is_valid_async_ref(''), 'rejects empty async ref');

echo "== Admin password migration ==\n";
$plain = 'TestAdminPassw0rd!';
$legacy = hash('sha256', $plain);
expect_true(jirafeau_verify_admin_password($plain, $legacy), 'legacy SHA-256 verifies');
expect_true(!jirafeau_verify_admin_password('wrong', $legacy), 'legacy SHA-256 rejects wrong password');
expect_true(jirafeau_admin_password_needs_rehash($legacy), 'legacy needs rehash');

$modern = jirafeau_hash_admin_password($plain);
expect_true(jirafeau_verify_admin_password($plain, $modern), 'password_hash verifies');
expect_true(!jirafeau_verify_admin_password('wrong', $modern), 'password_hash rejects wrong password');
expect_true(isset($modern[0]) && $modern[0] === '$', 'modern hash uses password_hash format');
expect_true(!jirafeau_admin_password_needs_rehash($modern), 'fresh password_hash does not need rehash');

echo "== Config export path (JIRAFEAU_CFG) ==\n";
expect_true(defined('JIRAFEAU_CFG'), 'JIRAFEAU_CFG is defined for export');
$export_cfg = array('installation_done' => true, 'admin_password' => $modern, 'title' => 'sec-test');
jirafeau_export_cfg($export_cfg);
expect_true(is_file(JIRAFEAU_CFG), 'export_cfg writes config file');
$exported = file_get_contents(JIRAFEAU_CFG);
expect_true(strpos($exported, 'sec-test') !== false, 'exported config contains updated values');

echo "== CSV env parsing ==\n";
expect_eq(jirafeau_parse_csv_env(false), null, 'unset env stays null');
expect_eq(jirafeau_parse_csv_env(''), array(), 'empty string becomes empty array');
expect_eq(jirafeau_parse_csv_env('   '), array(), 'whitespace becomes empty array');
expect_eq(jirafeau_parse_csv_env(',,'), array(), 'comma-only becomes empty array');
expect_eq(jirafeau_parse_csv_env('a, b,,c'), array('a', 'b', 'c'), 'csv values trimmed and filtered');

echo "== Download password storage ==\n";
$stored_new = jirafeau_store_download_password('secret-dl');
expect_true(strpos($stored_new, '[PASSWORD]') === 0, 'new download passwords use [PASSWORD] prefix');
expect_true(jirafeau_verify_download_password('secret-dl', $stored_new), 'new download password verifies');
expect_true(!jirafeau_verify_download_password('nope', $stored_new), 'new download password rejects wrong');

$stored_sha = '[SHA256]' . hash('sha256', 'legacy-dl');
expect_true(jirafeau_verify_download_password('legacy-dl', $stored_sha), 'legacy [SHA256] still verifies');
expect_true(!jirafeau_verify_download_password('nope', $stored_sha), 'legacy [SHA256] rejects wrong');

$stored_md5 = md5('very-old');
expect_true(jirafeau_verify_download_password('very-old', $stored_md5), 'legacy bare MD5 still verifies');

echo "== XSS escape ==\n";
expect_eq(
    jirafeau_escape('<script>alert(1)</script>'),
    '&lt;script&gt;alert(1)&lt;/script&gt;',
    'htmlspecialchars escapes script tags'
);

echo "== Async push rejects bad refs ==\n";
$err = jirafeau_async_push('../etc/passwd', array('error' => UPLOAD_ERR_OK, 'tmp_name' => ''), 'abcd', 0);
expect_true(strpos($err, 'Error:') === 0, 'async_push rejects path traversal ref');

echo "== One-time link claim ==\n";
$link_name = 'claimtest01';
$link_path = VAR_LINKS . s2p($link_name) . $link_name;
@mkdir(dirname($link_path), 0700, true);
file_put_contents($link_path, "name\nmime\n1\n\n-1\nhash\nO\n0\n\ncode\nO\n");
$first = jirafeau_try_claim_onetime_link($link_name);
expect_true($first !== false && is_file($first), 'first onetime claim succeeds');
expect_true(!is_file($link_path), 'original link removed after claim');
$second = jirafeau_try_claim_onetime_link($link_name);
expect_true($second === false, 'second onetime claim fails');
@unlink($first);

echo "== is_ssl proxy trust ==\n";
$_SERVER['HTTPS'] = 'off';
$_SERVER['SERVER_PORT'] = '80';
$_SERVER['REMOTE_ADDR'] = '1.2.3.4';
$_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https';
$cfg['proxy_ip'] = array();
expect_true(!is_ssl(), 'does not trust X-Forwarded-Proto without proxy_ip');
$cfg['proxy_ip'] = array('1.2.3.4');
expect_true(is_ssl(), 'trusts X-Forwarded-Proto from configured proxy');
unset($_SERVER['HTTPS'], $_SERVER['HTTP_X_FORWARDED_PROTO']);
$cfg['proxy_ip'] = array();

echo "== H-01 admin HTTP auth ignores PHP_AUTH_USER ==\n";
$cfg['admin_http_auth_user'] = array('alice');
$_SERVER['PHP_AUTH_USER'] = 'alice';
unset($_SERVER['REMOTE_USER'], $_SERVER['REDIRECT_REMOTE_USER']);
expect_true(!jirafeau_admin_http_auth_matches($cfg), 'PHP_AUTH_USER alone does not authenticate admin');
$_SERVER['HTTP_AUTHORIZATION'] = 'Basic ' . base64_encode('alice:x');
expect_true(!jirafeau_admin_http_auth_matches($cfg), 'Authorization header alone does not authenticate admin');
$_SERVER['REMOTE_USER'] = 'alice';
expect_true(jirafeau_admin_http_auth_matches($cfg), 'REMOTE_USER matching configured user authenticates');
$_SERVER['REMOTE_USER'] = 'bob';
expect_true(!jirafeau_admin_http_auth_matches($cfg), 'wrong REMOTE_USER rejected');
unset($_SERVER['PHP_AUTH_USER'], $_SERVER['HTTP_AUTHORIZATION'], $_SERVER['REMOTE_USER']);

echo "== H-11 non-blocking / atomic export ==\n";
$cfg_snapshot = array('installation_done' => true, 'admin_password' => 'x', 'title' => 'ro-test');
$is_windows = strncasecmp(PHP_OS, 'WIN', 3) === 0;
if (is_file(JIRAFEAU_CFG)) {
    $prev_cfg = file_get_contents(JIRAFEAU_CFG);
    $over = jirafeau_export_cfg(array('installation_done' => true, 'title' => 'no-truncate-fallback'), false);
    if ($over === false) {
        // Platforms where rename-over fails must keep the previous file untouched.
        expect_eq(file_get_contents(JIRAFEAU_CFG), $prev_cfg, 'failed atomic replace leaves previous config bytes unchanged');
        @unlink(JIRAFEAU_CFG);
    } else {
        expect_true(
            strpos(file_get_contents(JIRAFEAU_CFG), 'no-truncate-fallback') !== false,
            'atomic rename-over replaces config without truncate fallback'
        );
    }
}
$ok_write = jirafeau_export_cfg($cfg_snapshot, false);
if ($ok_write !== true && is_file(JIRAFEAU_CFG)) {
    // Target still occupied and rename-over unavailable: free the path then retry.
    @unlink(JIRAFEAU_CFG);
    $ok_write = jirafeau_export_cfg($cfg_snapshot, false);
}
expect_true($ok_write === true, 'export_cfg succeeds when atomic replace is possible or path is free');
expect_true(strpos(file_get_contents(JIRAFEAU_CFG), 'ro-test') !== false, 'exported title persisted');
if ($is_windows) {
    echo "[SKIP] concurrent export stress on Windows — optional\n";
} else {
    // Concurrent exports: last writer wins without corrupting PHP syntax.
    $export_worker = <<<'PHP'
<?php
define('JIRAFEAU_ROOT', getenv('JF_ROOT'));
define('JIRAFEAU_CFG', getenv('JF_CFG'));
define('NL', "\n");
require JIRAFEAU_ROOT . 'lib/functions.php';
$id = getenv('JF_ID');
jirafeau_export_cfg(array('installation_done' => true, 'title' => 'w' . $id), false);
PHP;
    $ew = $cfg['var_root'] . 'export_worker.php';
    file_put_contents($ew, $export_worker);
    $eprocs = array();
    for ($i = 0; $i < 4; $i++) {
        $desc = array(array('pipe', 'r'), array('pipe', 'w'), array('pipe', 'w'));
        $env = array('JF_ROOT' => JIRAFEAU_ROOT, 'JF_CFG' => JIRAFEAU_CFG, 'JF_ID' => (string) $i) + $_ENV;
        $eprocs[] = proc_open(PHP_BINARY . ' ' . escapeshellarg($ew), $desc, $pipes, null, $env);
        if (is_resource($eprocs[$i])) {
            fclose($pipes[0]);
            fclose($pipes[1]);
            fclose($pipes[2]);
        }
    }
    foreach ($eprocs as $p) {
        if (is_resource($p)) {
            proc_close($p);
        }
    }
    $exported = file_get_contents(JIRAFEAU_CFG);
    expect_true(strpos($exported, '<?php') === 0, 'concurrent export keeps PHP opening tag');
    expect_true(preg_match("/\\\$cfg = array/", $exported) === 1, 'concurrent export keeps valid \$cfg assignment');
}
// chmod-based "read-only dir" checks are unreliable as root (CI containers) and on Windows.
$running_as_root = function_exists('posix_geteuid') && posix_geteuid() === 0;
if ($is_windows || $running_as_root) {
    echo "[SKIP] read-only config directory chmod simulation — ineffective as root/Windows\n";
} else {
    $deny_dir = $cfg['var_root'] . 'deny-cfg';
    @mkdir($deny_dir, 0700, true);
    $deny_cfg = $deny_dir . DIRECTORY_SEPARATOR . 'config.local.php';
    file_put_contents($deny_cfg, "<?php\n\$cfg = array();\n");
    @chmod($deny_cfg, 0444);
    @chmod($deny_dir, 0555);
    $content = '<?php' . "\n" . '$cfg = array();';
    $tmp = $deny_cfg . '.tmp.test';
    $wrote = @file_put_contents($tmp, $content);
    expect_true($wrote === false, 'write into read-only config directory fails');
    @chmod($deny_dir, 0700);
    @chmod($deny_cfg, 0600);
}

echo "== H-13 IPv6 CIDR ==\n";
expect_true(jirafeau_ip_in_cidr('192.168.1.10', '192.168.1.0/24'), 'IPv4 CIDR match');
expect_true(!jirafeau_ip_in_cidr('192.168.2.10', '192.168.1.0/24'), 'IPv4 CIDR miss');
expect_true(jirafeau_ip_in_cidr('2001:db8::1', '2001:db8::/32'), 'IPv6 CIDR match');
expect_true(!jirafeau_ip_in_cidr('2001:db9::1', '2001:db8::/32'), 'IPv6 CIDR miss');
expect_true(jirafeau_challenge_ip(array('2001:db8::/32'), '2001:db8::abcd'), 'challenge_ip accepts IPv6 CIDR');
expect_true(!jirafeau_is_valid_ip('not-an-ip'), 'rejects invalid IP');
expect_true(!jirafeau_is_valid_ip('1.2.3'), 'rejects incomplete IPv4');

echo "== H-07 hashed upload passwords ==\n";
$plain_up = 'UploadSecret!';
$cfg['upload_password'] = array('[PASSWORD]' . password_hash($plain_up, PASSWORD_DEFAULT), 'legacy-plain');
expect_true(jirafeau_challenge_upload_password($cfg, $plain_up), 'hashed upload password verifies');
expect_true(jirafeau_challenge_upload_password($cfg, 'legacy-plain'), 'plaintext upload password still verifies');
expect_true(!jirafeau_challenge_upload_password($cfg, 'wrong'), 'rejects wrong upload password');

echo "== H-12 storage id validation ==\n";
expect_true(jirafeau_is_valid_storage_id(str_repeat('a', 32)), 'hex storage id ok');
expect_true(!jirafeau_is_valid_storage_id('../etc/passwd'), 'path traversal storage id rejected');
expect_true(!jirafeau_is_valid_storage_id(''), 'empty storage id rejected');

echo "== H-14 cross-site upload helper ==\n";
$cfg['web_root'] = 'http://localhost/';
$_SERVER['HTTP_ORIGIN'] = 'http://evil.example';
$_SERVER['HTTP_SEC_FETCH_SITE'] = 'cross-site';
expect_true(jirafeau_reject_browser_cross_site_upload($cfg), 'rejects cross-site Origin');
unset($_SERVER['HTTP_ORIGIN'], $_SERVER['HTTP_SEC_FETCH_SITE']);
expect_true(!jirafeau_reject_browser_cross_site_upload($cfg), 'allows non-browser (no Origin)');

echo "== H-04 crypt key / decrypt ==\n";
if (extension_loaded('sodium')) {
    if (!defined('JIRAFEAU_CRYPT_MAGIC_V1')) {
        define('JIRAFEAU_CRYPT_MAGIC_V1', 'JFCR1');
    }
    $plain = str_repeat('A', 3072);
    $src = $cfg['var_root'] . 'plain.bin';
    $enc = $cfg['var_root'] . 'enc.bin';
    $dec = $cfg['var_root'] . 'dec.bin';
    file_put_contents($src, $plain);
    $key = jirafeau_encrypt_file($src, $enc);
    expect_true(jirafeau_crypt_key_is_valid($key), 'generated key length valid');
    expect_true(strpos(file_get_contents($enc), JIRAFEAU_CRYPT_MAGIC_V1) === 0, 'v1 ciphertext starts with magic');
    expect_true(jirafeau_probe_decrypt_key($enc, $key), 'probe accepts good key');
    expect_true(!jirafeau_probe_decrypt_key($enc, str_repeat('0', 32)), 'probe rejects wrong key');
    expect_true(!jirafeau_crypt_key_is_valid('short'), 'malformed key rejected');
    expect_true(jirafeau_decrypt_file($enc, $dec, $key, true), 'decrypt good key with require_v1');
    expect_eq(file_get_contents($dec), $plain, 'decrypt restores plaintext');
    expect_true(!jirafeau_decrypt_file($enc, $dec . '.bad', str_repeat('1', 32), true), 'decrypt wrong key fails');
    expect_true(jirafeau_probe_decrypt_key($enc, $key, true), 'probe accepts v1 with require_v1');

    // Truncation after complete frames but before TAG_FINAL must fail for v1.
    $full_enc = file_get_contents($enc);
    expect_true(strlen($full_enc) > 2048, 'ciphertext larger than 2048 for truncation case');
    $trunc = $cfg['var_root'] . 'trunc.bin';
    file_put_contents($trunc, substr($full_enc, 0, 2048));
    expect_true(!jirafeau_decrypt_file($trunc, $dec . '.t', $key, true), 'truncated v1 ciphertext (2048/full) fails');
    file_put_contents($trunc, substr($full_enc, 0, 40));
    expect_true(!jirafeau_decrypt_file($trunc, $dec . '.t2', $key, true), 'short truncated ciphertext fails');

    $trail = $cfg['var_root'] . 'trail.bin';
    file_put_contents($trail, $full_enc . 'EXTRA');
    expect_true(!jirafeau_decrypt_file($trail, $dec . '.tr', $key, true), 'trailing bytes after v1 final are rejected');

    // Downgrade attack: strip JFCR1 + final frame must not succeed when C3/require_v1.
    $magic_len = strlen(JIRAFEAU_CRYPT_MAGIC_V1);
    $stripped = substr($full_enc, $magic_len, 2048);
    $down = $cfg['var_root'] . 'downgrade.bin';
    file_put_contents($down, $stripped);
    expect_true(!jirafeau_decrypt_file($down, $dec . '.dg', $key, true), 'C3 require_v1 rejects magic-stripped truncated blob');
    expect_true(!jirafeau_probe_decrypt_key($down, $key, true), 'C3 probe rejects magic-stripped blob');
    // Without require_v1 (C2), stripped truncated content must not be treated as success either when incomplete:
    // (may still accept complete legacy — only assert require_v1 path here.)

    $tampered = $cfg['var_root'] . 'tamp.bin';
    $blob = $full_enc;
    $blob[strlen($blob) - 5] = $blob[strlen($blob) - 5] === 'A' ? 'B' : 'A';
    file_put_contents($tampered, $blob);
    expect_true(!jirafeau_decrypt_file($tampered, $dec . '.x', $key), 'tampered ciphertext fails');

    // Legacy Sodium layout (no magic, no TAG_FINAL) still decrypts when complete.
    $legacy = $cfg['var_root'] . 'legacy.bin';
    $legacy_dec = $cfg['var_root'] . 'legacy.out';
    $legacy_key = bin2hex(random_bytes(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES / 2));
    [$st, $hdr] = sodium_crypto_secretstream_xchacha20poly1305_init_push($legacy_key);
    $lw = fopen($legacy, 'wb');
    fwrite($lw, $hdr);
    for ($i = 0; $i < strlen($plain); $i += JIRAFEAU_SODIUM_CHUNKSIZE) {
        $piece = substr($plain, $i, JIRAFEAU_SODIUM_CHUNKSIZE);
        fwrite($lw, sodium_crypto_secretstream_xchacha20poly1305_push($st, $piece));
    }
    fclose($lw);
    expect_true(jirafeau_decrypt_file($legacy, $legacy_dec, $legacy_key), 'legacy complete ciphertext still accepted');
    expect_eq(file_get_contents($legacy_dec), $plain, 'legacy decrypt restores plaintext');
    $legacy_trunc = $cfg['var_root'] . 'legacy-trunc.bin';
    file_put_contents($legacy_trunc, substr(file_get_contents($legacy), 0, 2048));
    // Legacy without FINAL cannot prove completeness; truncated-between-frames may still look "complete".
    // We only assert mid-frame truncation fails:
    $legacy_mid = $cfg['var_root'] . 'legacy-mid.bin';
    file_put_contents($legacy_mid, substr(file_get_contents($legacy), 0, 50));
    expect_true(!jirafeau_decrypt_file($legacy_mid, $dec . '.lm', $legacy_key), 'legacy mid-frame truncation fails');

    $ot = 'cryptot01';
    $ot_path = VAR_LINKS . s2p($ot) . $ot;
    @mkdir(dirname($ot_path), 0700, true);
    file_put_contents($ot_path, "n\nm\n1\n\n-1\nhash\nO\n0\n\ncode\nO\n");
    expect_true(!jirafeau_probe_decrypt_key($enc, 'badkeybadkeybadkeybadkeybadkeyba'), 'bad key probe fails before claim');
    expect_true(is_file($ot_path), 'onetime link still present when probe would fail');
    $claimed_ot = jirafeau_try_claim_onetime_link($ot);
    expect_true($claimed_ot !== false, 'claim works');
    expect_true(jirafeau_release_onetime_claim($claimed_ot, $ot), 'release restores link after failed decrypt path');
    expect_true(is_file($ot_path), 'link restored after release');
} else {
    echo "[SKIP] sodium extension not available — H-04 crypt tests not executed\n";
}

echo "== H-02 upload quota helpers ==\n";
$cfg['max_concurrent_async'] = 0;
$cfg['async_init_rate_per_minute'] = 0;
$cfg['max_storage_bytes'] = 0;
expect_true(jirafeau_upload_quota_check($cfg, '127.0.0.1') === true, 'unlimited quotas allow');
$cfg['max_concurrent_async'] = 1;
$aref = str_repeat('d', 32);
@mkdir(VAR_ASYNC . s2p($aref), 0755, true);
file_put_contents(VAR_ASYNC . s2p($aref) . $aref, "f\nm\n\n-1\nR\n\n" . time() . "\nabcd\n");
expect_true(jirafeau_count_async_transfers() >= 1, 'counts async transfer');
$q = jirafeau_upload_quota_check($cfg, '127.0.0.1');
expect_true(is_string($q) && strpos($q, 'Error:') === 0, 'blocks when concurrent async exceeded');
@unlink(VAR_ASYNC . s2p($aref) . $aref);
$cfg['max_concurrent_async'] = 0;

// Storage ceiling accounts for additional bytes (as async_push / classic commit do under lock).
@file_put_contents(VAR_FILES . 'quota-pad.bin', str_repeat('x', 80));
$cfg['max_storage_bytes'] = 100;
$qpad = jirafeau_upload_quota_check($cfg, null, 30);
expect_true(is_string($qpad) && strpos($qpad, 'storage quota') !== false, 'additional write beyond storage ceiling rejected');
expect_true(jirafeau_upload_quota_check($cfg, null, 5) === true, 'additional write within ceiling allowed');
// Classic commit path refuses oversized install under the same ceiling.
$big = $cfg['var_root'] . 'classic-big.bin';
file_put_contents($big, str_repeat('y', 50));
$hash_big = str_repeat('e', 32);
$cfg['max_storage_bytes'] = 100;
$commit_blocked = jirafeau_file_commit_payload($hash_big, $big, 'rename');
expect_true($commit_blocked === false, 'classic file_commit_payload blocked by storage quota');
expect_true(!is_file(VAR_FILES . s2p($hash_big) . $hash_big), 'payload not installed when over quota');
@unlink(VAR_FILES . 'quota-pad.bin');
@unlink($big);

// Async finalize: source already in VAR_ASYNC must not be double-counted.
$async_src = VAR_ASYNC . 'async-fin-600.bin';
file_put_contents($async_src, str_repeat('z', 600));
expect_true(jirafeau_path_in_storage_tree($async_src), 'async temp path is inside storage tree');
expect_eq(jirafeau_storage_install_delta($async_src, 600, 'rename'), 0, 'async rename install delta is zero');
$cfg['max_storage_bytes'] = 1000;
$hash_async = str_repeat('f', 32);
$commit_async = jirafeau_file_commit_payload($hash_async, $async_src, 'rename');
expect_true($commit_async !== false, 'async finalize allowed when 600-byte payload fits 1000-byte quota');
expect_true(is_file(VAR_FILES . s2p($hash_async) . $hash_async), 'async payload installed under quota');
expect_true(!is_file($async_src), 'async source consumed by rename');
// Clean installed payload for later tests.
jirafeau_file_refcount_adjust($hash_async, -1);
$cfg['max_storage_bytes'] = 0;

echo "== crypt_flag C3 vs C2 parsing ==\n";
$link_c3 = $cfg['var_root'] . 'link-c3';
file_put_contents($link_c3, "n\nm\n1\n\n-1\nhash\nO\n0\n\ncode\nC3\n");
$parsed_c3 = jirafeau_get_link_from_path($link_c3);
expect_true(!empty($parsed_c3['crypted']) && !empty($parsed_c3['crypt_v1']), 'C3 sets crypted + crypt_v1');
$link_c2 = $cfg['var_root'] . 'link-c2';
file_put_contents($link_c2, "n\nm\n1\n\n-1\nhash\nO\n0\n\ncode\nC2\n");
$parsed_c2 = jirafeau_get_link_from_path($link_c2);
expect_true(!empty($parsed_c2['crypted']) && empty($parsed_c2['crypt_v1']), 'C2 sets crypted without crypt_v1');

// Atomic slot reserve + init.
$cfg['max_concurrent_async'] = 1;
$cfg['async_init_rate_per_minute'] = 0;
jirafeau_async_slots_write_unlocked(0);
$init1 = jirafeau_async_init('a.bin', 'application/octet-stream', false, '', time() + 3600, '127.0.0.1');
expect_true(strpos($init1, 'Error:') !== 0, 'first async_init under slot ceiling succeeds');
$init2 = jirafeau_async_init('b.bin', 'application/octet-stream', false, '', time() + 3600, '127.0.0.1');
expect_true(strpos($init2, 'Error:') === 0, 'second async_init blocked by atomic slot ceiling');
$ref1 = strtok($init1, "\n");
if (jirafeau_is_valid_async_ref($ref1)) {
    jirafeau_async_delete($ref1);
}
$cfg['max_concurrent_async'] = 0;
jirafeau_async_slots_reconcile();

echo "== export_cfg keeps previous file on failure ==\n";
$marker = 'keep-me-' . bin2hex(random_bytes(4));
if (is_file(JIRAFEAU_CFG)) {
    @unlink(JIRAFEAU_CFG);
}
expect_true(
    jirafeau_export_cfg(array('installation_done' => true, 'title' => $marker), false) === true,
    'baseline config written on free path'
);
expect_true(strpos(file_get_contents(JIRAFEAU_CFG), $marker) !== false, 'baseline config written');
// Simulate lock held by another process: open lock and hold EX, child export must fail and keep file.
$lock_path = JIRAFEAU_CFG . '.lock';
$held = fopen($lock_path, 'c');
expect_true($held && flock($held, LOCK_EX), 'test holds config lock');
$child = <<<'PHP'
<?php
define('JIRAFEAU_ROOT', getenv('JF_ROOT'));
define('JIRAFEAU_CFG', getenv('JF_CFG'));
define('NL', "\n");
require JIRAFEAU_ROOT . 'lib/functions.php';
$ok = jirafeau_export_cfg(array('installation_done' => true, 'title' => 'should-not-appear'), false);
echo $ok ? "OK\n" : "FAIL\n";
PHP;
$child_file = $cfg['var_root'] . 'export_fail_child.php';
file_put_contents($child_file, $child);
$desc = array(array('pipe', 'r'), array('pipe', 'w'), array('pipe', 'w'));
$proc = proc_open(PHP_BINARY . ' ' . escapeshellarg($child_file), $desc, $pipes, null, array(
    'JF_ROOT' => JIRAFEAU_ROOT,
    'JF_CFG' => JIRAFEAU_CFG,
) + $_ENV);
$out = stream_get_contents($pipes[1]);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($proc);
flock($held, LOCK_UN);
fclose($held);
expect_true(trim($out) === 'FAIL', 'export without lock returns false');
expect_true(strpos(file_get_contents(JIRAFEAU_CFG), $marker) !== false, 'previous config retained when lock unavailable');
expect_true(strpos(file_get_contents(JIRAFEAU_CFG), 'should-not-appear') === false, 'failed export did not replace config');
expect_true(is_file(JIRAFEAU_CFG), 'live config path remains present after failed export');

echo "== Download password auth scope unified ==\n";
expect_eq(
    jirafeau_download_password_auth_scope('abc'),
    'download_password:abc',
    'web and API share download_password scope'
);

function jirafeau_test_rmdir($dir)
{
    if (!is_dir($dir)) {
        return;
    }
    foreach (scandir($dir) as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        $path = $dir . DIRECTORY_SEPARATOR . $item;
        is_dir($path) ? jirafeau_test_rmdir($path) : @unlink($path);
    }
    @rmdir($dir);
}
jirafeau_test_rmdir(rtrim($cfg['var_root'], '/\\'));

echo "\n$passed passed, $failures failed\n";
exit($failures === 0 ? 0 : 1);
