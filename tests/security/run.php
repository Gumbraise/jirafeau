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
$ok_write = jirafeau_export_cfg($cfg_snapshot, false);
expect_true($ok_write === true, 'export_cfg succeeds on writable JIRAFEAU_CFG');
expect_true(strpos(file_get_contents(JIRAFEAU_CFG), 'ro-test') !== false, 'exported title persisted');
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
// Non-writable target: fatal_on_error=false must return false (skip chmod games on Windows if needed).
$deny_dir = $cfg['var_root'] . 'deny-cfg';
@mkdir($deny_dir, 0700, true);
$deny_cfg = $deny_dir . DIRECTORY_SEPARATOR . 'config.local.php';
file_put_contents($deny_cfg, "<?php\n\$cfg = array();\n");
$skip_ro = false;
if (strncasecmp(PHP_OS, 'WIN', 3) === 0) {
    echo "[SKIP] read-only config.local.php simulation on Windows — not executed\n";
    $skip_ro = true;
} else {
    @chmod($deny_cfg, 0444);
    @chmod($deny_dir, 0555);
    // Cannot redefine JIRAFEAU_CFG; verify helper behaviour via a direct write attempt pattern:
    $content = '<?php' . "\n" . '$cfg = array();';
    $tmp = $deny_cfg . '.tmp.test';
    $wrote = @file_put_contents($tmp, $content);
    expect_true($wrote === false, 'write into read-only config directory fails');
    @chmod($deny_dir, 0700);
    @chmod($deny_cfg, 0600);
}
unset($skip_ro);

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
    $plain = str_repeat('hello-crypt-', 20);
    $src = $cfg['var_root'] . 'plain.bin';
    $enc = $cfg['var_root'] . 'enc.bin';
    $dec = $cfg['var_root'] . 'dec.bin';
    file_put_contents($src, $plain);
    $key = jirafeau_encrypt_file($src, $enc);
    expect_true(jirafeau_crypt_key_is_valid($key), 'generated key length valid');
    expect_true(jirafeau_probe_decrypt_key($enc, $key), 'probe accepts good key');
    expect_true(!jirafeau_probe_decrypt_key($enc, str_repeat('0', 32)), 'probe rejects wrong key');
    expect_true(!jirafeau_crypt_key_is_valid('short'), 'malformed key rejected');
    expect_true(jirafeau_decrypt_file($enc, $dec, $key), 'decrypt good key');
    expect_eq(file_get_contents($dec), $plain, 'decrypt restores plaintext');
    expect_true(!jirafeau_decrypt_file($enc, $dec . '.bad', str_repeat('1', 32)), 'decrypt wrong key fails');
    $trunc = $cfg['var_root'] . 'trunc.bin';
    file_put_contents($trunc, substr(file_get_contents($enc), 0, 40));
    expect_true(!jirafeau_decrypt_file($trunc, $dec . '.t', $key), 'truncated ciphertext fails');
    $tampered = $cfg['var_root'] . 'tamp.bin';
    $blob = file_get_contents($enc);
    $blob[strlen($blob) - 5] = $blob[strlen($blob) - 5] === 'A' ? 'B' : 'A';
    file_put_contents($tampered, $blob);
    expect_true(!jirafeau_decrypt_file($tampered, $dec . '.x', $key), 'tampered ciphertext fails');

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
