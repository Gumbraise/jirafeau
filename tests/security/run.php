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
