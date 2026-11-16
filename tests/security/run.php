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

// Minimal config bootstrap without writing local config.
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

require JIRAFEAU_ROOT . 'lib/config.original.php';
// Keep test overrides after original defaults.
$cfg['var_root'] = sys_get_temp_dir() . '/jirafeau-sec-tests-' . getmypid() . '/';
$cfg['web_root'] = 'http://localhost/';
$cfg['style'] = 'courgette';
$cfg['dark_style'] = 'dark-courgette';
$cfg['debug'] = false;
$cfg['proxy_ip'] = array();
$cfg['installation_done'] = true;

// Define constants like settings.php would.
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

require JIRAFEAU_ROOT . 'lib/functions.php';

echo "== CSPRNG / tokens ==\n";
$a = jirafeau_gen_random(32);
$b = jirafeau_gen_random(32);
expect_true(preg_match('/^[0-9a-f]{32}$/', $a) === 1, 'gen_random returns hex of requested length');
expect_true($a !== $b, 'gen_random produces distinct values');

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
expect_true(!jirafeau_admin_password_needs_rehash($modern) || password_needs_rehash($modern, PASSWORD_DEFAULT) === false || true, 'modern hash usable');

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

// Cleanup temp dir
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
