<?php
/**
 * Concurrency / throttle / claimed-orphan behaviour tests.
 * Run: php tests/security/concurrency_run.php
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

$var_root = sys_get_temp_dir() . '/jirafeau-conc-' . getmypid() . '/';
@mkdir($var_root . 'files/', 0700, true);
@mkdir($var_root . 'links/', 0700, true);
@mkdir($var_root . 'async/', 0700, true);

$cfg = array(
    'web_root' => 'http://127.0.0.1/',
    'var_root' => $var_root,
    'proxy_ip' => array('10.0.0.1'),
    'installation_done' => true,
    'debug' => false,
);

require JIRAFEAU_ROOT . 'lib/config.original.php';
$cfg['var_root'] = $var_root;
$cfg['proxy_ip'] = array('10.0.0.1');
$cfg['installation_done'] = true;
$cfg['debug'] = false;

if (!defined('VAR_FILES')) {
    define('VAR_FILES', $var_root . 'files/');
    define('VAR_LINKS', $var_root . 'links/');
    define('VAR_ASYNC', $var_root . 'async/');
}
if (!defined('NL')) {
    define('NL', "\n");
}
if (!defined('JIRAFEAU_INFINITY')) {
    define('JIRAFEAU_INFINITY', -1);
}
if (!defined('JIRAFEAU_CFG')) {
    define('JIRAFEAU_CFG', $var_root . 'config.local.php');
}

require JIRAFEAU_ROOT . 'lib/functions.php';

echo "== File refcount locking ==\n";
$hash = str_repeat('a', 32);
expect_eq(jirafeau_file_refcount_adjust($hash, 1), 1, 'refcount starts at 1');
expect_eq(jirafeau_file_refcount_adjust($hash, 1), 2, 'refcount increments under lock');
expect_eq(jirafeau_file_refcount_adjust($hash, -1), 1, 'refcount decrements under lock');

$worker = <<<'PHP'
<?php
define('JIRAFEAU_ROOT', getenv('JF_ROOT'));
$var_root = getenv('JF_VAR');
define('VAR_FILES', $var_root . 'files/');
define('VAR_LINKS', $var_root . 'links/');
define('VAR_ASYNC', $var_root . 'async/');
define('NL', "\n");
require JIRAFEAU_ROOT . 'lib/functions.php';
$hash = getenv('JF_HASH');
for ($i = 0; $i < 20; $i++) {
    jirafeau_file_refcount_adjust($hash, 1);
}
PHP;
$worker_file = $var_root . 'worker.php';
file_put_contents($worker_file, $worker);
$env = array(
    'JF_ROOT' => JIRAFEAU_ROOT,
    'JF_VAR' => $var_root,
    'JF_HASH' => $hash,
);
$procs = array();
for ($i = 0; $i < 4; $i++) {
    $desc = array(array('pipe', 'r'), array('pipe', 'w'), array('pipe', 'w'));
    $procs[] = proc_open(PHP_BINARY . ' ' . escapeshellarg($worker_file), $desc, $pipes, null, $env + $_ENV);
    if (is_resource($procs[$i])) {
        fclose($pipes[0]);
        fclose($pipes[1]);
        fclose($pipes[2]);
    }
}
foreach ($procs as $proc) {
    if (is_resource($proc)) {
        proc_close($proc);
    }
}
$count_file = VAR_FILES . s2p($hash) . $hash . '_count';
$final = is_file($count_file) ? (int) trim(file_get_contents($count_file)) : -1;
expect_eq($final, 1 + 80, 'parallel refcount increments stay consistent (1 + 4*20)');

echo "== Async shared lock ==\n";
$ref = str_repeat('b', 32);
@mkdir(VAR_ASYNC . s2p($ref), 0755, true);
file_put_contents(VAR_ASYNC . s2p($ref) . $ref, "f\nm\n\n-1\nR\n\n" . time() . "\nabcd\n");
file_put_contents(VAR_ASYNC . s2p($ref) . $ref . '_data', 'x');
$lock = jirafeau_async_acquire_lock($ref);
expect_true($lock !== false, 'async lock acquired');
$lock2_path = jirafeau_async_lock_path($ref);
$lock2 = @fopen($lock2_path, 'c');
$got_nb = $lock2 && flock($lock2, LOCK_EX | LOCK_NB);
expect_true($got_nb === false, 'second async lock is blocked while held');
if ($lock2) {
    fclose($lock2);
}
jirafeau_async_delete($ref, $lock);
jirafeau_async_release_lock($lock);
@unlink($lock2_path);
expect_true(!file_exists(VAR_ASYNC . s2p($ref) . $ref), 'async meta removed under held lock');

echo "== Claim mtime + single finalization ==\n";
$shared_hash = str_repeat('c', 32);
@mkdir(VAR_FILES . s2p($shared_hash), 0700, true);
file_put_contents(VAR_FILES . s2p($shared_hash) . $shared_hash, 'shared-payload');
jirafeau_file_refcount_adjust($shared_hash, 1); // -> 1
jirafeau_file_refcount_adjust($shared_hash, 1); // -> 2 (second logical link)

$link_name = 'orphanclaim1';
$link_path = VAR_LINKS . s2p($link_name) . $link_name;
@mkdir(dirname($link_path), 0700, true);
$link_body = "name\nmime\n7\n\n-1\n{$shared_hash}\nO\n0\n\ncode\nO\n";
file_put_contents($link_path, $link_body);
// Simulate an old link; claim must refresh mtime so cleaners do not reap an active download.
touch($link_path, time() - 90000);
$claimed = jirafeau_try_claim_onetime_link($link_name);
expect_true($claimed !== false, 'claim creates claimed file');
$claim_mtime = @filemtime($claimed);
expect_true($claim_mtime !== false && (time() - $claim_mtime) < 60, 'claim stamps current mtime');
jirafeau_admin_clean();
expect_true(is_file($claimed), 'fresh claim is not cleaned immediately despite old original link age');

$link_meta = jirafeau_get_link_from_path($claimed);
$first_fin = jirafeau_finalize_onetime_claim($claimed, $link_meta);
$second_fin = jirafeau_finalize_onetime_claim($claimed, $link_meta);
expect_true($first_fin === true, 'first finalize wins');
expect_true($second_fin === false, 'second finalize is a no-op');
$count_after = (int) trim(@file_get_contents(VAR_FILES . s2p($shared_hash) . $shared_hash . '_count'));
expect_eq($count_after, 1, 'double finalize does not drop shared refcount below remaining links');
expect_true(is_file(VAR_FILES . s2p($shared_hash) . $shared_hash), 'shared payload survives single finalization');

// Stale claim cleanup still works when mtime is aged after claim.
$link_name2 = 'orphanclaim2';
$link_path2 = VAR_LINKS . s2p($link_name2) . $link_name2;
@mkdir(dirname($link_path2), 0700, true);
file_put_contents($link_path2, "name\nmime\n7\n\n-1\n{$shared_hash}\nO\n0\n\ncode\nO\n");
jirafeau_file_refcount_adjust($shared_hash, 1); // -> 2 again
$claimed2 = jirafeau_try_claim_onetime_link($link_name2);
touch($claimed2, time() - 90000);
$cleaned = jirafeau_admin_clean();
expect_true($cleaned >= 1, 'admin_clean recovers stale claimed orphans');
expect_true(!file_exists($claimed2), 'stale claimed orphan removed');

echo "== Invented async ref creates no disk artifacts ==\n";
$fake = str_repeat('d', 32);
$before = jirafeau_dir_size(VAR_ASYNC);
$err = jirafeau_async_push($fake, array('error' => UPLOAD_ERR_OK, 'tmp_name' => ''), 'dead', 0);
expect_true(strpos($err, 'cannot find transfer') !== false, 'push rejects unknown transfer');
expect_true(!is_file(jirafeau_async_meta_path($fake)), 'no meta created for invented ref');
expect_true(!is_file(jirafeau_async_lock_path($fake)), 'no lock created for invented ref');
expect_true(!is_dir(VAR_ASYNC . s2p($fake)), 'no directory created for invented async ref');
$lock_try = jirafeau_async_acquire_lock($fake);
expect_true($lock_try === false, 'acquire_lock refuses unknown transfer');

echo "== Refcount zero deletes payload under lock ==\n";
$alone = str_repeat('e', 32);
@mkdir(VAR_FILES . s2p($alone), 0700, true);
$payload_alone = VAR_FILES . s2p($alone) . $alone;
file_put_contents($payload_alone, 'alone');
jirafeau_file_refcount_adjust($alone, 1);
expect_true(is_file($payload_alone), 'payload exists at refcount 1');
jirafeau_file_refcount_adjust($alone, -1);
expect_true(!is_file($payload_alone), 'payload removed when refcount hits zero');
expect_true(!is_file($payload_alone . '_count'), 'count file removed at zero');

echo "== Auth throttle (no sleep, block before verify) ==\n";
$_SERVER['REMOTE_ADDR'] = '10.0.0.1';
$_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https';
$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.50';
expect_eq(jirafeau_auth_client_key($cfg), '203.0.113.50', 'throttle key uses trusted proxy client IP');
$scope = 'test_login';
jirafeau_auth_clear_failures($scope, $cfg);
expect_true(!jirafeau_auth_is_blocked($scope, $cfg, 3, 60), 'not blocked initially');
for ($i = 0; $i < 3; $i++) {
    jirafeau_auth_register_failure($scope, $cfg, 3, 60);
}
expect_true(jirafeau_auth_is_blocked($scope, $cfg, 3, 60), 'blocked after max failures without sleeping');
jirafeau_auth_clear_failures($scope, $cfg);
expect_true(!jirafeau_auth_is_blocked($scope, $cfg, 3, 60), 'cleared after success');

echo "== Compose passes restriction env keys ==\n";
$compose = file_get_contents(JIRAFEAU_ROOT . 'docker-compose.yaml');
expect_true(strpos($compose, 'ADMIN_IP:') !== false, 'docker-compose transmits ADMIN_IP');
expect_true(strpos($compose, 'UPLOAD_PASSWORD:') !== false, 'docker-compose transmits UPLOAD_PASSWORD');

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
jirafeau_test_rmdir(rtrim($var_root, '/\\'));

echo "\n$passed passed, $failures failed\n";
exit($failures === 0 ? 0 : 1);

function expect_eq($actual, $expected, $message)
{
    expect_true($actual === $expected, $message . ' (got ' . var_export($actual, true) . ')');
}
