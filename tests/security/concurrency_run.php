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
expect_true(!is_file(jirafeau_file_count_path($alone)), 'count file removed at zero');
expect_true(is_file(jirafeau_file_lock_path($alone)), 'stable lock file kept after counter hits zero');

echo "== Upload/delete interleave cannot create counter without file ==\n";
$race = str_repeat('f', 32);
$race_payload = VAR_FILES . s2p($race) . $race;
@mkdir(dirname($race_payload), 0700, true);
file_put_contents($race_payload, 'original');
jirafeau_file_refcount_adjust($race, 1);
$src = $var_root . 'upload-src.bin';
file_put_contents($src, 'replacement-not-used-on-dedup');
// Simulate delete winning first under the same locking API used in production.
jirafeau_file_refcount_adjust($race, -1);
expect_true(!is_file($race_payload), 'delete removed payload');
expect_true(is_file(jirafeau_file_lock_path($race)), 'lock survives delete-to-zero');
// Concurrent-style commit must reinstall payload before incrementing.
$new_count = jirafeau_file_commit_payload($race, $src, 'rename');
expect_eq($new_count, 1, 'commit after delete restores refcount to 1');
expect_true(is_file($race_payload), 'commit after delete restores payload');
expect_true(!is_file($src), 'source consumed or removed');

// Opposite order: commit while file exists (dedup), then ensure payload remains.
$src2 = $var_root . 'upload-src2.bin';
file_put_contents($src2, 'dedup-src');
expect_eq(jirafeau_file_commit_payload($race, $src2, 'rename'), 2, 'dedup commit increments');
expect_true(is_file($race_payload), 'dedup keeps existing payload');
expect_true(!is_file($src2), 'dedup drops spare source');

echo "== Real concurrent delete vs upload at counter zero ==\n";
$cz = str_repeat('7', 32);
$cz_payload = VAR_FILES . s2p($cz) . $cz;
$deleter = <<<'PHP'
<?php
define('JIRAFEAU_ROOT', getenv('JF_ROOT'));
$var_root = getenv('JF_VAR');
define('VAR_FILES', $var_root . 'files/');
define('VAR_LINKS', $var_root . 'links/');
define('VAR_ASYNC', $var_root . 'async/');
define('NL', "\n");
require JIRAFEAU_ROOT . 'lib/functions.php';
$hash = getenv('JF_HASH');
$gate = getenv('JF_GATE');
while (!is_file($gate)) {
    usleep(1000);
}
jirafeau_file_refcount_adjust($hash, -1);
PHP;
$uploader = <<<'PHP'
<?php
define('JIRAFEAU_ROOT', getenv('JF_ROOT'));
$var_root = getenv('JF_VAR');
define('VAR_FILES', $var_root . 'files/');
define('VAR_LINKS', $var_root . 'links/');
define('VAR_ASYNC', $var_root . 'async/');
define('NL', "\n");
require JIRAFEAU_ROOT . 'lib/functions.php';
$hash = getenv('JF_HASH');
$gate = getenv('JF_GATE');
$src = getenv('JF_SRC');
while (!is_file($gate)) {
    usleep(1000);
}
file_put_contents($src, 'concurrent-upload-' . getmypid());
$n = jirafeau_file_commit_payload($hash, $src, 'rename');
file_put_contents(getenv('JF_OUT'), (string) $n);
PHP;
$deleter_file = $var_root . 'deleter.php';
$uploader_file = $var_root . 'uploader.php';
file_put_contents($deleter_file, $deleter);
file_put_contents($uploader_file, $uploader);
$cz_ok = true;
for ($round = 0; $round < 40; $round++) {
    @mkdir(dirname($cz_payload), 0700, true);
    file_put_contents($cz_payload, 'seed-' . $round);
    // Ensure clean counter via locked adjust.
    $fpz = jirafeau_file_refcount_lock($cz);
    if ($fpz) {
        jirafeau_file_refcount_write_unlocked($cz, 1);
        flock($fpz, LOCK_UN);
        fclose($fpz);
    }
    $gate = $var_root . 'gate-' . $round;
    $src_r = $var_root . 'cz-src-' . $round . '.bin';
    $out_r = $var_root . 'cz-out-' . $round . '.txt';
    @unlink($gate);
    @unlink($src_r);
    @unlink($out_r);
    $env_r = array(
        'JF_ROOT' => JIRAFEAU_ROOT,
        'JF_VAR' => $var_root,
        'JF_HASH' => $cz,
        'JF_GATE' => $gate,
        'JF_SRC' => $src_r,
        'JF_OUT' => $out_r,
    ) + $_ENV;
    $desc = array(array('pipe', 'r'), array('pipe', 'w'), array('pipe', 'w'));
    $p_del = proc_open(PHP_BINARY . ' ' . escapeshellarg($deleter_file), $desc, $pipes_d, null, $env_r);
    foreach ($pipes_d as $p) {
        if (is_resource($p)) {
            fclose($p);
        }
    }
    $p_up = proc_open(PHP_BINARY . ' ' . escapeshellarg($uploader_file), $desc, $pipes_u, null, $env_r);
    foreach ($pipes_u as $p) {
        if (is_resource($p)) {
            fclose($p);
        }
    }
    // Release both workers together so they race at counter zero.
    file_put_contents($gate, 'go');
    if (is_resource($p_del)) {
        proc_close($p_del);
    }
    if (is_resource($p_up)) {
        proc_close($p_up);
    }
    $cnt_path = jirafeau_file_count_path($cz);
    $cnt = is_file($cnt_path) ? (int) trim(file_get_contents($cnt_path)) : 0;
    $has_file = is_file($cz_payload);
    $has_lock = is_file(jirafeau_file_lock_path($cz));
    // Both orderings end at count=1 with payload; never counter without file.
    if (!($cnt === 1 && $has_file && $has_lock)) {
        $cz_ok = false;
        echo "[FAIL detail] round $round count=$cnt file=" . ($has_file ? '1' : '0') . " lock=" . ($has_lock ? '1' : '0') . "\n";
        break;
    }
}
expect_true($cz_ok, '40 concurrent delete/upload races keep count=1, payload, and stable lock');

echo "== Finalize crash markers are idempotent ==\n";
$fin_hash = str_repeat('1', 32);
@mkdir(VAR_FILES . s2p($fin_hash), 0700, true);
file_put_contents(VAR_FILES . s2p($fin_hash) . $fin_hash, 'keep-me');
jirafeau_file_refcount_adjust($fin_hash, 1);
jirafeau_file_refcount_adjust($fin_hash, 1); // shared: 2
$claim_base = VAR_LINKS . s2p('finishcrash') . 'finishcrash';
@mkdir(dirname($claim_base), 0700, true);
$link_meta = array('hash' => $fin_hash);

// Crash window A: .done exists and decrement already applied once.
$finishing = $claim_base . '.claimed-aabbccdd.finishing-dead';
file_put_contents($finishing, "name\nmime\n7\n\n-1\n{$fin_hash}\nO\n0\n\ncode\nO\n");
$done = $finishing . '.done';
rename($finishing, $done);
jirafeau_file_refcount_adjust($fin_hash, -1); // real decrement -> 1
$again = jirafeau_finalize_onetime_claim($done, $link_meta);
expect_true($again === false, 'resume on .done does not finalize again');
$count_fin = (int) trim(@file_get_contents(VAR_FILES . s2p($fin_hash) . $fin_hash . '_count'));
expect_eq($count_fin, 1, 'post-decrement .done resume does not double-decrement');
expect_true(is_file(VAR_FILES . s2p($fin_hash) . $fin_hash), 'shared payload retained after .done resume');

// Crash window B: finishing→done happened, decrement never ran (safe leak).
@mkdir(dirname($claim_base), 0700, true);
$finishing3 = $claim_base . '.claimed-ccddeeff.finishing-cafe';
file_put_contents($finishing3, "name\nmime\n7\n\n-1\n{$fin_hash}\nO\n0\n\ncode\nO\n");
$done3 = $finishing3 . '.done';
rename($finishing3, $done3);
$resume = jirafeau_finalize_onetime_claim($done3, $link_meta);
expect_true($resume === false, 'done-before-decrement marker skips decrement');
$count_fin3 = (int) trim(@file_get_contents(VAR_FILES . s2p($fin_hash) . $fin_hash . '_count'));
expect_eq($count_fin3, 1, 'done-before-decrement keeps existing count (safe leak)');
expect_true(is_file(VAR_FILES . s2p($fin_hash) . $fin_hash), 'payload kept on done-before-decrement crash');

// Normal finishing (no .done yet) still decrements exactly once.
@mkdir(dirname($claim_base), 0700, true);
$finishing2 = $claim_base . '.claimed-bbccddee.finishing-beef';
file_put_contents($finishing2, "name\nmime\n7\n\n-1\n{$fin_hash}\nO\n0\n\ncode\nO\n");
$one = jirafeau_finalize_onetime_claim($finishing2, $link_meta);
expect_true($one === true, 'finalize of finishing performs single decrement');
$count_fin2 = @file_get_contents(VAR_FILES . s2p($fin_hash) . $fin_hash . '_count');
expect_true($count_fin2 === false || trim((string) $count_fin2) === '' || (int) trim($count_fin2) === 0, 'last finalize reaches zero refs');

echo "== In-flight upload: admin_clean must not delete pre-link payload ==\n";
$inflight = str_repeat('6', 32);
$inflight_payload = VAR_FILES . s2p($inflight) . $inflight;
$inflight_src = $var_root . 'inflight-src.bin';
file_put_contents($inflight_src, 'upload-before-link');
expect_eq(jirafeau_file_commit_payload($inflight, $inflight_src, 'rename'), 1, 'upload committed payload before link publish');
expect_true(is_file($inflight_payload), 'payload exists after commit');
expect_true(!is_file(VAR_LINKS . s2p('inflightlink') . 'inflightlink'), 'link not published yet');
jirafeau_admin_clean();
expect_true(is_file($inflight_payload), 'admin_clean keeps in-flight payload with no link yet');
expect_eq(
    (int) trim(@file_get_contents(jirafeau_file_count_path($inflight))),
    1,
    'admin_clean does not zero in-flight refcount'
);
// Document why reconcile stays offline-only: same window would destroy the file.
$would_fix = jirafeau_admin_reconcile_file_refcounts();
expect_true($would_fix >= 1, 'offline reconcile would treat pre-link upload as orphan');
expect_true(!is_file($inflight_payload), 'reconcile deletes payload when no link exists yet');
// Publish link after reconcile → broken share (link without file).
$late_link = 'inflightlink';
$late_path = VAR_LINKS . s2p($late_link) . $late_link;
@mkdir(dirname($late_path), 0700, true);
file_put_contents($late_path, "name\nmime\n7\n\n-1\n{$inflight}\nO\n0\n\ncode\nO\n");
expect_true(is_file($late_path), 'link published after reconcile');
expect_true(!is_file($inflight_payload), 'link exists but payload already gone (unsafe online reconcile)');

echo "== Orphan refcount reconcile (quiescent / offline only) ==\n";
$orph = str_repeat('8', 32);
@mkdir(VAR_FILES . s2p($orph), 0700, true);
file_put_contents(VAR_FILES . s2p($orph) . $orph, 'leaked-payload');
jirafeau_file_refcount_adjust($orph, 1);
jirafeau_file_refcount_adjust($orph, 1); // pretend crash skipped one decrement → 2
// Only one live link remains.
$orph_link = 'orphlive1';
$orph_path = VAR_LINKS . s2p($orph_link) . $orph_link;
@mkdir(dirname($orph_path), 0700, true);
file_put_contents($orph_path, "name\nmime\n7\n\n-1\n{$orph}\nO\n0\n\ncode\nO\n");
$fixed = jirafeau_admin_reconcile_file_refcounts();
expect_true($fixed >= 1, 'quiescent reconcile trims leaked refcount');
$orph_count = (int) trim(@file_get_contents(jirafeau_file_count_path($orph)));
expect_eq($orph_count, 1, 'quiescent reconcile aligns counter to live links');
expect_true(is_file(VAR_FILES . s2p($orph) . $orph), 'payload kept when a live link remains');
// Zero live links → payload removed.
@unlink($orph_path);
$fixed2 = jirafeau_admin_reconcile_file_refcounts();
expect_true($fixed2 >= 1, 'quiescent reconcile removes fully orphaned payload');
expect_true(!is_file(VAR_FILES . s2p($orph) . $orph), 'orphan payload deleted at zero live refs');
expect_true(!is_file(jirafeau_file_count_path($orph)), 'orphan count removed');
expect_true(is_file(jirafeau_file_lock_path($orph)), 'stable lock retained after orphan cleanup');

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

echo "== Atomic begin_attempt under parallel workers ==\n";
$scope2 = 'parallel_login';
jirafeau_auth_clear_failures($scope2, $cfg);
$auth_worker = <<<'PHP'
<?php
define('JIRAFEAU_ROOT', getenv('JF_ROOT'));
$var_root = getenv('JF_VAR');
define('VAR_FILES', $var_root . 'files/');
define('VAR_LINKS', $var_root . 'links/');
define('VAR_ASYNC', $var_root . 'async/');
define('NL', "\n");
require JIRAFEAU_ROOT . 'lib/functions.php';
$cfg = array('proxy_ip' => array());
$_SERVER['REMOTE_ADDR'] = getenv('JF_IP');
$scope = getenv('JF_SCOPE');
$max = (int) getenv('JF_MAX');
$r = jirafeau_auth_begin_attempt($scope, $cfg, $max, 120, 900);
file_put_contents(getenv('JF_OUT') . '/' . getmypid() . '.json', json_encode($r));
PHP;
$auth_worker_file = $var_root . 'auth_worker.php';
file_put_contents($auth_worker_file, $auth_worker);
$out_dir = $var_root . 'auth_out/';
@mkdir($out_dir, 0700, true);
$max_att = 5;
$auth_env = array(
    'JF_ROOT' => JIRAFEAU_ROOT,
    'JF_VAR' => $var_root,
    'JF_IP' => '198.51.100.10',
    'JF_SCOPE' => $scope2,
    'JF_MAX' => (string) $max_att,
    'JF_OUT' => $out_dir,
);
$auth_procs = array();
$parallel = 12;
for ($i = 0; $i < $parallel; $i++) {
    $desc = array(array('pipe', 'r'), array('pipe', 'w'), array('pipe', 'w'));
    $auth_procs[] = proc_open(PHP_BINARY . ' ' . escapeshellarg($auth_worker_file), $desc, $pipes, null, $auth_env + $_ENV);
    if (is_resource($auth_procs[$i])) {
        fclose($pipes[0]);
        fclose($pipes[1]);
        fclose($pipes[2]);
    }
}
foreach ($auth_procs as $proc) {
    if (is_resource($proc)) {
        proc_close($proc);
    }
}
$allowed = 0;
$blocked = 0;
foreach (glob($out_dir . '*.json') ?: array() as $f) {
    $r = json_decode(file_get_contents($f), true);
    if (!empty($r['allowed'])) {
        $allowed++;
    } else {
        $blocked++;
    }
}
expect_true($allowed === $max_att, 'exactly max_attempts parallel begin_attempt allowed (got ' . $allowed . ')');
expect_true($blocked === ($parallel - $max_att), 'remaining parallel attempts blocked (got ' . $blocked . ')');
$_SERVER['REMOTE_ADDR'] = '198.51.100.10';
unset($_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_X_FORWARDED_PROTO']);
$cfg['proxy_ip'] = array();
expect_true(jirafeau_auth_is_blocked($scope2, $cfg, $max_att, 120), 'blocked for client after concurrent reservations');
jirafeau_auth_clear_failures($scope2, $cfg);

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
