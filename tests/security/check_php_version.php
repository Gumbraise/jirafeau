<?php
/**
 * Ensure the running PHP engine is at least the first patched release for
 * CVE-2026-109618 / CVE-2026-109619 (PHP2Shell).
 *
 * Usage: php tests/security/check_php_version.php
 * Exit 0 on success, 1 on failure.
 */

$minimums = array(
    '8.2' => '8.2.35',
    '8.3' => '8.3.36',
    '8.4' => '8.4.27',
    '8.5' => '8.5.12',
);

$version = PHP_VERSION;
$id = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;

echo "PHP_VERSION=$version\n";

if (!isset($minimums[$id])) {
    fwrite(STDERR, "Unsupported or unlisted PHP branch $id (running $version).\n");
    fwrite(STDERR, "Expected one of: " . implode(', ', array_keys($minimums)) . "\n");
    exit(1);
}

$min = $minimums[$id];
if (version_compare($version, $min, '<')) {
    fwrite(
        STDERR,
        "FAIL: PHP $version is older than required $min for branch $id "
        . "(CVE-2026-109618 / CVE-2026-109619).\n"
    );
    exit(1);
}

echo "OK: PHP $version meets minimum $min for branch $id\n";
exit(0);
