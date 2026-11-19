<?php

declare(strict_types=1);

/**
 * Copies vectors.json from the authz-spec repo into tests/fixtures and re-pins its sha256.
 *
 *   php scripts/sync-vectors.php [path-to-authz-spec]     (default: ../authz-spec or $AUTHZ_SPEC_DIR)
 *   php scripts/sync-vectors.php --check [path]           exit 1 if the fixture differs from the spec
 *
 * Never edit tests/fixtures/vectors.json by hand: change the spec, then sync.
 */

$args = array_slice($argv, 1);
$check = false;
if (isset($args[0]) && '--check' === $args[0]) {
    $check = true;
    array_shift($args);
}
$spec = $args[0] ?? getenv('AUTHZ_SPEC_DIR') ?: dirname(__DIR__) . '/../authz-spec';
$source = $spec . '/vectors.json';
$fixtures = dirname(__DIR__) . '/tests/fixtures';

if (!is_file($source)) {
    fwrite(STDERR, "vectors.json not found at $source\n");
    exit(2);
}
$content = (string) file_get_contents($source);
$hash = hash('sha256', $content);

if ($check) {
    $pin = json_decode((string) @file_get_contents($fixtures . '/vectors.pin.json'), true);
    $pinned = is_array($pin) && is_string($pin['sha256'] ?? null) ? $pin['sha256'] : '';
    if ($pinned !== $hash || (string) @file_get_contents($fixtures . '/vectors.json') !== $content) {
        fwrite(STDERR, "fixture differs from spec (spec sha256 $hash, pinned $pinned). Run: composer vectors:sync\n");
        exit(1);
    }
    echo "fixture matches spec ($hash)\n";
    exit(0);
}

file_put_contents($fixtures . '/vectors.json', $content);
$decoded = json_decode($content, true);
$version = is_array($decoded) && is_string($decoded['specVersion'] ?? null) ? $decoded['specVersion'] : null;
if (null === $version) {
    fwrite(STDERR, "vectors.json has no specVersion\n");
    exit(2);
}
file_put_contents(
    $fixtures . '/vectors.pin.json',
    json_encode(['sha256' => $hash, 'specVersion' => $version], JSON_PRETTY_PRINT) . "\n",
);
echo "synced $source -> tests/fixtures/vectors.json\nsha256 $hash specVersion $version\n";
