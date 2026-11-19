<?php

declare(strict_types=1);

namespace NoidOss\Authz\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Keeps the fixture a verbatim, pinned copy of the spec's vectors.json.
 * Nothing here skips: a missing or mismatching pin is a failure.
 * Drift against a live authz-spec checkout is checked by `composer vectors:check`.
 */
final class VectorsPinTest extends TestCase
{
    /**
     * @return array{sha256: string, specVersion: string}
     */
    private static function pin(): array
    {
        $raw = file_get_contents(__DIR__ . '/fixtures/vectors.pin.json');
        self::assertIsString($raw, 'tests/fixtures/vectors.pin.json is missing; run composer vectors:sync');
        $pin = json_decode($raw, true, 4, JSON_THROW_ON_ERROR);
        self::assertIsArray($pin);
        self::assertIsString($pin['sha256'] ?? null);
        self::assertIsString($pin['specVersion'] ?? null);

        return ['sha256' => $pin['sha256'], 'specVersion' => $pin['specVersion']];
    }

    public function testFixtureMatchesItsPin(): void
    {
        $fixture = file_get_contents(__DIR__ . '/fixtures/vectors.json');
        self::assertIsString($fixture, 'tests/fixtures/vectors.json is missing; run composer vectors:sync');

        self::assertSame(self::pin()['sha256'], hash('sha256', $fixture), 'fixture does not match its pin; run composer vectors:sync');
    }

    public function testFixtureSpecVersionMatchesPin(): void
    {
        $file = json_decode((string) file_get_contents(__DIR__ . '/fixtures/vectors.json'), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($file);

        self::assertSame(self::pin()['specVersion'], $file['specVersion'] ?? null);
    }
}
