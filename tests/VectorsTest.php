<?php

declare(strict_types=1);

namespace AuthZ\Tests;

use AuthZ\Config;
use AuthZ\Grammar;
use AuthZ\Manifest;
use AuthZ\Perms;
use AuthZ\Tests\Support\StubChecker;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Runs every case of tests/fixtures/vectors.json (a pinned copy of authz-spec/vectors.json).
 * Conformance rule: feed config (file default merged with the vector's), manifest, claims, request
 * and a stub driven by liveCheck; compare allowed, reason and the ordered live calls
 * (permission and object; keto_object is for service implementers).
 */
final class VectorsTest extends TestCase
{
    /**
     * @return array<string, array{array<string, mixed>, array<string, mixed>}>
     */
    public static function vectors(): array
    {
        $file = json_decode((string) file_get_contents(__DIR__ . '/fixtures/vectors.json'), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($file);
        self::assertSame(2, $file['version']);
        self::assertIsArray($file['config']);
        self::assertIsArray($file['vectors']);
        $cases = [];
        foreach ($file['vectors'] as $i => $vector) {
            self::assertIsArray($vector);
            self::assertIsString($vector['name']);
            $cases[sprintf('#%d %s', (int) $i, $vector['name'])] = [$file['config'], $vector];
        }
        self::assertGreaterThan(0, count($cases));

        return $cases;
    }

    /**
     * @param array<string, mixed> $defaults
     * @param array<string, mixed> $vector
     */
    #[DataProvider('vectors')]
    public function testVector(array $defaults, array $vector): void
    {
        $override = $vector['config'] ?? [];
        self::assertIsArray($override);
        $config = array_merge($defaults, $override);
        foreach (['brand', 'app', 'issuer', 'tenant_id'] as $field) {
            self::assertIsString($config[$field] ?? null, $field);
        }
        self::assertIsInt($config['now'] ?? null);
        $now = $config['now'];
        /** @var array{reads: list<string>, resources?: array<mixed>} $manifest */
        $manifest = $vector['manifest'];
        /** @var array<string, mixed> $claims */
        $claims = $vector['claims'];
        /** @var array{permission: string, object?: array{type: mixed, id: mixed}} $request */
        $request = $vector['request'];
        /** @var array{role?: string, object?: string} $liveCheck */
        $liveCheck = $vector['liveCheck'];
        /** @var array{allowed: bool, reason: string, liveCalls: list<array{permission: string, object?: array<string, mixed>}>} $expect */
        $expect = $vector['expect'];

        try {
            $sdkConfig = new Config($config['brand'], $config['app'], $config['issuer'], $config['tenant_id']);
        } catch (\InvalidArgumentException) {
            // The SDK refuses an invalid brand/app at construction: no Perms, hence no call, can exist.
            self::assertSame('invalid_config', $expect['reason']);
            self::assertFalse($expect['allowed']);
            self::assertSame([], $expect['liveCalls']);

            return;
        }
        self::assertNotSame('invalid_config', $expect['reason'], 'Config accepted a value the spec rejects');

        $checker = new StubChecker($liveCheck);
        $perms = new Perms(
            $sdkConfig,
            new Manifest($manifest['reads'], $manifest['resources'] ?? null),
            $checker,
            static fn(): int => $now,
        );

        $decision = $perms->explain($claims, $request['permission'], $request['object'] ?? null);

        self::assertSame($expect['allowed'], $decision->allowed, 'allowed');
        self::assertSame($expect['reason'], $decision->reason->value, 'reason');
        self::assertSame($expect['allowed'], $perms->can($claims, $request['permission'], $request['object'] ?? null), 'can() agrees with explain()');

        // Ordered live calls: permission and object only.
        $expectedCalls = array_map(
            static fn(array $call): array => array_filter(
                ['permission' => $call['permission'], 'object' => $call['object'] ?? null],
                static fn(mixed $v): bool => null !== $v,
            ),
            $expect['liveCalls'],
        );
        self::assertSame($expectedCalls, $decision->liveCalls, 'decision liveCalls');
        $sent = array_map(
            static fn(array $r): array => array_filter(
                ['permission' => $r['permission'], 'object' => $r['object'] ?? null],
                static fn(mixed $v): bool => null !== $v,
            ),
            // can() above ran the algorithm a second time: only compare the first run.
            array_slice($checker->requests, 0, count($expectedCalls)),
        );
        self::assertSame($expectedCalls, $sent, 'calls received by the live service');
        self::assertCount(2 * count($expectedCalls), $checker->requests, 'no extra live calls');

        // The subject of every live call is the token `sub`, never the caller's.
        foreach ($checker->requests as $r) {
            self::assertSame($claims['sub'], $r['subject']);
        }
    }

    /**
     * @return array<string, array{array<string, mixed>}>
     */
    public static function linkVectors(): array
    {
        $file = json_decode((string) file_get_contents(__DIR__ . '/fixtures/vectors.json'), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($file);
        self::assertIsArray($file['linkVectors']);
        $cases = [];
        foreach ($file['linkVectors'] as $i => $vector) {
            self::assertIsArray($vector);
            self::assertIsString($vector['name']);
            $cases[sprintf('#%d %s', (int) $i, $vector['name'])] = [$vector];
        }
        self::assertGreaterThan(0, count($cases));

        return $cases;
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[DataProvider('linkVectors')]
    public function testLinkVector(array $vector): void
    {
        /** @var array{object: string, app: string, parent?: string} $input */
        $input = $vector['input'];
        /** @var array{valid: bool, reason: string} $expect */
        $expect = $vector['expect'];

        $reason = Grammar::linkReason($input['object'], $input['app'], $input['parent'] ?? null);

        self::assertSame($expect['reason'], $reason);
        self::assertSame($expect['valid'], 'ok' === $reason);
    }
}
