<?php

declare(strict_types=1);

namespace NoidOss\Authz\Tests;

use Firebase\JWT\JWT;
use NoidOss\Authz\Config;
use NoidOss\Authz\Hint;
use NoidOss\Authz\Tests\Support\FakeHttp;
use NoidOss\Authz\Tests\Support\Keys;
use NoidOss\Authz\TokenException;
use NoidOss\Authz\TokenVerifier;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\TestCase;

final class TokenVerifierTest extends TestCase
{
    private const ISS = 'https://auth.idbi.example/';
    private const NOW = 1_800_000_000;

    private Keys $keys;
    /** @var list<string> */
    private array $fetched = [];

    protected function setUp(): void
    {
        $this->keys = new Keys('k1');
        $this->fetched = [];
    }

    /**
     * @param array<string, string> $issuers
     */
    private function verifier(?FakeHttp $http = null, ?string $audience = null, array $issuers = []): TokenVerifier
    {
        $http ??= new FakeHttp(function ($r): Response {
            $this->fetched[] = (string) $r->getUri();

            return new Response(200, [], Keys::jwks([$this->keys]));
        });
        $f = new Psr17Factory();

        return new TokenVerifier(
            new Config('idbi', 'billing', self::ISS, 'idbi', audience: $audience, issuers: $issuers),
            $http,
            $f,
            static fn(): int => self::NOW,
        );
    }

    /**
     * @param array<string, mixed> $over
     *
     * @return array<string, mixed>
     */
    private function payload(array $over = []): array
    {
        return array_merge([
            'iss' => self::ISS, 'sub' => 'ana', 'tenant_id' => 'idbi',
            'exp' => self::NOW + 600, 'permissions' => ['invoice.view'],
        ], $over);
    }

    private function reason(string $token, ?TokenVerifier $v = null): string
    {
        try {
            ($v ?? $this->verifier())->verify($token);
        } catch (TokenException $e) {
            return $e->reason;
        }
        self::fail('token was accepted');
    }

    public function testAcceptsAValidToken(): void
    {
        $token = $this->verifier()->verify($this->keys->sign($this->payload()));

        self::assertSame('ana', $token->subject());
        self::assertSame(['https://auth.idbi.example/.well-known/jwks.json'], $this->fetched);
        self::assertTrue(TokenVerifier::hint($token)->can('invoice.view'));
        self::assertFalse(TokenVerifier::hint($token)->can('invoice.print'));
    }

    public function testRejectsExpiredAndExpEqualNow(): void
    {
        self::assertSame('token_expired', $this->reason($this->keys->sign($this->payload(['exp' => self::NOW - 1]))));
        self::assertSame('token_expired', $this->reason($this->keys->sign($this->payload(['exp' => self::NOW]))));
    }

    public function testRejectsMissingExp(): void
    {
        $p = $this->payload();
        unset($p['exp']);

        self::assertNotSame('', $this->reason($this->keys->sign($p)));
    }

    public function testRejectsUnknownIssuerWithoutFetchingAnything(): void
    {
        $reason = $this->reason($this->keys->sign($this->payload(['iss' => 'https://auth.other.example/'])));

        self::assertSame('unknown_issuer', $reason);
        self::assertSame([], $this->fetched);
    }

    public function testIssuerTrailingSlashIsADifferentIssuer(): void
    {
        self::assertSame('unknown_issuer', $this->reason($this->keys->sign($this->payload(['iss' => 'https://auth.idbi.example']))));
    }

    public function testRejectsOtherBrandsValidlySignedToken(): void
    {
        $other = new Keys('k1');
        $http = new FakeHttp(fn() => new Response(200, [], Keys::jwks([$other])));
        $token = $other->sign($this->payload(['iss' => 'https://auth.other.example/']));

        // Signature is valid for the other brand's key, but its issuer is not in our list.
        self::assertSame('unknown_issuer', $this->reason($token, $this->verifier($http)));
    }

    public function testKnownIssuerListAcceptsSeveralIssuers(): void
    {
        $other = new Keys('o1');
        $http = new FakeHttp(fn($r) => new Response(200, [], Keys::jwks(str_contains((string) $r->getUri(), 'other') ? [$other] : [$this->keys])));
        $v = $this->verifier($http, issuers: [
            self::ISS => 'https://auth.idbi.example/jwks.json',
            'https://auth.other.example/' => 'https://auth.other.example/jwks.json',
        ]);

        self::assertSame('ana', $v->verify($other->sign($this->payload(['iss' => 'https://auth.other.example/'])))->subject());
        self::assertSame('ana', $v->verify($this->keys->sign($this->payload()))->subject());
    }

    public function testRejectsTenantMismatchAndMissingTenant(): void
    {
        self::assertSame('invalid_tenant', $this->reason($this->keys->sign($this->payload(['tenant_id' => 'other']))));
        $p = $this->payload();
        unset($p['tenant_id']);
        self::assertSame('invalid_tenant', $this->reason($this->keys->sign($p)));
    }

    public function testTenantMayComeFromExtButNeverOverridesTopLevel(): void
    {
        $p = $this->payload();
        unset($p['tenant_id']);
        $p['ext'] = ['tenant_id' => 'idbi', 'sub' => 'mallory', 'permissions' => ['invoice.view']];
        $token = $this->verifier()->verify($this->keys->sign($p));

        self::assertSame('idbi', $token->claims['tenant_id']);
        self::assertSame('ana', $token->claims['sub'], 'standard claims are read from the top level only');

        $p['tenant_id'] = 'other';
        self::assertSame('invalid_tenant', $this->reason($this->keys->sign($p)));
    }

    public function testRejectsMissingOrEmptySubject(): void
    {
        self::assertSame('invalid_subject', $this->reason($this->keys->sign($this->payload(['sub' => '']))));
        $p = $this->payload();
        unset($p['sub']);
        self::assertSame('invalid_subject', $this->reason($this->keys->sign($p)));
    }

    public function testRejectsBadSignature(): void
    {
        $attacker = new Keys('k1'); // same kid, different key
        self::assertSame('invalid_signature', $this->reason($attacker->sign($this->payload())));
    }

    public function testRejectsTamperedPayload(): void
    {
        [$h, , $s] = explode('.', $this->keys->sign($this->payload()));
        $evil = rtrim(strtr(base64_encode((string) json_encode($this->payload(['sub' => 'mallory']))), '+/', '-_'), '=');

        self::assertSame('invalid_signature', $this->reason("$h.$evil.$s"));
    }

    public function testRejectsAlgNone(): void
    {
        $b = static fn(array $v): string => rtrim(strtr(base64_encode((string) json_encode($v)), '+/', '-_'), '=');
        $token = $b(['alg' => 'none', 'typ' => 'JWT', 'kid' => 'k1']) . '.' . $b($this->payload()) . '.';

        self::assertSame('malformed_token', $this->reason($token));
    }

    public function testRejectsHmacConfusionUsingThePublicKeyAsSecret(): void
    {
        $token = JWT::encode($this->payload(), (string) json_encode($this->keys->jwk), 'HS256', 'k1');

        self::assertSame('malformed_token', $this->reason($token));
    }

    public function testRejectsUnknownKidAndGarbage(): void
    {
        $other = new Keys('rotated');
        self::assertSame('invalid_signature', $this->reason($other->sign($this->payload())));
        self::assertSame('malformed_token', $this->reason('not-a-jwt'));
        self::assertSame('malformed_token', $this->reason('a.b.c'));
        self::assertSame('malformed_token', $this->reason(''));
    }

    public function testJwksFailuresFailClosed(): void
    {
        $token = $this->keys->sign($this->payload());
        $cases = [
            new FakeHttp(fn() => new Response(500)),
            new FakeHttp(fn() => new Response(200, [], 'not json')),
            new FakeHttp(fn() => new Response(200, [], '{"keys":"x"}')),
            new FakeHttp(fn($r) => throw new Support\NetworkError($r, 'down')),
        ];
        foreach ($cases as $http) {
            self::assertSame('jwks_unavailable', $this->reason($token, $this->verifier($http)));
        }
    }

    public function testJwksIsCachedAndRefetchedOnUnknownKidOnlyAfterCooldown(): void
    {
        $now = self::NOW;
        $rotated = new Keys('k2');
        $served = [$this->keys];
        $calls = 0;
        $http = new FakeHttp(function () use (&$served, &$calls): Response {
            ++$calls;

            return new Response(200, [], Keys::jwks($served));
        });
        $f = new Psr17Factory();
        $v = new TokenVerifier(new Config('idbi', 'billing', self::ISS, 'idbi'), $http, $f, function () use (&$now): int {
            return $now;
        });

        $v->verify($this->keys->sign($this->payload()));
        $v->verify($this->keys->sign($this->payload()));
        self::assertSame(1, $calls, 'cached');

        $served = [$this->keys, $rotated];
        $now += 5;
        self::assertSame('invalid_signature', $this->reason($rotated->sign($this->payload(['exp' => $now + 600])), $v));
        self::assertSame(1, $calls, 'no refetch inside the cooldown');

        $now += 40;
        $v->verify($rotated->sign($this->payload(['exp' => $now + 600])));
        self::assertSame(2, $calls, 'refetched after the cooldown, new kid accepted');
    }

    public function testAudienceWhenConfigured(): void
    {
        $v = $this->verifier(audience: 'billing');

        self::assertSame('invalid_audience', $this->reason($this->keys->sign($this->payload()), $v));
        self::assertSame('invalid_audience', $this->reason($this->keys->sign($this->payload(['aud' => ['crm']])), $v));
        self::assertSame('ana', $v->verify($this->keys->sign($this->payload(['aud' => 'billing'])))->subject());
        self::assertSame('ana', $v->verify($this->keys->sign($this->payload(['aud' => ['crm', 'billing']])))->subject());
    }

    public function testHintReadsPermissionsClaimOnly(): void
    {
        $token = $this->verifier()->verify($this->keys->sign($this->payload(['permissions' => 'invoice.view'])));
        self::assertFalse((new Hint($token))->can('invoice.view'), 'a string is not an array');

        $token = $this->verifier()->verify($this->keys->sign($this->payload(['permissions' => ['invoice.*', 'Invoice.view']])));
        self::assertFalse((new Hint($token))->can('invoice.view'));
        self::assertFalse((new Hint($token))->can('invoice.print'));
    }
}
