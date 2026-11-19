<?php

declare(strict_types=1);

namespace NoidOss\Authz;

use Closure;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

/**
 * verify(token): signature + exp against the issuer's JWKS, issuer in the known list,
 * tenant_id equal to the configured tenant.
 *
 * The JWKS URI is looked up in configuration by the token's `iss` only after that
 * issuer is confirmed to be known, so a forged token cannot make the SDK fetch
 * an attacker-chosen URL.
 */
final class TokenVerifier
{
    /** @var array<string, array{keys: array<string, Key>, fetchedAt: int}> */
    private array $jwksCache = [];

    /** @var Closure(): int */
    private Closure $clock;

    /**
     * @param (Closure(): int)|null $clock
     * @param int                   $jwksTtl       seconds a JWKS is reused
     * @param int                   $jwksCooldown  minimum seconds between refetches triggered by an unknown `kid`
     */
    public function __construct(
        private readonly Config $config,
        private readonly ClientInterface $http,
        private readonly RequestFactoryInterface $requests,
        ?Closure $clock = null,
        private readonly int $jwksTtl = 300,
        private readonly int $jwksCooldown = 30,
    ) {
        $this->clock = $clock ?? static fn(): int => time();
    }

    /**
     * @throws TokenException
     */
    public function verify(string $token): VerifiedToken
    {
        $parts = explode('.', $token);
        if (3 !== count($parts)) {
            throw new TokenException(TokenException::MALFORMED);
        }
        $header = self::decodeSegment($parts[0]);
        $unverified = self::decodeSegment($parts[1]);
        $alg = $header['alg'] ?? null;
        $kid = $header['kid'] ?? null;
        if (!is_string($alg) || !in_array($alg, $this->config->algorithms, true)) {
            throw new TokenException(TokenException::MALFORMED, 'algorithm not allowed');
        }
        if (!is_string($kid) || '' === $kid) {
            throw new TokenException(TokenException::MALFORMED, 'missing kid');
        }
        $iss = $unverified['iss'] ?? null;
        $known = $this->config->knownIssuers();
        if (!is_string($iss) || !array_key_exists($iss, $known)) {
            throw new TokenException(TokenException::UNKNOWN_ISSUER);
        }

        $key = $this->key($iss, $known[$iss], $kid, $alg);
        $previous = JWT::$timestamp;
        JWT::$timestamp = ($this->clock)();
        try {
            $decoded = JWT::decode($token, $key);
        } catch (\Firebase\JWT\ExpiredException $e) {
            throw new TokenException(TokenException::EXPIRED, '', $e);
        } catch (\Throwable $e) {
            throw new TokenException(TokenException::INVALID_SIGNATURE, $e->getMessage(), $e);
        } finally {
            JWT::$timestamp = $previous;
        }
        $raw = json_decode((string) json_encode($decoded), true);
        if (!is_array($raw)) {
            throw new TokenException(TokenException::MALFORMED);
        }
        /** @var array<string, mixed> $raw */
        $verified = VerifiedToken::fromRaw($raw);
        $claims = $verified->claims;

        // Exact issuer (also guards a spoofed header-vs-payload mismatch), integer exp, sub, tenant.
        if (($claims['iss'] ?? null) !== $iss) {
            throw new TokenException(TokenException::UNKNOWN_ISSUER);
        }
        if (!is_int($claims['exp'] ?? null) || $claims['exp'] <= ($this->clock)()) {
            throw new TokenException(TokenException::EXPIRED);
        }
        if (null === $verified->subject()) {
            throw new TokenException(TokenException::INVALID_SUBJECT);
        }
        if (($claims['tenant_id'] ?? null) !== $this->config->tenantId) {
            throw new TokenException(TokenException::INVALID_TENANT);
        }
        if (null !== $this->config->audience && !self::hasAudience($claims['aud'] ?? null, $this->config->audience)) {
            throw new TokenException(TokenException::INVALID_AUDIENCE);
        }

        return $verified;
    }

    /**
     * Claim-only view of a token (no network). Pass a token that went through verify().
     */
    public static function hint(VerifiedToken $token): Hint
    {
        return new Hint($token);
    }

    private function key(string $iss, string $uri, string $kid, string $alg): Key
    {
        $now = ($this->clock)();
        $entry = $this->jwksCache[$iss] ?? null;
        if (null !== $entry && $now - $entry['fetchedAt'] < $this->jwksTtl && isset($entry['keys'][$kid])) {
            return $entry['keys'][$kid];
        }
        // Refetch when stale, or when the kid is unknown (rotation) but not more often than the cooldown.
        if (null === $entry || $now - $entry['fetchedAt'] >= $this->jwksTtl || $now - $entry['fetchedAt'] >= $this->jwksCooldown) {
            $entry = ['keys' => $this->fetchKeys($uri, $alg), 'fetchedAt' => $now];
            $this->jwksCache[$iss] = $entry;
        }
        if (!isset($entry['keys'][$kid])) {
            throw new TokenException(TokenException::INVALID_SIGNATURE, 'unknown kid');
        }

        return $entry['keys'][$kid];
    }

    /**
     * @return array<string, Key>
     */
    private function fetchKeys(string $uri, string $alg): array
    {
        try {
            $response = $this->http->sendRequest($this->requests->createRequest('GET', $uri)->withHeader('Accept', 'application/json'));
        } catch (ClientExceptionInterface $e) {
            throw new TokenException(TokenException::JWKS_UNAVAILABLE, $e->getMessage(), $e);
        }
        if (200 !== $response->getStatusCode()) {
            throw new TokenException(TokenException::JWKS_UNAVAILABLE, 'status ' . $response->getStatusCode());
        }
        $jwks = json_decode((string) $response->getBody(), true);
        if (!is_array($jwks) || !isset($jwks['keys']) || !is_array($jwks['keys'])) {
            throw new TokenException(TokenException::JWKS_UNAVAILABLE, 'malformed JWKS');
        }
        $keys = [];
        foreach ($jwks['keys'] as $jwk) {
            if (!is_array($jwk) || !is_string($jwk['kid'] ?? null)) {
                continue;
            }
            // Only the key's declared alg (or the token's, if the JWK has none) can be used with it.
            try {
                $parsed = JWK::parseKey($jwk, $alg);
            } catch (\Throwable) {
                continue;
            }
            if (null !== $parsed) {
                $keys[$jwk['kid']] = $parsed;
            }
        }

        return $keys;
    }

    /**
     * @return array<string, mixed>
     */
    private static function decodeSegment(string $segment): array
    {
        $json = base64_decode(strtr($segment, '-_', '+/'), true);
        $data = false === $json ? null : json_decode($json, true);
        if (!is_array($data)) {
            throw new TokenException(TokenException::MALFORMED);
        }

        /** @var array<string, mixed> $data */
        return $data;
    }

    private static function hasAudience(mixed $aud, string $expected): bool
    {
        if (is_string($aud)) {
            return $aud === $expected;
        }

        return is_array($aud) && in_array($expected, $aud, true);
    }
}
