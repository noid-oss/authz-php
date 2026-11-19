<?php

declare(strict_types=1);

namespace AuthZ\Tests\Support;

use Firebase\JWT\JWT;
use OpenSSLAsymmetricKey;

/** Throwaway RSA key pair plus JWKS / JWT builders. */
final class Keys
{
    public readonly OpenSSLAsymmetricKey $private;
    public readonly string $privatePem;
    /** @var array<string, string> */
    public readonly array $jwk;

    public function __construct(public readonly string $kid = 'k1')
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        if (false === $key) {
            throw new \RuntimeException('openssl_pkey_new failed');
        }
        $this->private = $key;
        openssl_pkey_export($key, $pem);
        $this->privatePem = (string) $pem;
        $details = openssl_pkey_get_details($key);
        $n = is_array($details) && is_array($details['rsa'] ?? null) ? ($details['rsa']['n'] ?? null) : null;
        $e = is_array($details) && is_array($details['rsa'] ?? null) ? ($details['rsa']['e'] ?? null) : null;
        if (!is_string($n) || !is_string($e)) {
            throw new \RuntimeException('cannot read RSA parameters');
        }
        $b64 = static fn(string $v): string => rtrim(strtr(base64_encode($v), '+/', '-_'), '=');
        $this->jwk = ['kty' => 'RSA', 'use' => 'sig', 'alg' => 'RS256', 'kid' => $kid, 'n' => $b64($n), 'e' => $b64($e)];
    }

    /**
     * @param list<self> $keys
     */
    public static function jwks(array $keys): string
    {
        return (string) json_encode(['keys' => array_map(static fn(self $k): array => $k->jwk, $keys)]);
    }

    /**
     * @param array<string, mixed> $payload
     */
    public function sign(array $payload, string $alg = 'RS256'): string
    {
        return JWT::encode($payload, $this->privatePem, $alg, $this->kid);
    }
}
