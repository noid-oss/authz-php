<?php

declare(strict_types=1);

namespace NoidOss\Authz;

/**
 * Claims of a token whose signature and issuer were verified.
 * Standard claims come from the top level only; custom claims fall back to `ext`
 * and can never replace a standard one (CLAIMS.md).
 */
final readonly class VerifiedToken
{
    private const STANDARD = ['iss', 'sub', 'exp', 'aud', 'scope', 'iat', 'nbf', 'jti'];
    private const CUSTOM = ['tenant_id', 'roles', 'permissions', 'acr', 'amr', 'auth_time', 'email'];

    /**
     * @param array<string, mixed> $claims normalized claims
     */
    public function __construct(public array $claims) {}

    /**
     * @param array<string, mixed> $raw decoded JWT payload or introspection response
     */
    public static function fromRaw(array $raw): self
    {
        $claims = [];
        foreach (self::STANDARD as $name) {
            if (array_key_exists($name, $raw)) {
                $claims[$name] = $raw[$name];
            }
        }
        $ext = isset($raw['ext']) && is_array($raw['ext']) ? $raw['ext'] : [];
        foreach (self::CUSTOM as $name) {
            if (array_key_exists($name, $raw)) {
                $claims[$name] = $raw[$name];
            } elseif (array_key_exists($name, $ext)) {
                $claims[$name] = $ext[$name];
            }
        }

        return new self($claims);
    }

    public function subject(): ?string
    {
        $sub = $this->claims['sub'] ?? null;

        return is_string($sub) && '' !== $sub ? $sub : null;
    }
}
