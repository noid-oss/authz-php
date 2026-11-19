<?php

declare(strict_types=1);

namespace NoidOss\Authz;

/**
 * The token's `permissions` claim, and nothing else. Never authoritative:
 * it may be stale until the token expires and must not gate a write on its own.
 */
final readonly class Hint
{
    public function __construct(private VerifiedToken $token) {}

    /**
     * True only when `permissions` is an array holding exactly this string (no wildcards).
     */
    public function can(string $permission): bool
    {
        $permissions = $this->token->claims['permissions'] ?? null;

        return is_array($permissions) && array_is_list($permissions) && in_array($permission, $permissions, true);
    }
}
