<?php

declare(strict_types=1);

namespace AuthZ;

use RuntimeException;

/** A token that must not be trusted. `reason` is a stable machine code. */
final class TokenException extends RuntimeException
{
    public const MALFORMED = 'malformed_token';
    public const UNKNOWN_ISSUER = 'unknown_issuer';
    public const INVALID_SIGNATURE = 'invalid_signature';
    public const EXPIRED = 'token_expired';
    public const INVALID_TENANT = 'invalid_tenant';
    public const INVALID_SUBJECT = 'invalid_subject';
    public const INVALID_AUDIENCE = 'invalid_audience';
    public const JWKS_UNAVAILABLE = 'jwks_unavailable';

    public function __construct(public readonly string $reason, string $message = '', ?\Throwable $previous = null)
    {
        parent::__construct('' === $message ? $reason : $reason . ': ' . $message, 0, $previous);
    }
}
