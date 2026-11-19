<?php

declare(strict_types=1);

namespace AuthZ;

use InvalidArgumentException;

/**
 * Static configuration of one app in one brand.
 *
 * `brand` and `app` are sent on every live check and always come from here,
 * never from a caller or a token.
 */
final readonly class Config
{
    /**
     * @param string                $brand          brand slug (tenant slug)
     * @param string                $app            the app's OAuth client_id
     * @param string                $issuer         the brand's token issuer, matched exactly
     * @param string                $tenantId       tenant slug the app serves, matched against `tenant_id`
     * @param string                $checkUrl       full URL of POST /v1/check
     * @param string                $appCredential  bearer credential of this app for the check service
     * @param float                 $timeoutSeconds live check budget; the PSR-18 client must enforce it too
     * @param array<string, string> $issuers        known issuer => JWKS URI. Defaults to just `$issuer`
     *                                              with `<issuer>/.well-known/jwks.json`
     * @param list<string>          $algorithms     accepted JWS algorithms (asymmetric only)
     * @param string|null           $audience       when set, `aud` must equal / contain it
     */
    public function __construct(
        public string $brand,
        public string $app,
        public string $issuer,
        public string $tenantId,
        public string $checkUrl = '',
        public string $appCredential = '',
        public float $timeoutSeconds = 2.0,
        public array $issuers = [],
        public array $algorithms = ['RS256', 'ES256'],
        public ?string $audience = null,
    ) {
        // Reason::InvalidConfig: brand and app build the Keto object, so they never reach a call unvalidated.
        if (!Grammar::isBrand($brand)) {
            throw new InvalidArgumentException('invalid_config: brand must match ^[a-z0-9][a-z0-9-]{0,62}$');
        }
        if (!Grammar::isApp($app)) {
            throw new InvalidArgumentException('invalid_config: app must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ and not contain ".."');
        }
        if ('' === $issuer || '' === $tenantId) {
            throw new InvalidArgumentException('issuer and tenantId must not be empty');
        }
        if ($timeoutSeconds <= 0) {
            throw new InvalidArgumentException('timeoutSeconds must be positive');
        }
        foreach ($algorithms as $alg) {
            if (!in_array($alg, ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'PS256', 'PS384', 'PS512', 'EdDSA'], true)) {
                throw new InvalidArgumentException(sprintf('Unsupported or symmetric algorithm "%s"', $alg));
            }
        }
    }

    /**
     * Known issuers with their JWKS URIs. The token's `iss` must be a key of this map:
     * a JWKS URI is never derived from an unverified token.
     *
     * @return array<string, string>
     */
    public function knownIssuers(): array
    {
        if ([] !== $this->issuers) {
            return $this->issuers;
        }

        return [$this->issuer => rtrim($this->issuer, '/') . '/.well-known/jwks.json'];
    }
}
