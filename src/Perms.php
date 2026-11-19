<?php

declare(strict_types=1);

namespace NoidOss\Authz;

use Closure;
use NoidOss\Authz\Http\Checker;
use NoidOss\Authz\Http\CheckOutcome;

/**
 * perms.can(user, permission, object?): the algorithm of authz-spec README "The helper".
 *
 * Steps run in order and the first failing step denies and stops:
 *  1 token checks, 2 request checks, 3 claim hint, 4 live permission check (writes only),
 *  5 live object check (when an object is given), 6 any error/timeout denies, 7 allowed.
 */
final class Perms
{
    /** @var Closure(): int */
    private Closure $clock;

    /**
     * @param (Closure(): int)|null $clock
     */
    public function __construct(
        private readonly Config $config,
        private readonly Manifest $manifest,
        private readonly Checker $checker,
        ?Closure $clock = null,
    ) {
        $this->clock = $clock ?? static fn(): int => time();
    }

    /**
     * @param VerifiedToken|array<string, mixed> $user                already verified token or its claims
     * @param array{type: mixed, id: mixed}|null $object
     */
    public function can(VerifiedToken|array $user, string $permission, ?array $object = null): bool
    {
        return $this->explain($user, $permission, $object)->allowed;
    }

    /**
     * Same decision as can(), with the denying step and the live calls made.
     *
     * @param VerifiedToken|array<string, mixed> $user
     * @param array{type: mixed, id: mixed}|null $object
     */
    public function explain(VerifiedToken|array $user, string $permission, ?array $object = null): Decision
    {
        $claims = $this->claims($user);
        $calls = [];

        $early = $this->preflight($claims, $permission, $object, $normalized);
        if (null !== $early) {
            return $early;
        }

        /** @var string $sub */
        $sub = $claims['sub'];

        if (!$this->manifest->isRead($permission)) {
            $calls[] = ['permission' => $permission];
            $denied = $this->live(['permission' => $permission, 'subject' => $sub], Reason::Denied, Step::LivePermission, $calls);
            if (null !== $denied) {
                return $denied;
            }
        }
        if (null !== $normalized) {
            $calls[] = ['permission' => $permission, 'object' => $normalized];
            $denied = $this->live(
                ['permission' => $permission, 'subject' => $sub, 'object' => $normalized],
                Reason::ObjectDenied,
                Step::LiveObject,
                $calls,
            );
            if (null !== $denied) {
                return $denied;
            }
        }

        return new Decision(true, [] === $calls ? Reason::AllowedClaim : Reason::AllowedLive, null, $calls);
    }

    /**
     * Claim-only decision (steps 1 to 3), used by the guard's explicit 'hint' mode.
     * Refuses anything that is not listed under `reads`: a hint never allows a write.
     *
     * @param VerifiedToken|array<string, mixed> $user
     */
    public function explainHint(VerifiedToken|array $user, string $permission): Decision
    {
        if (!$this->manifest->isRead($permission)) {
            throw new \LogicException(sprintf('"%s" is not listed under reads; only reads can be decided from the hint.', $permission));
        }

        return $this->preflight($this->claims($user), $permission, null, $normalized)
            ?? new Decision(true, Reason::AllowedClaim, null, []);
    }

    public function isRead(string $permission): bool
    {
        return $this->manifest->isRead($permission);
    }

    /**
     * @param array<string, mixed>                          $claims
     * @param array{type: mixed, id: mixed}|null            $object
     * @param array{type: string, id: string}|null          $normalized set when an object was given and is valid
     */
    private function preflight(array $claims, string $permission, ?array $object, ?array &$normalized): ?Decision
    {
        $normalized = null;
        $deny = static fn(Reason $r, Step $s): Decision => new Decision(false, $r, $s, []);

        // 1. token checks
        if (($claims['iss'] ?? null) !== $this->config->issuer) {
            return $deny(Reason::InvalidIssuer, Step::Token);
        }
        if (($claims['tenant_id'] ?? null) !== $this->config->tenantId) {
            return $deny(Reason::InvalidTenant, Step::Token);
        }
        $sub = $claims['sub'] ?? null;
        if (!is_string($sub) || '' === $sub) {
            return $deny(Reason::InvalidSubject, Step::Token);
        }
        $exp = $claims['exp'] ?? null;
        if (!is_int($exp) || $exp <= ($this->clock)()) {
            return $deny(Reason::TokenExpired, Step::Token);
        }

        // 2. request checks (no network on invalid input)
        if (!Grammar::isPermission($permission)) {
            return $deny(Reason::InvalidRequest, Step::Request);
        }
        if (null !== $object) {
            $normalized = Grammar::object($object);
            if (null === $normalized || !$this->manifest->acceptsObjectType($normalized['type'])) {
                $normalized = null;

                return $deny(Reason::InvalidObject, Step::Request);
            }
        }

        // 3. claim hint: absent / non-array / not exactly listed means deny
        if (!(new Hint(new VerifiedToken($claims)))->can($permission)) {
            return $deny(Reason::PermissionNotInClaim, Step::Claim);
        }

        return null;
    }

    /**
     * @param array{permission: string, subject: string, object?: array{type: string, id: string}} $request
     * @param list<array{permission: string, object?: array{type: string, id: string}}>             $calls    live calls so far, including this one
     */
    private function live(array $request, Reason $denyReason, Step $step, array $calls): ?Decision
    {
        $result = $this->checker->check($request);
        $reason = match ($result->outcome) {
            CheckOutcome::Allow => null,
            CheckOutcome::Deny => $denyReason,
            CheckOutcome::Timeout => Reason::CheckTimeout,
            CheckOutcome::Error => Reason::CheckError, // also covers anything unexpected: fail closed
        };

        return null === $reason ? null : new Decision(false, $reason, $step, $calls);
    }

    /**
     * @param VerifiedToken|array<string, mixed> $user
     *
     * @return array<string, mixed>
     */
    private function claims(VerifiedToken|array $user): array
    {
        return $user instanceof VerifiedToken ? $user->claims : VerifiedToken::fromRaw($user)->claims;
    }
}
