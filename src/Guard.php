<?php

declare(strict_types=1);

namespace NoidOss\Authz;

use Closure;
use InvalidArgumentException;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * PSR-15 guard for one permission.
 *
 * Mode 'live' (default): the full perms.can algorithm. Writes (anything not under `reads`)
 * are always checked live, reads are decided from the claim, plus a live object check
 * when an object resolver yields an object.
 *
 * Mode 'hint' (explicit opt-out): claim only, no network. Allowed only for permissions
 * listed under `reads` (checked at construction) and incompatible with an object resolver,
 * because an object check is live by definition.
 *
 * 401 = no/invalid token. 403 = authenticated but denied (including check errors and timeouts).
 * On success the request gets attributes `authz.token` (VerifiedToken) and `authz.decision` (Decision).
 */
final class Guard implements MiddlewareInterface
{
    public const MODE_LIVE = 'live';
    public const MODE_HINT = 'hint';
    public const ATTR_TOKEN = 'authz.token';
    public const ATTR_DECISION = 'authz.decision';

    /**
     * @param (Closure(ServerRequestInterface): (array{type: mixed, id: mixed}|null))|null $objectResolver
     */
    public function __construct(
        private readonly TokenVerifier $verifier,
        private readonly Perms $perms,
        private readonly ResponseFactoryInterface $responses,
        private readonly string $permission,
        private readonly string $mode = self::MODE_LIVE,
        private readonly ?Closure $objectResolver = null,
    ) {
        if (self::MODE_LIVE !== $mode && self::MODE_HINT !== $mode) {
            throw new InvalidArgumentException('mode must be "live" or "hint"');
        }
        if (self::MODE_HINT === $mode) {
            if (!$perms->isRead($permission)) {
                throw new InvalidArgumentException(sprintf('mode "hint" is only allowed for permissions listed under reads; "%s" is a write.', $permission));
            }
            if (null !== $objectResolver) {
                throw new InvalidArgumentException('mode "hint" cannot be combined with an object resolver.');
            }
        }
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $header = $request->getHeaderLine('Authorization');
        if (1 !== preg_match('/^Bearer ([A-Za-z0-9._~+\/-]+=*)\z/i', $header, $m)) {
            return $this->reject(401, 'missing_token');
        }
        try {
            $token = $this->verifier->verify($m[1]);
        } catch (TokenException $e) {
            return $this->reject(401, $e->reason);
        }

        if (self::MODE_HINT === $this->mode) {
            $decision = $this->perms->explainHint($token, $this->permission);
        } else {
            $object = null !== $this->objectResolver ? ($this->objectResolver)($request) : null;
            $decision = $this->perms->explain($token, $this->permission, $object);
        }
        if (!$decision->allowed) {
            return $this->reject(403, $decision->reason->value);
        }

        return $handler->handle(
            $request->withAttribute(self::ATTR_TOKEN, $token)->withAttribute(self::ATTR_DECISION, $decision),
        );
    }

    private function reject(int $status, string $reason): ResponseInterface
    {
        $response = $this->responses->createResponse($status)->withHeader('Content-Type', 'application/json');
        if (401 === $status) {
            $response = $response->withHeader('WWW-Authenticate', 'Bearer');
        }
        $response->getBody()->write((string) json_encode(['error' => 401 === $status ? 'unauthorized' : 'forbidden', 'reason' => $reason]));

        return $response;
    }
}
