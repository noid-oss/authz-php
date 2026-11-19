<?php

declare(strict_types=1);

namespace NoidOss\Authz\Tests\Support;

use Closure;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/** PSR-18 client answering from a closure; records every request. */
final class FakeHttp implements ClientInterface
{
    /** @var list<RequestInterface> */
    public array $sent = [];

    /**
     * @param Closure(RequestInterface): ResponseInterface $handler
     */
    public function __construct(private readonly Closure $handler) {}

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->sent[] = $request;

        return ($this->handler)($request);
    }
}
