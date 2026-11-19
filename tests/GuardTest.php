<?php

declare(strict_types=1);

namespace NoidOss\Authz\Tests;

use InvalidArgumentException;
use NoidOss\Authz\Config;
use NoidOss\Authz\Decision;
use NoidOss\Authz\Guard;
use NoidOss\Authz\Manifest;
use NoidOss\Authz\Perms;
use NoidOss\Authz\Tests\Support\FakeHttp;
use NoidOss\Authz\Tests\Support\Keys;
use NoidOss\Authz\Tests\Support\StubChecker;
use NoidOss\Authz\TokenVerifier;
use NoidOss\Authz\VerifiedToken;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class GuardTest extends TestCase
{
    private const ISS = 'https://auth.idbi.example/';
    private const NOW = 1_800_000_000;

    private Keys $keys;
    private Psr17Factory $f;
    private StubChecker $checker;
    private int $handled = 0;
    private ?ServerRequestInterface $seen = null;

    protected function setUp(): void
    {
        $this->keys = new Keys('k1');
        $this->f = new Psr17Factory();
        $this->handled = 0;
        $this->seen = null;
    }

    /**
     * @param array{role?: string, object?: string} $live
     * @param \Closure(ServerRequestInterface): (array{type: mixed, id: mixed}|null)|null $resolver
     */
    private function guard(string $permission, array $live = [], string $mode = Guard::MODE_LIVE, ?\Closure $resolver = null): Guard
    {
        $config = new Config('idbi', 'billing', self::ISS, 'idbi');
        $clock = static fn(): int => self::NOW;
        $this->checker = new StubChecker($live);
        $http = new FakeHttp(fn() => new Response(200, [], Keys::jwks([$this->keys])));

        return new Guard(
            new TokenVerifier($config, $http, $this->f, $clock),
            new Perms($config, new Manifest(['invoice.view']), $this->checker, $clock),
            $this->f,
            $permission,
            $mode,
            $resolver,
        );
    }

    private function request(?string $token): ServerRequest
    {
        $r = new ServerRequest('GET', 'https://app.example/invoices/inv-001');

        return null === $token ? $r : $r->withHeader('Authorization', 'Bearer ' . $token);
    }

    /**
     * @param list<string> $permissions
     */
    private function token(array $permissions = ['invoice.view', 'invoice.print']): string
    {
        return $this->keys->sign([
            'iss' => self::ISS, 'sub' => 'ana', 'tenant_id' => 'idbi',
            'exp' => self::NOW + 600, 'permissions' => $permissions,
        ]);
    }

    private function dispatch(Guard $guard, ServerRequest $request): ResponseInterface
    {
        $handler = new class ($this) implements RequestHandlerInterface {
            public function __construct(private readonly GuardTest $test) {}

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->test->handled($request);

                return new Response(204);
            }
        };

        return $guard->process($request, $handler);
    }

    public function handled(ServerRequestInterface $request): void
    {
        ++$this->handled;
        $this->seen = $request;
    }

    public function testMissingOrBadTokenIs401(): void
    {
        $guard = $this->guard('invoice.print', ['role' => 'allow']);

        self::assertSame(401, $this->dispatch($guard, $this->request(null))->getStatusCode());
        self::assertSame(401, $this->dispatch($guard, $this->request('garbage'))->getStatusCode());
        self::assertSame(401, $this->dispatch($guard, $this->request($this->keys->sign(['iss' => self::ISS, 'sub' => 'a', 'tenant_id' => 'idbi', 'exp' => self::NOW - 1])))->getStatusCode());
        self::assertSame(0, $this->handled);
        self::assertSame([], $this->checker->requests);
    }

    public function testWriteIsCheckedLiveByDefault(): void
    {
        $allow = $this->guard('invoice.print', ['role' => 'allow']);
        self::assertSame(204, $this->dispatch($allow, $this->request($this->token()))->getStatusCode());
        self::assertCount(1, $this->checker->requests);
        self::assertInstanceOf(VerifiedToken::class, $this->seen?->getAttribute(Guard::ATTR_TOKEN));
        self::assertInstanceOf(Decision::class, $this->seen->getAttribute(Guard::ATTR_DECISION));

        $deny = $this->guard('invoice.print', ['role' => 'deny']);
        $response = $this->dispatch($deny, $this->request($this->token()));
        self::assertSame(403, $response->getStatusCode());
        self::assertSame('{"error":"forbidden","reason":"denied"}', (string) $response->getBody());
    }

    public function testLiveErrorAndTimeoutAre403(): void
    {
        foreach (['error' => 'check_error', 'timeout' => 'check_timeout', 'not_called' => 'check_error'] as $outcome => $reason) {
            $response = $this->dispatch($this->guard('invoice.print', ['role' => $outcome]), $this->request($this->token()));
            self::assertSame(403, $response->getStatusCode());
            self::assertStringContainsString($reason, (string) $response->getBody());
        }
    }

    public function testClaimMissingIs403WithoutLiveCall(): void
    {
        $response = $this->dispatch($this->guard('invoice.print', ['role' => 'allow']), $this->request($this->token(['invoice.view'])));

        self::assertSame(403, $response->getStatusCode());
        self::assertSame([], $this->checker->requests);
    }

    public function testObjectResolverAddsALiveObjectCheck(): void
    {
        $resolver = static fn(ServerRequestInterface $r): array => ['type' => 'invoice', 'id' => basename($r->getUri()->getPath())];

        $ok = $this->guard('invoice.view', ['object' => 'allow'], Guard::MODE_LIVE, $resolver);
        self::assertSame(204, $this->dispatch($ok, $this->request($this->token()))->getStatusCode());
        self::assertSame('inv-001', $this->checker->requests[0]['object']['id'] ?? null);

        $no = $this->guard('invoice.view', ['object' => 'deny'], Guard::MODE_LIVE, $resolver);
        self::assertSame(403, $this->dispatch($no, $this->request($this->token()))->getStatusCode());
    }

    public function testHintModeIsClaimOnlyForReads(): void
    {
        $guard = $this->guard('invoice.view', ['role' => 'deny'], Guard::MODE_HINT);

        self::assertSame(204, $this->dispatch($guard, $this->request($this->token()))->getStatusCode());
        self::assertSame([], $this->checker->requests);
        self::assertSame(403, $this->dispatch($guard, $this->request($this->token([])))->getStatusCode());
    }

    public function testHintModeIsRefusedForWrites(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->guard('invoice.print', [], Guard::MODE_HINT);
    }

    public function testHintModeIsRefusedWithAnObjectResolver(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->guard('invoice.view', [], Guard::MODE_HINT, static fn(): array => ['type' => 'invoice', 'id' => 'x']);
    }

    public function testUnknownModeIsRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->guard('invoice.view', [], 'fast');
    }
}
