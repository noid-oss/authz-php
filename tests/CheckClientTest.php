<?php

declare(strict_types=1);

namespace NoidOss\Authz\Tests;

use NoidOss\Authz\Config;
use NoidOss\Authz\Http\CheckClient;
use NoidOss\Authz\Http\CheckOutcome;
use NoidOss\Authz\Tests\Support\FakeHttp;
use NoidOss\Authz\Tests\Support\NetworkError;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

final class CheckClientTest extends TestCase
{
    private const REQ = ['permission' => 'invoice.print', 'subject' => 'ana'];

    private function client(FakeHttp $http, float $timeout = 2.0): CheckClient
    {
        $f = new Psr17Factory();
        $config = new Config('idbi', 'billing', 'https://auth.idbi.example/', 'idbi', 'https://authz.example/v1/check', 's3cret', $timeout);

        return new CheckClient($config, $http, $f, $f);
    }

    private static function json(int $status, string $body): ResponseInterface
    {
        return new Response($status, ['Content-Type' => 'application/json'], $body);
    }

    public function testSendsBrandAppAndCredentialFromConfig(): void
    {
        $http = new FakeHttp(fn() => self::json(200, '{"allowed":true,"reason":"allowed"}'));
        $result = $this->client($http)->check(self::REQ + ['object' => ['type' => 'invoice', 'id' => 'inv-001']]);

        self::assertTrue($result->allowed());
        $sent = $http->sent[0];
        self::assertSame('POST', $sent->getMethod());
        self::assertSame('https://authz.example/v1/check', (string) $sent->getUri());
        self::assertSame('Bearer s3cret', $sent->getHeaderLine('Authorization'));
        self::assertSame(
            ['brand' => 'idbi', 'app' => 'billing', 'subject' => 'ana', 'permission' => 'invoice.print', 'object' => ['type' => 'invoice', 'id' => 'inv-001']],
            json_decode((string) $sent->getBody(), true),
        );
    }

    public function testCallerCannotOverrideBrandOrApp(): void
    {
        $http = new FakeHttp(fn() => self::json(200, '{"allowed":true,"reason":"allowed"}'));
        $this->client($http)->check(self::REQ + ['brand' => 'other', 'app' => 'crm']);

        $body = json_decode((string) $http->sent[0]->getBody(), true);
        self::assertIsArray($body);
        self::assertSame('idbi', $body['brand']);
        self::assertSame('billing', $body['app']);
    }

    /**
     * @return iterable<string, array{ResponseInterface, CheckOutcome}>
     */
    public static function responses(): iterable
    {
        yield 'allowed false' => [self::json(200, '{"allowed":false,"reason":"denied"}'), CheckOutcome::Deny];
        yield 'unknown_permission' => [self::json(200, '{"allowed":false,"reason":"unknown_permission"}'), CheckOutcome::Deny];
        yield 'allowed string "true"' => [self::json(200, '{"allowed":"true"}'), CheckOutcome::Error];
        yield 'allowed 1' => [self::json(200, '{"allowed":1}'), CheckOutcome::Error];
        yield 'allowed missing' => [self::json(200, '{"reason":"allowed"}'), CheckOutcome::Error];
        yield 'empty object' => [self::json(200, '{}'), CheckOutcome::Error];
        yield 'list' => [self::json(200, '[true]'), CheckOutcome::Error];
        yield 'scalar true' => [self::json(200, 'true'), CheckOutcome::Error];
        yield 'invalid json' => [self::json(200, '{allowed:true'), CheckOutcome::Error];
        yield 'empty body' => [self::json(200, ''), CheckOutcome::Error];
        yield '201 with allowed true' => [self::json(201, '{"allowed":true}'), CheckOutcome::Error];
        yield '204' => [self::json(204, ''), CheckOutcome::Error];
        yield '400' => [self::json(400, '{"error":"invalid_request"}'), CheckOutcome::Error];
        yield '401' => [self::json(401, '{"error":"unauthorized"}'), CheckOutcome::Error];
        yield '403 even with allowed true' => [self::json(403, '{"allowed":true}'), CheckOutcome::Error];
        yield '429' => [self::json(429, ''), CheckOutcome::Error];
        yield '500' => [self::json(500, '{"allowed":true}'), CheckOutcome::Error];
        yield '502' => [self::json(502, ''), CheckOutcome::Error];
        yield '504' => [self::json(504, ''), CheckOutcome::Error];
    }

    #[DataProvider('responses')]
    public function testOnlyA200WithLiteralTrueAllows(ResponseInterface $response, CheckOutcome $expected): void
    {
        $result = $this->client(new FakeHttp(fn() => $response))->check(self::REQ);

        self::assertSame($expected, $result->outcome);
        self::assertFalse($result->allowed());
    }

    public function testNetworkErrorIsErrorAndTimeoutIsTimeout(): void
    {
        $error = $this->client(new FakeHttp(fn($r) => throw new NetworkError($r, 'connection refused')))->check(self::REQ);
        self::assertSame(CheckOutcome::Error, $error->outcome);

        $curl = $this->client(new FakeHttp(fn($r) => throw new NetworkError($r, 'cURL error 28', 28)))->check(self::REQ);
        self::assertSame(CheckOutcome::Timeout, $curl->outcome);

        $text = $this->client(new FakeHttp(fn($r) => throw new NetworkError($r, 'Operation timed out after 2000 ms')))->check(self::REQ);
        self::assertSame(CheckOutcome::Timeout, $text->outcome);
    }

    public function testNonPsrThrowableIsAnErrorNotAnException(): void
    {
        $result = $this->client(new FakeHttp(fn() => throw new \RuntimeException('boom')))->check(self::REQ);

        self::assertSame(CheckOutcome::Error, $result->outcome);
    }

    public function testSlowAllowIsTreatedAsTimeout(): void
    {
        $http = new FakeHttp(function (): ResponseInterface {
            usleep(60_000);

            return self::json(200, '{"allowed":true}');
        });
        $result = $this->client($http, 0.01)->check(self::REQ);

        self::assertSame(CheckOutcome::Timeout, $result->outcome);
    }

    public function testInvalidInputMakesNoNetworkCall(): void
    {
        $http = new FakeHttp(fn() => self::json(200, '{"allowed":true}'));
        $client = $this->client($http);

        self::assertFalse($client->check(['permission' => 'Invoice.print', 'subject' => 'ana'])->allowed());
        self::assertFalse($client->check(['permission' => 'invoice.print', 'subject' => ''])->allowed());
        self::assertFalse($client->check(self::REQ + ['object' => ['type' => 'invoice', 'id' => '../x']])->allowed());
        self::assertFalse($client->check(self::REQ + ['object' => 'inv-001'])->allowed());
        self::assertSame([], $http->sent);
    }

    public function testEveryCallHitsTheServiceNothingIsCached(): void
    {
        $http = new FakeHttp(fn() => self::json(200, '{"allowed":true}'));
        $client = $this->client($http);
        $client->check(self::REQ);
        $client->check(self::REQ);

        self::assertCount(2, $http->sent);
    }
}
