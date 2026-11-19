<?php

declare(strict_types=1);

namespace NoidOss\Authz\Tests;

use NoidOss\Authz\Config;
use NoidOss\Authz\Manifest;
use NoidOss\Authz\Perms;
use NoidOss\Authz\Reason;
use NoidOss\Authz\Step;
use NoidOss\Authz\Tests\Support\StubChecker;
use NoidOss\Authz\VerifiedToken;
use PHPUnit\Framework\TestCase;

final class PermsTest extends TestCase
{
    private const NOW = 1_800_000_000;

    private StubChecker $checker;

    /**
     * @param array{role?: string, object?: string} $live
     */
    private function perms(array $live): Perms
    {
        $this->checker = new StubChecker($live);

        return new Perms(
            new Config('idbi', 'billing', 'https://auth.idbi.example/', 'idbi'),
            new Manifest(['invoice.view']),
            $this->checker,
            static fn(): int => self::NOW,
        );
    }

    /**
     * @param array<string, mixed> $over
     *
     * @return array<string, mixed>
     */
    private function claims(array $over = []): array
    {
        return array_merge([
            'iss' => 'https://auth.idbi.example/', 'sub' => 'ana', 'tenant_id' => 'idbi',
            'exp' => self::NOW + 60, 'permissions' => ['invoice.view', 'invoice.print'],
        ], $over);
    }

    public function testExplainNamesTheDenyingStep(): void
    {
        $cases = [
            [$this->claims(['iss' => 'x']), 'invoice.view', null, Step::Token, Reason::InvalidIssuer],
            [$this->claims(), 'nope', null, Step::Request, Reason::InvalidRequest],
            [$this->claims(), 'invoice.view', ['type' => 'invoice', 'id' => 'a/b'], Step::Request, Reason::InvalidObject],
            [$this->claims(), 'invoice.void', null, Step::Claim, Reason::PermissionNotInClaim],
        ];
        foreach ($cases as [$claims, $permission, $object, $step, $reason]) {
            $d = $this->perms(['role' => 'allow', 'object' => 'allow'])->explain($claims, $permission, $object);
            self::assertFalse($d->allowed);
            self::assertSame($step, $d->deniedAt);
            self::assertSame($reason, $d->reason);
            self::assertSame([], $d->liveCalls);
        }

        $d = $this->perms(['role' => 'deny'])->explain($this->claims(), 'invoice.print');
        self::assertSame([Step::LivePermission, Reason::Denied], [$d->deniedAt, $d->reason]);

        $d = $this->perms(['role' => 'allow', 'object' => 'deny'])->explain($this->claims(), 'invoice.print', ['type' => 'invoice', 'id' => 'i1']);
        self::assertSame([Step::LiveObject, Reason::ObjectDenied], [$d->deniedAt, $d->reason]);
        self::assertCount(2, $d->liveCalls);

        $d = $this->perms(['role' => 'timeout'])->explain($this->claims(), 'invoice.print');
        self::assertSame([Step::LivePermission, Reason::CheckTimeout], [$d->deniedAt, $d->reason]);

        $d = $this->perms(['role' => 'allow'])->explain($this->claims(), 'invoice.print');
        self::assertTrue($d->allowed);
        self::assertNull($d->deniedAt);
        self::assertSame(Reason::AllowedLive, $d->reason);
    }

    public function testCanAcceptsAVerifiedTokenAndUsesItsSubAsSubject(): void
    {
        $perms = $this->perms(['role' => 'allow']);

        self::assertTrue($perms->can(new VerifiedToken($this->claims()), 'invoice.print'));
        self::assertSame([['permission' => 'invoice.print', 'subject' => 'ana']], $this->checker->requests);
    }

    public function testReadWithoutObjectNeverCallsTheService(): void
    {
        $perms = $this->perms(['role' => 'deny', 'object' => 'deny']);

        self::assertTrue($perms->can($this->claims(), 'invoice.view'));
        self::assertSame([], $this->checker->requests);
    }

    public function testCustomClaimsFallBackToExtButStandardOnesDoNot(): void
    {
        $raw = $this->claims();
        unset($raw['permissions'], $raw['tenant_id']);
        $raw['ext'] = ['permissions' => ['invoice.view'], 'tenant_id' => 'idbi', 'iss' => 'evil'];

        self::assertTrue($this->perms([])->can($raw, 'invoice.view'));

        $raw['exp'] = self::NOW + 60;
        unset($raw['iss']);
        self::assertSame(Reason::InvalidIssuer, $this->perms([])->explain($raw, 'invoice.view')->reason);
    }

    public function testExplainHintIsClaimOnlyAndRefusesWrites(): void
    {
        $perms = $this->perms(['role' => 'allow']);

        self::assertTrue($perms->explainHint($this->claims(), 'invoice.view')->allowed);
        self::assertSame([], $this->checker->requests);
        self::assertSame(Reason::PermissionNotInClaim, $perms->explainHint($this->claims(['permissions' => []]), 'invoice.view')->reason);

        $this->expectException(\LogicException::class);
        $perms->explainHint($this->claims(), 'invoice.print');
    }

    public function testConfigAcceptsUuidAppAndDigitBrand(): void
    {
        $config = new \NoidOss\Authz\Config('9idbi', '3F2B8C1E-9a4d-4e57-b6a0-1c2d3e4f5a6b', 'https://auth.example/', 'idbi');

        self::assertSame('3F2B8C1E-9a4d-4e57-b6a0-1c2d3e4f5a6b', $config->app);
    }
}
