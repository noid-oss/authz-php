<?php

declare(strict_types=1);

namespace AuthZ\Tests\Support;

use AuthZ\Http\Checker;
use AuthZ\Http\CheckOutcome;
use AuthZ\Http\CheckResult;

/** Stub of the live service driven by a vector's `liveCheck` (role = no object, object = with object). */
final class StubChecker implements Checker
{
    /** @var list<array{permission: string, subject: string, object?: array{type: string, id: string}}> */
    public array $requests = [];

    /**
     * @param array{role?: string, object?: string} $liveCheck
     */
    public function __construct(private readonly array $liveCheck) {}

    public function check(array $request): CheckResult
    {
        $this->requests[] = $request;
        $kind = array_key_exists('object', $request) ? 'object' : 'role';
        // Default is not_called: an unexpected call is an error, never an allow.
        $outcome = CheckOutcome::tryFrom($this->liveCheck[$kind] ?? 'not_called') ?? CheckOutcome::Error;

        return new CheckResult($outcome);
    }
}
