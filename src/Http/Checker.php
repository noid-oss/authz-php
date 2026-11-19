<?php

declare(strict_types=1);

namespace AuthZ\Http;

interface Checker
{
    /**
     * @param array{permission: string, subject: string, object?: array{type: string, id: string}} $request
     *
     * Must never throw for transport or decision problems: those are Error / Timeout / Deny.
     */
    public function check(array $request): CheckResult;
}
