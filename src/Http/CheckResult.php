<?php

declare(strict_types=1);

namespace AuthZ\Http;

use AuthZ\Reason;

final readonly class CheckResult
{
    public function __construct(
        public CheckOutcome $outcome,
        public ?Reason $reason = null,
        public string $detail = '',
    ) {}

    /** True only for a 200 response whose `allowed` is literally `true`. */
    public function allowed(): bool
    {
        return CheckOutcome::Allow === $this->outcome;
    }
}
