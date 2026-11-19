<?php

declare(strict_types=1);

namespace AuthZ;

/** Result of Perms::explain(). */
final readonly class Decision
{
    /**
     * @param Step|null                                                              $deniedAt  null when allowed
     * @param list<array{permission: string, object?: array{type: string, id: string}}> $liveCalls in order
     */
    public function __construct(
        public bool $allowed,
        public Reason $reason,
        public ?Step $deniedAt,
        public array $liveCalls = [],
    ) {}
}
