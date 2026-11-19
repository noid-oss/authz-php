<?php

declare(strict_types=1);

namespace AuthZ\Http;

enum CheckOutcome: string
{
    case Allow = 'allow';
    case Deny = 'deny';
    case Error = 'error';
    case Timeout = 'timeout';
}
