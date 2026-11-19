<?php

declare(strict_types=1);

namespace NoidOss\Authz\Http;

enum CheckOutcome: string
{
    case Allow = 'allow';
    case Deny = 'deny';
    case Error = 'error';
    case Timeout = 'timeout';
}
