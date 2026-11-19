<?php

declare(strict_types=1);

namespace NoidOss\Authz;

/** The algorithm step that produced a denial (README "The helper"). */
enum Step: string
{
    case Token = 'token';                    // step 1
    case Request = 'request';                // step 2
    case Claim = 'claim';                    // step 3
    case LivePermission = 'live_permission'; // step 4
    case LiveObject = 'live_object';         // step 5
}
