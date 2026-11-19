<?php

declare(strict_types=1);

namespace NoidOss\Authz;

/** Decision reasons, identical to the spec's vectors.schema.json. */
enum Reason: string
{
    case AllowedClaim = 'allowed_claim';
    case AllowedLive = 'allowed_live';
    case InvalidIssuer = 'invalid_issuer';
    case InvalidTenant = 'invalid_tenant';
    case InvalidSubject = 'invalid_subject';
    case TokenExpired = 'token_expired';
    case InvalidConfig = 'invalid_config';
    case InvalidRequest = 'invalid_request';
    case InvalidObject = 'invalid_object';
    case PermissionNotInClaim = 'permission_not_in_claim';
    case Denied = 'denied';
    case ObjectDenied = 'object_denied';
    case CheckError = 'check_error';
    case CheckTimeout = 'check_timeout';
}
