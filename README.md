# noid-oss/authz (PHP)

PHP 8.2+ SDK for the [authz-spec](../authz-spec) contract: one account across brands, a Kratos + Hydra per brand, Keto as the permission store.

- `verify($token)`: signature and `exp` against the issuer's JWKS, issuer in a known list, `tenant_id` equals the configured tenant.
- `hint($token)->can($permission)`: reads the token's `permissions` claim only. A hint, never authority.
- `CheckClient::check([...])`: live `POST /v1/check`, short timeout, fail closed, no retry, no cache.
- `Perms::can($user, $permission, $object = null)` and `Perms::explain(...)`: the exact algorithm of the spec README.
- `Guard`: PSR-15 middleware. Writes are checked live by default.

Dependencies: `firebase/php-jwt` and the PSR interfaces (PSR-7, 15, 17, 18). Bring your own PSR-18 client and PSR-17 factories.

## Rules the SDK enforces

1. The token's `permissions` claim is a hint. A missing claim denies without a network call.
2. A permission not listed under `reads` in the manifest is a write, including typos and names not in the manifest. Writes are always checked live.
3. Any error, non-200, malformed body, `allowed` that is not literally `true`, or timeout is a deny.
4. A read with an object still gets a live object check. A read revoked in Keto stays allowed until the token expires (known, accepted).
5. `brand`, `app` and `subject` of every live call come from `Config` and the token `sub`, never from the caller.
6. Object ids are namespaced `<brand>/<app>/<type>/<id>` by the check service; the SDK rejects any `type`/`id` outside the grammar before any call. `brand` is the tenant slug (`^[a-z0-9][a-z0-9-]{0,62}$`), `app` and object ids match `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` without `..`; an invalid `brand`/`app` makes `Config` throw (spec reason `invalid_config`). `Grammar::linkReason()` implements the Resource link rules (`#app` and `#parent` stay inside the object's brand/app).
7. Apps never call keto-read. Only the check service.

## Install

```sh
composer require noid-oss/authz
```

Needs a PSR-18 client (for example `guzzlehttp/guzzle`) and PSR-17 factories (Guzzle's `HttpFactory`, `nyholm/psr7`, ...).

## Setup

```php
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\HttpFactory;
use NoidOss\Authz\{Config, Manifest, Perms, TokenVerifier};
use NoidOss\Authz\Http\CheckClient;

$config = new Config(
    brand: 'idbi',
    app: 'billing',                            // the app's OAuth client_id (a Hydra UUID is fine)
    issuer: 'https://auth.idbi.example/',      // matched exactly, trailing slash included
    tenantId: 'idbi',
    checkUrl: 'https://authz.idbi.example/v1/check',
    appCredential: getenv('AUTHZ_APP_CREDENTIAL'),
    timeoutSeconds: 2.0,
    // issuers: ['https://auth.idbi.example/' => 'https://auth.idbi.example/jwks.json'],  // optional JWKS override / several brands
    // audience: 'billing',                                                              // optional aud check
);

// IMPORTANT: PSR-18 has no portable timeout. Set it on the client (<= timeoutSeconds).
$http = new Client(['timeout' => 2.0, 'connect_timeout' => 1.0, 'http_errors' => false]);
$factory = new HttpFactory();

$verifier = new TokenVerifier($config, $http, $factory);
$checks = new CheckClient($config, $http, $factory, $factory);
$manifest = Manifest::fromYamlFile(__DIR__ . '/permissions.yaml'); // needs symfony/yaml; or: new Manifest(['invoice.view'])
$perms = new Perms($config, $manifest, $checks);
```

`CheckClient` also denies as `timeout` any call that took longer than `timeoutSeconds`, but it cannot interrupt a hanging client.

## Examples

Verify a token, then ask for permissions.

```php
use NoidOss\Authz\TokenException;

try {
    $user = $verifier->verify($bearerToken);       // VerifiedToken
} catch (TokenException $e) {
    // $e->reason: malformed_token, unknown_issuer, invalid_signature, token_expired,
    //             invalid_tenant, invalid_subject, invalid_audience, jwks_unavailable
    http_response_code(401);
    exit;
}

$perms->can($user, 'invoice.view');                                          // read: claim only
$perms->can($user, 'invoice.print', ['type' => 'invoice', 'id' => 'inv-001']); // write + object: two live calls, in order
```

Claim hint only (never use it to authorize a write):

```php
TokenVerifier::hint($user)->can('invoice.view');   // true only if permissions is an array containing exactly that string
```

Live check directly (no token checks, no claim step):

```php
$result = $checks->check([
    'permission' => 'invoice.print',
    'subject' => $user->subject(),
    'object' => ['type' => 'invoice', 'id' => 'inv-001'],   // optional
]);
$result->allowed();   // true only for HTTP 200 with allowed === true
$result->outcome;     // CheckOutcome::Allow | Deny | Error | Timeout
```

Find out why something was denied.

```php
$d = $perms->explain($user, 'invoice.print', ['type' => 'invoice', 'id' => 'inv-001']);
$d->allowed;     // false
$d->reason;      // Reason::ObjectDenied
$d->deniedAt;    // Step::LiveObject  (Token, Request, Claim, LivePermission, LiveObject; null when allowed)
$d->liveCalls;   // [['permission' => 'invoice.print'], ['permission' => 'invoice.print', 'object' => [...]]]
```

Reasons: `allowed_claim`, `allowed_live`, `invalid_issuer`, `invalid_tenant`, `invalid_subject`, `token_expired`, `invalid_request`, `invalid_object`, `permission_not_in_claim`, `denied`, `object_denied`, `check_error`, `check_timeout`.

## HTTP guard (PSR-15)

```php
use NoidOss\Authz\Guard;

// Default 'live' mode: writes are checked live. 401 = no/invalid token, 403 = denied (also on check error/timeout).
$print = new Guard($verifier, $perms, $factory, 'invoice.print');

// With an object taken from the request (adds a live object check, also for reads):
$print = new Guard($verifier, $perms, $factory, 'invoice.print', Guard::MODE_LIVE,
    fn ($request) => ['type' => 'invoice', 'id' => $request->getAttribute('invoiceId')]);

// Explicit opt-out for reads only: claim hint, no network. The constructor throws for any permission
// not listed under `reads`, and for an object resolver (an object check is live by definition).
$list = new Guard($verifier, $perms, $factory, 'invoice.view', Guard::MODE_HINT);
```

On success the request carries `Guard::ATTR_TOKEN` (`VerifiedToken`) and `Guard::ATTR_DECISION` (`Decision`).

## Conformance with the spec

`tests/fixtures/vectors.json` is a pinned, verbatim copy of `authz-spec/vectors.json`, and `VectorsTest` runs every case through `Perms`
(allowed, reason and ordered live calls). See `tests/fixtures/README.md`.

```sh
composer vectors:sync            # copy from ../authz-spec (or $AUTHZ_SPEC_DIR) and re-pin the sha256
php scripts/sync-vectors.php --check
```

`VectorsPinTest` fails if the copy was edited by hand or differs from a spec checkout next to this repo. Do not diverge: change the spec, then sync.

## Development

```sh
composer install
composer test     # PHPUnit
composer stan     # PHPStan level 9
composer cs       # php-cs-fixer (dry run); composer cs:fix to apply
composer lint     # php -l + cs + stan
composer check    # lint + test
```
