<?php

declare(strict_types=1);

namespace AuthZ\Http;

use AuthZ\Config;
use AuthZ\Grammar;
use AuthZ\Reason;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Client\NetworkExceptionInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * Live check via POST /v1/check. Fails closed, never retries, never caches.
 *
 * Only `allowed === true` on a 200 JSON object is an allow. A PSR-18 client has no
 * portable timeout setting, so configure one on the client (<= Config::$timeoutSeconds);
 * this class additionally denies as a timeout any call that took longer than the budget.
 */
final class CheckClient implements Checker
{
    public function __construct(
        private readonly Config $config,
        private readonly ClientInterface $http,
        private readonly RequestFactoryInterface $requests,
        private readonly StreamFactoryInterface $streams,
    ) {}

    /**
     * Widened on purpose: input is re-validated here even though the interface documents a shape.
     *
     * @param array<string, mixed> $request
     */
    public function check(array $request): CheckResult
    {
        $permission = $request['permission'] ?? null;
        $subject = $request['subject'] ?? null;
        if (!Grammar::isPermission($permission)) {
            return new CheckResult(CheckOutcome::Error, Reason::InvalidRequest, 'invalid permission name');
        }
        if (!is_string($subject) || '' === $subject) {
            return new CheckResult(CheckOutcome::Error, Reason::InvalidSubject, 'empty subject');
        }
        $body = [
            'brand' => $this->config->brand,
            'app' => $this->config->app,
            'subject' => $subject,
            'permission' => $permission,
        ];
        if (array_key_exists('object', $request)) {
            $object = Grammar::object($request['object']);
            if (null === $object) {
                return new CheckResult(CheckOutcome::Error, Reason::InvalidObject, 'invalid object');
            }
            $body['object'] = $object;
        }

        try {
            $http = $this->requests->createRequest('POST', $this->config->checkUrl)
                ->withHeader('Content-Type', 'application/json')
                ->withHeader('Accept', 'application/json')
                ->withHeader('Authorization', 'Bearer ' . $this->config->appCredential)
                ->withBody($this->streams->createStream(json_encode($body, JSON_THROW_ON_ERROR)));
            $start = hrtime(true);
            $response = $this->http->sendRequest($http);
            $elapsed = (hrtime(true) - $start) / 1e9;
        } catch (ClientExceptionInterface $e) {
            return new CheckResult(self::isTimeout($e) ? CheckOutcome::Timeout : CheckOutcome::Error, null, $e->getMessage());
        } catch (\Throwable $e) {
            return new CheckResult(CheckOutcome::Error, null, $e->getMessage());
        }

        if ($elapsed > $this->config->timeoutSeconds) {
            return new CheckResult(CheckOutcome::Timeout, null, 'check exceeded the timeout budget');
        }
        if (200 !== $response->getStatusCode()) {
            return new CheckResult(CheckOutcome::Error, null, 'status ' . $response->getStatusCode());
        }
        try {
            $data = json_decode((string) $response->getBody(), true, 8, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return new CheckResult(CheckOutcome::Error, null, 'invalid JSON');
        }
        if (!is_array($data) || array_is_list($data) || !array_key_exists('allowed', $data) || !is_bool($data['allowed'])) {
            return new CheckResult(CheckOutcome::Error, null, 'malformed body');
        }

        return true === $data['allowed']
            ? new CheckResult(CheckOutcome::Allow)
            : new CheckResult(CheckOutcome::Deny);
    }

    private static function isTimeout(ClientExceptionInterface $e): bool
    {
        if (!$e instanceof NetworkExceptionInterface) {
            return false;
        }

        return 28 === $e->getCode() // CURLE_OPERATION_TIMEDOUT
            || 1 === preg_match('/time[ds]?[ -]?out/i', $e->getMessage());
    }
}
