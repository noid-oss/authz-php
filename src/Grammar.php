<?php

declare(strict_types=1);

namespace AuthZ;

/**
 * Naming grammars from authz-spec MANIFEST.md.
 *
 * All patterns end with \z (not $) so a trailing "\n" never passes, and none use /u,
 * so non-ASCII bytes (fullwidth solidus, division slash, ...) never match.
 */
final class Grammar
{
    private const PERMISSION = '/^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\z/';
    private const OBJECT_TYPE = '/^[a-z][a-z0-9_]{0,31}\z/';
    /** Object id and app (the OAuth client_id, so a Hydra UUID fits) share one grammar. */
    private const OBJECT_ID = '/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z/';
    /** Brand: the tenant slug (same as TENANT_SLUG in noid-console). */
    private const BRAND = '/^[a-z0-9][a-z0-9-]{0,62}\z/';

    private function __construct() {}

    public static function isPermission(mixed $value): bool
    {
        return is_string($value) && strlen($value) <= 64 && 1 === preg_match(self::PERMISSION, $value);
    }

    public static function isObjectType(mixed $value): bool
    {
        return is_string($value) && strlen($value) <= 32 && 1 === preg_match(self::OBJECT_TYPE, $value);
    }

    public static function isObjectId(mixed $value): bool
    {
        return is_string($value)
            && 1 === preg_match(self::OBJECT_ID, $value)
            && !str_contains($value, '..');
    }

    public static function isBrand(mixed $value): bool
    {
        return is_string($value) && 1 === preg_match(self::BRAND, $value);
    }

    /** The app is the OAuth client_id: same grammar as an object id, no "..". */
    public static function isApp(mixed $value): bool
    {
        return self::isObjectId($value);
    }

    /**
     * Parses a Keto object `<brand>/<app>/<type>/<id>`: exactly four segments, each valid under its own grammar.
     *
     * @return array{brand: string, app: string, type: string, id: string}|null
     */
    public static function ketoObject(mixed $value): ?array
    {
        if (!is_string($value)) {
            return null;
        }
        $parts = explode('/', $value);
        if (4 !== count($parts)) {
            return null;
        }
        [$brand, $app, $type, $id] = $parts;
        if (!self::isBrand($brand) || !self::isApp($app) || !self::isObjectType($type) || !self::isObjectId($id)) {
            return null;
        }

        return ['brand' => $brand, 'app' => $app, 'type' => $type, 'id' => $id];
    }

    /**
     * Link rules for a Resource tuple (checked in order: object, #app, #parent).
     * `$app` is the value of the `#app` link (the part after `App:`), `$parent` the optional `#parent` object.
     *
     * @return 'ok'|'invalid_object'|'app_mismatch'|'invalid_parent'|'parent_mismatch'
     */
    public static function linkReason(mixed $object, mixed $app, mixed $parent = null): string
    {
        $o = self::ketoObject($object);
        if (null === $o) {
            return 'invalid_object';
        }
        if (!is_string($app) || $app !== $o['app']) {
            return 'app_mismatch';
        }
        if (null === $parent) {
            return 'ok';
        }
        $p = self::ketoObject($parent);
        if (null === $p) {
            return 'invalid_parent';
        }

        return ($p['brand'] === $o['brand'] && $p['app'] === $o['app']) ? 'ok' : 'parent_mismatch';
    }

    /**
     * @return array{type: string, id: string}|null null when the value is not a well-formed object reference
     */
    public static function object(mixed $value): ?array
    {
        if (!is_array($value)) {
            return null;
        }
        $type = $value['type'] ?? null;
        $id = $value['id'] ?? null;
        if (!is_string($type) || !is_string($id) || !self::isObjectType($type) || !self::isObjectId($id)) {
            return null;
        }

        return ['type' => $type, 'id' => $id];
    }
}
