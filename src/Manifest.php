<?php

declare(strict_types=1);

namespace NoidOss\Authz;

use InvalidArgumentException;

/**
 * The part of an app's permissions.yaml the SDK needs: which permissions are reads.
 * Everything else, including names not in the manifest, is a write.
 */
final readonly class Manifest
{
    /** @var list<string> */
    private array $reads;

    /** @var list<string>|null declared object types; null when the manifest declares none (any well-formed type is accepted) */
    private ?array $resources;

    /**
     * @param array<mixed>      $reads     list of permission names; anything but strings is refused
     * @param array<mixed>|null $resources declared object types (list of types, or map type => options); null = undeclared
     */
    public function __construct(array $reads = [], ?array $resources = null)
    {
        foreach ($reads as $read) {
            if (!is_string($read)) {
                throw new InvalidArgumentException('reads must be a list of strings');
            }
        }
        $this->reads = array_values(array_unique($reads));

        if (null === $resources) {
            $this->resources = null;

            return;
        }
        $types = array_is_list($resources) ? $resources : array_keys($resources);
        foreach ($types as $type) {
            if (!Grammar::isObjectType($type)) {
                throw new InvalidArgumentException('resources must be a list of object types or a map keyed by object type');
            }
        }
        /** @var list<string> $types */
        $this->resources = array_values(array_unique($types));
    }

    /**
     * @param array<mixed> $manifest decoded permissions.yaml (needs at least `reads`)
     */
    public static function fromArray(array $manifest): self
    {
        $reads = $manifest['reads'] ?? null;
        if (!is_array($reads) || !array_is_list($reads)) {
            throw new InvalidArgumentException('manifest.reads is required and must be a list (use [] for none)');
        }
        $permissions = $manifest['permissions'] ?? null;
        if (is_array($permissions)) {
            foreach ($reads as $read) {
                if (!in_array($read, $permissions, true)) {
                    throw new InvalidArgumentException(sprintf('reads entry "%s" is not a declared permission', is_string($read) ? $read : get_debug_type($read)));
                }
            }
        }
        $resources = $manifest['resources'] ?? null;
        if (null !== $resources && !is_array($resources)) {
            throw new InvalidArgumentException('manifest.resources must be a list or a map');
        }

        return new self($reads, $resources);
    }

    public static function fromYamlFile(string $path): self
    {
        if (!class_exists(\Symfony\Component\Yaml\Yaml::class)) {
            throw new \LogicException('Manifest::fromYamlFile() needs symfony/yaml (composer require symfony/yaml).');
        }
        $data = \Symfony\Component\Yaml\Yaml::parseFile($path);
        if (!is_array($data)) {
            throw new InvalidArgumentException('permissions.yaml must be a mapping');
        }

        return self::fromArray($data);
    }

    public function isRead(string $permission): bool
    {
        return in_array($permission, $this->reads, true);
    }

    /** True when the manifest declares no resources (any well-formed type) or declares this type. */
    public function acceptsObjectType(string $type): bool
    {
        return null === $this->resources || in_array($type, $this->resources, true);
    }

    /**
     * @return list<string>
     */
    public function reads(): array
    {
        return $this->reads;
    }
}
