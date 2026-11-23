# Conformance fixtures

`vectors.json` is a verbatim copy of `vectors.json` from the `authz-spec` repo. Do not edit it.

- Pin: `vectors.pin.json` holds its SHA-256 and `specVersion`. `VectorsPinTest` fails (never skips) if the copy does not match the pin.
- Sections: the SDK runs `vectors` and `linkVectors`. `relationVectors` and `bindingVectors` (added in spec 2.2.0, 6 cases) are about the check service, not the SDK: they are pinned (presence and count, in `VectorsPinTest`) but not implemented here.
- Sync: `composer vectors:sync` (or `php scripts/sync-vectors.php /path/to/authz-spec`) copies the spec file and rewrites the pin.
- Drift check: `composer vectors:check` (`php scripts/sync-vectors.php --check`) fails when the fixture differs from the
  spec checkout (`../authz-spec` or `$AUTHZ_SPEC_DIR`). It needs the checkout, so it is not part of `composer check`.
- authz-spec had no commits when this was pinned, so the pin is the file hash, not a git revision. Once the spec
  is tagged, add the tag here.
