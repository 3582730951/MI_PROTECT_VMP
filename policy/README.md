# Policy IR

`policy/` implements the shared Protection Policy IR described in `plan.txt` §4/§5/§9/§13/§14/§19.

## Format
- Serialization format: **JSON**
- Schema version: `1`
- Unknown fields: **rejected** during load (`deny_unknown_fields` / strict parser)
- Loader behavior: missing entry fields inherit from `defaults`

## Root schema
```json
{
  "schema_version": 1,
  "defaults": { ... },
  "entries": [ { ... } ]
}
```

## Field reference
### Shared policy fields (`defaults` and resolved `entries`)
- `language_origin`: `c | cpp | rust | binary`
- `annotation_origin`: `attribute | pragma | proc_macro | external_manifest`
- `protection_domain`: `native | vm1 | vm2`
- `jit_policy`: `off | hot_only | aggressive`
- `plaintext_budget`: `none | transient_only`
- `reaction_policy`: `log | degrade | decoy_terminate | audit_only | audit_then_delayed_exit`
- `integrity_level`: `none | basic | strict`
- `platform_caps`: array of `windows | linux | android | ios | x86 | x64 | arm | arm64 | jit_allowed | execmem_allowed | wx_enforced`
- `sensitivity_level`: `normal | sensitive | highly_sensitive`
- `profile_seed`: `uint64`
- `mobile_bridge_mode`: `off | android_jni | ios_swift_objc | both`
- `event_types`: semantic event tags used by validation (for example `hw_breakpoint`)

### Entry-only fields
- `symbol_or_region`: protected symbol name or binary region identifier
- `source_location.file`
- `source_location.line`
- `source_location.column`
- `annotation_tags`: semantic source annotations (`vm_func`, `vm_string`)

## Annotation mapping (§5)
### `VM_func` / `#[vm_func]`
- `apply_vm_func_annotation(entry)`
- Adds semantic tag `vm_func`
- Ensures `protection_domain` is at least `vm1`
- Raises `sensitivity_level` to at least `sensitive`

### `VM_string` / `#[vm_string]`
- `apply_vm_string_annotation(entry)`
- Adds semantic tag `vm_string`
- Forces `sensitivity_level = highly_sensitive`
- Forces `plaintext_budget` to `transient_only` unless it is already `none`

### Combined use
When both annotations are applied to the same function:
- execution domain follows `VM_func`
- data protection follows `VM_string`

## Example JSON
```json
{
  "schema_version": 1,
  "defaults": {
    "language_origin": "cpp",
    "annotation_origin": "attribute",
    "protection_domain": "native",
    "jit_policy": "off",
    "plaintext_budget": "transient_only",
    "reaction_policy": "log",
    "integrity_level": "basic",
    "platform_caps": ["linux", "x64", "jit_allowed"],
    "sensitivity_level": "normal",
    "profile_seed": 123456,
    "mobile_bridge_mode": "off",
    "event_types": []
  },
  "entries": [
    {
      "symbol_or_region": "secure::verify_score",
      "protection_domain": "vm1",
      "reaction_policy": "audit_then_delayed_exit",
      "sensitivity_level": "highly_sensitive",
      "annotation_tags": ["vm_func", "vm_string"],
      "event_types": ["hw_breakpoint"],
      "source_location": {
        "file": "src/secure.cpp",
        "line": 42,
        "column": 3
      }
    }
  ]
}
```

## Hard constraints
Validation errors are emitted for:
1. `vm_func` entries with `protection_domain = native`
2. `vm_string` entries without `sensitivity_level = highly_sensitive`
3. `vm_string` entries must keep `plaintext_budget` within `none | transient_only` (other values are rejected at load time)
4. `reaction_policy = audit_then_delayed_exit` without `event_types` containing `hw_breakpoint`
5. `platform_caps` containing `ios` without `jit_allowed` while `jit_policy = aggressive`
6. `protection_domain = vm2` without `integrity_level = strict`
7. invalid enum/capability values or unknown JSON fields during load

## Soft constraints
Validation warnings are emitted for:
- `profile_seed == 0`
- `sensitivity_level = normal` with `plaintext_budget = none`

## CLI
```bash
/workspace/vmp/build-linux-x64/tools/vmp-protect --policy tests/policy/examples/good.json
/workspace/vmp/build-linux-x64/tools/vmp-protect --policy tests/policy/examples/good.json --emit-policy-json /tmp/policy.json
/workspace/vmp/build-linux-x64/tools/vmp-protect --dump-schema
```
