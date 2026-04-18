# backends/rewriter

Binary rewriter backend for post-hoc protection of existing PE / ELF / Mach-O / APK / IPA containers.

## Supported container formats
- **PE (PE32+)**
  - Parses DOS header, COFF header, optional header, section table, and the export/import/resource/reloc data-directory RVAs.
  - Rewrites:
    - adds `.vmpload`
    - adds `.CRT$XLB` registration section if absent
    - emits VM thunk metadata section when binary-origin policy entries target `vm1` / `vm2`
- **ELF (ELF64 little-endian)**
  - Parses ELF header, program headers, section headers, section/string tables, and symbol tables.
  - Rewrites:
    - creates `.vmpstrings`
    - creates `.vmp_init_array` companion constructor section
    - zeroes protected literals resolved from binary-origin `vm_string` policy entries
    - emits `.vmpvmthk` for VM bridge thunk metadata
- **Mach-O (64-bit little-endian synthetic/minimal images)**
  - Parses `mach_header_64`, `LC_SEGMENT_64`, `LC_DYLD_INFO`, `LC_SYMTAB`, `LC_DYSYMTAB`.
  - Rewrites:
    - adds `__DATA,__vmp_load`
    - adds `__DATA,__mod_init_func`
    - adds `__DATA,__vmp_strings`
    - emits `__DATA,__vmp_vmthk` when VM routes are requested
- **APK / IPA**
  - Stored-ZIP parser/writer.
  - APK rewrites matching `lib/<abi>/*.so` entries by running the ELF backend.
  - IPA resolves `CFBundleExecutable` from `Payload/*.app/Info.plist` and rewrites that Mach-O.

## Policy IR integration
- Input: Policy IR JSON schema v1.
- Only `language_origin = binary` entries drive this backend.
- `annotation_tags` containing `vm_string` + `sensitivity_level = highly_sensitive` trigger literal extraction, encrypted pool rebuild, zeroing, and `.vmpstrings` emission.
- `protection_domain = vm1|vm2` emits bridge-thunk metadata and preserves CLI-provided `--vm1-module` / `--vm2-module` paths in the emitted thunk descriptor blob.
- Symbol selectors may be written as:
  - `symbol_name`
  - `symbol_name+0xOFFSET`
  - `path/in/container::symbol_name`
  - `path/in/container::symbol_name+0xOFFSET`

## CLI
```bash
build/tools/vmp-protect \
  --policy policy.json \
  --input sample.elf \
  --output sample.protected \
  --strings-pool string_pool.bin \
  --strings-idx string_pool.idx.json \
  --vm1-module secure.vm1 \
  --vm2-module crown.vm2
```

## Test harness
CTest coverage lives in `tests/backends_rewriter/`:
- `rewriter_elf_roundtrip`
- `rewriter_pe_roundtrip` (feature-gated by MinGW availability)
- `rewriter_macho_roundtrip`
- `rewriter_apk_passthrough`
- `rewriter_ipa_passthrough`
- `rewriter_unknown_format_rejected`
- `rewriter_policy_mismatch`

## Limitations
- No code signing / notarization / re-signing. For PE, Mach-O, APK, IPA that remains a user step.
- PE support is intentionally MVP-level and assumes sufficient header slack for the injected section headers.
- ELF constructor emission uses a companion init-array section in this round instead of full PT_LOAD relocation surgery.
- Mach-O support is aimed at deterministic synthetic/minimal images used by the current harness.
- ZIP support currently handles stored entries only.
