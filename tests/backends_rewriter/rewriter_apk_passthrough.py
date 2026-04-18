#!/usr/bin/env python3
import json, pathlib, shutil, struct, subprocess, sys, zipfile
from rewriter_elf_roundtrip import read_elf_sections


def main():
    tool = pathlib.Path(sys.argv[1])
    binary_dir = pathlib.Path(sys.argv[2])
    work = binary_dir / 'tests' / 'rewriter_apk_passthrough'
    if work.exists(): shutil.rmtree(work)
    work.mkdir(parents=True)
    src = work / 'libfoo.c'
    src.write_text('extern const char kProtectedString[] __attribute__((visibility("default"))); const char kProtectedString[] = "apk-secret"; int foo(void){return kProtectedString[0];}\n')
    so = work / 'libfoo.so'
    subprocess.run(['cc', '-shared', '-fPIC', str(src), '-o', str(so)], check=True)
    apk = work / 'in.apk'
    manifest = b'<manifest package="x" />'
    with zipfile.ZipFile(apk, 'w', compression=zipfile.ZIP_STORED) as zf:
        zf.writestr('AndroidManifest.xml', manifest)
        zf.writestr('classes.dex', b'dex\n035\x00dummy')
        zf.write(so, 'lib/arm64-v8a/libfoo.so', compress_type=zipfile.ZIP_STORED)
    out = work / 'out.apk'
    policy = work / 'policy.json'
    policy.write_text(json.dumps({'schema_version':1,'defaults':{'language_origin':'binary','annotation_origin':'external_manifest','protection_domain':'native','jit_policy':'off','plaintext_budget':'transient_only','reaction_policy':'log','integrity_level':'basic','platform_caps':['android','arm64'],'sensitivity_level':'normal','profile_seed':1,'mobile_bridge_mode':'off','event_types':[]},'entries':[{'symbol_or_region':'lib/arm64-v8a/libfoo.so::kProtectedString','language_origin':'binary','annotation_origin':'external_manifest','protection_domain':'native','jit_policy':'off','plaintext_budget':'transient_only','reaction_policy':'log','integrity_level':'basic','platform_caps':['android','arm64'],'sensitivity_level':'highly_sensitive','profile_seed':1,'mobile_bridge_mode':'off','annotation_tags':['vm_string'],'event_types':[]}]}, indent=2))
    subprocess.run([str(tool), '--policy', str(policy), '--input', str(apk), '--output', str(out)], check=True)
    with zipfile.ZipFile(out, 'r') as zf:
        if zf.read('AndroidManifest.xml') != manifest:
            raise SystemExit('manifest changed')
        inner = work / 'inner.so'
        inner.write_bytes(zf.read('lib/arm64-v8a/libfoo.so'))
    _, sections = read_elf_sections(inner)
    if '.vmpstrings' not in sections:
        raise SystemExit('inner so missing .vmpstrings')
    print('rewriter_apk_passthrough OK')

if __name__ == '__main__':
    main()
