#!/usr/bin/env python3
import json, pathlib, shutil, subprocess, sys, zipfile
from rewriter_macho_roundtrip import build_macho, parse_sections


def main():
    tool = pathlib.Path(sys.argv[1])
    binary_dir = pathlib.Path(sys.argv[2])
    work = binary_dir / 'tests' / 'rewriter_ipa_passthrough'
    if work.exists(): shutil.rmtree(work)
    work.mkdir(parents=True)
    macho = work / 'X'
    build_macho(macho)
    ipa = work / 'in.ipa'
    plist = b'<?xml version="1.0"?><plist><dict><key>CFBundleExecutable</key><string>X</string></dict></plist>'
    with zipfile.ZipFile(ipa, 'w', compression=zipfile.ZIP_STORED) as zf:
        zf.writestr('Payload/X.app/Info.plist', plist)
        zf.write(macho, 'Payload/X.app/X', compress_type=zipfile.ZIP_STORED)
    out = work / 'out.ipa'
    policy = work / 'policy.json'
    policy.write_text(json.dumps({'schema_version':1,'defaults':{'language_origin':'binary','annotation_origin':'external_manifest','protection_domain':'native','jit_policy':'off','plaintext_budget':'transient_only','reaction_policy':'log','integrity_level':'basic','platform_caps':['ios','arm64'],'sensitivity_level':'normal','profile_seed':1,'mobile_bridge_mode':'off','event_types':[]},'entries':[]}, indent=2))
    subprocess.run([str(tool), '--policy', str(policy), '--input', str(ipa), '--output', str(out)], check=True)
    with zipfile.ZipFile(out, 'r') as zf:
        inner = work / 'X.out'
        inner.write_bytes(zf.read('Payload/X.app/X'))
    sections = parse_sections(inner)
    if ('__DATA', '__vmp_load') not in sections:
        raise SystemExit('inner macho missing __vmp_load')
    print('rewriter_ipa_passthrough OK')

if __name__ == '__main__':
    main()
