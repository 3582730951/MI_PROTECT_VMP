#!/usr/bin/env python3
import json, pathlib, subprocess, sys

def main():
    tool = pathlib.Path(sys.argv[1])
    binary_dir = pathlib.Path(sys.argv[2])
    work = binary_dir / 'tests' / 'rewriter_unknown_format'
    work.mkdir(parents=True, exist_ok=True)
    bad = work / 'bad.bin'
    policy = work / 'policy.json'
    out = work / 'out.bin'
    bad.write_bytes(b'not a known format')
    policy.write_text(json.dumps({'schema_version':1,'defaults':{'language_origin':'binary','annotation_origin':'external_manifest','protection_domain':'native','jit_policy':'off','plaintext_budget':'transient_only','reaction_policy':'log','integrity_level':'basic','platform_caps':['linux','x64'],'sensitivity_level':'normal','profile_seed':1,'mobile_bridge_mode':'off','event_types':[]},'entries':[]}, indent=2))
    res = subprocess.run([str(tool), '--policy', str(policy), '--input', str(bad), '--output', str(out)], text=True, capture_output=True)
    if res.returncode == 0:
        raise SystemExit('expected non-zero exit for unknown format')
    if 'binary_format_unknown' not in (res.stdout + res.stderr):
        raise SystemExit('missing binary_format_unknown audit/error')
    print('rewriter_unknown_format_rejected OK')

if __name__ == '__main__':
    main()
