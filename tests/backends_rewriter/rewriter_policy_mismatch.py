#!/usr/bin/env python3
import json, pathlib, subprocess, sys

def main():
    tool = pathlib.Path(sys.argv[1])
    binary_dir = pathlib.Path(sys.argv[2])
    srcroot = pathlib.Path(sys.argv[3])
    work = binary_dir / 'tests' / 'rewriter_policy_mismatch'
    work.mkdir(parents=True, exist_ok=True)
    src = work / 'a.c'
    src.write_text('int main(){return 0;}\n')
    elf = work / 'a.out'
    subprocess.run(['cc', str(src), '-o', str(elf)], check=True)
    policy = work / 'policy.json'
    out = work / 'out.elf'
    policy.write_text(json.dumps({'schema_version':1,'defaults':{'language_origin':'binary','annotation_origin':'external_manifest','protection_domain':'native','jit_policy':'off','plaintext_budget':'transient_only','reaction_policy':'log','integrity_level':'basic','platform_caps':['linux','x64'],'sensitivity_level':'normal','profile_seed':1,'mobile_bridge_mode':'off','event_types':[]},'entries':[{'symbol_or_region':'missing_symbol','language_origin':'binary','annotation_origin':'external_manifest','protection_domain':'native','jit_policy':'off','plaintext_budget':'transient_only','reaction_policy':'log','integrity_level':'basic','platform_caps':['linux','x64'],'sensitivity_level':'highly_sensitive','profile_seed':1,'mobile_bridge_mode':'off','annotation_tags':['vm_string'],'event_types':[]}]}, indent=2))
    res = subprocess.run([str(tool), '--policy', str(policy), '--input', str(elf), '--output', str(out)], text=True, capture_output=True)
    if res.returncode == 0:
        raise SystemExit('expected mismatch failure')
    if 'missing_symbol' not in (res.stdout + res.stderr):
        raise SystemExit('missing symbol name in error')
    print('rewriter_policy_mismatch OK')

if __name__ == '__main__':
    main()
