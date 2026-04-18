#!/usr/bin/env python3
import json, pathlib, struct, subprocess, sys, shutil

LC_SEGMENT_64 = 0x19
MH_MAGIC_64 = 0xfeedfacf


def build_macho(path: pathlib.Path):
    header = struct.pack('<IiiIIIII', MH_MAGIC_64, 0x01000007, 3, 2, 2, 0, 0, 0)
    seg_text_cmdsize = 72 + 80
    seg_data_cmdsize = 72 + 80
    sizeofcmds = seg_text_cmdsize + seg_data_cmdsize
    header = struct.pack('<IiiIIIII', MH_MAGIC_64, 0x01000007, 3, 2, 2, sizeofcmds, 0, 0)
    load_off = len(header)
    fileoff = len(header) + sizeofcmds
    text_data = b'\xc3\x90\x90\x90'
    data_data = b'DATA'
    text_off = fileoff
    data_off = text_off + len(text_data)
    seg_text = struct.pack('<II16sQQQQIIII', LC_SEGMENT_64, seg_text_cmdsize, b'__TEXT\0'*2, 0x100000000 + text_off, len(text_data), text_off, len(text_data), 5, 5, 1, 0)
    sec_text = struct.pack('<16s16sQQIIIIIIII', b'__text\0'*2, b'__TEXT\0'*2, 0x100000000 + text_off, len(text_data), text_off, 2, 0, 0, 0, 0, 0, 0)
    seg_data = struct.pack('<II16sQQQQIIII', LC_SEGMENT_64, seg_data_cmdsize, b'__DATA\0'*2, 0x100000000 + data_off, len(data_data), data_off, len(data_data), 3, 3, 1, 0)
    sec_data = struct.pack('<16s16sQQIIIIIIII', b'__data\0'*2, b'__DATA\0'*2, 0x100000000 + data_off, len(data_data), data_off, 2, 0, 0, 0, 0, 0, 0)
    path.write_bytes(header + seg_text + sec_text + seg_data + sec_data + text_data + data_data)


def parse_sections(path: pathlib.Path):
    data = path.read_bytes()
    if struct.unpack_from('<I', data, 0)[0] != MH_MAGIC_64:
        raise SystemExit('not macho')
    ncmds = struct.unpack_from('<I', data, 16)[0]
    off = 32
    out = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', data, off)
        if cmd == LC_SEGMENT_64:
            nsects = struct.unpack_from('<I', data, off + 64)[0]
            sec_off = off + 72
            for _ in range(nsects):
                sectname = data[sec_off:sec_off+16].split(b'\0',1)[0].decode()
                segname = data[sec_off+16:sec_off+32].split(b'\0',1)[0].decode()
                out.append((segname, sectname))
                sec_off += 80
        off += cmdsize
    return out


def main():
    tool = pathlib.Path(sys.argv[1])
    binary_dir = pathlib.Path(sys.argv[2])
    work = binary_dir / 'tests' / 'rewriter_macho_roundtrip'
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    inp = work / 'sample.macho'
    out = work / 'out.macho'
    build_macho(inp)
    policy = work / 'policy.json'
    policy.write_text(json.dumps({'schema_version':1,'defaults':{'language_origin':'binary','annotation_origin':'external_manifest','protection_domain':'native','jit_policy':'off','plaintext_budget':'transient_only','reaction_policy':'log','integrity_level':'basic','platform_caps':['ios','arm64'],'sensitivity_level':'normal','profile_seed':1,'mobile_bridge_mode':'off','event_types':[]},'entries':[]}, indent=2))
    subprocess.run([str(tool), '--policy', str(policy), '--input', str(inp), '--output', str(out)], check=True)
    sections = parse_sections(out)
    if ('__DATA', '__vmp_load') not in sections:
        raise SystemExit('missing __DATA,__vmp_load')
    print('rewriter_macho_roundtrip OK')

if __name__ == '__main__':
    main()
