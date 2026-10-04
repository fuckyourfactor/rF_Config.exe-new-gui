import struct
import sys

MANIFEST = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
    '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">'
    '<assemblyIdentity type="win32" name="rFactor.Config" version="1.0.0.0" processorArchitecture="x86"/>'
    '<dependency><dependentAssembly>'
    '<assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" '
    'processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>'
    '</dependentAssembly></dependency>'
    '<application xmlns="urn:schemas-microsoft-com:asm.v3"><windowsSettings>'
    '<dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true</dpiAware>'
    '</windowsSettings></application></assembly>'
).encode()

src, dst = sys.argv[1], sys.argv[2]
d = bytearray(open(src, 'rb').read())


def u16(b, o):
    return struct.unpack_from('<H', b, o)[0]


def u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


pe = u32(d, 0x3C)
sections = pe + 24 + u16(d, pe + 20)
dirs = pe + 24 + 96
for i in range(u16(d, pe + 6)):
    if d[sections + 40 * i:sections + 40 * i + 8].rstrip(b'\0') == b'.rsrc':
        hdr = sections + 40 * i
rva, size, raw = u32(d, hdr + 12), u32(d, hdr + 16), u32(d, hdr + 20)

res = []


def walk(off, path):
    for i in range(u16(d, raw + off + 12) + u16(d, raw + off + 14)):
        ident, sub = struct.unpack_from('<II', d, raw + off + 16 + 8 * i)
        if sub & 0x80000000:
            walk(sub & 0x7FFFFFFF, path + [ident])
        else:
            r, n, cp, _ = struct.unpack_from('<IIII', d, raw + sub)
            start = r - rva + raw
            res.append((path[0], path[1], ident, cp, bytes(d[start:start + n])))


walk(0, [])


def skip(b, p):
    if u16(b, p) == 0xFFFF:
        return p + 4
    while u16(b, p):
        p += 2
    return p + 2


def set_font(b):
    p = 26
    for _ in range(3):
        p = skip(b, p)
    tail = (skip(b, p + 6) + 3) & ~3
    head = b[:p] + struct.pack('<HHBB', 9, 400, 0, 1) + 'Segoe UI\0'.encode('utf-16-le')
    head += b'\0' * (-len(head) % 4)
    return head + b[tail:]


res = [(t, i, l, c, set_font(b) if t == 5 else b) for t, i, l, c, b in res]
res.append((24, 1, 1033, 0, MANIFEST))
res.sort(key=lambda r: r[:3])

tree = {}
for r in res:
    tree.setdefault(r[0], {}).setdefault(r[1], []).append(r)

off = 16 + 8 * len(tree)
type_at, name_at, leaf_at, data_at = {}, {}, {}, {}
for t, names in tree.items():
    type_at[t] = off
    off += 16 + 8 * len(names)
for t, names in tree.items():
    for i, langs in names.items():
        name_at[t, i] = off
        off += 16 + 8 * len(langs)
for r in res:
    leaf_at[r[:3]] = off
    off += 16
off = (off + 3) & ~3
for r in res:
    data_at[r[:3]] = off
    off += (len(r[4]) + 3) & ~3
used = off

rs = bytearray(size)


def table(at, entries):
    struct.pack_into('<IIHHHH', rs, at, 0, 0, 4, 0, 0, len(entries))
    for k, (ident, target) in enumerate(entries):
        struct.pack_into('<II', rs, at + 16 + 8 * k, ident, target)


table(0, [(t, 0x80000000 | type_at[t]) for t in tree])
for t, names in tree.items():
    table(type_at[t], [(i, 0x80000000 | name_at[t, i]) for i in names])
    for i, langs in names.items():
        table(name_at[t, i], [(r[2], leaf_at[r[:3]]) for r in langs])
for t, i, l, cp, b in res:
    struct.pack_into('<IIII', rs, leaf_at[t, i, l], rva + data_at[t, i, l], len(b), cp, 0)
    rs[data_at[t, i, l]:data_at[t, i, l] + len(b)] = b

out = d[:raw] + rs
struct.pack_into('<I', out, hdr + 8, used)
struct.pack_into('<II', out, dirs + 16, rva, used)
struct.pack_into('<II', out, dirs + 32, 0, 0)
struct.pack_into('<I', out, pe + 24 + 64, 0)
open(dst, 'wb').write(out)
