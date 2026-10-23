#!/usr/bin/env python3
"""python3 embed.py <prelude.js> <script.js> <out blobs.c>  -> bettet beide JS-Dateien als C-Arrays in die Dylib ein."""
import sys
def arr(name, data):
    rows = []
    for i in range(0, len(data), 24):
        rows.append(",".join(str(b) for b in data[i:i + 24]))
    return f"const unsigned char {name}[] = {{\n" + ",\n".join(rows) + f",0}};\nconst unsigned long {name}_len = {len(data)};\n"
pre, scr, out = sys.argv[1:4]
open(out, "w").write(arr("km_prelude", open(pre, "rb").read()) + arr("km_script", open(scr, "rb").read()))
print("geschrieben:", out)
