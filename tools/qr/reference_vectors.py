#!/usr/bin/env python3
"""Independent PGPONY2 reference. Python stdlib only; no application code imports.

Uses bitwise polynomial multiplication (rather than the Kotlin log tables) and
Lagrange interpolation (rather than Kotlin matrix inversion) to derive parity.
Run with --write to refresh the checked-in deterministic vectors; otherwise
compare reference output with the checked-in artifact and exit on disagreement.
"""
import argparse
import base64
import binascii
import hashlib
from pathlib import Path


def mul(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 256:
            a ^= 0x11D
        b >>= 1
    return result


def power(a, n):
    result = 1
    for _ in range(n):
        result = mul(result, a)
    return result


def coefficients(k, x):
    result = []
    for j in range(k):
        numerator = denominator = 1
        for m in range(k):
            if m != j:
                numerator = mul(numerator, x ^ m)
                denominator = mul(denominator, j ^ m)
        result.append(mul(numerator, power(denominator, 254)))
    return result


def encode(data, parity):
    shards = list(data)
    for x in range(len(data), len(data) + parity):
        row = coefficients(len(data), x)
        output = bytearray(len(data[0]))
        for coefficient, source in zip(row, data):
            for j, byte in enumerate(source):
                output[j] ^= mul(coefficient, byte)
        shards.append(bytes(output))
    return shards


def vectors():
    output = ['# k|r|data shards hex separated by comma|all systematic+parity shards hex']
    for k, r, size in [(1, 1, 3), (2, 1, 9), (4, 2, 19), (20, 4, 7), (128, 32, 2)]:
        data = [bytes((i * 83 + j * 31 + (i ^ j)) & 255 for j in range(size)) for i in range(k)]
        output.append(f'{k}|{r}|' + ','.join(d.hex() for d in data) + '|' + ','.join(d.hex() for d in encode(data, r)))
    return '\n'.join(output) + '\n'


def base45(raw):
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
    result = []
    for offset in range(0, len(raw), 2):
        paired = offset + 1 < len(raw)
        value = raw[offset] * 256 + raw[offset + 1] if paired else raw[offset]
        result += [alphabet[value % 45], alphabet[value // 45 % 45]]
        if paired:
            result.append(alphabet[value // 2025])
    return ''.join(result)


def certificate_frames(root):
    armor = (root / 'app/src/test/resources/pqc/rfc9980-a3-mldsa65-ed25519-cert.asc').read_text()
    payload = armor.split('\n\n', 1)[1].split('-----END', 1)[0]
    raw = base64.b64decode(''.join(line for line in payload.splitlines() if not line.startswith('=')), validate=True)
    digest = hashlib.sha256(raw).hexdigest().upper()
    k = (len(raw) + 511) // 512
    r = (k + 3) // 4
    padded = raw + bytes(k * 512 - len(raw))
    shards = encode([padded[i * 512:(i + 1) * 512] for i in range(k)], r)
    frames = []
    for index, shard in enumerate(shards):
        header = f'PGPONY2:{digest}:{len(raw)}:{k}:{r}:{index}:'
        crc = binascii.crc32(header.encode('ascii') + shard)
        frames.append(f'{header}{crc:08X}:{base45(shard)}')
    return '\n'.join(frames) + '\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    artifacts = {
        'app/src/test/resources/qr/v2/erasure-vectors.txt': vectors(),
        'app/src/test/resources/qr/v2/certificate-frames.txt': certificate_frames(root),
    }
    for relative, expected in artifacts.items():
        target = root / relative
        if args.write:
            target.write_text(expected)
        else:
            assert target.read_text() == expected, f'Independent reference differs: {relative}'
            print(f'Matches independent reference: {relative}')
