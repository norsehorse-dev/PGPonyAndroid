#!/usr/bin/env python3
"""Run production pure-Kotlin QR checks or regenerate public evidence without Android.

Requires a compatible JDK (17), a downloaded project Gradle distribution, and cached
ZXing 3.5.3. The script does not install packages or access the network. Outputs use
an isolated temporary directory unless --output is supplied.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
MAIN = ROOT / 'app/src/main/java/com/pgpony/android/qr'
TEST = ROOT / 'app/src/test/kotlin/com/pgpony/android/qr'
PRODUCTION = ['QrChunking', 'QrEncodingPolicy', 'QrSymbolLayout', 'QrScanMetrics',
              'LuminanceFrame', 'QrFrameDecoder']
TESTS = ['QrChunkingTest', 'QrEncodingPolicyTest', 'QrSymbolLayoutTest',
         'QrEncodingProbeTest', 'LuminanceExtractionTest', 'QrFrameReplayUnitTest']


def first_file(paths, description):
    for path in paths:
        if path.is_file():
            return path
    raise SystemExit(f'Missing {description}; run the project Gradle wrapper first or use the documented override.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, default=os.environ.get('JAVA_HOME'))
    parser.add_argument('--gradle-lib', type=Path, default=os.environ.get('QR_GRADLE_LIB'))
    parser.add_argument('--zxing', type=Path, default=os.environ.get('QR_ZXING_JAR'))
    parser.add_argument('--probe', action='store_true', help='Generate CSV, public certificate copies and synthetic Y-plane replay assets.')
    parser.add_argument('--verify-assets', action='store_true', help='Regenerate and compare the checked-in public assets and encoding CSV.')
    parser.add_argument('--output', type=Path, help='Directory for classes and generated evidence; defaults to a temporary directory.')
    args = parser.parse_args()
    java = str(Path(args.java_home) / 'bin/java') if args.java_home else 'java'
    caches = [Path(os.environ.get('GRADLE_USER_HOME', Path.home() / '.gradle')), Path.home() / '.gradle']
    if args.gradle_lib:
        lib = args.gradle_lib
    else:
        distributions = [p for cache in caches for p in cache.glob('wrapper/dists/gradle-8.14.3-bin/*/gradle-8.14.3/lib')]
        if not distributions:
            raise SystemExit('Project Gradle distribution missing. Run ./gradlew --version or set QR_GRADLE_LIB.')
        lib = distributions[0]
    compiler = first_file(lib.glob('kotlin-compiler-embeddable-*.jar'), 'Gradle Kotlin compiler')
    stdlib = first_file(lib.glob('kotlin-stdlib-*.jar'), 'Kotlin standard library')
    junit = first_file(lib.glob('junit-4.13.2.jar'), 'JUnit 4.13.2')
    hamcrest = first_file(lib.glob('hamcrest-core-1.3.jar'), 'Hamcrest 1.3')
    zxing = args.zxing or first_file(
        (p for cache in caches for p in cache.glob('caches/modules-2/files-2.1/com.google.zxing/core/3.5.3/*/core-3.5.3.jar')),
        'ZXing core 3.5.3')
    if hashlib.sha256(Path(zxing).read_bytes()).hexdigest() != '8d8064c1636fdaef7189dd9055c7d59950a8940a12f2293956446ec3c109fd82':
        raise SystemExit('ZXing 3.5.3 binary SHA-256 does not match the pinned Maven Central artifact.')
    output = (args.output or Path(tempfile.mkdtemp(prefix='pgpony-qr-evidence-'))).resolve()
    output.mkdir(parents=True, exist_ok=True)
    classpath = os.pathsep.join(str(p) for p in [stdlib, junit, hamcrest, zxing])
    classes = output / 'classes.jar'
    sources = [MAIN / f'{name}.kt' for name in PRODUCTION]
    sources += [TEST / f'{name}.kt' for name in TESTS]
    print(f'Compiler: {compiler.name}; output: {output}', flush=True)
    subprocess.run([java, '-cp', str(lib / '*'), 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler',
                    '-no-stdlib', '-no-reflect', '-jvm-target', '17', '-classpath', classpath,
                    '-d', str(classes), *map(str, sources)], check=True, cwd=ROOT)
    runtime = os.pathsep.join([str(classes), str(ROOT / 'app/src/test/resources'), classpath])
    if args.probe or args.verify_assets:
        subprocess.run([java, '-cp', runtime, 'com.pgpony.android.qr.QrEncodingProbe',
                        str(ROOT / 'app/src/test/resources'), str(output)], check=True, cwd=ROOT)
        if args.verify_assets:
            packaged = ROOT / 'app/src/androidTest/assets/qr'
            generated = output / 'assets/qr'
            manifest = json.loads((generated / 'manifest.json').read_text())
            if manifest != json.loads((packaged / 'manifest.json').read_text()):
                raise SystemExit('Packaged replay manifest differs from regenerated metadata.')
            for entry in manifest['certificates'] + manifest['replays']:
                name = entry['asset']
                if (generated / name).read_bytes() != (packaged / name).read_bytes():
                    raise SystemExit(f'Packaged public asset differs: {name}')
            if (output / 'encoding.csv').read_bytes() != (ROOT / 'docs/qa/qr-encoding.csv').read_bytes():
                raise SystemExit('Production encoding CSV differs from checked-in evidence.')
            print('Verified all 16 public assets, manifest metadata and production encoding CSV.', flush=True)
    else:
        subprocess.run([java, '-cp', runtime, 'org.junit.runner.JUnitCore',
                        *['com.pgpony.android.qr.' + name for name in TESTS]], check=True, cwd=ROOT)


if __name__ == '__main__':
    main()
