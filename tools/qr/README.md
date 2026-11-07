# QR evidence tools

`run_core_tests.py` compiles the production pure Kotlin encoder, layout, luminance extractor
and scanner decoder with the project's downloaded Gradle Kotlin compiler. It does not
require an Android SDK, emulator, application installation, network access or a Python
package installation. Use Python 3.9 or newer and JDK 17. The tool validates the SHA-256
of the ZXing 3.5.3 Maven Central binary before executing it.

Download the Gradle distribution and populate the ZXing dependency cache through the
normal project setup first. Compiler, Kotlin standard library, JUnit and Hamcrest are
read from Gradle 8.14.3's `lib` directory; ZXing comes from the Gradle dependency cache.
`JAVA_HOME` and `GRADLE_USER_HOME` are respected. Alternative locations can be supplied
with `--java-home`, `--gradle-lib`/`QR_GRADLE_LIB`, and `--zxing`/`QR_ZXING_JAR`.

From the repository root:

```sh
python3 tools/qr/run_core_tests.py
python3 tools/qr/run_core_tests.py --verify-assets --output /tmp/pgpony-qr-reproduced
```

The first command executes six JVM test classes. The second regenerates the production
encoding report and synthetic luminance assets, then compares every file and parsed
manifest with the checked-in evidence. These operations only write to the chosen
output directory, which defaults to a new temporary directory. `--probe` generates the
same artifacts without comparing them; it is useful when reviewing a deliberate change
to encoding policy. Review the generated evidence before copying changes into the repo.

The canonical replay metadata is
`app/src/androidTest/assets/qr/manifest.json`. Each `.y` file is a raw synthetic luminance
plane containing a QR of the first BASELINE frame of one pinned public certificate.
`bufferPosition` is the plane start offset. `rowStride`, `pixelStride`, width, height,
unrotated crop rectangle, clockwise rotation and preview-to-analysis matrix are explicit.
The files contain deterministic padding and either an exact production QR matrix or a
radius-one integer box blur. They are not camera captures. The matrix is rendered at
3 or 4 pixels per module, including all four white quiet-zone modules.

The manifest records one first-attempt miss for the dense ML-DSA symbol at 3 pixels per
module with rotation. This observation is retained as evidence. It does not claim a
failure of all decoder retries, a complete multipart scan or any physical camera.
See `docs/qa/QR_EXCHANGE_BENCHMARK.md` for results and physical validation still required.

`reference_vectors.py` independently calculates the enhanced transport's Base45 and
Reed–Solomon vectors; it is maintained with the PGPONY2 protocol tests.
