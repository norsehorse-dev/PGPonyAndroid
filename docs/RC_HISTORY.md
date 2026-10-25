# Release candidate history (PGPony Android)

Every release candidate still published on pgpony.app/rc/, the commit it was built from, and whether a clean
build of that commit reproduces it.

From 4.7.2 on, RCs are tagged and published as GitHub pre-releases (docs/RC_BUILD_SIGN_DEPLOY.md), so their rows
are exact. Before that, RCs were built without a tag, often from a working tree that was committed later. For
those, the candidate commits are read from the history and the upload time: the first is the last commit on the
release line before the upload, and a second, where listed, is the next commit that carries the same work. A row
is verified when a clean build of one of its candidates has the same content hash as the RC APK on pgpony.app.

A row that does not verify is listed as such. A working-tree build can differ from a clean build of the same
source (uncommitted files, R8 and daemon state), so "not reproduced" is not proof of different source, and it is
not claimed to be. RCs from before 9 August 2026 predate the reproducible build work (vcsInfo, the gate) and are
not expected to reproduce.

Upload times are the file times on pgpony.app, in UTC. The content hash ignores the signature (see
tools/verify_repro.sh content-hash); the whole-file SHA-256 is of the APK as published. 4.0.5-test was a test
build for one fix, not a release candidate, and is listed because it is on the same page.

| RC | Uploaded (UTC) | Candidate commits | Content hash of the RC APK | Whole-file SHA-256 | Status |
|---|---|---|---|---|---|
| 4.0.4-rc1 | 2026-07-24 23:32 | `971fb65`, `5ac5756` | `7bbd8b5598039f58bff33fb7a3bfd81e7ba00d5e716bb56ed6510d2fa3867690` | `6fdc2efa46aeb52a361a455497269ed0f131e52ec34f37165705e8f34616d2bb` | Not yet rebuilt |
| 4.0.5-test | 2026-07-26 03:01 | `c3f137e`, `75e0190` | `3cba479894ab44b60372a8c5c90006ebfc1dc50723910540fab141a2b0a57bdb` | `8c66f79f3fbc0e89f1ba2d155a4d96bdc3c7b88e1b495580eca36fc806797896` | Not yet rebuilt |
| 4.1.0-rc2 | 2026-07-31 01:41 | `75e0190`, `c053a2e` | `119281dfdcee05faed742233eb7a0a005c900b0e978ccc138a82a227ec682ca9` | `1bbd5146dead2c17c6d7ac2e564043afd3b614fec5d3182a68c36c7ecb57bc75` | Not yet rebuilt |
| 4.1.0-rc3 | 2026-07-31 20:35 | `75e0190`, `c053a2e` | `49b2e3bd219dfeb680819709d484bc64181cf94560b19c96c2ce14f600d74dd3` | `5f4c3ac1daa6020c60d2552e965df3f9a6a6e949da1633d7ccbd40b036fa1e96` | Not yet rebuilt |
| 4.2.0-RC1 | 2026-08-08 00:57 | `ee22242`, `f092573` | `6a61f26d6a9a838e4e4d9d147ed1025e191230f7ecee15ad484161aefb3d2dab` | `8ff8f92436c8f8e286bdf9f5a8cfd80d1824bacc7fb88d8a9aaf459310526855` | Not yet rebuilt |
| 4.2.0-RC2 | 2026-08-08 23:26 | `7b3ff08`, `570104c` | `e728c4ccbe49df68eaeb245874c173abc2405637061079ebda12bc54c769309a` | `2546880709e0b652012299ea09c3c480147fede81d5465d012a44a9ce984705e` | Not yet rebuilt |
| 4.2.0-RC3 | 2026-08-10 02:06 | `8e23cc8`, `87a9d7b` | `574590dccae858aa85b6a789d5672d45cef555b34dc73eac3cf81ed7a751e6c4` | `2a6ffa0c70a4bacccf9296128807f5c8e657b74b8ec61c6d3d75180d3c31f041` | Not yet rebuilt |
| 4.2.0-RC4 | 2026-08-11 01:16 | `87a9d7b` | `eae3f95d80391cf73779d58ebb435a407f07efb9ade102eede5e67c2720daced` | `59a0aa492982072d81c2ccd706d5d7096758c999a7ad065354e191b126563e2a` | Same file as the v4.2.0 release |
| 4.2.0-RC5 | 2026-08-12 00:53 | `87a9d7b`, `232f104` | `cdc6a92b28beaff25b12e7892eb78ba91f45a901ed74af794c5c326d7b74fc16` | `cb2c7f2071891b318dfeb99705a219045b86b3f302f12f5e7ac7a2a61ec183a1` | Not yet rebuilt |
| 4.2.0-RC6 | 2026-08-13 01:24 | `87a9d7b`, `232f104` | `d159521b68795b1a325dd0c318fd00220e9a135c552794091df353cab8b2b61f` | `7ba903f7f56f81e2dd7474dd65fbade03ac634419d18d30371c6e7161ec5d748` | Not yet rebuilt |
| 4.2.1-RC1 | 2026-08-16 19:30 | `5552b9b`, `4e12ce9` | `afb0fd16cb1beef6c98a059d26013e98d060695c40d6fcb25126cf2495f1d390` | `a6db202812b5fc30ea78cad29ff5eedda81bc4cebc7edb1dbc1979852aa6764f` | Same file as the v4.2.1 release |
| 4.3.0-RC1 | 2026-08-17 16:43 | `8395d8c`, `680b063` | `cc5172a7ed51128363b085a1218f8755ff344cc85949b0213f3ceda03ce403fa` | `1bea74f8669617e977040c256bc4d529804aa6b9afc88a83d339b56e4d1dfbf9` | Not yet rebuilt |
| 4.3.0-RC2 | 2026-08-18 00:28 | `8395d8c`, `680b063` | `1b83d6a92fa1dc608334574788749a3e5cc86b565ec2a68cd4a7476a1b0c0263` | `48e7f7ab92c6511b4242e89da93ea5f6c6793ed8ffd1c037f13ddf191b86bde1` | Not yet rebuilt |
| 4.3.0-RC3 | 2026-08-18 22:09 | `39f1eec`, `680b063` | `259acb30d439cf6486d6702dc89282bfc932b37661c6865eba0637552c00fca9` | `8114d61cbb14b8c42077e5d4af4068b4dcbd9726bebf20ac27185118b37fd25c` | Not yet rebuilt |
| 4.3.0-RC4 | 2026-08-20 00:11 | `39f1eec`, `680b063` | `be74190e41891969aada3be6003e232e2c3240a32bb32bef0ede7cba62aa935d` | `7b9dc513d196de7d3d6640ca4ad296c4f14b4bf4c5c9bb508f31b24022ef764e` | Not yet rebuilt |
| 4.3.0-RC5 | 2026-08-20 16:27 | `1110ec6`, `0ad5882` | `2a03903eda6a3524c651975009901a847fd4cffac7dd4930ff92d863c5c2ac23` | `ad685fa6e8147b883d2ab16219f6f520a9df6b88e403f9e42cd91d3693daefda` | Not yet rebuilt |
| 4.3.1-RC1 | 2026-08-21 15:15 | `082b02c`, `d96d1a2` | `8d47734bdddc7f2d5a8fdcb54658f0943357438bd296b13e25b049c081c5c5b3` | `ba4df7101171f1f891fba7017a65c395c081835524510441107f491d48c1871d` | Not yet rebuilt |
| 4.4.0-RC1 | 2026-08-23 22:05 | `c9be1cf` | `d8e77edadea731b945173f2e7516ba020db41ffc4f1cd3d17b6cc64267fd23c9` | `59e2aeec18013a7bbe373de9234a208359be12dd7a108d211fc186e260563695` | Not yet rebuilt |
| 4.4.0-RC2 | 2026-08-24 17:23 | `484ca9c` | `117dc3f019166509b5a2c15dce15ec2de939d54e13865526cba41d23f7e9202b` | `93078904c26632a788997b7523e38204f09b139b33520f9f5368ddbc79cb0f04` | Not yet rebuilt |
| 4.4.0-RC3 | 2026-08-25 01:14 | `a02c4db` | `da92d78e8388eef711c5f91dff385c1533c8170cffcc8663e7f5c6f734740df7` | `72f278f0c4cf89f7a65f1bddcc1ad52ed09a616505c98f38aa48ebb2dd5b16f8` | Not yet rebuilt |
| 4.4.0-RC4 | 2026-08-25 20:45 | `b99682d` | `2fd3cc08a84c67275ae8ca9d774f5b39e46ab09231a15d0774f135709fa31d5e` | `1d5136a629f96b4acc56f8b91720ff20ca5e537da922b744e7680375c5218b7a` | Not yet rebuilt |
| 4.4.0-RC5 | 2026-08-25 23:38 | `b99682d`, `778f9a1` | `9145c137533c502ea2e27fdaa23d54fdc09706568544f8cffe8c2491c3cd2824` | `93ef5778405ca40c8d64b5a7933f28901ac28cce087a40e52fe819986f7abda1` | Not yet rebuilt |
| 4.4.0-RC6 | 2026-08-26 04:23 | `778f9a1` | `a2980faadbb8342e54f393d2736bfa2a19314dd7a7a762d25d9b772170d8fd4d` | `2e9edd01bedd2dceb226636fcdf6c42f881450bb9328d53e2041ea75182bb7f5` | Not yet rebuilt |
| 4.4.0-RC7 | 2026-08-26 04:58 | `af433cd` | `7171c446e75147f380faba2649ae5bc23503c26ed18b2131df4742e2a8ac4e29` | `3bec8beb1daecdfb10aa96e13970125791a188488469ef65d45cec2fbe3c9d63` | Not yet rebuilt |
| 4.4.0-RC8 | 2026-08-26 16:37 | `17c854a` | `3067698981a6f6da146e10dbd479b6cb4b66ad73cc0c4d5f15899472ed8582c9` | `696098becf7af4cfe0f0217936c654afec117069b9a05558cff2a528616e0891` | Not yet rebuilt |
| 4.4.0-RC9 | 2026-08-26 17:19 | `0926f0d` | `c2dee6506172ca9586cceb5cf389bc5c5172f0678b2614ea812e708fc6fb694e` | `1f58d22e18774baef0eff07a9b4a4305e9cd0ffe49d54f12e6a7b52055158c2c` | Not yet rebuilt |
| 4.4.0-RC10 | 2026-08-27 02:57 | `cca0d0d` | `3ec6e4962a43837252c0d13b47f69c3280e06245ed20036bfc27d0967ed91fda` | `93a66b11ca9118d8400bb2ac59f1c9d164a9577dc8f794fc19e17b7c9082992a` | Not yet rebuilt |
| 4.4.0-RC11 | 2026-08-27 17:20 | `7405999` | `2f733f0290e4adc354820e5d7f188224bdf409171c151a0deba39c8a1244b7e5` | `e6e51f08e3c77a4584c1e58b1ffc40dbf87c7717db731ccb5de46893c8d06e6a` | Not yet rebuilt |
| 4.4.0-RC12 | 2026-08-27 18:50 | `1882826` | `89b1d63ff7f39b4f16931f753a6330b6134750312603b47cdec739782b9d2bb4` | `c3e86c3c647579324421aaac22f169f450c2f1793e8e476226aff04c54ff3e8f` | Not yet rebuilt |
| 4.4.0-RC13 | 2026-08-27 19:37 | `e494cee` | `26e5bded7bbdcbfe52efc73d9113c72e5d8343d339aee306fcc526355a812121` | `caefa7841809e36774b2db1e24d0463972b0088799eac9d04b83edefa2a1514e` | Not yet rebuilt |
| 4.4.0-RC14 | 2026-08-28 03:10 | `a337a58`, `ccda589` | `c7b4a5b9b000c074ba87a1fe5f80b75c5cb3cd3efd7baa105b680829da8e78ed` | `52fd01021c6d06a017501738c650ad91f36954cb173fbe3f64c813bc744171dd` | Not yet rebuilt |
| 4.4.1-RC1 | 2026-08-31 17:39 | `ccda589`, `837337f` | `11fdba640cd57abbf92f41d7f39c919314d9dc5e4524535d9ab32a06b40ccb1f` | `0810d09ca0cdb113e50fd610a6c3eadebd1541e95b64f2c156ca25d32fa5cb42` | Not yet rebuilt |
| 4.5.0-RC1 | 2026-09-08 20:11 | `22dadb2`, `25ff1da` | `59e921d0cbc7cbd499689eaa804494c851607f7393f2c8b5caf820dcb76c9d4e` | `538e540e488e13fb6df3e33f7c58bcf67369267ee9fa28653cce07559347483f` | Not yet rebuilt |
| 4.5.0-RC2 | 2026-09-12 05:39 | `f5503ca` | `28aba2106a191d7c4e9821d047d8cfce6e8d8feb6a01568b90a342df53c018c9` | `f578d68aabbbe2137015018a4e9030fe5a0cdb8eef4ac59c56c5ad4b81afccb4` | Not yet rebuilt |
| 4.5.0-RC3 | 2026-09-13 03:59 | `37b6ebf`, `35a50cc` | `bf42934ff3a389fbc0926de5734b37a4e2787d6fc94317ea1cbf9f6acd26e786` | `9e85b88f8524a5721d831182d51e1f40084d0e14292ae162edd7ecf6da0229f4` | Not yet rebuilt |
| 4.5.0-RC4 | 2026-09-13 04:41 | `a0e8e43` | `c4a04f4778f92fa8af03c7051db93fc972398fdeb0ee69c2b4e11785d2e93d9e` | `b791c046adf97d5ba8677d91c0ff46defeb1dabf1af67233be2b2bd4ad52e1ce` | Not yet rebuilt |
| 4.5.0-RC5 | 2026-09-14 22:07 | `2a84de0` | `047cba5e3a72303a7752be1d7bd8dff4d3a8efd7298398dfa0e42ee8d8d08146` | `4fecec3cad5145291f5e21e5a7d7e7a3a00aa7f6dfe72143b884ad7c787d905d` | Not yet rebuilt |
| 4.5.0-RC6 | 2026-09-14 23:58 | `5695582` | `49c5fe15efe39dc787deb498c7d75864388419b9fb64206ed52922806798796c` | `eb941cb28c84e3a6de725a7209e29c94befeddf98f7dbf985625f3cb935963a4` | Not yet rebuilt |
| 4.5.0-RC7 | 2026-09-15 00:16 | `6c5f789` | `f000e4ae7a328a6064f6cb1a131581e1bf96688fa9c6f7b7d9faeaba02353768` | `39e97685cdf6eab4c6188054124dd5ae7ade0788d950aedbe5bd3d0d5fb44a81` | Not yet rebuilt |
| 4.5.0-RC8 | 2026-09-15 04:59 | `ea3148d` | `f12983afd074a5016e9e0b0a9222e53374756fd8eb5a841117505bb08123cab4` | `34cb0fb8f0fc35219187d1f8110d5caee0ea34f2c0d4ed3668c3d090b76da923` | Not yet rebuilt |
| 4.5.0-RC9 | 2026-09-15 17:07 | `ea3148d`, `3b12e78` | `0e2cd4eced9621a92609d0b57440750c300acafedf07131443e22f800f4db89d` | `ef64f2dfddc604654da2f1be9828e71c17512ec5a741650fcd479c1f574f4270` | Not yet rebuilt |
| 4.5.1-RC1 | 2026-09-16 22:03 | `4f792d1`, `8c5f411` | `9caa36488c3107b1855c8d99a652eb7b66f99c23402fece64ffbe2eb283b35aa` | `f5d10cbd284bd7ee4537cc528ce4211b49211db7c21f110f804fbfc42d0132f4` | Not yet rebuilt |
| 4.5.1-RC2 | 2026-09-16 22:15 | `4f792d1`, `8c5f411` | `8a392d356d3db81dad9149e92782541e1ffdd19feab414a33a418e3ce345eef4` | `d7e5e25b0a069af7c9da17718c7faec14dc788bebc3dd2511af608892ba9b3de` | Not yet rebuilt |
| 4.5.3-RC1 | 2026-09-19 05:33 | `6c21d64`, `094fae9` | `d9d761469bd0944579b80f9fdc6eaddf291e014478dc1653d993e6e38ae1e74b` | `b5d18cbab27dbda94ea8bf7f44356b0eaa0da0081740de5597d7201c082a81d3` | Not yet rebuilt |
| 4.5.3-RC2 | 2026-09-20 04:52 | `6c21d64`, `094fae9` | `0ce48f1bb887e1cacb17dbd60156640eb55589e42faed70e3d28023fd408839c` | `77b1bcc1d519d17827f7bbbc6e3ec7f4cef2db72c56e123192d5d31092f878bf` | Not yet rebuilt |
| 4.5.3-RC3 | 2026-09-21 01:48 | `6c21d64`, `094fae9` | `1241205c011605211e57864830983b825446542c3cb05f2ecc7238d54adcbf43` | `196cb6430ea35dfb228b4096608706a2901be63f0737f23cf3d276dae2f8577b` | Not yet rebuilt |
| 4.6.0-RC1 | 2026-09-23 23:51 | `d333001` | `fbf68141ef6fab8b9800ccc93c1882489d1a21af628ef7e1f88d3f6623e2bd60` | `fcc826c128a9b355cbc18b847427283925c428fac1882941778edcf144921e2f` | Not yet rebuilt |
| 4.6.1-RC1 | 2026-09-25 02:51 | `ce13072` | `8cae0bc8029233d4ee0bb21c27e7b708b8b547ea85af4bb35d211bf2798934aa` | `bdf11f37448ae183f3ff33f78fe751a1e22ef08fb19ca2196751ae3bc1c744e4` | Not yet rebuilt |
| 4.6.3-RC1 | 2026-10-03 03:36 | `bc00cb1`, `d304a58` | `726d56194cc3750bf01639b10a148909158441c38591389fbb101b50a778eeb1` | `228a466f98af162021147a1ebf3a09cb8417782897b853004016d11c8045a128` | Not yet rebuilt |
| 4.6.4-RC1 | 2026-10-06 21:14 | `863f8c4`, `c73de77` | `16c8e9484c7e1b89c426839cce7213768a7c76a19f482cb8f6fa662b41004451` | `3ae551b26577492d4b60fa8ded8d021d01c16957d19f2854f0790e500cd09547` | Same file as the v4.6.4 release |
| 4.7.0-RC1 | 2026-10-10 02:00 | `25a5137` | `183872e3186624a6bdb15b5e66ace945914f828a4aab9d216eec7cfb1b3dc5cd` | `f54a48b0c42440445e5566f841a0fb7644186a8deb5e8c9d38980f076de1672b` | Not yet rebuilt |
| 4.7.0-RC2 | 2026-10-13 03:18 | `f663f7d` | `bc9d3df999f21511b4eb42033d54e743e44a4bd3a5c00f0fafb5d2a8ee54bed0` | `a34c30a9f68e3b8c06e83f83e18fecdf7858ae623b357a1dc3c0262a9361c468` | Not yet rebuilt |
| 4.7.0-RC3 | 2026-10-14 04:46 | `c7b9957` | `778545fa4b33a6475b42e53d177182f1c8378958e02d14d54765ec4e673f8eea` | `2f55f3b3cb060f783526677f4b48c896a395f0a10a5e097ad361b8139ed2a6be` | Not yet rebuilt |
| 4.7.0-RC4 | 2026-10-14 20:49 | `7b1f92f` | `a3f23bcfee90c9f4bd76d9ee18aeff96cfdfe1806e4625a0be243509a6c9dfa5` | `5d20850fdab1cd1c4ef5296d7178c0c9faedbc39b9a08ec6f4afdb47e520d8c3` | Not yet rebuilt |
| 4.7.0-RC5 | 2026-10-15 22:11 | `2b67bc1` | `7bba78ba34925b2d0c027001a9e822faaa9401bb80be04a9ced8f192b74a1914` | `d5d94f479e88271857add808a53bdfcb08e19b4ea3f02bc1f78dce19ef8a7297` | Not yet rebuilt |
| 4.7.0-RC6 | 2026-10-16 23:11 | `f04501a` | `d24c7bcc473d6c5753e079221547856f9d53032d1bb74def77eea90f22a8fe34` | `6e3eeb3bd0307dd193315d1bf4c9d97c6301786c866930cacaa339b0abdfb383` | Not yet rebuilt |
| 4.7.0-RC7 | 2026-10-19 17:36 | `34f4b8d` | `2eefc88d6f7cb7f19beb7b6f68046b474aa076b5a378a45869a2961d23ba8c10` | `8efc9562c18712f780f06cfc7089020f8f5c5ff994afddd74dd08c3684df7130` | Not yet rebuilt |
| 4.7.1-RC1 | 2026-10-23 01:24 | `7662832`, `b127b2d` | `b4d1a98acf62b7d1d38d8c1a047785756869c238318c79f2e0e76668764de29b` | `99d36b8c6aa7ac6bbfbea0a3f03bd3ba242fa28b8e3ddaa160aba6b721d1dc45` | Same file as the v4.7.1 release |
| 4.7.2-RC1 | 2026-10-25 00:58 | `9ead039` (branch rc/4.7.2-rc1) | `66ed5523fec9b77dae2bc4b4725842a0b9d3fdb3a963b8625fac7f03700dbddf` | `07217a9a817cbb4d3737529659b405aa5b411aea3dcd8884b76247e6b6c9102a` | Verified: two clean-clone builds of the branch are identical, and the signed RC matches them |

Four RCs were published unchanged as the release that followed them: the 4.2.0 RC4, 4.2.1 RC1, 4.6.4 RC1 and
4.7.1 RC1 files have the same whole-file SHA-256 as the release files listed in docs/releases. They verify
wherever the release tag does.

## How the rows are checked

All rows at once, from a clone of the repository, with the RC APKs downloaded from pgpony.app/rc/ into a
directory:

```
tools/rc_history_check.sh <directory with the RC APKs>
```

The candidates are in tools/rc_history_candidates.txt. The script builds each candidate commit once from a clean
checkout and prints MATCH with the commit, or NO MATCH with the content hash each candidate produced. It is a
history check with one build per commit, not the release gate.

One row, through the release gate (two isolated clean builds, then the RC APK compared to them):

```
git tag rccheck <commit>
REPO_URL="$PWD" tools/verify_repro.sh rebuild rccheck PGPony-X.Y.Z-RCN-foss.apk
git tag -d rccheck
```
