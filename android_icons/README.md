# PGPony Android Icon Assets

Generated from the iOS 1024×1024 source. Drop the `res/` folder contents
into `app/src/main/res/` in your Android project (merge with existing).

## What's included

```
res/
├── mipmap-anydpi-v26/
│   ├── ic_launcher.xml          ← Adaptive icon definition
│   └── ic_launcher_round.xml    ← Same (Android picks one based on launcher)
├── mipmap-{m,h,xh,xxh,xxxh}dpi/
│   ├── ic_launcher.png              ← Legacy square (pre-Android 8)
│   ├── ic_launcher_round.png        ← Legacy round
│   ├── ic_launcher_foreground.png   ← Adaptive foreground (108dp)
│   └── ic_launcher_background.png   ← Adaptive background gradient (108dp)
└── drawable/
    └── ic_launcher_monochrome.png   ← Themed icon for Android 13+

play_store/
└── playstore-icon.png   ← 512×512, upload to Play Console
```

## AndroidManifest.xml

Make sure your `<application>` tag references both:

```xml
<application
    android:icon="@mipmap/ic_launcher"
    android:roundIcon="@mipmap/ic_launcher_round"
    ...>
```

## Verifying after install

1. Build → Clean Project
2. Uninstall the app from the device/emulator (launcher caches icons)
3. Reinstall

## Notes

- Background is a full-bleed gradient PNG (TL #5C6EEE → BR #AF39E5)
  matching the iOS source. If you'd rather use a vector for smaller APK
  size, replace `ic_launcher_background.png` with a `drawable/ic_launcher_background.xml`
  containing a gradient drawable and update the adaptive XML to reference
  `@drawable/ic_launcher_background` instead of `@mipmap/`.
- Monochrome (themed icon) uses the dark outlines from the source as a
  white silhouette. Looks good on Pixel devices with themed icons enabled.
- Foreground content is sized at 72% of the 108dp canvas, well within the
  66dp safe zone — content will not clip on any launcher mask.
