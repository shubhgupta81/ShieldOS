<div align="center">

# ShieldOS

**Scam call and SMS protection that runs entirely on your phone.**

Catches fake KYC alerts, look-alike bank links, UPI and OTP traps, lottery fraud and spoofed callers, then warns you before you act.

[![Download Latest APK](https://img.shields.io/badge/Download-Latest%20APK-0071E3?style=for-the-badge&logo=android&logoColor=white)](../../releases/latest/download/ShieldOS.apk)

![Android 8.0+](https://img.shields.io/badge/Android-8.0%2B-34C759?style=flat-square&logo=android&logoColor=white)
![Kotlin](https://img.shields.io/badge/Kotlin-1.9-0071E3?style=flat-square&logo=kotlin&logoColor=white)
![Jetpack Compose](https://img.shields.io/badge/Jetpack%20Compose-Material%203-0071E3?style=flat-square)
![Offline](https://img.shields.io/badge/100%25-Offline-34C759?style=flat-square)
![License MIT](https://img.shields.io/badge/License-MIT-8E8E93?style=flat-square)

</div>

---

## Install in one tap

1. On your Android phone, tap **Download Latest APK** above (or open the **Releases** tab and grab `ShieldOS.apk`).
2. Open the file. If Android asks, allow installs from your browser or Files app.
3. Open ShieldOS and tap **Grant All Permissions**.

Every push to `main` rebuilds the app in GitHub Actions and refreshes the `latest` release, so the download is always current.

## Turn on restricted settings (sideloaded installs)

Android 13 and newer block sensitive permissions, SMS above all, for apps installed from outside the Play Store. If the SMS permission is greyed out or silently denied:

1. Tap **Grant All Permissions** once, so Android registers the blocked attempt.
2. Open **Settings, Apps, ShieldOS** (the in-app link **Installed from GitHub? Allow restricted settings** jumps straight there).
3. Tap the **three-dot menu** in the top-right corner and choose **Allow restricted settings**. Confirm with your fingerprint or PIN.
4. Go back to ShieldOS and tap **Grant All Permissions** again.

The three-dot menu only appears after step 1. Menu wording varies slightly between Samsung, Pixel and Xiaomi phones.

## Make ShieldOS your call screener

After the runtime permissions, ShieldOS asks Android for the **Call Screening** role (Android 10+). If your phone does not show the prompt, open **Settings, Apps, Default apps, Caller ID and spam app** and choose ShieldOS.

ShieldOS never blocks or hangs up a call. It scores the caller, logs the event and shows a warning, so a false alarm can never hide a real call.

## What it detects

| Threat | What ShieldOS looks for |
| --- | --- |
| KYC expiry scams | "KYC expired / pending / update now" wording |
| Fake bank links | Look-alike domains such as `hdfc-kyc-update.xyz`, raw IP links, shortened links, high-abuse domain endings |
| OTP, PIN and UPI traps | Requests to share an OTP, CVV or PIN, and "enter your UPI PIN to receive money" refund tricks |
| Lottery and prize fraud | Lucky draw, KBC, "you have won", processing-fee demands |
| Digital-arrest and authority threats | Fake TRAI, CBI, customs or courier notices |
| Account, Aadhaar, PAN and utility threats | "Blocked", "suspended", "disconnected tonight" notices |
| Fake jobs and loan apps | Work-from-home task offers, instant-loan bait, `.apk` downloads, AnyDesk and TeamViewer requests |
| Spoofed senders | A bank name sent from an ordinary mobile number, look-alike and hidden Unicode characters |
| Spoofed callers | Failed carrier caller-ID check (Android 11+), hidden numbers, foreign numbers, repeated or sequential digits, 140 telemarketing series |

Each match adds weight. The total becomes a **risk score from 0 to 98 percent**: 40 and above is *Suspicious*, 70 and above is *High risk*. Safe phrases such as "do not share your OTP" are stripped before scanning, so ordinary bank OTP texts stay quiet.

## Try it in a live demo

1. Tap **Grant All Permissions** (or at minimum allow notifications).
2. Tap **Simulate Incoming Scam Call** or **Simulate Phishing SMS**.
3. A real heads-up notification appears and the threat lands in **Recent threats** with its risk badge.

The demo uses the same pipeline as real traffic. Each tap plays a different scenario, including one that scores *Suspicious* so you can show both badge colours.

## Project layout

```
ShieldOS/
├── .github/workflows/build-apk.yml      cloud build + GitHub Release
├── app/src/main/
│   ├── AndroidManifest.xml
│   └── java/com/shieldos/app/
│       ├── ScamDetectorEngine.kt        offline heuristic + regex analyzer
│       ├── ScamCallScreeningService.kt  incoming call hook
│       ├── SmsFraudReceiver.kt          incoming SMS hook
│       ├── AlertNotificationHelper.kt   heads-up warning banners
│       ├── ThreatStore.kt               on-device event log
│       ├── ThreatPipeline.kt            analyze, log, alert + demo scenarios
│       └── MainActivity.kt              Jetpack Compose UI
├── build.gradle.kts, settings.gradle.kts, gradle.properties
└── README.md
```

## Build it yourself

No local setup is needed: push to GitHub and the workflow does everything. To build on your own machine instead, install JDK 17 and Gradle 8.7, then run:

```
gradle assembleDebug
```

The APK appears at `app/build/outputs/apk/debug/app-debug.apk`. You can also open the folder in Android Studio.

## Tune the detector

All rules live in `ScamDetectorEngine.kt`. To add a scam pattern, add one `Rule("label", weight, """regex""")` line to `messageRules`. Change `HOME_COUNTRY_CODE` if you are not in India, and edit `WANGIRI_PREFIXES` to match the call waves you see.

## Privacy

ShieldOS has no internet permission and no analytics. Messages and numbers are scanned in memory; only the last 50 flagged events (a short preview, never the full text of safe messages) are kept in the app's private storage, and **Clear** wipes them.

## Honest limitations

- It is a heuristic, not a guarantee. Expect some false alarms and some misses; treat the warning as a prompt to stop and verify, not a verdict.
- Android only exposes a caller's number before a call rings, so call scoring uses the number, not what is said on the line.
- SMS permissions are restricted on Google Play, so this app is distributed as a GitHub APK.
- `SYSTEM_ALERT_WINDOW` is declared for future full-screen overlays; the current build does not use it.

## License

MIT. See [LICENSE](LICENSE). Built as an open-source college project: fork it, improve the rules, send a pull request.
