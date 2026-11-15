# Ta3alm Platform — Android Release Signing, R8 Obfuscation & Play Console Guide

## 1. Security Rules for Keystores & Secrets
1. **NEVER** commit `.jks`, `.keystore`, `.p12`, or `android/key.properties` to Git (`flutter_app/.gitignore` excludes them explicitly).
2. Store the **Upload Keystore** in an encrypted password manager / CI secret vault, and enable **Play App Signing** in Google Play Console (so Google secures the master App Signing Key while you sign uploads with your upload key).
3. Record the **App Signing Key Certificate SHA-256** from Google Play Console (`Setup -> App integrity -> App signing`) and set it in backend environment variable `ANDROID_RELEASE_CERT_SHA256` and Google Cloud / Play Integrity settings.

---

## 2. Generate Your Upload Keystore (Run Once Locally)
```bash
keytool -genkey -v \
  -keystore ta3alm-release-upload.jks \
  -alias ta3alm_upload \
  -keyalg RSA \
  -keysize 2048 \
  -validity 10000
```
*Store `ta3alm-release-upload.jks` outside the repository (or in a private encrypted vault) and back up its passwords securely.*

Extract the SHA-256 fingerprint for Play Console / Firebase / Google Sign-In:
```bash
keytool -list -v -keystore ta3alm-release-upload.jks -alias ta3alm_upload
```

---

## 3. Configure Signing Credentials (`build.gradle.kts`)
`flutter_app/android/app/build.gradle.kts` reads signing credentials via **either**:

### Option A: Local `android/key.properties` (Copied from `android/key.properties.example`)
Create `flutter_app/android/key.properties` (never committed):
```properties
storeFile=C:/secure-keys/ta3alm-release-upload.jks
storePassword=YOUR_STRONG_STORE_PASSWORD
keyAlias=ta3alm_upload
keyPassword=YOUR_STRONG_KEY_PASSWORD
```

### Option B: CI/CD Environment Variables (Recommended for GitHub Actions / Bitrise)
```bash
export TA3ALM_REQUIRE_RELEASE_SIGNING=true
export TA3ALM_KEYSTORE_PATH=/runner/secrets/ta3alm-release-upload.jks
export TA3ALM_KEYSTORE_PASSWORD=...
export TA3ALM_KEY_ALIAS=ta3alm_upload
export TA3ALM_KEY_PASSWORD=...
export TA3ALM_PLAY_CLOUD_PROJECT_NUMBER=123456789012
```
Notice `TA3ALM_REQUIRE_RELEASE_SIGNING=true` causes Gradle to **fail fast** if release signing credentials are absent, guaranteeing CI never produces an accidentally debug-signed release artifact.

---

## 4. Code Shrinking, R8 Obfuscation & Debug Symbol Splitting

In `flutter_app/android/app/build.gradle.kts` (`buildTypes.release`):
- `isMinifyEnabled = true` (enables R8 shrinking & obfuscation)
- `isShrinkResources = true` (strips unused Android resources)
- `proguardFiles(..., "proguard-rules.pro")`
- `ndk { debugSymbolLevel = "SYMBOL_TABLE" }`

### Building Production Release AAB (with Dart `--obfuscate` & `--split-debug-info`)
```bash
cd flutter_app
flutter pub get
flutter build appbundle --release \
  --obfuscate \
  --split-debug-info=build/app/outputs/symbols \
  --dart-define=API_BASE_URL=https://www.ta3alm.online/api/v1 \
  --dart-define=PLAY_CLOUD_PROJECT_NUMBER=123456789012
```
Upload `build/app/outputs/bundle/release/app-release.aab` to Google Play Console, and archive `build/app/outputs/symbols/` + `build/app/outputs/mapping/release/mapping.txt` privately for crash symbolication.

