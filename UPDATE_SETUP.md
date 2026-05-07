# 🔄 SentinelDroid — Update System Setup Guide

This guide walks you through setting up the free GitHub-based update server,
and explains exactly what to do every time you want to push a new version.

---

## Part 1 — One-Time GitHub Setup (5 minutes)

### Step 1 — Create a free GitHub account
Go to https://github.com and sign up (it's free).

### Step 2 — Create a new repository
1. Click the **+** button (top right) → **New repository**
2. Name it exactly: `sentineldroid-updates`
3. Set it to **Public** ✅ (required so the app can read it without login)
4. Check **"Add a README file"**
5. Click **Create repository**

### Step 3 — Upload version.json
1. Inside the new repository, click **Add file → Upload files**
2. Upload the `version.json` file from your SentinelDroid folder
3. Click **Commit changes**

### Step 4 — Get your raw URL
1. Click on `version.json` in your repository
2. Click the **Raw** button
3. Copy the URL — it will look like:
   `https://raw.githubusercontent.com/YOUR_USERNAME/sentineldroid-updates/main/version.json`

### Step 5 — Update the app with your URL
Open this file in Android Studio:
```
app/src/main/java/com/sentineldroid/update/UpdateChecker.kt
```

Find this line:
```kotlin
const val VERSION_URL = "https://raw.githubusercontent.com/sentineldroid-app/updates/main/version.json"
```

Replace it with YOUR URL from Step 4:
```kotlin
const val VERSION_URL = "https://raw.githubusercontent.com/YOUR_USERNAME/sentineldroid-updates/main/version.json"
```

Then **Run** the app again on your phone to install this version.

---

## Part 2 — How to Push a New Update

Every time you want to update the app on your phone:

### Step A — Make your code changes in Android Studio

### Step B — Bump the version numbers in UpdateChecker.kt
```kotlin
const val CURRENT_VERSION = "1.4.0"   // Change this (e.g. 1.3.0 → 1.4.0)
const val CURRENT_VERSION_CODE = 4    // Increment by 1 (e.g. 3 → 4)
```

### Step C — Build and install on your phone
In Android Studio: click ▶️ **Run** with your phone connected.

### Step D — Update version.json on GitHub
1. Go to your `sentineldroid-updates` repository on GitHub
2. Click `version.json`
3. Click the ✏️ pencil icon to edit
4. Update these fields:
```json
{
  "version": "1.4.0",
  "version_code": 4,
  "release_date": "2025-04-15",
  "release_notes": "• What you changed or fixed",
  "download_url": "https://github.com/YOUR_USERNAME/sentineldroid-updates/releases/latest"
}
```
5. Click **Commit changes**

### Step E — Done!
Anyone still on the old version will see a blue update banner on their dashboard
the next time they open the app. The banner shows the release notes and a link
to download the new version.

---

## How the update check works

- The app checks GitHub **once every 6 hours** (not on every open, to save battery)
- It compares `version_code` (an integer) — not the version string
- So `version_code: 4` > `version_code: 3` = update banner appears
- The user can tap **"Later"** to dismiss — the banner won't show again for that version
- If GitHub is unreachable (no internet), the check silently fails — no error shown

---

## Sharing future updates with others

If you share SentinelDroid with friends/family:
1. Build the APK: **Build → Build Bundle(s)/APK(s) → Build APK(s)**
2. Find the `.apk` file in `app/build/outputs/apk/debug/`
3. Upload it to your GitHub repository as a **Release**:
   - Go to your repo → **Releases** → **Create a new release**
   - Tag it (e.g. `v1.4.0`), upload the APK, publish
4. The `download_url` in version.json will point them there automatically

---

## Troubleshooting

| Problem | Solution |
|---|---|
| Banner never appears | Check that `version_code` in version.json is higher than the one in the app |
| "Network error" | Make sure your repository is Public, not Private |
| URL not working | Verify you're using the **Raw** URL (contains `raw.githubusercontent.com`) |
| Can't edit version.json | Make sure you're logged into GitHub |
