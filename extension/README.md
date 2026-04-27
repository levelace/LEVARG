# LEVARG OS-Browser Bridge

A tiny Chrome / Edge / Brave extension (MV3) that captures cookies from your
primary browser and ships them to LEVARG's SessionVault, so you can complete
SSO / MFA / OAuth login flows in your real browser (with your password
manager, biometrics, saved sessions) and still use the resulting authenticated
session inside LEVARG's hunts.

## Install (unpacked)

1. In LEVARG, go to **Sessions → Pair OS browser**, pick the scope, click
   **Generate token**. Copy the pairing URL or the token + ingest URL.
2. Open `chrome://extensions`, enable **Developer mode** (top-right), click
   **Load unpacked**, select this `extension/` folder.
3. Click the extension's options page (or the popup → "Configure"), paste
   the **ingest URL** and **token**, save.

## Use

1. Open the target site (e.g. `https://www.tiktok.com/`) in your normal tab.
2. Log in normally — your password manager, biometrics, MFA all work as usual.
3. Click the LEVARG extension icon → **Capture cookies for this tab**.
4. The popup shows how many cookies were captured. The new session appears in
   LEVARG's Sessions panel; pick it for your next Auto-Hunter run.

## Scope enforcement

Cookies are filtered server-side: any cookie whose host falls outside the
token's bound scope is silently dropped at ingest. The extension never types
or transmits credentials — it only forwards cookies the operator already
acquired in their normal browser session.

## Mobile

Most mobile browsers don't support extensions. Use the **bookmarklet** path
on the LEVARG pairing page instead — it captures whatever cookies the page
can see (HttpOnly cookies are excluded by browser policy).
