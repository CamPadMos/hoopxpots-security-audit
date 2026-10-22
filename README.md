# HoopXpots — Cloud & Application Security Audit

**Author:** Cristobal Padilla Mosquera · **Date:** October 2026 · **Scope:** Production (Google Cloud / Firebase project + Next.js app on Vercel)

HoopXpots is a pickup-basketball platform for Houston (Next.js on Vercel, Firebase Authentication with Google sign-in, Cloud Firestore). I audited my own production project the way a security analyst would: automated configuration checks first, then a manual review of the code and database rules, then remediation and a re-scan.

> The application source stays private. This repo contains the report, the read-only audit script, and the database rules before and after. No keys, credentials or personal data are included.

## Results at a glance

| | Count |
|---|---|
| Findings identified | **11** (2 high · 4 medium · 3 low · 2 informational) |
| Remediated | **9** |
| Risk accepted with mitigation | 1 |
| Verified not applicable | 1 |
| Automated scan | 3 issues before → 2 after (both explained below) |
| Unused cloud APIs disabled | **23** |

The most important finding came from the **manual review, not the scanner**: the database rules allowed anyone on the internet to read every user's email address.

## Methodology

1. **Automated configuration scan** — [`scripts/gcp_audit.sh`](scripts/gcp_audit.sh), a read-only Bash script using the `gcloud` CLI. It checks IAM roles, service account keys, public storage buckets, open firewall rules, unauthenticated Cloud Run services, Cloud SQL exposure, secret management and audit logging.
2. **Manual code review** — searched the codebase for hard-coded secrets, reviewed how the client writes to Firestore, and compared every write against the security rules.
3. **Rules review** — tested each Firestore rule against two questions: *who* is allowed to write, and *what exactly* they may change.
4. **Remediation and re-scan** — fixed issues in order of severity, verified the app still worked in production after each change, then re-ran the scan.

## Findings

| ID | Severity | Finding | Status |
|---|---|---|---|
| F-01 | 🔴 High | User profiles (including email addresses) were publicly readable | ✅ Remediated |
| F-02 | 🔴 High | Any signed-in user could modify any game | ✅ Remediated |
| F-03 | 🟠 Medium | Users could edit their own stats (Elo, wins), enabling leaderboard cheating | ✅ Remediated |
| F-04 | 🟠 Medium | Four unused collections accepted writes, allowing impersonation | ✅ Remediated |
| F-05 | 🟠 Medium | A second API key had no website restriction and access to 25 APIs | ✅ Remediated |
| F-06 | 🟠 Medium | Data Access audit logs were disabled | ✅ Remediated |
| F-07 | 🟡 Low | The app's API key allowed Maps APIs it no longer needed | ✅ Remediated |
| F-08 | 🟡 Low | 23 unused Google Maps Platform APIs were enabled | ✅ Remediated |
| F-09 | 🟡 Low | Errors were shown as success; games had no recorded creator | ✅ Remediated |
| F-10 | ⚪ Info | My account holds the Owner role | ⚖️ Accepted, mitigated |
| F-11 | ⚪ Info | Secret Manager not used | ✔️ Not applicable |

### F-01 · User emails publicly readable — High
**Issue.** The `users` collection allowed `read: if true`, and each profile stores the user's email. Anyone could download the email address of every registered user without signing in.
**Fix.** Profiles are now readable only by their owner (`isSelf(userId)`). The app never needed to read other users' profiles, so nothing broke.
**Lesson.** The original comment said "each user can only read/write their own data" — the rule did not match the comment. Rules must be tested, not trusted.

### F-02 · Any user could modify any game — High
**Issue.** `games` allowed `update: if request.auth != null`. Any signed-in user could remove players, change the time or rewrite any game.
**Fix.** Only the creator can edit a game. Everyone else can only *join*: the rule checks that the update changes nothing but `players` and `playerCount`, adds exactly the caller's own ID once, increases the count by one and does not exceed `maxPlayers`.

### F-03 · Users could edit their own stats — Medium
**Issue.** Owners had full write access to their profile, including `elo`, `wins`, `losses` and `gamesPlayed`.
**Fix.** New profiles must start at default values, and updates may only change `lastLogin`, `position`, `displayName` and `photoURL` (enforced with `diff().affectedKeys().hasOnly()`).

### F-04 · Unused collections open to writes — Medium
**Issue.** `notifications`, `interested`, `gamePlayers` and `activity` were not used by the app but accepted creates from any signed-in user without checking that `userId` matched the caller, so one user could create records as someone else.
**Fix.** Closed (`allow read, write: if false`) until a feature needs them — less attack surface. The rules file documents the check to add when they are reopened.

### F-05 · Unrestricted second API key — Medium
**Issue.** Besides the key the app uses, the project had an auto-created key with **no website restriction** and access to 25 APIs. If leaked, it could be used from any site.
**Fix.** Restricted to the production domain and the 5 Firebase APIs. Scheduled for deletion after a monitoring period, since unused credentials should not exist.

### F-06 · Data Access audit logs disabled — Medium
**Issue.** Only administrative changes were logged; there was no record of who created, changed or deleted data.
**Fix.** Enabled Data Write audit logs for Cloud Firestore. Data Read logs were left off on purpose to keep log volume and cost low.

### F-07 · App key allowed unneeded APIs — Low
**Issue.** The app's key (already restricted by website — a good existing control) also allowed the Maps JavaScript and Geocoding APIs.
**Fix.** Limited to exactly the 5 APIs Firebase needs: Identity Toolkit, Token Service, Firebase Installations, Firebase Management and Cloud Firestore.

### F-08 · 23 unused Maps Platform APIs enabled — Low
**Issue.** Enabling Google Maps Platform had turned on 23 APIs (Places, Directions, Street View, etc.). None were used, and the map had stopped working because the project had no billing account.
**Fix.** Disabled all 23 from the CLI and replaced Google Maps with **Leaflet + OpenStreetMap**, which needs no API key or billing. This removed a dependency, a cost risk and a broken feature at the same time.

### F-09 · Fail-open error handling — Low
**Issue.** Failed actions showed success messages ("Game created!" even when the write was rejected), which hides both bugs and blocked attacks. Games also never stored a creator, so the existing delete rule could never match.
**Fix.** Errors now show a real message, games store `createdBy`, and joining uses `arrayUnion` with a duplicate check.

### F-10 · Owner role — Informational, risk accepted
As the sole developer, holding Owner is expected, and removing it could lock me out. **Mitigation:** the account is protected with 2-Step Verification, there are no other members, and there are no user-managed service account keys.

### F-11 · Secret Manager not used — Informational, not applicable
Verified that all secrets live in **Vercel's encrypted environment variables**, `.env*` files are git-ignored, and no keys are hard-coded. The only third-party secret (NewsAPI) is used exclusively in a server-side route, so it never reaches the browser. The Firebase web config is public by design; access is controlled by the security rules and key restrictions above.

## What the scanner missed

The automated scan reported 3 issues. The two high-severity findings (F-01, F-02) were in the database rules and were only found through manual review. Configuration scanners check *settings*; they can't tell whether your access rules match what your application is supposed to allow.

## Validation

- Re-ran the scan: **3 → 2** flagged items, both documented above (F-10, F-11).
- Tested in production after each change: Google sign-in, viewing courts, creating and joining games, and editing a profile.
- Kept a copy of the previous rules and used the Firebase rules history so every change could be rolled back in one click.

## Next steps

- Delete the unused API key (F-05) after the monitoring period.
- Add automated rules tests with the Firebase Emulator in CI.
- Add security headers (CSP, HSTS) in the Next.js config.
- Move leaderboard stats to a server-side function so they can't be written from the client at all.

## Repository contents

| File | Description |
|---|---|
| [`scripts/gcp_audit.sh`](scripts/gcp_audit.sh) | Read-only GCP audit script (`./gcp_audit.sh PROJECT_ID`) |
| [`rules/firestore.rules.before`](rules/firestore.rules.before) | Original Firestore rules |
| [`rules/firestore.rules.after`](rules/firestore.rules.after) | Hardened rules, with comments |
