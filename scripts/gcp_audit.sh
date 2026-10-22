#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# GCP Security Audit (READ-ONLY) — runs list/describe commands only.
# Nothing in this script changes your project.
#
# Usage:  ./gcp_audit.sh YOUR_PROJECT_ID
# Output: audit_report_<project>_<date>.md
# Needs:  gcloud CLI logged in (gcloud auth login), gsutil
# ---------------------------------------------------------------------------
set -uo pipefail
# Never wait for interactive prompts (e.g. "enable this API? y/N") — skip instead.
export CLOUDSDK_CORE_DISABLE_PROMPTS=1

PROJECT="${1:-$(gcloud config get-value project 2>/dev/null)}"
[ -z "$PROJECT" ] && { echo "Usage: $0 PROJECT_ID"; exit 1; }
OUT="audit_report_${PROJECT}_$(date +%Y%m%d).md"
ISSUES=0

w()    { echo -e "$*" >> "$OUT"; }
flag() { w "- ⚠️ **$1** — $2"; ISSUES=$((ISSUES+1)); }
ok()   { w "- ✅ $1"; }

echo "# Security Audit — \`$PROJECT\`" > "$OUT"
w "_Generated $(date '+%Y-%m-%d %H:%M'). Read-only checks._\n"

# 1. IAM: broad roles and personal accounts with Owner/Editor ----------------
w "## 1. IAM (least privilege)"
POLICY=$(gcloud projects get-iam-policy "$PROJECT" --format=json 2>/dev/null)
BROAD=$(echo "$POLICY" | python3 -c '
import json,sys
p=json.load(sys.stdin)
for b in p.get("bindings",[]):
    if b["role"] in ("roles/owner","roles/editor"):
        for m in b["members"]: print(b["role"], m)')
if [ -n "$BROAD" ]; then
  while read -r role member; do
    flag "Broad role" "\`$member\` has \`$role\`. Replace with specific roles if possible."
  done <<< "$BROAD"
else ok "No Owner/Editor bindings found."; fi
if echo "$POLICY" | grep -q '"allUsers"\|"allAuthenticatedUsers"'; then
  flag "Public IAM binding" "Project grants a role to allUsers/allAuthenticatedUsers."
fi

# 2. Service account keys ----------------------------------------------------
w "\n## 2. Service account keys"
BEFORE=$ISSUES
for SA in $(gcloud iam service-accounts list --project "$PROJECT" --format="value(email)" 2>/dev/null); do
  KEYS=$(gcloud iam service-accounts keys list --iam-account "$SA" \
         --managed-by=user --format="value(name,validAfterTime)" 2>/dev/null)
  if [ -n "$KEYS" ]; then
    flag "User-managed key" "\`$SA\` has downloadable keys. Prefer Workload Identity / attached SAs; rotate or delete old keys."
  fi
done
[ "$ISSUES" -eq "$BEFORE" ] && ok "No user-managed service account keys."

# 3. Cloud Storage: public buckets ------------------------------------------
w "\n## 3. Cloud Storage"
BUCKETS=$(gsutil ls -p "$PROJECT" 2>/dev/null)
[ -z "$BUCKETS" ] && ok "No Cloud Storage buckets (or API not enabled)."
for B in $BUCKETS; do
  IAM=$(gsutil iam get "$B" 2>/dev/null)
  if echo "$IAM" | grep -q 'allUsers\|allAuthenticatedUsers'; then
    flag "Public bucket" "\`$B\` is readable by the internet. Confirm it only holds public assets."
  else ok "\`$B\` is private."; fi
done

# 4. Firewall rules open to the internet -------------------------------------
w "\n## 4. Network firewall"
OPEN=$(gcloud compute firewall-rules list --project "$PROJECT" \
  --filter="direction=INGRESS AND sourceRanges:0.0.0.0/0 AND disabled=false" \
  --format="value(name,allowed[].map().firewall_rule().list())" 2>/dev/null)
if [ -n "$OPEN" ]; then
  while read -r line; do
    if echo "$line" | grep -Eq '(^|[^0-9])(22|3389)([^0-9]|$)|all'; then
      flag "Admin port open to internet" "\`$line\` (SSH/RDP from 0.0.0.0/0). Restrict to your IP or use IAP."
    else w "- ℹ️ Open to internet: \`$line\` (OK if it's a public web port)"; fi
  done <<< "$OPEN"
else ok "No ingress rules open to 0.0.0.0/0 (or Compute API not enabled)."; fi

# 5. Cloud Run: unauthenticated services -------------------------------------
w "\n## 5. Cloud Run"
SVCS=$(gcloud run services list --project "$PROJECT" --format="value(metadata.name,region)" 2>/dev/null | tr '\t' ',')
[ -z "$SVCS" ] && ok "No Cloud Run services (or API not enabled)."
for SVC in $SVCS; do
  NAME=${SVC%%,*}; REGION=${SVC##*,}
  if gcloud run services get-iam-policy "$NAME" --region "$REGION" --project "$PROJECT" 2>/dev/null | grep -q allUsers; then
    w "- ℹ️ \`$NAME\` allows unauthenticated calls. Expected for a public frontend/API; make sure sensitive endpoints check auth in code."
  else ok "\`$NAME\` requires authentication."; fi
done

# 6. Cloud SQL: public IP / open networks ------------------------------------
w "\n## 6. Cloud SQL"
DBS=$(gcloud sql instances list --project "$PROJECT" --format="value(name)" 2>/dev/null)
[ -z "$DBS" ] && ok "No Cloud SQL instances (or API not enabled)."
for DB in $DBS; do
  NETS=$(gcloud sql instances describe "$DB" --project "$PROJECT" \
         --format="value(settings.ipConfiguration.authorizedNetworks[].value)" 2>/dev/null)
  SSL=$(gcloud sql instances describe "$DB" --project "$PROJECT" \
         --format="value(settings.ipConfiguration.sslMode)" 2>/dev/null)
  echo "$NETS" | grep -q "0.0.0.0/0" && flag "Database open to internet" "\`$DB\` accepts connections from 0.0.0.0/0."
  [[ "$SSL" != *ENCRYPTED* && "$SSL" != *TRUSTED* ]] && flag "SSL not enforced" "\`$DB\` does not require encrypted connections."
done

# 7. Secrets & logging -------------------------------------------------------
w "\n## 7. Secrets and logging"
if gcloud secrets list --project "$PROJECT" --format="value(name)" 2>/dev/null | grep -q .; then
  ok "Secret Manager in use."
else
  flag "No Secret Manager" "Secrets may be in code or env files. Use Secret Manager or your host's encrypted env vars (e.g. Vercel), and verify none are committed."
fi
AUDIT=$(echo "$POLICY" | grep -c '"auditConfigs"')
[ "$AUDIT" -eq 0 ] && flag "Data Access audit logs off" "Enable Data Access logs for key services (IAM → Audit Logs)."

w "\n---\n**Total issues flagged: $ISSUES**"
w "\n## Manual checks (code review)"
w "- [ ] No API keys or passwords committed to the repo (search git history)."
w "- [ ] User passwords hashed (bcrypt/argon2) or handled by Firebase Auth / Identity Platform."
w "- [ ] Inputs validated server-side (OWASP Top 10: injection, broken access control)."
w "- [ ] Users can only read/edit their own data (test by changing IDs in requests)."
w "- [ ] HTTPS everywhere; security headers set (CSP, HSTS)."

echo "Done. $ISSUES issue(s) flagged → $OUT"
