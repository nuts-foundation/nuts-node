#!/usr/bin/env bash
# Fails when govulncheck reports a vulnerability that is not covered by a VEX statement.
#
# govulncheck can't skip findings itself. This script reads its JSON output and the OpenVEX document
# of this repository, and skips findings for which the document contains a "not_affected" statement.
# A statement is only used for MAX_AGE_DAYS after its timestamp (or last_updated, if set).
# After that the finding fails the check again, until the statement is reviewed and its date is updated.
#
# Usage: govulncheck-vex.sh <govulncheck JSON output> <OpenVEX document>
set -euo pipefail

MAX_AGE_DAYS="${MAX_AGE_DAYS:-180}"
findings_file="$1"
vex_file="$2"

# Vulnerabilities that are called by our code, the same set that makes "govulncheck" (text output) fail.
# Output: one JSON object per vulnerability, with its ID, aliases, summary, module and fixed version.
called=$(jq -c -s '
  (map(select(.osv) | {key: .osv.id, value: .osv}) | from_entries) as $osv
  | map(select(.finding and .finding.trace[0].function) | .finding)
  | group_by(.osv)
  | map({
      id: .[0].osv,
      aliases: ($osv[.[0].osv].aliases // []),
      summary: ($osv[.[0].osv].summary // ""),
      module: .[0].trace[0].module,
      fixed: (.[0].fixed_version // "no fix available")
    })
  | .[]' "$findings_file")

# IDs (name and aliases) of "not_affected" statements that are still within MAX_AGE_DAYS.
valid_ids=$(jq -r --argjson maxAge "$MAX_AGE_DAYS" '
  .statements[]
  | select(.status == "not_affected")
  | select((now - ((.last_updated // .timestamp) | fromdateiso8601)) <= ($maxAge * 86400))
  | .vulnerability | (.name, (.aliases // [])[])' "$vex_file")

# IDs of "not_affected" statements that are too old.
expired_ids=$(jq -r --argjson maxAge "$MAX_AGE_DAYS" '
  .statements[]
  | select(.status == "not_affected")
  | select((now - ((.last_updated // .timestamp) | fromdateiso8601)) > ($maxAge * 86400))
  | .vulnerability | (.name, (.aliases // [])[])' "$vex_file")

failed=0
while IFS= read -r vuln; do
  [ -z "$vuln" ] && continue
  id=$(jq -r '.id' <<<"$vuln")
  description=$(jq -r '"\(.id) (\(.aliases | join(", "))): \(.summary)\n  module: \(.module), fixed in: \(.fixed)"' <<<"$vuln")
  ids=$(jq -r '.id, .aliases[]' <<<"$vuln")

  if grep -qxFf <(echo "$ids") <<<"$valid_ids"; then
    echo -e "SKIPPED (VEX: not affected) $description"
  elif grep -qxFf <(echo "$ids") <<<"$expired_ids"; then
    echo -e "::error::VEX statement for $id is older than $MAX_AGE_DAYS days. Review it and update its date in $vex_file.\nFOUND $description"
    failed=1
  else
    echo -e "::error::$id is called by the code and not covered by a VEX statement.\nFOUND $description"
    failed=1
  fi
done <<<"$called"

if [ "$failed" -ne 0 ]; then
  exit 1
fi
echo "No vulnerabilities found, other than the ones skipped above."
