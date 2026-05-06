#!/usr/bin/env bash
set -euo pipefail

failed=0

normalize_action() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"

    if [[ "${#value}" -ge 2 ]]; then
        local first="${value:0:1}"
        local last="${value: -1}"

        if [[ ( "$first" == '"' && "$last" == '"' ) || ( "$first" == "'" && "$last" == "'" ) ]]; then
            value="${value:1:${#value}-2}"
        fi
    fi

    printf '%s' "$value"
}

while IFS= read -r -d '' file; do
    line_number=0

    while IFS= read -r line || [[ -n "$line" ]]; do
        ((line_number += 1))

        if [[ ! "$line" =~ ^[[:space:]-]*uses:[[:space:]]*([^[:space:]#]+)([[:space:]]*#(.*))? ]]; then
            continue
        fi

        action="$(normalize_action "${BASH_REMATCH[1]}")"
        comment="${BASH_REMATCH[3]:-}"

        case "$action" in
            ./*|docker://*)
                continue
                ;;
        esac

        if [[ "$action" != *@* ]]; then
            echo "$file:$line_number: action is missing an explicit ref: $action" >&2
            failed=1
            continue
        fi

        ref="${action##*@}"
        if [[ ! "$ref" =~ ^[0-9a-fA-F]{40}$ ]]; then
            echo "$file:$line_number: action ref is not pinned to a full commit SHA: $action" >&2
            failed=1
            continue
        fi

        if [[ -z "${comment//[[:space:]]/}" ]]; then
            echo "$file:$line_number: pinned action is missing a version comment: $action" >&2
            failed=1
        fi
    done < "$file"
done < <(find .github/workflows -type f \( -name '*.yml' -o -name '*.yaml' \) -print0)

if [[ "$failed" -ne 0 ]]; then
    exit 1
fi

echo "All GitHub Actions are pinned to full commit SHAs."
