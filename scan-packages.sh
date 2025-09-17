#!/bin/sh
# scanner for compromised npm packages
# Usage: ./scan-packages.sh compromised-packages.txt [findings-output.txt]

set -eu

if [ $# -lt 1 ]; then
  echo "Usage: $0 compromised-packages.txt [findings-output.txt]" >&2
  exit 2
fi

pkgfile=$1
outfile=${2:-findings-$(date -u +%Y%m%dT%H%M%SZ).log}

if [ ! -f "$pkgfile" ]; then
  echo "Package list file not found: $pkgfile" >&2
  exit 2
fi

# empty/create the output file
: > "$outfile"
echo "# Findings from $(date -u)" >> "$outfile"

echo "🔍 Scanning for compromised NPM packages..."

# ---------------------------------------
# Helpers
# ---------------------------------------
report() {
  msg=$1
  echo "$msg"
  printf '%s\n' "$msg" >> "$outfile"
}

split_entry() {
  entry=$1
  pkg=${entry%@*}
  ver=${entry#*@}
  if [ -z "$pkg" ] || [ -z "$ver" ] || [ "$pkg" = "$ver" ]; then
    return 1
  fi
  return 0
}

scan_file() {
  file=$1
  while IFS= read -r entry; do
    case $entry in \#*|"") continue ;; esac
    if split_entry "$entry"; then
      if grep -q -- "$pkg" "$file" 2>/dev/null && grep -q -- "$ver" "$file" 2>/dev/null; then
        report "Found $pkg@$ver in $file"
      fi
    fi
  done <"$pkgfile"
}

scan_npm_cache() {
  cache_dir=$1
  [ -d "$cache_dir" ] || return
  while IFS= read -r entry; do
    case $entry in \#*|"") continue ;; esac
    if split_entry "$entry"; then
      grep -RIl -- "$pkg@$ver" "$cache_dir" 2>/dev/null | while IFS= read -r match; do
        report "Found $pkg@$ver in cached file: $match"
      done
    fi
  done <"$pkgfile"
}

scan_pnpm_store() {
  cache_dir=$1
  [ -d "$cache_dir" ] || return

  echo "📦 Scanning pnpm store at: $cache_dir"
  printf '# Scanning pnpm store %s\n' "$cache_dir" >> "$outfile"

  patterns=$(mktemp); trap 'rm -f "$patterns"' 0 1 2 3 15
  while IFS= read -r line; do
    case $line in \#*|"") continue ;; esac
    printf '%s\n' "$line"
  done <"$pkgfile" > "$patterns"

  total=$(find "$cache_dir" -type f 2>/dev/null | wc -l | tr -d '[:space:]')
  [ -z "$total" ] && total=0
  echo "  Total files in pnpm store: $total"

  interval=500
  count=0
  find "$cache_dir" -type f 2>/dev/null | while IFS= read -r file; do
    count=$((count + 1))
    if [ $((count % interval)) -eq 0 ]; then
      echo "  ...scanned $count/$total files in pnpm store"
    fi
    if grep -F -q -f "$patterns" "$file" 2>/dev/null; then
      while IFS= read -r entry; do
        case $entry in \#*|"") continue ;; esac
        if split_entry "$entry"; then
          if grep -q -- "$pkg@$ver" "$file" 2>/dev/null; then
            report "Found $pkg@$ver in cached file: $file"
          fi
        fi
      done <"$patterns"
    fi
  done

  echo "  ...finished scanning pnpm store"
}

scan_lockfile_resolved() {
  file=$1
  while IFS= read -r entry; do
    case $entry in \#*|"") continue ;; esac
    if split_entry "$entry"; then
      if grep -q -- "$pkg/-/$pkg-$ver.tgz" "$file" 2>/dev/null; then
        report "Resolved $pkg@$ver in $file"
      fi
    fi
  done <"$pkgfile"
}

# ---------------------------------------
# Scans
# ---------------------------------------
echo "🔒 Scanning project lockfiles..."
find . -type f \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \) 2>/dev/null \
  | while IFS= read -r f; do
      scan_lockfile_resolved "$f"
    done

echo "📦 Scanning npm caches..."
[ -d "$HOME/.npm/_cacache" ] && scan_npm_cache "$HOME/.npm/_cacache"
[ -d "$HOME/.npm-packages" ] && scan_npm_cache "$HOME/.npm-packages"

echo "📦 Scanning Yarn global cache..."
if command -v yarn >/dev/null 2>&1; then
  yarn_cache=$(yarn cache dir 2>/dev/null || true)
  [ -n "$yarn_cache" ] && [ -d "$yarn_cache" ] && scan_npm_cache "$yarn_cache"
fi

echo "📦 Scanning pnpm store..."
if command -v pnpm >/dev/null 2>&1; then
  pnpm_cache=$(pnpm store path 2>/dev/null || true)
  [ -n "$pnpm_cache" ] && [ -d "$pnpm_cache" ] && scan_pnpm_store "$pnpm_cache"
fi

# ---------------------------------------
# Summary
# ---------------------------------------
echo ""
echo "📊 Summary of Findings:"
if grep -q "Found" "$outfile"; then
  cat "$outfile"
  exit 1
else
  echo "✅ No compromised packages found."
  printf '✅ No compromised packages found. (%s)\n' "$(date -u)" >> "$outfile"
  exit 0
fi
