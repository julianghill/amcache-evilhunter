#!/usr/bin/env bash
set -e

BIN="/usr/local/bin/amcache-evilhunter"
MAN="/usr/local/share/man/man1/amcache-evilhunter.1"

install -Dm755 ./amcache-evilhunter.elf "$BIN"
install -Dm644 ./amcache-evilhunter.1 "$MAN"

# Refresh man database if available (quietly)
command -v mandb >/dev/null 2>&1 && mandb >/dev/null 2>&1 || true

echo "Installed:"
echo "  $BIN"
echo "  $MAN"
echo "Try: amcache-evilhunter  |  man amcache-evilhunter"

