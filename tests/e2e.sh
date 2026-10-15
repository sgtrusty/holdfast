#!/bin/sh
# Real-bwrap smoke test. Usage: sh tests/e2e.sh path/to/holdfast   (run as a non-root user)
set -u
HF="${1:?usage: e2e.sh path/to/holdfast}"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/proj/.git" "$T/proj/sub/.git" "$T/profiles"
cat > "$T/profiles/e2e.profile" <<P
[profile]
name = e2e
command = sh
cwd = yes
new_session = no
[bin]
allow = sh ls cat id touch mv
P
export HOLDFAST_PROFILES="$T/profiles" HOLDFAST_HOME="$T/data"
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1 (got '$2', want '$3')"; fail=1; fi; }
run() { (cd "$T/proj" && "$HF" run e2e -- sh -c "$1" 2>/dev/null); }

check "worktree writable"        "$(run 'touch /shared/f && echo y')" "$(printf 'y')"
check ".git read-only"           "$(run 'touch /shared/.git/x 2>/dev/null && echo bad || echo ro')" ro
check "nested .git read-only"    "$(run 'touch /shared/sub/.git/x 2>/dev/null && echo bad || echo ro')" ro
check ".git cannot be renamed"   "$(run 'mv /shared/.git /shared/g2 2>/dev/null && echo bad || echo blocked')" blocked
check "no host /etc/shadow"      "$(run 'ls /etc/shadow 2>/dev/null && echo bad || echo none')" none
check "fake passwd"              "$(run 'cat /etc/passwd' | grep -c '^root:x:0:0')" 1
check "whitelist: no 'uname'"    "$(run 'uname 2>/dev/null && echo bad || echo none')" none
check "no network"               "$(run 'cat /proc/net/dev' | grep -cv -e Inter -e face -e '^ *lo:')" 0
check "HOME is not the real one" "$(run 'ls /home')" sandbox
check "policy refuses \$HOME"    "$(cd "$HOME" && "$HF" run -y e2e -- true >/dev/null 2>&1; echo $?)" 3
exit $fail
