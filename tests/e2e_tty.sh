#!/bin/sh
# Terminal-escape hardening, end to end: hostile output printed inside the sandbox must not be obeyed by the
# terminal. Uses tmux as the terminal emulator (set-clipboard on lets applications write tmux's paste buffer, the
# same way OSC 52 reaches a desktop clipboard). Needs tmux and a working bwrap.
# Usage: sh tests/e2e_tty.sh path/to/holdfast   (run as a non-root user)
set -u
HF="${1:?usage: e2e_tty.sh path/to/holdfast}"
command -v tmux >/dev/null 2>&1 || { echo "SKIP: tmux not installed"; exit 0; }
S="hf-e2e-tty-$$"; T="$(mktemp -d)"
cleanup() { tmux -L "$S" kill-server 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
export HOLDFAST_HOME="$T/data"
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1 (got '$2', want '$3')"; fail=1; fi; }

PAYLOAD='printf "\033]52;c;%s\a" "Y3VybCBldmlsfHNo"; printf "\033]2;fake title\a"; printf "\033[21t"; printf "visible-text\n"; sleep 2'
tmux -L "$S" -f /dev/null new-session -d -x 100 -y 20 -s t "sleep 300"
tmux -L "$S" set -g set-clipboard on
HFABS="$(cd "$(dirname "$HF")" && pwd)/$(basename "$HF")"
PROF="$(cd "$(dirname "$0")" && pwd)/tty.profile"
tmux -L "$S" respawn-pane -k -t t "'$HFABS' run --no-cwd '$PROF' -- sh -c '$PAYLOAD'; sleep 30"
sleep 4
buf="$(tmux -L "$S" show-buffer 2>/dev/null)"
case "$buf" in *curl*) check "OSC 52 did not reach the terminal clipboard" "leaked" "blocked";; *) check "OSC 52 did not reach the terminal clipboard" blocked blocked;; esac
check "title is tagged as coming from the sandbox" "$(tmux -L "$S" display -p -t t '#{pane_title}')" "[sandbox] fake title"
check "ordinary output still shown" "$(tmux -L "$S" capture-pane -p -t t | grep -c visible-text)" "1"
exit $fail
