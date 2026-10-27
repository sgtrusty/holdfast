# wssch (https://github.com/sgtrusty/wssch): one entry point that drives AI coding assistants
# (opencode, forge, qwencode, kilocode, goose, crush, antigravity) over a workspace.
#
#   holdfast run wssch                                    # online: private pasta netns, outbound only
#   holdfast run --net=none wssch                         # no network at all (local files, no API calls)
#   cd ~/Projects/foo && holdfast run -y wssch -- opencode
#
# holdfast IS the sandbox here, so wssch must not build another one: `disable_userns` stays `yes`
# (nothing inside may create user namespaces), which makes wssch's own bwrap call fail. The command is
# therefore `wssch orchestrate` (alias `orcs`): the orchestrator without its inner sandbox. Running
# `holdfast run wssch -- wssch run` cannot work and is not a configuration to reach for.
#
# The network is on by default, because talking to a model API is what this tool is for. pasta gives a
# private namespace with outbound internet only: no host loopback, no host X11/D-Bus sockets, no inbound
# ports, an explicit resolver (never the host's /etc/resolv.conf). It does not make sending data away
# safe: whatever the assistant reads it can also send, and what it sends is decided by prompts, so keep
# the tree you mount (`cwd`) and the keys you pass (`[env] pass`) small, and use --net=none when you only
# want local work.
#
# The host's ~/.config/wssch is a denied path (it holds the whitelist database), so nothing here binds
# it. wssch keeps its own config, bun/rtk binaries and database in the sandbox's private home
# (<data>/profiles/wssch/home), which persists between runs:
#   holdfast run wssch -- wssch deps                              # once, to fetch its own binaries into it

[profile]
name        = wssch
description = wssch AI-coding orchestrator, offline, project tree read-write
mode        = host
command     = wssch orchestrate
hostname    = holdfast-wssch
cwd         = ask             # confirm before mounting the current directory

[bin]
# The host binaries that exist inside. Anything not listed cannot be executed, even if it is installed.
allow = wssch node bun npm npx git sh bash env id uname which readlink dirname basename realpath
allow = ls cat head tail sort uniq tee grep sed awk tr cut wc cp mv mkdir rm chmod find xargs printf
# The assistants wssch can drive. Ones you have not installed are skipped with a warning; delete the
# lines you do not need. Pin a binary that is not in /usr/bin with name=/absolute/path, e.g.
# allow = bun=$HOME/.local/bin/bun
allow = opencode forge qwencode kilocode goose crush

[fs]
# node, bun and the assistants dlopen and spawn far too much to be derived from ELF headers (module
# trees, loaders, CA trust, locales), so this profile opts out of `libs = minimal`.
libs = full
ro_try = /usr/lib/node_modules
ro_try = /usr/local/lib/node_modules
ro_try = /usr/share/nodejs
# /tmp is already a private tmpfs in every sandbox; only add one here if wssch needs another scratch dir.

[home]
user = agent
dirs = .config .local/share .local/state .cache .local/bin
# Never bind ~/.config/wssch or ~/.config/opencode here: both are denied paths (the policy refuses
# anything that would expose credentials or the whitelist database).

[env]
pass = TERM COLORTERM
# Only pass keys the assistant actually needs; everything passed here is readable by every process
# in the sandbox (including whatever a prompt injection makes it run).
# pass = ANTHROPIC_API_KEY OPENAI_API_KEY GEMINI_API_KEY OPENROUTER_API_KEY
unset = DBUS_SESSION_BUS_ADDRESS

[network]
mode = pasta                  # private outbound-only namespace; override with --net=none
# Required with pasta: the host's /etc/resolv.conf never enters a sandbox unless you ask for it.
dns   = 1.1.1.1
# `pasta` has no route to the host's loopback: a local Ollama for embeddings is NOT reachable from the
# sandbox. Either install and run Ollama inside this sandbox (ollama serve, then pass OLLAMA_HOST), or
# accept that RAG falls back to what wssch does without embeddings.

[clipboard]
# Inside the sandbox:  printf '%s' "$TEXT" > /tmp/clip_pipe   -> lands in the HOST clipboard.
# One-way only; the sandbox can never read your clipboard.
mode = out
path = /tmp/clip_pipe

[git]
# Every .git under the mounted tree is re-bound READ-ONLY: an assistant that is talked into something
# cannot add hooks, change `core.*`, rewrite history or move refs. It also means `git commit` has to
# happen outside this sandbox.
protect = yes

[audio]
mode = none
