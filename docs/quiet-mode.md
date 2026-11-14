# Quiet mode (fewer questions)

Deus Witness asks least when Claude Code's own strict sandbox is on. In quiet mode the agent's commands:

- reach only the hosts you list. Quiet mode starts with npm, PyPI and GitHub downloads: `registry.npmjs.org`, `pypi.org`,
  `files.pythonhosted.org`, `github.com`, `codeload.github.com`, `objects.githubusercontent.com` and `raw.githubusercontent.com`.
  With these, `npm install`, `pip install` (including `git+https://github.com/...`) and `git pull` of a public repository work from
  the first try;
- cannot read your SSH and cloud keys, your login keychain, your browser cookies, or your editors' and CLIs' token stores;
- don't see your Deus Witness agent key or your GitHub / npm / PyPI tokens (`GITHUB_TOKEN`, `NPM_TOKEN`, ...). These are hidden by name
  with Claude Code's `sandbox.credentials`.

With all of this in place, Deus Witness asks only about what could leave your Mac or can't be undone.

**What stays the same:** your permission mode (`acceptEdits` stays `acceptEdits`), your other environment variables (your tests still
see `OPENAI_API_KEY`, `DATABASE_URL`, ...), your hooks and plugins.

**What changes:**

- A `git push`, `gh pr create` or `npm publish` that the agent runs can't use your login, because your keychain and tokens are closed
  to its commands. Deus Witness asks you about it; run it yourself in your terminal.
- `git clone` and `git init` into the project fail, because Claude Code's sandbox protects `.git/config`. Run them yourself in your
  terminal.
- A host that isn't on the list is refused. Add your own in your terminal:
  `uvx --from "deus-witness==0.2.74" deus-witness-hook --setup-strict --host git.example.com`
  (a host name only: no `*`, no IP, no port).

## Turning it on

 `deus-witness try` in a terminal offers it once at the end (type yes: quiet from your first session); `/deus-witness:try`
asks you after the setup. Without quiet mode Deus Witness asks about most commands (tests, installs, a virtualenv): measured on our friction
stand, ~40-110 questions on the first day of real work instead of 0-6. `/deus-witness:quiet` lists what changes in `~/.claude/settings.json`
in a few lines (the line-by-line change: `--quiet-offer --full`). If you say yes, Deus Witness asks YOU to
approve it with your passkey; the agent can't switch it on or off by itself. Or, in your own terminal:
`uvx --from "deus-witness==0.2.74" deus-witness-hook --setup-strict`, which shows the change and asks you to type yes (a real terminal:
`echo yes |` and runs from a script or an agent are refused). Quiet mode keeps a backup next to the file,
`~/.claude/settings.json.bak-strict-<date>`, and starts with your next Claude Code session.

## Undo

Run `uvx --from "deus-witness==0.2.74" deus-witness-hook --undo-strict` in your terminal: it restores the newest backup and keeps the
backup files (delete them when you no longer need them).

## Reminders

 if you said "later", from your second session on the session start reminds you at most once a week. To stop the
reminders, say no in `/deus-witness:quiet`, answer anything but yes to `deus-witness-hook --setup-strict` in the terminal, or run
`deus-witness-hook --quiet-no`. `DEUS_WITNESS_QUIET_HINT=0` silences them too.

## Linux and WSL2

 quiet mode works there too, with Claude Code's own Linux sandbox (bubblewrap). First install two packages: `sudo apt install bubblewrap socat` (Fedora / RHEL: `sudo dnf install bubblewrap socat`). Then turn it on as above (`/deus-witness:quiet`, or `deus-witness-hook --setup-strict` in your terminal): it checks the machine first and, if something is missing, says what to do and changes nothing. Ubuntu 24.04 blocks bubblewrap by default (AppArmor, `kernel.apparmor_restrict_unprivileged_userns`): the command prints the small AppArmor profile that allows it for bubblewrap only. WSL2: turn Windows interop off (`[interop]` `enabled=false` in `/etc/wsl.conf`, then `wsl --shutdown`), because a `.exe` started from Linux runs outside the sandbox; WSL1 has no sandbox. Containers are not supported: Azure Container Instances and similar (their `/proc/version` names Microsoft, so Claude Code takes them for WSL1, and `--setup-strict` says so and changes nothing, with or without `--weaker-nested`); in a Docker container that cannot mount `/proc`, `--setup-strict --weaker-nested` writes Claude Code's weaker sandbox if you ask for it, and Deus Witness does not count it as quiet mode and keeps asking. What we checked (13.11, Debian 12 on Azure Container Instances, Claude Code 2.1.323): Claude Code's sandbox itself, run with two workarounds of our test bench that this tool does not apply (a substituted `/proc/version` and the weaker nested mode) - a test of the sandbox, not a path you can take. Ubuntu and WSL2 are not checked live yet.
