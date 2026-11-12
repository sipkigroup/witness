"""06.11 (r0260): `env | grep -i node` with the secret values masked (client and server copies are equal: server/tests/test_0611_shum.py).

Friction: `env | grep -i node` was asked every day (the danger `secrets: whole environment`): it can print NODE_AUTH_TOKEN, an npm token.
The hook (PreToolUse `updatedInput`) appends MASK_STAGE to such a line and sends THAT line to the witness, so the receipt names what runs.
MASK_STAGE prints a variable's value only when its NAME is on a list of well-known non-secret names, has no secret word in it (KEY, TOKEN,
SECRET, PASS, AUTH, ...) and the value has no credential shape (URL with user:password@, sk-, ghp_, AKIA, PEM, Bearer); every other line
is `NAME=[masked]`, a line that is not `NAME=...` (a continuation of a multi-line value, grep -c / -o output) is `[masked]`. POSIX awk
only (macOS awk 20200816, gawk, mawk: no interval expressions). The witness takes away the environment danger only for the EXACT line
ENV_LINE + MASK_STAGE (masked_line): anything after the mask, another grep option, a variable or a substitution -- asked as before."""
import re

MASK_STAGE = 'awk \'{if(match($0,/^[A-Za-z_][A-Za-z0-9_]*=/)){n=substr($0,1,RLENGTH-1);v=substr($0,RLENGTH+1);u=toupper(n);if(u~/^(PATH|MANPATH|INFOPATH|HOME|USER|LOGNAME|SHELL|TERM|TERM_PROGRAM|TERM_PROGRAM_VERSION|COLORTERM|LANG|LANGUAGE|LC_[A-Z]+|PWD|OLDPWD|TMPDIR|EDITOR|VISUAL|PAGER|TZ|SHLVL|HOSTNAME|OSTYPE|XDG_[A-Z_]+|NODE_ENV|NODE_OPTIONS|NODE_PATH|NODE_VERSION|NVM_[A-Z_]+|VOLTA_HOME|PNPM_HOME|BUN_INSTALL|COREPACK_[A-Z_]+|NPM_CONFIG_[A-Z_]+|NPM_PACKAGE_[A-Z_]+|NPM_LIFECYCLE_[A-Z_]+|NPM_EXECPATH|NPM_NODE_EXECPATH|PYTHONPATH|PYTHONHOME|PYTHONUNBUFFERED|PYTHONDONTWRITEBYTECODE|PYTHONIOENCODING|VIRTUAL_ENV|VIRTUAL_ENV_PROMPT|CONDA_[A-Z_]+|PYENV_[A-Z_]+|UV_[A-Z_]+|PIP_[A-Z_]+|POETRY_[A-Z_]+|JAVA_HOME|GOPATH|GOROOT|GOBIN|GOFLAGS|GO111MODULE|CARGO_HOME|RUSTUP_HOME|HOMEBREW_PREFIX|HOMEBREW_CELLAR|HOMEBREW_REPOSITORY|CI|DEBUG|LOG_LEVEL|PORT|ENV|ENVIRONMENT|CLAUDECODE|CLAUDE_CODE_ENTRYPOINT|CLAUDE_PROJECT_DIR)$/&&u!~/KEY|TOKEN|SECRET|PASS|AUTH|CRED|SESSION|COOKIE|PRIVATE|SIGN|CERT/&&v!~/:\\/\\/[^\\/]*@|sk-|gh[pousr]_|AKIA|AIza|xox[abprs]-|BEGIN|Bearer/)print;else print n"=[masked]"}else print "[masked]"}\''
ENV_LINE = re.compile(r"""^\s*(?:env|printenv)(?:\s*\|\s*grep(?:\s+-[iEFvwcxnhoHsq]+)*\s+(?:'[^'\n]*'|"[^"\\$`\n]*"|[A-Za-z0-9_.:=^-]+))+\s*$""")


def mask(cmd):
    """-> the line with MASK_STAGE appended when `cmd` is ENV_LINE (`env | grep -i node`, `printenv | grep PATH`), else None.
    A bare `env` / `printenv` (every name of the environment) is not rewritten: asked as before."""
    if not isinstance(cmd, str) or len(cmd) > 500 or not ENV_LINE.match(cmd):
        return None
    return cmd.rstrip() + " | " + MASK_STAGE


def masked_line(cmd) -> bool:
    """True when `cmd` is exactly an ENV_LINE followed by `| MASK_STAGE` and nothing else."""
    if not isinstance(cmd, str) or len(cmd) > 500 + len(MASK_STAGE) + 8:
        return False
    s = cmd.rstrip()
    if not s.endswith(MASK_STAGE):
        return False
    head = s[:-len(MASK_STAGE)].rstrip()
    if not head.endswith("|"):
        return False
    return ENV_LINE.match(head[:-1]) is not None
