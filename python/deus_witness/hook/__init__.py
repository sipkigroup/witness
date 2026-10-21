"""Claude Code PreToolUse hook (deus-witness-hook): Bash/Edit/Write/WebFetch/mcp__* calls go through the witness.
0.2.16: a thin client - raw facts to the witness, its signed decisions back (main.py)."""
from .form import default_form
from .main import judge, run

__all__ = ["default_form", "judge", "run"]
