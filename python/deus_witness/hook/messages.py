"""0.2.16: texts of the codes the hook gives by itself (no witness answer, or a broken one). Every other text comes from the witness with
its answer (the server keeps the table; a test keeps these entries equal to it)."""
from __future__ import annotations

LOCAL = {
    "RESERVED_KEY": ("deny", "the tool input carries the reserved key `_witness`"),
    "EVENT_MALFORMED": ("deny", "Claude Code sent an event the hook cannot read"),
    "EVENT_TOO_LARGE": ("deny", "the tool call is too large to be judged"),
    "WITNESS_NOT_CONFIGURED": ("deny", "the hook has no agent key (set DEUS_WITNESS_KEY)"),
    "WITNESS_UNAVAILABLE": ("deny", "the witness cannot be reached; the call does not run without it"),
    "WITNESS_TIMEOUT": ("deny", "the witness did not answer in time; the call does not run without it"),
    "WITNESS_KEY_CHANGED": ("deny", "the witness key is not the one pinned on this machine"),
    "REQUEST_MISMATCH": ("deny", "the receipt is for a different call than the one being run"),
    "HOOK_ERROR": ("deny", "the hook failed; the call does not run (fail-closed)"),
}
