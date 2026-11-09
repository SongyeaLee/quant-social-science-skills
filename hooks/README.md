# Hooks

PreToolUse hooks for Claude Code. Each hook reads the tool call as JSON on stdin and writes a `hookSpecificOutput` decision to stdout.

| File | What it does |
|------|--------------|
| `destructive-guard.js` | Blocks permanent-deletion commands in `Bash` and `PowerShell` calls, redirecting to the Recycle-Bin helper |
| `trash.ps1` | Windows Recycle-Bin deletion helper, the sanctioned and recoverable delete path |

---

## destructive-guard.js

A two-tier guard on shell commands. Design informed by [Dicklesworthstone/destructive_command_guard](https://github.com/Dicklesworthstone/destructive_command_guard): whitelist-first, two-tier deny/ask, fail-open on parse errors.

**DENY** is a hard block, not clearable by approving the prompt in-session:

`rm -rf` (and nested forms via `bash -c`, `xargs`, loops), `Remove-Item` with `-Recurse` or `-Force`, deletion calls with a recursive argument (R `unlink(x, recursive = TRUE)`, Node `fs.rm(x, { recursive: true })`, .NET `Delete($true)` and `[IO.Directory]::Delete(x, $true)`), `find -delete`, `rsync --delete`, `git clean -f`, `git reset --hard`, whole-tree `git checkout .` and `git restore .`, `del /s`, `rd /q`, `robocopy /MIR`, `shutil.rmtree`, `shred`, `Clear-RecycleBin`, `mkfs`, `format`, `dd of=`, and PowerShell `-EncodedCommand`, which cannot be screened because it cannot be inspected.

**ASK** forces a manual approval prompt even in auto-accept modes:

single-target deletions (`rm`, `del`, `unlink`, `Remove-Item`, `os.remove`, `fs.rm`, `file.remove`, `fs::file_delete`, `.Delete()`, `[IO.File]::Delete()`), recoverable-but-destructive git operations (`git stash drop`, `git push --force`, `git branch -D`, single-file `git checkout --`), and destructive SQL (`DROP DATABASE`, `DROP SCHEMA`, `DROP TABLE`, `TRUNCATE TABLE`).

**PASS** covers everything else, plus an explicit whitelist: `git clean -n`, `rm --help`, and a call to `trash.ps1`.

The whitelist applies per command segment, split on `;`, `&&`, `||`, `|`, `&`, and newlines. A whitelisted segment is dropped and the rest of the line is still checked, so `git clean -n && git clean -fd` is denied. A segment that contains command substitution (`$(...)` or backticks) is never whitelisted.

The deny tier exists because an auto-accept session plus one bad glob is enough to lose a directory tree. `Remove-Item` on Windows bypasses the Recycle Bin entirely, so there is no cheap undo. The guard makes the recoverable path the only path the agent can take on its own.

### Why regex and not a shell parser

Command strings reach the hook already assembled, often nested inside `bash -c "..."`, `xargs`, or `for` loops. Patterns are `\b`-anchored to catch those nested forms, which means the occasional false positive on prose. That tradeoff is deliberate. A spurious approval prompt costs a keystroke; a missed `rm -rf` costs the tree. Short aliases (`rm`, `rd`, `del`, `ri`, `erase`) are anchored to command position so paths like `man/foo.Rd` do not trip the guard.

If stdin is unparseable, the hook exits silently and the command proceeds. Failing open is the deliberate choice here: a guard that hard-fails on malformed input is one people turn off.

---

## trash.ps1

Moves paths to the Windows Recycle Bin via `Microsoft.VisualBasic.FileIO.FileSystem`, which is what Explorer itself uses. Recoverable, unlike `Remove-Item`.

```powershell
powershell -ExecutionPolicy Bypass -File hooks/trash.ps1 <path> [<path> ...]
```

It fails closed on cloud placeholders. Dropbox and OneDrive online-only files are reparse points that the Recycle Bin API rejects. The script detects them by attribute mask (`Offline | RecallOnOpen | RecallOnDataAccess`), throws before touching anything, and reports how many it found. Make the folder available offline, then retry. Nothing is deleted on a partial failure.

---

## Install

Requires Node.js on `PATH`. Copy both files into `~/.claude/hooks/`, then wire the guard in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell",
        "hooks": [
          {
            "type": "command",
            "command": "node \"C:/Users/<you>/.claude/hooks/destructive-guard.js\"",
            "timeout": 15,
            "statusMessage": "Checking for destructive commands"
          }
        ]
      }
    ]
  }
}
```

The `command` path is absolute and machine-specific, so adjust it. On macOS and Linux use `node "$HOME/.claude/hooks/destructive-guard.js"`. `trash.ps1` needs no wiring: the guard locates it next to itself and prints the full invocation in its block message.

Pair it with the [`destructive-command-safety`](../skills/destructive-command-safety/SKILL.md) skill, which gives the agent the two-phase enumerate-inspect-delete procedure to follow once the guard has stopped it. It is a skill rather than an always-loaded rule because the hook already does the enforcing; the procedure is only needed when a deletion is actually happening.

### Verify the install

```bash
echo '{"tool_input":{"command":"rm -rf build/"}}' | node hooks/destructive-guard.js
```

Expect a JSON blob with `"permissionDecision":"deny"`. An empty response means the hook is not matching, so check that Node is on `PATH` and that the path in `settings.json` resolves.

---

## Platform notes

The guard's patterns are cross-platform. Its remedy is Windows-only. On macOS and Linux, replace the `TRASH` constant in `destructive-guard.js` with `trash <path>` ([macOS Homebrew](https://formulae.brew.sh/formula/trash)) or `gio trash <path>` (Linux/GNOME), and drop `trash.ps1`.
