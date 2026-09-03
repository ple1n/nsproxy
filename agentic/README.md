# Agentic notes

This directory is the repository's hierarchical agent-context system. Root `AGENTS.md` is the stable entry point recognized by IDEs and coding agents; it routes work to the smallest relevant topic note here.

## Loading policy

1. Read `AGENTS.md` first.
2. Load only the topic note matching the owning code path.
3. Follow links to another note only when the task crosses that ownership boundary.
4. Prefer searchable symbols and file anchors over broad prose or repository-wide exploration.
5. Update the narrowest topic note when a durable implementation convention is added or changed.

## Maintenance

- Keep `AGENTS.md` as the short IDE-facing router; put detailed facts in the narrowest topic note.
- Add a new topic note only when it represents a real ownership boundary, then add its route to `AGENTS.md`.
- Prefer searchable symbols, file anchors, invariants, and validation commands over narrative duplication.
- When a repeating implementation or UI pattern is discovered, evaluate whether it should be unified; document the resulting shared rule, renderer, or ownership boundary in the narrowest relevant note.
- After code edits, validate with `./build-ui.sh` or its release variant when appropriate.
- Commit completed coherent changes with a simple project-focused message; never include agent/tool identity in commit messages or source notes.

This keeps each workload contextually dense while minimizing repeated context and token use.
