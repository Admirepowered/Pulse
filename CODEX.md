# Pulse Development Notes

This file is for future Codex sessions working on Pulse.

## Project Shape

- Wails application entry points stay small. Put Go application logic under `internal/pulse`.
- Frontend pages live in `frontend/src/pages`.
- Page-specific subcomponents should live next to the page, for example `frontend/src/pages/settings`.
- Shared UI helpers belong in `frontend/src/components`.
- Wails generated bindings live in `frontend/wailsjs`. If Go exported methods change, run a Wails build and verify TypeScript still builds.

## UX Rules

- Settings do not use a manual save button.
- Text inputs save on blur and Enter.
- Toggles, segmented buttons, and direct commands apply immediately.
- Range sliders update the draft UI while dragging and save when the interaction finishes.
- Node selection should not show a global notice; keep it quiet unless there is an error.
- Right-clicking a proxy node runs a delay test for that node only.
- If a setting needs mihomo restart, let the backend decide and log the restart reason.
- Keep user-visible notices short and auto-dismissed.

## Lists And Pagination

- Large lists must be paginated with `frontend/src/components/pagination.tsx`.
- Use 100 items per page by default.
- Rules, profiles, proxy providers, connections, and logs should not render unbounded lists.
- Connections and logs should also keep a display cap so long-running sessions do not make the UI sluggish.
- The active profile must be visibly highlighted in the Profiles page.

## Profile Rules

- Custom profile rules are stored on the profile metadata in `store.json`, not in the subscription YAML.
- Runtime config generation injects custom rules at the beginning of `rules:` so they win before subscription rules.
- Subscription updates must not erase custom rules.
- One custom rule per line is expected, using Clash rule syntax such as `DOMAIN-SUFFIX,example.com,DIRECT`.

## Build And Verification

- Before commit, run:
  - `npm run build` in `frontend`
  - `go test ./...`
  - `git diff --check`
  - `make build-windows` on Windows when frontend or Go runtime code changed
- Local Windows builds output to `build/bin/Pulse-P<COUNT>-windows-amd64.exe`.
- `make build-windows` cleans old Pulse Windows binaries first and runs UPX `--best` when UPX is available.
- Version format is `P<commit-count>`. After committing, build again if the local artifact should contain the new version number.

## Git

- Commit and push after requested changes are complete.
- Do not amend unless explicitly requested.
- Do not revert user changes. Work with dirty files carefully and only stage files touched for the task.

## Code Style

- Prefer small focused files over growing `App.tsx` or one large page file.
- Use typed helpers instead of ad hoc string manipulation when YAML, JSON, or API data is involved.
- Keep generated files in sync when Wails bindings or model fields change.
