# Pulse Development Notes

This file is for future Codex sessions working on Pulse.

## Project Shape

- Wails application entry points stay small. Put Go application logic under `internal/pulse`.
- Frontend pages live in `frontend/src/pages`.
- Page-specific subcomponents should live next to the page, for example `frontend/src/pages/settings`.
- Shared UI helpers belong in `frontend/src/components`.
- Wails generated bindings live in `frontend/wailsjs`. If Go exported methods change, run a Wails build and verify TypeScript still builds.
- Pulse has not shipped a public release yet, so do not preserve old config formats or migration compatibility unless the user explicitly asks for it.

## UX Rules

- Settings do not use a manual save button.
- Text inputs save on blur and Enter.
- Toggles, segmented buttons, and direct commands apply immediately.
- Range sliders update the draft UI while dragging and save when the interaction finishes.
- Background opacity controls component transparency only. Do not add frosted-glass blur to components for this setting.
- Background images must be copied into the data directory `backgrounds/` and selected by internal id; do not persist or display external image paths.
- Node selection should not show a global notice; keep it quiet unless there is an error.
- Right-clicking a proxy node runs a delay test for that node only.
- Proxy delay tests use `settings.delayTestUrl`; keep group and node delay tests on the same configurable URL.
- Successful actions should stay quiet. Only failures should show global notices.
- Disabled controls should use a clear `not-allowed` cursor, not a loading cursor.
- If a setting needs mihomo restart, let the backend decide and log the restart reason.
- Keep user-visible notices short and auto-dismissed.

## Lists And Pagination

- Large lists must be paginated with `frontend/src/components/pagination.tsx`.
- Use 100 items per page by default.
- Rules, profiles, proxy providers, connections, and logs should not render unbounded lists.
- Connections and logs should also keep a display cap so long-running sessions do not make the UI sluggish.
- The active profile must be visibly highlighted in the Profiles page.
- Profiles are activated by clicking the whole row. Profile rename/edit/update/delete actions belong in the right-click context menu, not inline row buttons.

## Profile Rules

- Custom profile rules are stored as structured JSON files under the data directory, not in `store.json` and not in the subscription YAML.
- Custom rules are edited with typed controls, not a raw textarea.
- Supported custom rule rows include type, payload, policy, `no-resolve`, and drag ordering.
- Custom rule policy must be selected from the profile YAML `proxy-groups` plus built-in policies such as `DIRECT` and `REJECT`; do not use free-text policy input.
- Runtime config generation injects custom rules at the beginning of `rules:` so they win before subscription rules.
- Subscription updates must not erase custom rules.
- Subscription updates may optionally use the local mixed proxy when the user enables proxy updates.
- Local YAML profiles can be imported by dropping `.yaml` or `.yml` files onto the Profiles page. Keep Wails `DragAndDrop.EnableFileDrop` enabled.
- Subscription names are inferred automatically. Adding a subscription from URL should not require a separate name field.
- Subscription YAML editing should use the lightweight in-repo highlighter/autocomplete component; avoid adding a large editor dependency unless the user asks for a full IDE-style editor.

## Platform Integration

- On Windows startup, register the `clash://` URL protocol under `HKCU\Software\Classes\clash` with the current executable path and `"%1"` argument.
- `clash://install-config?...url=...` launches should decode the `url` parameter twice and import it through the same URL subscription flow so the name is inferred from remote metadata or URL. If another Pulse instance is already running, pass the URL protocol argument through `show.signal`.

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
