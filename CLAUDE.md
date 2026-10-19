# CLAUDE.md — working notes for PCAP Lens

Wireshark-like `.pcap`/`.pcapng` viewer for VS Code. TypeScript extension +
stdlib-only Python backend that orchestrates `tshark`. See README.md for the
user-facing description (users only: it is the Marketplace page) and
CONTRIBUTING.md for building, testing and releasing (not packaged).

## Commands

| Task                      | Command                                                                                                                                                  |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Install dev deps          | `uv sync` and `pnpm install`                                                                                                                             |
| Build extension           | `pnpm run compile` (tsc → `out/`)                                                                                                                        |
| Lint everything           | `pnpm run lint && pnpm run format:check && uv run ruff check && uv run ruff format --check && uv run mypy`                                               |
| Format                    | `make format` (ruff --fix, ruff format, eslint --fix, Prettier)                                                                                          |
| Backend tests             | `uv run pytest` (tshark tests skip if tshark is missing)                                                                                                 |
| Acceptance scenarios only | `uv run pytest test/backend/acceptance` (pytest-bdd, Gherkin in `features/`)                                                                             |
| TS unit + webview tests   | `pnpm run test:unit` (mocha; includes the Chromium e2e test of the webview)                                                                              |
| VS Code smoke test        | `pnpm run test:extension` (downloads VS Code; use `xvfb-run -a` on headless Linux)                                                                       |
| Regenerate fixtures       | `uv run python test/fixtures/generate.py`                                                                                                                |
| Coverage                  | `make coverage` (pytest-cov and c8; summaries in the terminal, HTML in `coverage/`; CI's Linux job adds both to the run summary)                         |
| Perf check                | `uv run python test/fixtures/generate.py --large 1000000 test/fixtures/large-1m.pcap && uv run python -u test/perf/bench.py test/fixtures/large-1m.pcap` |
| Package                   | `pnpm run package` (vsce, `--no-dependencies`)                                                                                                           |
| Prepare a release         | `pnpm run release:prepare 0.2.0` on `dev` (then PR `dev` → `main`, tag the merge, push the tag)                                                          |
| Icon / screenshots        | `node scripts/render-icon.js` / `node scripts/screenshots.js` (after `pnpm run compile`; `CHROMIUM_PATH` for another Chromium)                           |
| Update dev deps           | `make update` (`ncu -u` within `.ncurc.cjs`, `pnpm install`, `pnpm run codicons`, `uv lock --upgrade`, `uv sync`)                                        |

The `Makefile` wraps all of these (`make` lists the targets; `make check` = lint + tests).

## Toolchain

- **Python 3.12+ supported, 3.14 for development**: `requires-python >=3.12`,
  ruff `py312`, mypy `3.12` (CI also runs `mypy --python-version 3.14`);
  `.python-version` is 3.14 (uv's dev venv and CI's main jobs), and the CI job
  `python-3-12` runs the backend and webview tests on 3.12. The extension
  enforces the same minimum (`MIN_PYTHON` in `src/backendClient.ts`). Code
  must stay 3.12-compatible: every module starts with `from __future__ import
annotations` (ruff's isort `required-imports` adds it; 3.12/3.13 evaluate
  annotations eagerly, so forward references need it), `except (A, B):` keeps
  its parentheses (3.14's PEP 758 form is a SyntaxError before), PEP 695
  generics are fine (3.12). 3.13+/3.14-only APIs go behind `sys.version_info`
  checks: `compression.zstd` (packet comments of `.zst` captures are "can't be
  read" before 3.14; `generate.py` needs 3.14 for the `.zst` fixtures), and
  the TLS-PSK fixture (`SSLContext.set_psk_client_callback`, 3.13) skips its
  tests on 3.12. **Finding Python** (`findPython`): `pythonCandidates` =
  `python3.14`, `python3.13`, `python3.12`, `python3`, `python` (Windows: `py
-3.14` … `py -3`, `python`, `python3`), then `uv python find --no-project
--system ">=3.12"` with uv from PATH, `~/.local/bin` or `~/.cargo/bin`
  (`uvCandidates`; a desktop-launched VS Code often lacks `~/.local/bin`;
  `--system` skips a workspace `.venv`). _PCAP: Install Python…_
  (`installPython` in `commands/setup.ts`, offered by `offerSetupHelp` and the
  walkthrough) runs `uv python install 3.14` as a task (`ProcessExecution`,
  task type `pcapViewer.installPython` in `taskDefinitions`; it runs on the
  remote machine in a remote window) and re-runs the environment check when
  it exits 0; without uv it links python.org and uv's install page (it never
  pipes an install script into a shell).
- **pnpm** (version pinned by `packageManager` in package.json; use
  `corepack enable pnpm`). pnpm refuses to install until every dependency with
  an install script is allowed or denied: `pnpm-workspace.yaml` denies
  `keytar` and `@vscode/vsce-sign` (vsce's publishing/signing helpers, unused).
  `vsce package` runs with `--no-dependencies` because its dependency check
  runs `npm list`, which doesn't understand pnpm's layout (the extension has
  no runtime npm dependencies anyway). `.vscode/settings.json` makes VS Code's
  npm tasks use pnpm.
- **Dependency updates**: `pnpm dlx npm-check-updates -u` reads `.ncurc.cjs`:
  `@types/vscode` is never bumped (it must not exceed `engines.vscode`, or vsce
  refuses to package; raise both together), `@types/node` stays on Node 20
  (VS Code 1.90's extension host), and peer ranges are respected
  (typescript-eslint caps TypeScript, so TS 7 waits). mocha 12 is ESM-only:
  the VS Code smoke suite loads it with `await import("mocha")`. Node ≥ 22.13
  is needed for the dev tools. Python dev tools: `uv lock --upgrade`.
- Node tests that start the backend use `PCAP_VIEWER_PYTHON` if set, else the
  uv `.venv` interpreter, so they run on 3.14 even when the system `python3` is older.
- pytest turns `ResourceWarning` into errors: leaked tshark pipes are bugs.
- **Coverage**: pytest-cov (`[tool.coverage.*]` in pyproject: branch,
  `patch = ["subprocess"]` so the backend started as a child process counts,
  data in `coverage/`) and c8 (`.c8rc.json`: the compiled `out/src` the unit
  tests load, mapped to the `.ts` sources, plus `lib.js` and `release.mjs`;
  the VS Code-dependent host code only runs in the smoke test, which isn't
  measured). No thresholds: the numbers are for finding untested code
  (backend 93%, unit-tested TS 96% when added).
- **Accessibility checks**: `axeViolations(page)` in `test/webview/harness.js`
  runs axe-core (WCAG 2.0/2.1 A and AA, evaluated through the debugging
  protocol, so the CSP doesn't block it; `preload: false`, since its
  stylesheet fetches are refused) on the viewer after the e2e tests and on
  every panel as its test left it; both assert no violations.
- Tests change a service limit or tshark helper (`FIRST_BATCH`,
  `stream_lines`, `find_tool`, `MAX_FILTER_ARG`…) with the `patch_service`
  fixture (`test/backend/conftest.py`), which sets the name in every
  `pcap_backend.service` module that imports it; `monkeypatch.setattr` on
  `pcap_service` no longer reaches the code.
- **Formatting and lint rules**: Prettier (`.prettierrc.json`: 100 columns
  like ruff, 80 for Markdown, double quotes, trailing commas, LF) formats
  TS/JS/CSS/HTML/JSON/YAML/Markdown; `eslint-config-prettier` (last in
  `eslint.config.mjs`) turns off the ESLint style rules. Python goes through
  ruff (`[tool.ruff]`: pycodestyle, pyflakes, isort, naming, pyupgrade,
  bugbear, bandit, pylint, pytest-style, logging, T20 because the backend's
  stdout is the protocol, …; deliberate stderr prints and catch-alls carry
  `noqa` with a reason). `.editorconfig` and `.gitattributes` (LF everywhere,
  captures binary) cover the rest. CI checks formatting once, on Linux.
  Mass-reformat commits go in `.git-blame-ignore-revs`. Prettier needed two
  passes on `main.js` once; run it again if `format:check` still complains.
- **CI** (`.github/workflows/ci.yml`) runs everything on Linux (apt tshark),
  macOS (`brew install --formula wireshark`) and Windows (`choco install
wireshark`, `C:\Program Files\Wireshark` added to PATH): lint, backend and
  acceptance tests with tshark, unit + Chromium e2e tests, and the VS Code
  smoke test (Linux under xvfb), plus a Linux job on Python 3.12. Ubuntu
  26.04 (`ubuntu-latest` from 2026-10-19) enforces the apparmor package's
  tshark profile, so the Linux jobs add the local rules of `sandbox.py`'s
  hint when `/etc/apparmor.d/tshark` exists (else every fixture read fails;
  checked on `ubuntu-26.04` runners). It runs on
  pull requests, pushes to `main` and `dev`, and by hand (`workflow_dispatch`).
  The unit/webview mocha run has a 10 s timeout (`--timeout 10000` in
  `test:unit`): the Windows runner once took over 2 s on a 30 ms test.
- **Repository upkeep**: `codeql.yml` (javascript-typescript, python and
  actions, `build-mode: none`, security-extended; pushes, PRs, weekly) and
  `.github/dependabot.yml` (npm for the pnpm lockfile, uv, github-actions;
  weekly, grouped, into `dev`; it ignores `@types/vscode`, `@types/node`
  majors and `@vscode/codicons`, which `make update` vendors). Issue forms in
  `.github/ISSUE_TEMPLATE/` (the bug form asks for the versions,
  `tshark --version` and _PCAP: Show Log_); `SECURITY.md` points to private
  advisories. Third-party actions (`astral-sh/setup-uv`, `pnpm/action-setup`)
  are pinned to a commit with the version as a comment (CodeQL's
  unpinned-tag alert); GitHub's own `actions/*` and `github/*` keep major
  tags. Dependabot updates both kinds.

## Layout

- `src/extension.ts` activation, config-change handling. `src/pcapEditor.ts`
  the custom editor provider (re-exports the session and document, so
  importers use `./pcapEditor`), `src/editorSession.ts` one
  `PcapEditorSession` per panel (load, webview messages, rpc forwarding),
  `src/pcapDocument.ts` the document (unsaved comment edits). `src/backendClient.ts`
  JSON-RPC client (no `vscode` import: unit-testable). `src/settingsModel.ts`
  pure settings helpers. `src/commands/` command implementations
  (`export.ts`, `coloring.ts`, `dissectors.ts`, `tls.ts`, `merge.ts`,
  `filterButtons.ts`, `importHexDump.ts`, `openFile.ts`, `plugins.ts`, …).
  `src/luaChoice.ts` per-capture Lua choices. `src/hexDump.ts` guesses a hex
  dump's layout (pure).
  `src/rotation.ts` recognises rotated capture pieces (pure).
  AI: `src/aiFilter.ts`, `aiExplain.ts`, `aiSummary.ts`, `aiAnomaly.ts`,
  `aiTools.ts` (tool specs, `runTool`, `runToolLoop`) and `aiConsent.ts` are
  pure prompt builders/parsers; `src/ai.ts` (`FilterAssistant`) and
  `src/lmTools.ts` (the tools API, declared locally) talk to `vscode.lm`;
  `src/commands/ai.ts` holds commands, consent and the `@pcap` participant.
  `src/captureModel.ts` pure capture/editing helpers (file names, durations,
  date-times as bigint ns); `src/tempCaptures.ts` unsaved captures;
  `src/commands/capture.ts` and `editCapture.ts` (start/stop, editing),
  `src/commands/withBackend.ts` (active or short-lived backend).
  `src/environment.ts` the setup check (pure); `src/commands/setup.ts` the
  walkthrough's commands and context keys. `src/remote.ts` remote-window
  helpers (pure); `src/commands/reveal.ts` shows saved files.
  `src/commandMenu.ts` the viewer's ☰ command list from package.json (pure).
  `src/plugins.ts` the TShark plugins picker's rows (pure).
- `src/webview/` plain JS/CSS/HTML (no build step). `lib.js` = pure helpers
  shared with Node tests (a classic script, `window.PcapLib`, like the panels'
  scripts); `main.js` = the editor's entry, an ES module (`<script
type="module" nonce>`: imports inherit the nonce, and VS Code's resource
  server allows the CORS fetch) that imports `viewer/*.js`, one module per
  part of the UI (`core` = shared state, constants, element lookups and
  rpc, and imports nothing, so it is evaluated first; `host`, `list`,
  `columns`, `selection`, `detail`, `diagram`, `filterbar`, `autocomplete`,
  `navigation`, menus, `status`…). Function declarations make the cycles
  between modules safe; top-level code only touches `core` and its own
  module. Shared JSDoc types live in `globals.d.ts`. Type-checked via JSDoc +
  `tsconfig.webview.json` (`module: ES2022`). `codicons/` = the vendored Codicons font
  (`scripts/sync-codicons.mjs`). CSS: `base.css` (tokens and controls, loaded
  by the editor and the panels), `styles.css` (the viewer), `panel.css`.
- `src/panels/` statistics, follow-stream, coloring-rules, export-objects,
  flow-graph, TCP-graph, VoIP and compare-packets webview panels
  (`panelHtml.ts` builds their CSP'd HTML); their UIs are
  `src/webview/stats.js`, `follow.js`, `coloring.js`, `objects.js`,
  `flowgraph.js`, `tcpgraph.js`, `voip.js` and `compare.js` with `panel.css`.
- `backend/pcap_backend/` Python package run as `python -m pcap_backend`
  with `PYTHONPATH=backend`. `server.py` (JSON-RPC), `pcap_service.py`
  (`PcapService`, assembled from the `service/` mixins, `rpc_methods`, and
  re-exports for tests), `service/` (the request handlers, one mixin per
  feature, each inheriting only the mixins it calls: `base.py`
  `ServiceBase` = all per-session state, lifecycle and the `_require_*`
  guards; `dissection`, `packet_comments`, `opening` (open, index pass,
  saved indexes) → `capturing` (live capture), `packets` (pages, columns,
  sorting, times) → `filtering` → `navigation`; `detail`, `streams`
  (follow, TCP graphs), `statistics` → `telephony` (VoIP), `colors`,
  `exporting`, `tools` (merge, hex import, probe, plugins, editing),
  `flow`, `exported_objects`; plus `state.py` (constants and the per-capture
  dataclasses `_Open`, `_View`…), `indexing.py` (the index pass's
  module-level helpers) and `helpers.py`), `tshark.py` (discovery/argv/process helpers), `cache.py`
  (row store, frame index, LRU), `pdml.py` (PDML + hexdump parsing),
  `stats.py` (`-z` report and follow parsers), `fields.py` (field catalogue),
  `coloring.py` (coloring rules → `colorfilters`), `navigation.py` (find
  expressions, hex parsing, frame-set filters, time formatting), `export.py` (destination
  checks, atomic output, CSV/JSON writers), `objects.py` (export objects:
  linking files to packets, safe names), `comments.py` (pcapng packet
  comments, editcap options, packet counts), `capture.py` (live capture:
  dumpcap interfaces, filters, the pcapng tee), `editing.py` (editcap options
  of capture editing), `hexdump.py` (text2pcap options of Import from Hex
  Dump), `ber.py` (counting back-to-back BER records), `plugins.py` (`tshark -G
plugins` and the plugin folders), `voip.py` (RTP
  stream report, SIP calls, RTP stream
  analysis, G.711 decoding and WAV), `protocol.py` (error codes,
  request context), `cancellation.py`, `index_cache.py` (saved indexes),
  `procs.py` (stopping children, also
  when the kill is refused), `sandbox.py` (AppArmor/Snap detection and hints).
- `backend/dissectors/example.lua` sample dissector (UDP/9999).
- `media/` icon (`icon.svg` → `icon.png`), `sample.pcapng` (a copy of the
  `mixed.pcapng` fixture that `generate.py` writes), `walkthrough/*.md` (the
  walkthrough's pages) and `screenshots/` (README only, not packaged).
- `scripts/` release helper (`release.mjs`, tests in `test/scripts`), icon and
  screenshot renderers. Not packaged.
- `test/backend` pytest; `test/backend/acceptance` pytest-bdd scenarios
  (`features/*.feature` = brief's acceptance criteria against the backend,
  steps in its `conftest.py`, feature tag `@tshark` → skip without tshark,
  `@lua` → skip as root), `test/extension/unit` mocha (Node), `test/extension/suite`
  VS Code smoke test, `test/webview` mocha (lib + Chromium e2e), `test/fixtures`
  scapy-generated captures and `fake_dumpcap.py` (a stand-in dumpcap for
  capture tests: `PCAP_VIEWER_DUMPCAP` = JSON argv), `test/perf/bench.py`.

## Rules (from the brief — do not break)

- Never build shell strings; always argv arrays (`subprocess.Popen([...])`,
  `spawn(cmd, args, {shell: false})`). Never `shell=True`.
- Never put packet data into `innerHTML` (ESLint forbids `innerHTML`/`outerHTML`/
  `insertAdjacentHTML` in webview code). Use `textContent`/`createElement`.
- Webview CSP: `default-src 'none'`, scripts only with the per-load nonce.
- Backend runtime must stay **stdlib-only** (dev tools live in the uv `dev` group).
- stdout of the backend is protocol only; log to stderr.
- Kill child processes on close: `BackendClient.stop()` closes stdin → backend
  cancels requests and kills tshark (`PROCESSES.kill_all`) → SIGTERM/SIGKILL
  (tree kill with `taskkill /T` on Windows) as fallbacks.
- Never call `proc.kill()`/`terminate()` directly: use `procs.kill_process`
  (never raises) and `procs.stop_process` (reaps, closes pipes), or
  `procs.interrupt_process` (SIGINT for a clean stop; a kill on Windows). A
  sandbox can refuse the signal (see _Sandboxed tshark_).

## Writing acceptance scenarios

Add scenarios to `test/backend/acceptance/features/*.feature` using existing
steps where possible (`uv run pytest --collect-only test/backend/acceptance`
lists them; step definitions are in `acceptance/conftest.py`). New steps go in
that conftest. Keep step patterns specific: `parsers.parse` patterns such as
`the filter is {result}` also match longer sentences, so prefer `parsers.re`
with alternatives. Lists are written `a, b and c` and parsed by `items()`.
UI behaviour stays in the Chromium test (`test/webview/e2e.test.js`).

## Design decisions (defaults chosen where the brief was open)

- **Name**: the extension is shown as **PCAP Lens** (`displayName`, the
  editor, settings category, walkthrough, chat participant, messages). The
  Marketplace refused "PCAP Viewer" ("Similar extension display name:
  pcapviewer already exists"; it publishes nothing on that error), so 0.4.1
  renamed every user-visible string. The extension ID `denpaz.pcap-viewer`,
  the `pcapViewer.*` commands, settings and context keys, the
  `pcap-viewer-<version>.vsix` file and the repository keep the old name:
  changing the ID would make it a different extension, and changing the
  prefixes would drop users' settings. Capture fixtures still carry "PCAP
  Viewer" in their payloads (test data).
- **Packaging of the backend**: a package (`backend/pcap_backend/`) rather than
  loose `server.py`/`pcap_service.py` files, managed by `pyproject.toml` + uv
  (no `requirements.txt`: there are no runtime dependencies).
- **One backend per editor panel** (not per document): the backend holds the
  current filter/sort view, so two panels on one file must not share it.
- **Row store on disk**: the open pass writes tshark's `-T fields` output to a
  temp file and keeps an `array('Q')` of line offsets (8 B/frame). Filters keep
  an `array('I')` of matching frame numbers (4 B/match), cached in an LRU keyed
  by expression and bounded by `pcapViewer.maxCachedFrames`. Scrolling never
  runs tshark. `RowStore.publish()` flushes and makes appended rows visible
  (`len()` = published rows); the index pass publishes every progress tick.
- **Streaming open** (`open {stream: true}`, what the host sends): the index
  pass runs in the pool (`_run_index`); `open` returns once FIRST_BATCH (1000)
  rows are published or after FIRST_BATCH_S (0.5 s) with some (`indexing:
true`), else when done. The pass then reports through backend notifications
  `index {event: progress|done|failed}` (`service.notify` = `server.notify`;
  `BackendClient.onNotification`). An `_Indexing` object is "attached" under
  `_lock` when `open` publishes the partial capture, so a pass ending at the
  same moment either completes `open` or finalises the attached capture, never
  neither. The host subscribes before sending `open` and buffers events until
  the webview has its `init` (a fast "done" can beat the response). While
  indexing, `_require_view` grows the unfiltered view to the published rows;
  everything that needs all rows raises `IndexingError` (-32012): sorting,
  find, conversation stepping, extra column passes (follow stream), CSV/JSON
  export, coloring (the host starts coloring after "done"), and non-streaming
  filters. A streaming filter works (see _Streaming filters_). Non-relative
  time formats show relative times until done. Index notifications carry
  `view {filterId, matchCount}` when a filter is applied. The webview refuses
  sorting with a notice, grows `total` on `indexProgress` (`growList`, which
  drops the cached short last page), and `refreshRows()` on done. Closing cancels the pass and waits
  for it (`_close_file` drops `_lock` meanwhile: the pass takes it to finish),
  and also for the last pass's index save (`_last_index`: it runs after
  "done", and the work dir must not be removed under it). Progress events
  carry `phase`: `"catching-up"` (a resumed open re-reading its saved rows,
  with `resumedAt` and `position`) or `"indexing"` (was `"index"`), plus
  `restarted` once when a resume fell back to a full pass (see _Saved
  indexes_). **A pass counts as finished only when it really ended**: not
  cancelled, tshark not killed (`ProcessRegistry.kill_all` remembers what it
  killed, `was_killed`; `stream_lines` then raises CancelledError, and a
  negative returncode is a ToolError), every line read (`_read_rows` stops
  per line on a cancel; `_stream_rows` re-raises it after closing the
  generator). The old bug: at shutdown the server kills every child before
  the pass's token is cancelled, tshark's output just ended, and the rows so
  far were saved as a finished index.
- **Progress bar** (webview): `div#busy-bar.progress-bar` (created by
  `main.js`, between the filter bar and `#main`: `role="progressbar"`,
  `aria-valuemin/max`, `aria-valuenow` only when determinate, `aria-label`)
  with a `.progress-fill` whose width is set through CSSOM (allowed by the
  CSP, unlike a `style` attribute). `renderProgress()` shows what
  `lib.progressView` picks: indexing first (class `secondary` while catching
  up), then a streaming filter, an export (`exportProgress` from the host's
  `runExport`), coloring, and any request that reported progress
  (`busyRequests`: rpc id → fraction). A null fraction is `indeterminate` (a
  sliding animation; a static stripe under prefers-reduced-motion). The
  status bar text comes from `lib.indexingLabel` ("Indexing… 42% · 420,000
  packets", "Resuming… re-reading packets 1–N (already shown)").
- **Saved indexes** (`index_cache.py`, `open {cache: {dir, maxBytes}}`; the
  host passes `globalStorageUri/index-cache`, `pcapViewer.indexCache.*`): an
  entry `<key>/` holds `rows.tsv`, `offsets.bin`, `meta.json` (info, fields,
  column names, kept columns) and up to 4 `colors-<rules>.bin/.json`. The key
  hashes the capture's resolved path, size, mtime_ns and inode; tshark path and
  version (`--version`, cached per path); Lua scripts by content; Decode As;
  prefs; requested columns; and a fingerprint (names, sizes, mtimes) of tshark's
  personal configuration and plugin folders (`tshark -G folders`), which change
  dissection too. Entries are written to `.key.pid.tmp` and renamed; a load
  touches `meta.json` (LRU) and the rows are hard-linked (else copied) into the
  work dir, so pruning never pulls the file from under an open capture.
  Saving runs after the pass, in the background, also hard-linking. Size cap:
  least recently used first. Coloring results are saved per rules digest and
  reused by `set_coloring` (`_coloring_pass` is skipped). Finished filter
  results are saved as `filter-<sha256(expr)[:24]>.bin` (array('I') bytes, the
  8 most recent per entry) and loaded by `set_filter` before running tshark.
  A preference whose value is an absolute file path (the TLS key log) adds the
  file's size and mtime to the key, so new keys mean a new index. _PCAP: Clear
  Index Cache_ deletes the folder from the host. Custom columns added later are extra
  passes and not saved (the next open with them is a new key).
  **Complete and incomplete entries** (`CACHE_FORMAT` 2): meta.json has
  `frames` (= offsets) and `complete`; `load` returns both kinds and callers
  check `.complete`, and colors and filter results are only saved to, and
  loaded from, complete entries (`_complete` reads meta.json; format-1
  entries or a missing flag count as incomplete). `_save_index` (after the
  pass): finished → complete entry plus colors; cancelled (closed) → an
  incomplete entry with the rows read, when there are more than the entry it
  resumed from holds; a tshark failure → nothing (resuming would fail the
  same way). **Resume**: a streaming open whose key has an incomplete entry
  (`_resume_from`) copies its rows (a real copy: the pass appends to it;
  `RowStore.resume` truncates after the last row and reopens for appending),
  publishes them at once (`open` returns `indexing: true, resumedAt: N`) and
  starts the usual pass with `_Resume`. tshark can't start mid-file
  (dissection state such as TCP reassembly needs every earlier packet, and
  there is no seek by frame), so the pass re-reads from the start: rows ≤ N
  are not stored but compared at `RESUME_SAMPLES` (16) evenly spread frames
  plus the first and row N (`_sample_frames`, raw bytes). A mismatch (or a
  column tshark now rejects, or a capture that ends before N) raises
  `_ResumeMismatchError`: stderr says why, the entry is discarded and a full
  pass replaces the base store (`_replace_base`: filter/sort caches cleared,
  a "progress" event with `restarted`). Everything that needs every row
  keeps raising IndexingError until "done"; streaming filters work over the
  published rows. Closing again saves the larger N; finishing saves
  `complete: true`. Live and unsaved captures never get an entry (no key);
  pruning treats incomplete entries like complete ones. Tests close mid-pass
  with the cancel-aware `slow_index` fixture (`test_resume_index.py`).
- **Streaming filters** (`set_filter {stream: true}`, what the webview sends):
  after validation, `_start_filter` installs a view with a `_Filtering`
  (`view.live`) and runs `_filter_pass` in the pool; `set_filter` returns after
  FIRST_BATCH matches or FIRST_BATCH_S with `filtering: true`. The pass appends
  to `live.frames`; every progress tick copies it into `live.snapshot` (readers
  never see the array grow) and sends `filter {event: progress, filterId,
matchCount, fraction}`; the end sends `done`, `stopped` (`stop_filter
{filterId}`) or `failed` (with `message`). Stopped/failed views keep their
  matches (`view.partial`, not cached; applying the same filter reruns it).
  `_require_view` shows the snapshot, and while a streaming open still indexes
  only the matches among the published rows (bisect), even after the pass is
  done; such results are cached only once indexing is done. `_install_view`
  cancels the pass of the view it replaces; cancelling the `set_filter`
  request during its first wait restores the previous view. Matches stay in
  capture order while `live` is set (`_apply_sort` returns them unsorted and
  keeps `view.sort` None), so the first request after `done` sorts.
  `_require_complete` (IndexingError with `filtering: true`) guards find,
  conversation stepping and CSV/JSON export; `find_frame`/`view_frames` work
  (positions are stable while matches are appended). `_run_filter` checks the
  token per line, since tshark's buffered output would otherwise still come.
  Webview: `filtering`/`filterFraction`/`filterPartial`; ■ (`#filter-cancel`)
  cancels the request, then stops the filter; a sort chosen meanwhile gets a
  notice and applies on `done` (`resetView`); events for a newer `filterId`
  than the webview knows wait in `earlyFilterEvents` (a fast pass can report
  before its `set_filter` result arrives); a selected frame not found yet is
  kept and looked up again on `done`. The host forwards `filter` notifications
  as `filterEvent`.
- **TLS key log** (`pcapViewer.tlsKeyLogFile`, resource-scoped): `readSettings`
  resolves it like the dissectors folder (`resolveSettingPath`) and adds it to
  `prefs` as `tls.keylog_file` (`withTlsKeyLog`; it overrides that pref). Any
  pref ending in `.keylog_file` naming a missing file is a warning
  (`check_scripts`). Changing the setting reloads the sessions whose
  `keyLogFile` differs, without asking (extension.ts). Each load watches the
  file (`watchKeyLog`, RelativePattern on its folder, debounced 1 s) and offers
  a reload when it changes, one question at a time. _PCAP: Set TLS Key Log
  File…_ (`commands/tls.ts`) checks the file with `looksLikeKeyLog` (empty is
  fine: a fresh SSLKEYLOGFILE) and can stop using the current one. Tests use
  `generate.tls_keylog_capture`: a TLS 1.2 PSK session (no certificate) run in
  memory with `ssl.MemoryBIO` and `keylog_filename`, generated per run (the
  randoms differ, so it isn't committed; `tls_keylog` fixture, skipped without
  PSK support).
- **Column field names**: tshark ≥ 4.2 uses `_ws.col.def_src/def_dst/protocol/info`;
  older versions `_ws.col.Source/…`. The index pass tries the new names and
  falls back automatically when tshark rejects them. Unknown custom column
  fields are dropped with a warning (tshark's "Some fields aren't valid" is parsed).
- **Never duplicate `-e` fields**: tshark blanks the first copy of a duplicated
  field (found the hard way with `frame.number`).
- **File types**: tshark detects the format from the content, so the file name
  only picks the editor. Two `customEditors` contributions share one provider:
  `pcapViewer.editor` (priority `default`) for unambiguous capture files
  (pcap/pcapng/cap/ntar, `.gz`/`.zst`/`.lz4` compressed pcap(ng), `*.pcap[0-9]*`
  tcpdump rotation, snoop, ERF, PacketLogger, btsnoop) and
  `pcapViewer.editorOptional` (priority `option`: _Reopen Editor With…_ only)
  for generic extensions (`*.[0-9]`, `.log`, `.dmp`, `.trc`, `.ber`). VS Code
  matches selectors against the basename, ignoring case
  (`globMatchesResource`); the patterns were checked with VS Code's own
  `glob.ts`, and the smoke test opens every `test/fixtures/formats/` file to
  check which editor VS Code picks. `when` clauses use
  `activeCustomEditorId =~ /^pcapViewer\.editor(Optional)?$/`. Every pattern
  has a fixture (`test_every_file_pattern_has_a_fixture`); fixtures in other
  formats are hand-written by `generate.py` (stdlib only: gzip, `compression.zstd`
  (imported lazily: Pythons built without libzstd lack `_zstd`, and `--large`
  must work there),
  an LZ4 frame with stored blocks, snoop, ERF, PacketLogger, btsnoop, raw BER).
  Open progress is estimated only for uncompressed pcap/pcapng recognised by
  magic number (`sniff_format`); otherwise it's indeterminate (null fraction)
  instead of stalling at 99%. "isn't a capture file in a format TShark
  understands" becomes `UnsupportedFormatError` (-32011), shown in the viewer
  with a _Reopen Editor With…_ button. `exportFileName` strips compression and
  format suffixes (`trace.pcap.gz` → `trace-filtered.pcapng`).
- **Detail**: `tshark -r f -c N -Y frame.number==N -T pdml` plus `-x` in
  parallel. `-c N` stops reading after frame N (it counts packets _read_), so
  cost is proportional to N, and earlier packets are still dissected (TCP
  reassembly etc. stay correct). Detail of frame ~1M therefore costs about one
  pass over the file (20 s on the benchmark capture). **Two-pass details**
  (`packet_detail {twoPass: true}`): the webview asks for them when the
  capture is complete (not indexing or capturing) and has at most
  `pcapViewer.twoPassDetail` packets (default 10,000; carried in the
  `quickDetail` message as `twoPass`); the backend then runs `-2 -Y
frame.number==N` (no `-c`, both the PDML and the `-x` run), so references
  to later packets (`http.response_in`, …) appear, at the cost of two passes
  over the file per packet. It ignores the flag while `_indexing` is set.
  `_details` is keyed by (frame, two-pass); a quick request may answer with
  either kind's cached exact detail; a two-pass result carries `twoPass`.
- **Quick detail** (`packet_detail {mode: "quick", window}`): for frames past
  `pcapViewer.quickDetail.after` (default 20k) the webview asks for the exact
  and the quick detail together and shows whichever comes first; the exact one
  replaces the quick one (same frame: `showDetail` keeps expansion, the
  selected field and the scroll position; the quick request is cancelled when
  the exact one lands). Quick = `editcap -F pcapng -r <capture> <tmp> first-N`
  (reads records without dissecting: 0.13 s at the end of 1M packets) then
  `_dissect` of the window's last frame, ~0.3 s in all. The window numbers
  its frames from 1, so `pdml.renumber_tree` adds `first - 1` to
  `frame.number`, the "Frame N:" header, `*.segments` `#N(len)` references
  and every FT_FRAMENUM field (field catalogue; while it is still loading, a
  name list `_FRAMENUM_HINT`, and the catalogue is warmed in the background,
  once), only for values inside the window, and puts the capture's
  `frame.time_relative` back (the window measures from its own start).
  Result: `approximate: true, window: [first, N]`; the webview shows a sticky
  note ("only packets X–N were dissected…"). References to packets before
  the window are simply absent (e.g. `http.request_in`). A quick request
  returns the exact detail when cached or when the window starts at frame 1,
  and `{unavailable}` without editcap (the webview then waits for the exact
  one). Quick results have their own LRU (16) keyed by (frame, window). Ask
  Copilot uses quick details for late packets too, and the prompt says which
  trees are approximate.
- **Packet diagram** (`lib.packetDiagram`, `viewer/diagram.js`): the details
  pane's _Tree | Diagram_ switch (`#detail-views`, in the sticky
  `#detail-head` with the comment bar and the quick-view note;
  `state.detailView` and the _Values_ toggle `state.diagramValues` persist in
  the webview state). Like Wireshark's, it draws each protocol's top-level
  fields only (not `frame`, `_ws.*`), 32 bits a row (`DIAGRAM_BITS`). PDML
  has no bit offsets or masks, so `diagramBits` reads them from the labels:
  `bitPattern` parses tshark's "0100 .... = Version: 4" (groups of 4), placed
  at the end of the field's bytes, or of its parent's when the pattern is
  wider (TCP's flag bits: 12-bit patterns on 1-byte fields inside the 2-byte
  `tcp.flags`); a field without one whose patterned children tile one width
  gets that width (TCP's Flags, IPv4's DS field; children without a pattern,
  like `tcp.flags.str`, are ignored; Ethernet's LG/IG bits don't tile, so the
  address stays 48 bits); else whole bytes. Fields are sorted by start, and
  one overlapping a field already placed (`tcp.seq_raw`, the calculated
  window) or outside the protocol's bytes (the payload) is dropped; uncovered
  bits are hatched gap cells. A field or gap of more than `DIAGRAM_FULL_ROWS`
  full rows keeps one row standing for all (`rows`, dashed bottom, "…" on
  the offset); at most `DIAGRAM_MAX_ROWS` rows (`more`). Cells are buttons
  placed with CSSOM `gridRow`/`gridColumn` (allowed by the CSP) in a
  33-column grid (byte offsets, 32 bits); picking one calls
  `detail.revealPath([proto, field])`, so the tree, bytes and diagram stay in
  step (`selectNode` → `markDiagramSelection`: the cells of any node on the
  selected node's path, `aria-current`); one cell takes Tab, arrows move
  between fields; right-click is the tree's menu (`showTreeMenu`). The diagram
  is drawn when shown and redrawn per detail. The e2e test runs axe on it
  without the bytes pane (the harness has no theme, so the field highlight's
  fallback blue sits under the browser's black text). `scripts/screenshots.js`
  writes `diagram.png` (README).
- **Byte sources**: PDML does not say which data source (frame vs reassembled)
  a field's `pos` refers to. Heuristic in `pdml.py`: top-level items after a
  `*.segments`/`*.fragments` node belong to the next `-x` source. Documented
  limitation for exotic multi-source packets (e.g. decrypted TLS + decompression).
  The first source is always named "Frame" (`pdml.FRAME_SOURCE`): tshark 4.6
  prints "Packet (N bytes):" where 4.2/4.4 print "Frame", and single-source
  packets print no header at all, so the byte tabs and _Export Packet Bytes_
  read the same across versions.
- **Filter validation**: compile against a shared 24-byte empty pcap
  (`tshark -Y expr -r empty.pcap`), with the same `-X/-d/-o` options so Lua
  fields validate.
- **Sorting** is backend-side over the current filter's frames: one column is
  read from the row store (cached, 3 columns max), sorted in Python, and the
  resulting order is cached per (filter, column, direction). Source/Destination
  and custom columns of FT_IPv4/FT_IPv6/FT_ETHER fields (catalogue lookup) sort
  by `cache.address_key`: IPv4 < IPv6 < MAC < other text, numerically within
  each, as one fixed-width hex string per row (no tuples, so memory stays flat).
  The Time column sorts by the time format shown: the absolute formats (and a
  time reference) keep capture order, the two delta formats sort by the delta
  (internal sort keys `@delta_displayed`/`@delta_captured`, computed from
  `frame.time_epoch`). Every request that returns or takes row indexes
  (`list_packets`, `find_frame`, `view_frames`, `find_packet`,
  `neighbor_frame`) carries `sort`/`timeFormat` and applies it first
  (`_apply_sort`): an index request must not overtake the page request that
  changes the sort (found by the multi-select e2e test: the selection was
  relocated with the old order).
- **Load log and slow first start**: `PcapEditorSession.load(reason)` logs
  why it (re)loads ("open", "Reload", "settings changed", "Lua dissectors
  changed"…) and the time to a ready tshark, to the first rows (streaming)
  and to "done" (`onIndexEvent`), so a slow open shows whether the time went
  to tshark. `initialize` (find tshark, `tshark --version`) may take
  `INITIALIZE_TIMEOUT_MS` (2 min): a first run after installing or updating
  Wireshark took over 30 s on macOS (the system checks the app bundle), then
  60 ms. After `SLOW_START_MS` (5 s) the overlay says so; a backend whose
  `initialize` failed is stopped at once.
- **Progress** during open is estimated from summed frame lengths vs file size
  (no capinfos needed up front); capinfos runs in parallel for metadata.
- **Virtualized list**: fixed row height; above 10M px of content the scroll
  range is compressed (`lib.computeWindow`) so >1.6M rows still scroll.
- **Sandboxed tshark**: Ubuntu's apparmor package ships `/etc/apparmor.d/tshark`
  (upstream since 2025), which confines `/usr/bin/tshark` to `/tmp` and
  Wireshark's folders, so `-r ~/x.pcap` fails with "You don't have permission
  to read the file". The backend is unconfined: `open` first reads a byte
  itself (real permission problems get their own message), and every tshark
  failure goes through `Tshark.error()`, which appends `permission_hint()`
  (AppArmor profile loaded in enforce mode → local-rule instructions; Snap →
  use the distro package; else generic). Temp files (empty capture, coloring
  config) live in `/tmp`, which the profile allows.
  The profile also only lets tshark receive signals from itself, so killing a
  cancelled tshark raises `PermissionError` (kernel log: `operation="signal"
… peer="vscode"`, VS Code's own profile, or `peer="unconfined"` in the
  tests). Hints and detection live in `sandbox.py`: `APPARMOR_HINT` suggests
  `owner @{HOME}/** rw,`, `signal (receive) peer=unconfined,` and
  `signal (receive) peer=vscode,` plus `apparmor_parser -r`, both for tshark
  permission errors and (`kill_denied_hint`) for a refused kill, logged once
  to stderr. Cancellation never depends on the signal (`procs.py`): the thread
  that owns a process polls (`communicate(timeout)` in `run()`, a selector on
  stdout in `stream_lines` on POSIX; Windows reads blocking, its kill always
  works), and `stop_process` closes our end of stdout when the kill is refused,
  so tshark's next write fails (the kernel's SIGPIPE isn't mediated) and it
  exits. Anything still running after `STOP_TIMEOUT` goes to a reaper thread
  (it stays in `PROCESSES` until reaped), so no pipe or `Popen` is leaked
  (pytest turns ResourceWarning into errors). `test_procs.py` fakes the
  refusal with real children whose `kill` raises `PermissionError`.
- **Lua as root**: tshark refuses Lua when run as root; the backend warns. The
  Lua integration test skips as root (CI runs as a normal user).
- **Field catalogue** (`fields.py`): `tshark -G fields` must be tshark's
  _first_ option (anything after it is a name filter), so it can't take
  `-X lua_script:`. Lua fields are picked up by a second `-G fields` run with
  `WIRESHARK_PLUGIN_DIR` pointing at a temp folder holding numbered copies of
  the configured scripts; that run replaces the global plugin folder, so both
  outputs are merged (deduplicated). Prefix search bisects a sorted,
  lower-cased key list (~250k entries). The webview warms it after `init`.
- **Autocomplete UX**: nothing is preselected, so `Enter` always applies the
  filter unless a suggestion was picked with the arrows; `Tab` takes the
  first suggestion. Operators are only offered right after a space (or on
  `Ctrl+Space`). Context detection (`lib.completionContext`) is heuristic:
  field / comparison operator / logical operator / none (strings, values).
- **Per-capture settings**: `luaScripts`, `dissectorsFolder`, `decodeAs` and
  `prefs` are `resource`-scoped and always read with the capture's URI
  (`readSettings(session.uri)`, `getSetting`), so multi-root folders can differ.
  Writes go through `updateSetting(key, value, scope)`, which targets the most
  specific level that already defines the key (`configTargetFor`).
- **Saved filters** are the `pcapViewer.savedFilters` setting (not
  `globalState`): user vs workspace scope gives "global or workspace"
  persistence, and they sync and can be edited in settings.json. Recent-filter
  history stays in `globalState` (50 entries).
- **Follow stream** uses tshark's `-z follow,<proto>,raw,<n>`: one hex line per
  segment, lines starting with a tab come from node 1. Exact bytes, so ASCII,
  hex dump and raw views plus raw save are all rendered client-side. The
  stream number for a packet comes from `tcp.stream`/`udp.stream`, extracted
  once through the row-store column machinery (first follow costs one pass).
  TLS/HTTP/WebSocket follow the TCP stream number. Payload is capped
  (`maxBytes`, 16 MB). **HTTP/2 and QUIC** multiplex streams in one
  connection: `follow,http2,raw,<tcp.stream>,<http2.streamid>` and
  `follow,quic,raw,<quic.connection.number>,<quic.stream.stream_id>`
  (`STREAM_FIELDS`/`SUBSTREAM_FIELDS` in `service/streams.py`). One `-Y`
  fields pass per connection (`_substreams_of`, LRU 8 in `_substreams`) lists
  each packet's sub-stream ids; the result carries `substreams` and the
  `substream` followed: the asked one, else the frame's first, else the
  lowest (HTTP/2 skips 0, the connection's own frames, when it can; QUIC's
  stream 0 is data). No sub-streams (TLS without keys, not HTTP/2) answers
  at once with a `hint` (key log, Decode As) instead of running follow.
  tshark 4.2's SIP follow refuses every argument form from the command
  line, and DCCP is rare, so neither is offered. The panel's _Sub-stream_
  select (`#follow-substream`, "0 (connection)" for HTTP/2) posts `stream
{stream, substream}`; filters come from `lib.streamFilter(proto, stream,
substream)` (`… and http2.streamid eq N`). Views: the text ones
  (`lib.decodeStream`: ascii, utf-8, utf-16 LE, latin1 by hand since the
  web's "iso-8859-1" is windows-1252, ebcdic = code page 037), all cleaned
  like ASCII (CR before LF dropped, C0/DEL/C1 as "."), each segment decoded
  on its own; `lib.cArray` (`char peer0_0[] = {`, 8 bytes a line); YAML
  (`lib.yamlPeers` as a part without a direction, then `lib.yamlSegment`
  with base64 data; no packet numbers or times, which raw follow output
  lacks). Saving text names the extension (`ext`: txt, c, yaml). The
  fixture `streams.pcapng` (generate.py `streams_packets`) holds a
  prior-knowledge HTTP/2 connection (streams 1 and 3; tcp.stream 0), a
  WebSocket conversation (tcp.stream 1) and a QUIC connection (streams 0
  and 4) encrypted by `test/fixtures/quic.py` (pure-Python AES-128-GCM and
  header protection, checked against the NIST and RFC 9001 vectors in
  `test_follow.py`): client and server Initials with ClientHello/
  ServerHello, then 1-RTT packets keyed by made-up traffic secrets stored
  in the pcapng's Decryption Secrets Block, so tshark decrypts it without a
  key log setting.
  The panel's search (`#follow-find`, `lib.findRanges`: case-insensitive,
  non-overlapping, at most 10,000 matches) works on the rendered text of the
  current direction and format, per segment (a match can't span two), and
  rebuilds the segments with `<mark class="find-match">` text nodes (never
  markup); Enter / Shift+Enter / the arrows move `current` (wrapping,
  scrolled into view), Esc clears, Ctrl/Cmd+F focuses it. _Filter Out This
  Stream_ posts `filterOut {expr}` (`lib.streamFilter`); the host applies
  `settingsModel.filterOutExpr(currentFilter, expr)`: `(current) && !(…)`, or
  only `!(…)` when there is no filter or it is that stream's.
- **Statistics** parse tshark's human-readable `-z` reports into one generic
  table model (`stats.py`: columns, rows with optional `filter`/`frame`/`depth`),
  rendered by one panel (`src/webview/stats.js`). Sizes like "12 kB" are
  converted with SI units. tshark 4.6 adds a top-level `frame` row to the
  protocol hierarchy (eth at depth 1, dns at 4; 4.2: 0 and 3), so tests check
  parent rows ("dns one level below udp") and totals, never absolute depths.
  Percentages divide by the depth-0 rows, which cover every packet either way. Expert info joins `-z expert` (severity/group/
  protocol/count) with a `-T fields -e _ws.expert` pass (aggregator `\x1e`)
  to get frame numbers. Rows are matched by regex because multi-word groups
  ("Response code") overflow tshark's fixed-width column. The display-filter
  limit uses each tap's own filter argument (`conv,tcp,<filter>` etc.).
- **Expert indicator** (`expert_summary`, `lib.expertStatus`,
  `status.js` `loadExpertSummary`): one `-q -z expert,comment` pass
  (`stats.parse_expert_counts`: the section headers' totals per severity),
  cached on the `_Open` (`f.expert`); IndexingError while indexing, so the
  webview asks on init when not indexing and in `onIndexDone`. It reports
  no progress (a background pass mustn't show the busy bar; the progress-bar
  e2e test caught that). `#status-expert` shows the most severe of errors,
  warnings and notes ("No problems" else) with a Codicon in the editor's
  error/warning/info color, every count in the tooltip, and posts
  `runCommand` for _Expert Information_; `expertSeq` drops a stale answer.
- **Service statistics** (`stats {kind: http | dns | plen | srt}`): HTTP
  (`type` packets/requests/load = `-z http,tree` / `http_req,tree` /
  `http_srv,tree`), DNS and packet lengths are tshark's stats_tree reports,
  parsed by one `parse_stats_tree`: the header is the line above the first
  rule of dashes (its first column is "Topic / Item", or since tshark 4.4 a name
  the tree sets: "Packet Type" for HTTP and DNS, found on macOS/Windows CI), the
  first value column starts at "Count" (a long first-column name may leave one
  space), the others are two or more spaces apart, and the header's column
  starts cut each row (topics hold spaces, empty cells are blank). A
  first-column name longer than every topic isn't cut and pushes the header's
  value columns right: the rule is as long as a row, so the header's extra
  length is the shift. One space of indentation per level; columns empty in
  every row are dropped. Rows whose path maps onto a filter carry it (`_TREE_FILTERS`:
  status classes/codes, methods, host + URI, address/host/OK-Error chains in the
  load tree, DNS rcode/opcode/type/class/name by value, by the row's parent only (4.2 nests them
  under Total Packets, 4.6 puts them on top and adds Query Name and Answer Type), length buckets); the
  acceptance tests count each filter's matches against the row. Service response
  time: `-z icmp,srt` / `icmpv6,srt` (own format, one row going to the slowest
  reply) and the generic SRT table of the taps that need no arguments
  (`SRT_PROTOCOLS`; DCE-RPC/ONC-RPC/SCSI need one and aren't offered), whose
  single table's `Filter:` field + Index give row filters (several tables, as
  SMB prints: a Table column, no filters). `type: "auto"` picks the first
  protocol the protocol hierarchy shows (`SRT_PHS_NAMES` for names that
  differ); results carry `type` and `available` (the webview marks those ●).
  Tree kinds (`TREES` in stats.js) keep their order and aren't sortable.
  `services.pcap` (generate.py) has HTTP with several codes/methods/hosts, DNS
  of several types, SNMP gets and ICMP echoes (one unanswered).
- **Filter buttons** (`pcapViewer.filterButtons`: `{label, filter, comment?}`,
  `normalizeFilterButtons`, at most 50; window scope like saved filters): the
  host posts `filterButtons` on "ready" and on setting changes; the webview's
  `#filter-buttons` toolbar (after `#filter-bar`, hidden when empty) applies a
  button's filter on click (it goes into the filter box first) and marks the
  applied one `aria-pressed` (`updateFilterButtons`, from `updateStatus`). **+**
  posts `addFilterButton {filter}`; `contextmenu` (right-click, Shift+F10, the
  menu key) posts `editFilterButton {index, filter}` and the host
  (`commands/filterButtons.ts`) offers edit label/filter/comment, move, remove
  in a QuickPick, locating the button by index if it still holds that filter
  (the setting may have changed). Filters are validated with the session's
  `validateFilter` before they're stored.
- **Import from Hex Dump** (`import_hexdump {text | input, dest, …}`,
  `hexdump.py`; `commands/importHexDump.ts`): text2pcap (found next to
  tshark) with `-F pcapng` and options checked in `text2pcap_options` (offsets,
  `-t` time format, `-D`, `-a`, `-l` or a dummy header `-e/-i/-u/-T/-s/-S/-P`
  with `-4/-6` addresses; a dummy header forces Ethernet), text written to a
  temp file, output through `atomic_output`; "wrote 0 packets" is an
  InvalidParamsError and writes nothing. Needs no open capture (`withBackend`).
  The host asks source (editor/selection, clipboard, file), offsets
  (`guessOffsets`: bytes-only lines = none, else the base in which offsets
  advance by the previous line's byte count, hex on ties), what the bytes
  hold, and times; `hasAsciiColumn` adds `-a` for hexdump -C. Args
  `{text | input, options}` skip the questions (smoke test). The result opens
  as an unsaved capture named after the file. Fixtures: `hexdump/*.txt`
  (generate.py: http.pcap's frames as Wireshark copies them, SIP payloads,
  timed IPv4).
- **Never `str.splitlines()` on packet-derived text**: it also splits on
  `\x1c`–`\x1e`, `\x85`, `\u2028`… Stats parsers use `_lines()` (split on `\n`).
- **Panels** (`src/panels/`) are separate webview panels beside the editor. They
  share the editor's backend (`session.backend`), close with it
  (`session.onDidDispose`), and send filters/goto back to it. One stats panel
  per (editor, kind); follow panels are per invocation. The IO graph is a
  single-series SVG line in the theme's `--vscode-charts-blue` (no legend,
  hover crosshair, keyboard arrows/Home/End, the table below is the
  accessible view). Packets or bytes is a switch, never a second axis.
- **Dissector check**: `check_dissectors` loads the Lua scripts against the
  empty capture (no packets read) and returns tshark's `Lua:` stderr blocks
  (exit code stays 0 on Lua errors). Lua shortens long chunk paths to
  `...tail`, so the script is found by suffix (`script_in_lua_message`).
  "Reload Dissectors" runs it first, then re-indexes every open capture.
- **Lua per capture** (`luaChoice.ts`, `pcapViewer.chooseLuaDissectors`):
  _PCAP: Lua Dissectors…_ (☰ Dissectors, the webview's `#status-lua` link =
  `luaLabel`, posted in `init` as `lua`) offers the configured scripts
  (`luaAvailable` = luaScripts + dissectorsFolder, so Restricted Mode's
  user-only values apply) as a multi-select QuickPick. The choice is stored
  per capture path in `workspaceState` (`pcapViewer.luaChoices`, 500 most
  recent; [] = none; all checked = no entry, so scripts added later load).
  `readSettings(uri)` applies it (`applyLuaChoice`), so every caller (load,
  Reload Dissectors, the reload offer on save) sees the capture's own set;
  chosen scripts no longer configured become `luaWarnings`. Choosing reloads
  the sessions of that file; the saved index key already covers the scripts,
  so switching back is instant. `session.lua` is the latest load's set
  (smoke test). Args `{scripts}` (paths or basenames) skip the picker.
- **Open any file** (`probe_file {path}`, `ber.py`, `commands/openFile.ts`,
  `pcapViewer.openFile`): VS Code chooses editors by file name, and a glob
  can't say "no extension", so files tshark reads under other names (a pcap
  without suffix, a raw BER value: tshark's BER file type, `wtap_encap` 90,
  one value per file) need an explicit open. The command takes the Explorer's
  selection (`explorer/context`) or a QuickPick of `workspace.findFiles`
  (20k, files.exclude) plus Browse…, runs `probe_file` (`_readable_capture`,
  empty check, `tshark -r -c 1 -T fields -e frame.number` without dissection
  options) through `withBackend`, and opens with `vscode.openWith(uri,
"pcapViewer.editor")` (an explicit editor id needn't match the selector).
  Unreadable: a warning with the reason; `ber.count_records` recognises
  several BER values back to back (definite lengths, high tag numbers,
  trailing 0x00/0xFF block padding; up to MAX_RECORDS) so the message says
  so (`berRecords`) and offers _Open Records as Packets…_ (below).
- **BER records as packets** (`split_ber {path, dest, dissector}`,
  `dissector_names`, `ber.write_pcapng`, `commands/openBerRecords.ts`,
  `pcapViewer.openBerRecords`): there is no pcap link type for BER (tshark's
  BER file type is `wtap_encap` 90, one value per file), so each record
  becomes a packet of link type 252 (Wireshark upper PDU export) starting with
  the exported-PDU tag 12 (dissector name, padded to 4 bytes, the padding
  counted in the tag's length: an unpadded length shifts the record by one
  byte) and an end tag; `exported_pdu` hands the rest to that dissector. Any
  name passing `_DISSECTOR_RE` is written (tshark looks it up only when
  reading; a Lua `Proto` registers its lower-cased name, and a short-lived
  backend may not have the Lua scripts loaded); an unknown one shows the
  record as data. `records()` walks the headers (`NotRecordsError` where they
  stop), every packet gets the file's mtime, and records longer than
  `MAX_PACKET` (262,144 = WTAP_MAX_PACKET_SIZE_STANDARD: tshark calls a
  longer pcapng packet corrupt) are cut there, keeping the original length
  (`truncated`). Written through `atomic_output`, cancellable, progress by
  offset. The host picks the file (`pickFile`), the dissector (QuickPick of
  `tshark -G dissectors` via `Tshark.glossary`, cached per tshark and Lua
  scripts; `ber` first, the last choice next, a typed name allowed) and
  opens an unsaved capture (`splitFileName`: `cdrs.dat` → `cdrs.pcapng`).
  Offered by _Open File_ and, through `UnsupportedFormatError`'s
  `data.berRecords` (`_index_error`), by the editor (`OPEN_AS_PACKETS`).
  `{uri, dissector}` skip the questions (smoke test).
- **TShark plugins** (`tshark_plugins`, `plugins.py`, `commands/plugins.ts`,
  `pcapViewer.showPlugins`): Wireshark plugins (C dissectors as `.so`/`.dll`
  built for one major.minor, Lua scripts in the plugin folders) need no
  support from the viewer: tshark loads them from the personal folder, `-G
fields` brings their fields to autocomplete, and the saved-index key
  fingerprints the plugin folders. The command only shows them: `tshark -G
plugins` (never cached, so a plugin just installed shows up) through
  `withBackend`, `personal` = inside `-G folders`' Personal (Lua) Plugins
  folder, listed first, `install` = `<Personal Plugins>/epan`. As root
  Wireshark ignores personal plugins and `WIRESHARK_PLUGIN_DIR`
  (`started_with_special_privs` counts uid 0), so the result carries a
  warning; `test_plugins.py` installs a personal Lua script under a temporary
  HOME/APPDATA (skipped as root). The QuickPick (`pluginRows`): open the
  install folder (created if missing, `revealFile`) or copy its path, then
  your plugins and Wireshark's; picking one reveals its file. `{quiet: true}`
  returns the result (smoke test). README: _Wireshark plugins_.
- **Protocol preferences** (`protocol_prefs {protocol?}`, `prefs.py`,
  `prefsModel.ts` (pure), `commands/prefs.ts`, `pcapViewer.protocolPreferences`):
  `tshark -G defaultprefs` (cached per tshark and Lua scripts) and
  `-G currentprefs` (not cached: the user's Wireshark preferences) list each
  preference as description lines, a type line (`TRUE or FALSE`, `A decimal
number`, `One of: …` + `(case-insensitive).`, ranges, colors, paths,
  strings) and `name: value`, commented out while it is the default; only the
  "Protocols" section is kept. Enum choices are joined with ", ", which three
  choice names also contain: when the value isn't one of the pieces the
  preference becomes free text (`other`). tshark 4.6 (macOS/Windows CI)
  writes `true or false` (type lines match without case) and, for enums
  whose names differ from their descriptions, adds `Equivalently, one of:
<descriptions>`; the choices are the list that holds the value (4.6's
  defaults are descriptions, e.g. "0 (none)"). `Tshark.glossary` adds a run with
  the Lua scripts in `WIRESHARK_PLUGIN_DIR` (as for the field catalogue), so
  Lua preferences are included. No protocol: `protocols` with counts. The
  host's QuickPick shows each preference's effective value and source
  (`effectivePref`: `pcapViewer.prefs` "changed here", else the user's
  Wireshark value, else the default), asks booleans and enums with a pick and
  the rest in an input box checked by `validatePrefValue` (tshark silently
  ignores a bad enum value), stores `prefSettingValue` (booleans, numbers,
  tshark's spelling of a choice) with `updateSetting` for the capture's
  folder, and drops an override equal to Wireshark's value (`withPref`).
  `tls.keylog_file` opens _Set TLS Key Log File…_ (its setting wins).
  Writing sets a flag (`consumePrefsChange`) so extension.ts reloads the
  sessions whose `prefs` differ (`session.prefs`, `samePrefs`, debounced)
  instead of asking. The detail tree's menu offers _Protocol Preferences:
  <proto>…_ for the node's top-level protocol (`lib.prefsProtocol`; not
  geninfo or fake-field-wrapper), posting `protocolPrefs`. `{protocol,
quiet: true}` returns the list (smoke test).
- **Decode As choices** come from tshark itself: an invalid `-d` rule makes it
  print "Valid layer types are:" or "Valid protocols for layer type X are:"
  lists (parsed by `parse_decode_as_choices`, cached). An unknown layer gets
  the layer list back, which is detected and rejected.
- **Coloring rules** are evaluated by tshark (`--color`, field
  `frame.coloring_rule.name`, first match wins), which only reads them from
  `colorfilters` in the personal config folder. Each `set_coloring` pass sets
  `WIRESHARK_CONFIG_DIR` to a temp folder holding the generated file plus
  copies of the user's other personal config files (found via `tshark -G
folders`), so dissection matches the other passes. Rules are named by index
  (the file format can't quote names; filters with `@` are rejected), tshark's
  "Could not compile" stderr is mapped back to rule indexes. The result is one
  byte per frame (`array('B')`, max 255 rules); `list_packets` rows carry
  `color` plus the page's `coloringId`, and the webview only uses colors whose
  `coloringId` matches its palette (it's part of the page cache key).
  _At open_ the rules are evaluated by the index pass itself (`open {coloring:
{rules}}`, `_InlineColoring`): `--color` in the same `WIRESHARK_CONFIG_DIR`
  setup (`work_dir/colorfilters`) and `frame.coloring_rule.name` as the last
  `-e` field, split off each line before the row is stored (`_read_rows`,
  `_add_color`), so the row store is unchanged and every published row
  already has its color. Measured +2 s on 1M packets (34.6 → 36.7 s) instead
  of a separate ~30 s pass that had to wait for indexing. `open` returns
  `coloring: {coloringId}` (plus `colored`/`errors` when complete; else in
  "done"); compile-error stderr blocks are rules' errors, not warnings. If
  tshark rejects the field, the pass is retried without colors. The colors
  are saved with the index (`save_colors` after `save`, same rules digest as
  set_coloring), and a saved-index open loads them (else no `coloring` and
  the host runs set_coloring). _Rule changes_ still use `set_coloring`, a
  separate pass (never re-indexes): the host defers it while indexing
  (`coloringStale`, run on "done") and reports its progress to the webview
  (`coloringProgress`: "Coloring… 40%" in the status bar). The selected row
  keeps the theme's selection colors. Defaults in package.json
  are checked against tshark by `test_default_coloring_rules_compile`; note
  tshark 4.2 rejects space-separated sets (`{3 4}`), so they avoid sets.
  **Drawing for the theme** (`pcapViewer.coloringStyle`: auto/full/subtle/
  stripe, posted as `coloringStyle` on "ready" and on change): the rules are
  Wireshark's light pastels, which glare in a dark theme. `lib.ruleStyle(rule,
lib.themeKind(body.classList), style)` picks the mode and stripe color:
  auto = stripe in high contrast; in dark themes subtle when the rule's
  background is lighter than its text and has luminance > 0.25 (a dark "bad"
  rule stays full); else full. The stripe is the rule's background (deepened
  ×0.55 when pale in light themes; the foreground for a dark background in
  dark themes). main.js sets `--rule-bg/--rule-fg/--rule-stripe` and a
  `rule-<mode>` class; styles.css tints with `color-mix(… 22%,
editor-background)` and draws the 4 px stripe as `::after` (3 px right of
  a comment's stripe). VS Code swaps the body class on a theme change, so a
  MutationObserver re-renders.
- **Export**: captures via `tshark [-Y f] -F pcapng|pcap -w tmp` (`-P -T
fields -e frame.number` gives progress when filtering; without a filter
  nothing is dissected). Default filter = the current view's; `""` = all.
  CSV/JSON come from the row store in the view's current order (no tshark).
  Every export writes `.<name>.<pid>.part` and `replace()`s it at the end, and
  a destination that is the open capture is refused (tshark would truncate
  its input). CSV cells that look like formulas get a `'` prefix (packet text
  is untrusted); JSON is keyed by column id with numbers for numeric columns.
  _Dissections_ (`kind: "dissections"`, `format` text/pdml/json =
  `-V`/`-T pdml`/`-T json`, `-x` with `bytes`) stream tshark's stdout into the
  file. The scope is chosen like a capture export (`_export_scope`); a big
  frame set means several `-Y frame.number in {…}` passes, which
  `export.DissectionWriter` joins: text concatenated, PDML with one header and
  one `</pdml>`, JSON as one array (a held-back last line becomes `  },` when
  another pass's first object `  {` follows).
- **Merging** (`merge {inputs, dest, format, append}`, no open capture needed):
  `mergecap` (found next to tshark) into an atomic output, `-a` for a rotated
  capture's pieces (given in order), by timestamp otherwise; `dest` may not be
  an input. `rotation.ts` recognises pieces: tcpdump `-C`/`-W`
  (`trace.pcap`, `trace.pcap1`…, `-W` numbers the first too) and dumpcap ring
  buffers / `editcap -c` splits (`name_00001_<14-digit time>.pcapng`, which the
  tests make with editcap). Opening a piece offers the merge once per editor
  (`offerMerge`; "Don't Ask Again" is a globalState flag). _PCAP: Merge
  Captures…_ uses the active capture's backend, else a short-lived one.
- **Conversation filter and colorization** (row menu, `lib.conversationFilters`):
  the packet's conversations come from its exact detail tree (the
  innermost `eth.src/dst`, `ip.*`, `ipv6.*`, `tcp.stream`, `udp.stream`;
  values that aren't addresses or numbers are dropped), shown as a second
  flat menu at the same spot (`conversationMenu`; it fetches the exact
  detail when the selected one is missing or a quick view, whose stream
  numbers are the window's). _Conversation Filter_ applies the filter.
  _Colorize Conversation_ posts `colorizeConversation`: the session keeps
  `temporaryRules` (`settingsModel.colorizeConversation`: newest first, the
  first `COLORIZE_PALETTE` color the others don't use, at most ten, i.e.
  Wireshark's temporary colors) ahead of the configured rules in
  `coloringRules()` (also with coloring toggled off: they were asked for),
  per editor and kept across reloads, and runs `applyColoring`. The
  `coloring` message carries `temporary` (their count, `state.colorized`),
  which enables _Reset Colorization_ (`pcapViewer.resetColorization`; the
  ☰ requirement `colorized`). No Ctrl+1…0 keys: VS Code binds them.
- **Coloring rules editor** (`ColoringPanel`, `coloring.js`; the
  `pcapViewer.manageColoringRules` command, titled _Edit Coloring Rules_): one
  panel per window, reading and writing `pcapViewer.coloringRules` for the
  capture that was active (`editableColoringRules` keeps disabled rules;
  `coloringRulesSetting` writes `enabled` only when false and fills empty
  names from the filter). Filters are checked with the active (else any open)
  session's `validateFilter`, debounced; empty filters and `@` block saving,
  tshark compile errors only mark the row (tshark skips such rules). "saved"
  carries the stored rules and the editor reloads them; a settings change
  while the editor has unsaved edits only says so (Revert loads it).
- **Name resolution** (`pcapViewer.nameResolution.{mac,network,capturedDns,
transport,external}`, `open {names}`): `DissectionOptions.names` holds the
  `-N` letters (`name_flags`: m, n, d, N, t; d and N only with n; none = `-n`;
  `names` absent = tshark's own preferences, as before) and goes into every
  dissecting pass, so the list, details, filters (`ip.src_host`) and coloring
  agree. The `-z` passes (statistics, follow) add `-n` after it: their rows
  become address filters (this also fixed MAC names like "Broadcast" from the
  user's Wireshark preferences breaking eth endpoint filters). `-H` can't add
  a hosts file (tshark only uses it when writing), so names come from the
  capture's DNS answers, the system hosts file (fingerprinted in the index key,
  `system_hosts_file`) and the personal `hosts` file (in the config
  fingerprint). When names can replace addresses (m or n), the index pass sets
  `gui.column.format` (titles = the legacy field names) so
  `_ws.col.unres_src/unres_dst` exist, stores them after the custom columns,
  blanked when equal to Source/Destination (`_blank_same_addresses`), and
  `list_packets` rows carry `addresses: [src, dst]` when a name is shown
  (`_add_addresses`); a tshark rejecting those fields just drops them. The
  webview's `lib.cellAddress` gives cell filters the address and shows it as
  the cell's tooltip. tshark leaves port names off the first packet of a pass
  (the services table loads lazily); Wireshark shows it after re-dissecting.
  The host sends the switches, reloads sessions whose `names` differ when the
  settings change (debounced: _PCAP: Name Resolution…_ writes several keys),
  and posts the status-bar label (`nameResolutionLabel`) in `init`.
  `external` is application-scoped (a workspace can't make you send lookups).
- **Export Objects** (`export_objects`, `save_objects`, `objects.py`,
  `ObjectsPanel`): one `tshark -2 --export-objects <p>,<dir>` pass for all six
  protocols into `work_dir/objects/<p>/` (`-2`: TFTP transfers are only
  written in two-pass mode), cached per open capture (`_objects`, keyed by
  the `_Open`), and it runs while a streaming open still indexes. tshark
  only writes files, so the same pass prints fields (`objects.FIELDS`,
  aggregator `\x1e` since URIs contain commas) that `Linker` uses to link each
  file to its packet: HTTP by sha256 of `http.file_data` (the decoded body
  tshark saves: dechunked, gunzipped), else by name (URI's last segment, IMF
  `subject.eml`, TFTP requested file's basename; `name(1).ext` duplicates
  consume hints in order), and `object<N>.ext` names by N. Progress comes
  from frame lengths in the second pass (the first prints nothing). Linking
  fields tshark rejects are dropped and the pass retried. Saving copies from
  the work dir through `atomic_output`: `dest` for one object (the host's
  save dialog suggests `safeFileName`), `dir` for many (`safe_name`,
  `unique_path` → `name (1).ext`, never overwriting); object bytes never pass
  through JSON-RPC or the webview. The panel filters by protocol and text
  (`lib.filterObjects`), sorts, and goes to the packet on double-click/Enter.
  `objects.pcap` (generate.py) has HTTP (PNG, gzip+chunked text, a POST body,
  a body served twice), a two-block TFTP read and an SMTP mail.
- **Packet comments** (`comments.py`; `set_comments`, `packet_comments`,
  `save_comments`; `PcapDocument`): tshark's field output splits a
  multi-line comment into one occurrence per line plus the whole text, so
  comments are read from the pcapng itself (`read_comments`: `opt_comment` of
  EPB and obsolete PB, SPBs counted as frames, both byte orders, several
  sections; gzip/zstd through the stdlib; LZ4 raises `UnreadableError`, which
  `packet_comments` reports as `error` and `save_comments` refuses; pcap and
  other formats have none), in the pool after open (~1 s per million
  packets; a "comments" notification makes the viewer refresh). Rows carry
  `comment` (a packet's comments joined with "\n") and `commentEdited`.
  Writing uses editcap (`editcap_args`): `-a N:text` sets one comment per
  packet (a second `-a` for the same frame replaces the first) and there is
  no per-packet delete, so a deletion or an edit of a packet with several
  comments means `--discard-packet-comments` plus `-a` for every remaining
  comment (several joined into one); long option lists run in chained
  editcap passes (MAX_FILTER_ARG, only the first discards). `inPlace: true`
  writes a temp file next to the capture and replaces it under `_lock`
  (`_replace` retries: Windows refuses while a tshark reads it), then clears
  the detail/quick/filter caches; else `dest` via `atomic_output`. In place
  only for plain pcapng (`open` → `comments.inPlace`). The host keeps the
  unsaved edits in `PcapDocument` (frame → text, "" deletes):
  `PcapEditorProvider` is a `CustomEditorProvider`, so each edit is a
  `CustomDocumentEditEvent` (VS Code gives the dirty dot, undo/redo, save,
  save as, revert and hot-exit backups: `backupCustomDocument` writes the
  edits as JSON, `parseCommentBackup` restores them). Every session of the
  document pushes the whole set to its backend (`set_comments`) and posts
  `commentsChanged`; after an in-place save the other sessions send
  `reload: true` to re-read the file. Saving a non-pcapng capture asks to
  save a new `.pcapng` instead, opens it, and clears the edits here. The
  webview shows a stripe on commented rows (warning color while unsaved),
  the comment as the No. cell's tooltip, and a comment bar above the detail
  tree (textarea: Ctrl+Enter applies, Esc cancels); `setComment` goes to the
  host. `editPacketComment` (Ctrl+Alt+C) and `deletePacketComment` are
  viewer commands; _Delete All Packet Comments_ is one edit on the host.
  `comments.pcapng` (generate.py writes the pcapng by hand) has a comment, a
  multi-line comment and a packet with two.
- **Flow graph** (`flow_graph {offset, limit}`, `FlowGraphPanel`,
  `flowgraph.js`): the current view's matches in capture order (never the
  sort), nodes = Source/Destination values in order of first appearance
  (streamed with `RowStore.column` through the sort-column cache, cached per
  `filterId` in `_flow`), at most MAX_FLOW_NODES (200) columns, the rest
  share an "other" column (`from`/`to` = -1, `more` counts them). Needs a
  complete view (IndexingError while indexing or filtering). The panel
  draws only the rows on screen (SVG, `lib.computeWindow`, pages of 200),
  `lib.flowArrow` positions arrows, labels are centred when they fit, else
  run right from the arrow's start (`lib.truncate`). It follows the capture's
  filter: `PcapEditorSession.onDidChangeFilter` → "reset".
- **TCP stream graphs** (`tcp_graph {stream | frame}`, `TcpGraphPanel`,
  `tcpgraph.js`): one `-Y tcp.stream == N` pass (fields `_TCP_GRAPH_FIELDS`;
  FT_NONE flags like `tcp.analysis.retransmission` print 1 when set) parsed
  by `parse_tcp_graph` into compact points [frame, time, dir, seq, len, ack,
  win, rtt, retrans, syn] (dir 0 = the first packet's source → the other;
  tunnels: the innermost value), cached per stream (LRU 4). The webview
  computes the four graphs (`lib.tcpGraphSeries`: Stevens segments with
  retransmissions flagged; throughput as a moving average over a twentieth of
  the stream (1 ms–1 s); RTT from the receiver's `ack_rtt`; the receiver's
  window as a line plus bytes in flight), starts with the direction that
  sent more data, draws at most 6000 marks, and puts the time axis around the
  stream (`lib.niceRange`). One panel per editor; showing it again switches
  stream. Opened from the command or the row menu (`tcpGraph` message).
- **Compare packets** (`pcapViewer.comparePackets {frames}`,
  `ComparePanel`, `compare.js`, `lib.comparePackets`): one panel per editor
  (showing it again compares the new pair). The row menu posts `compare`
  with the two selected frames (_Compare 2 Selected Packets_) or the clicked
  one (_Compare with Packet…_: the command asks for the other's number;
  disabled for more than two); without args the command takes the
  selection. The host fetches both details with `session.detailParams`
  (two-pass for small captures, like the viewer) and posts `show {a, b}`;
  _Swap_ and _Go to Packet N_ go back to it. `lib.comparePackets` aligns
  the trees by the path of field names, repeated names and unnamed nodes
  by occurrence (unnamed ones keyed by label made two different DNS
  queries look like two one-sided subtrees), in A's order with B's extra
  fields after their predecessor; rows are same/changed/a/b with `differs`
  for the row or anything below. The table (`table.stats.compare`, fixed
  layout, labels wrap) marks rows with a diff Codicon plus visually hidden
  text, colors cells with the diff editor's removed/inserted backgrounds,
  and shows only differing rows (with their parents) by default, at most
  5000 rows.
- **Live capture** (`capture.py`, `capture_start {dest, interfaces, filter,
limits: {packets, seconds, bytes}, promiscuous, snaplen}` + the open
  parameters minus `path`/`cache`, `capture_stop`, `list_interfaces` =
  `dumpcap -D -M`, `validate_capture_filter` = `dumpcap -i -f -d`, which exits
  0 either way: `filter_problem` reads stderr). `dumpcap -q … -w -` writes
  pcapng to its stdout (it flushes per packet on a pipe); `LiveCapture` cuts
  the stream into complete blocks (`_Blocks`, both byte orders) and writes
  them to `dest` and to an `os.pipe()` that the index pass reads as `tshark
-r - -l` (`stream_lines(stdin=fd)`), so rows appear as packets arrive and
  `dest` is a valid pcapng at every block boundary: detail, streaming filters
  and follow read it while it grows. Neither dumpcap nor tshark touch `dest`,
  so AppArmor's tshark profile doesn't matter. The pipe can be read once, so
  the index pass first runs its argv against the empty capture (tshark checks
  `-e` fields before reading) and does its rejected-field retries there
  (`_pass_lines`). `capture_start` = `_open(live=…)`: returns once dumpcap
  wrote its first bytes (interfaces open) or failed (`capture_error`: its
  message plus `permission_hint` per OS), with `indexing: true` and
  `capture` (`describe()`); `on_rows` is called at once (`_PassProgress.ready`:
  a quiet interface has no rows). "capture" notifications: `stats` (packets,
  bytes, seconds, about every second, POSIX only when idle) and `stopped`
  (`dropped` from dumpcap's "received/dropped" line, `error`); then the
  usual "index" `done`, after which the capture is a plain file (capinfos
  runs then; no saved index; no comments to read). Stop: SIGINT
  (`procs.interrupt_process`), a kill on Windows (only complete blocks are
  written, so the file stays readable); a refused signal makes the copy loop
  close dumpcap's stdout. `limits.bytes` is enforced by the copy loop (`-a
filesize` needs a file) block by block: one chunk can hold many blocks, so
  `_Blocks.feed(chunk, budget)` stops at the first block reaching the limit,
  and what dumpcap writes while it stops is dropped. Packets/seconds are
  dumpcap's (`-c`, `-a duration`).
  Closing cancels the index token, which aborts the capture. A streaming
  filter started while capturing only sees the packets captured so far: its
  view is `stale` (the same filter reruns) and never cached
  (`_Filtering.during_capture`); the webview reapplies the filter when a
  capture's index is done. Host: _PCAP: Start Capture…_ (`commands/capture.ts`:
  interface QuickPick with the last choice checked, filter InputBox validated
  by the backend, debounced) creates an empty unsaved capture
  (`newTemporaryCapture`, named by `captureFileName`) and `queueCapture`s the
  request, so the document's first load sends `capture_start` (a failed start
  keeps the request: Reload retries). `session.capturing` →
  `pcapViewer.capturing` context key (Stop in the editor title) via
  `onDidChangeCapture`; `load()` while capturing only sets
  `reloadWhenCaptured` (restarting would end the capture). Webview:
  `state.capture`, `#status-capture` (red dot, "Capturing on eth0 · 0:12 ·
  1.2 KB", Stop; after it "Captured on eth0 in 0:12 · N dropped"), the list
  follows new rows while its end is in view (`atListEnd`), sorting says it
  waits for the capture. Tests use `fake_dumpcap.py` (replays a pcapng; knows
  `-D -M`, `-d`, `-c`, `-a duration:`, SIGINT; `FAKE_DUMPCAP_*` env), and a
  real loopback capture when allowed (CI sets dumpcap's capabilities on
  Linux).
- **Unsaved captures** (`tempCaptures.ts`; live captures and editing results):
  files in `globalStorageUri/captures/<random>/<name>.pcapng`
  (`isTemporaryCapture` by path). `PcapDocument.temporary`; the provider fires
  a `CustomDocumentContentChangeEvent` when the first editor resolves, so the
  tab is dirty: `Ctrl+S` (`saveTemporary`) asks where, writes through
  `save_comments {dest}` (comment edits included), opens the saved file and
  closes the unsaved one; Save As works as usual; either stops a running
  capture first (modal). Revert drops the edits and leaves it clean (closing
  then discards it). Disposing the document deletes its folder 5 s later
  (`discardTemporaryCapture`): at shutdown the extension host is gone by then,
  so a hot-exit backup still finds its file. Activation prunes folders older
  than 7 days. No saved index for them; no merge offer.
- **VoIP** (`voip.py`, `voip_calls {heuristic}`, `rtp_stream {stream}`,
  `rtp_audio {stream, dest, format}`; `VoipPanel`, `voip.js`): RTP streams
  come from tshark's `-z rtp,streams` report (`parse_rtp_streams`: the
  columns after "Lost" are found by name, since "Min Jitter(ms) Mean
  Jitter(ms)" are one space apart, and their set varies by version; payload
  names may hold spaces). tshark has no call list, so SIP calls are built
  from one `-Y sip` fields pass (`SIP_FIELDS`, aggregator `\x1e`: Call-IDs may
  hold commas), run in parallel with the report: a call is a Call-ID with an
  INVITE (REGISTER, OPTIONS… are skipped); state from INVITE responses, BYE
  and CANCEL; SDP `c=`/`m=` endpoints link streams (by either end). A
  stream's key (5-tuple + SSRC, `StreamKey`, checked: it becomes a display
  filter) comes back from the client with `heuristic`, and every per-stream
  pass is `-Y <stream filter>` (plus `-o rtp.heuristic_rtp:TRUE` for
  heuristic streams), streamed line by line. `analyse_stream` follows
  Wireshark's tap-rtp-analysis: extended (unwrapped) sequence numbers and
  timestamps, RFC 3550 jitter with the payload type's clock (static types;
  8000 for dynamic ones), delta, skew, and a status per packet (gap with the
  number missing, late/duplicate, payload type change); the jitter matches
  the report's (tests compare them). Audio: G.711 only (PT 0/8, 256-entry
  tables), packets placed by timestamp in sequence order, silence for gaps up
  to `MAX_GAP_S`, duplicates dropped, other payload types (DTMF events)
  skipped; stdlib `wave` writes it through `atomic_output`. Other codecs:
  `InvalidParamsError` with `data.unsupported`, and the host offers the raw
  payload (`format: "raw"`). Results are cached (`_voip`, `_rtp_streams`)
  only once the capture is completely indexed. Play: the host has the
  backend write `stream-N.wav` into the panel's own folder under
  `globalStorageUri/audio/<random>` (a `localResourceRoot`, removed with the
  panel) and posts its `asWebviewUri`; `panelHtml(…, {media: true})` adds
  `media-src cspSource`, so audio never goes through postMessage. The panel:
  calls table, call flow (`lib.callFlow`: SIP rows plus one dashed row per
  linked stream; SIP rows go to their packet, RTP rows select the stream),
  streams table (a call's streams highlighted), analysis (summary, jitter
  chart with flagged packets, `lib.rtpProblems` as links). `voip.pcap`
  (`generate.voip_packets`, a µ-law encoder in the generator) has a call with
  440/880 Hz tones, one lost packet and jitter, and a 486-rejected call.
- **Capture editing** (`editing.py`, `edit_capture {operation, …, dest | dir}`;
  `commands/editCapture.ts`): one editcap run over the whole file (not the
  view; comment edits not included) into `dest` via `atomic_output`, `-F
pcapng` always: `timeShift` `-t` (offset as an exact decimal string; the
  host parses durations and date-times to bigint ns: `captureModel.ts`),
  `dedup` `-D N`/`-w S` (editcap reports "N packets seen, M skipped" on
  stderr), `keep` `-r` + ranges after the file names and/or `-A`/`-B` (epoch
  seconds; `-B` is exclusive), `truncate` `-s`, `injectSecrets`
  `--inject-secrets tls,<keylog>` (a Decryption Secrets Block), `split` `-c
N`/`-i S` into a scratch folder inside `dir`, then each piece moved out
  under a free name (`objects.unique_path`); editcap's
  `<name>_NNNNN_<time>.pcapng` names are what `rotation.ts` recognises.
  Refused while indexing or capturing. Results report `packets`
  (`comments.packet_count`) and `removed`. The host writes into a new unsaved
  capture and opens it.
- **AI filter help** (`src/aiFilter.ts` pure, `src/ai.ts` host, `src/commands/ai.ts`):
  Copilot's inline completions can't reach the webview, so the host uses
  `vscode.lm.selectChatModels({ vendor: "copilot" })` (stable in 1.90 = our
  `engines.vscode`; 1.90 has no system role, so the instructions are the first
  user turn). The prompt holds only the request, the current filter, protocol
  names (`stats phs` column 0, cached per backend) and field names/types/
  descriptions (`field_index` prefix search on the request's keywords).
  **Never packet data.** The model answers JSON `[{filter, explanation}]` (the
  parser tolerates fences, prose and `{suggestions: [...]}`, max 3). Every filter
  goes through the backend's `validate_filter`; if none is valid, there is one
  retry that includes tshark's errors. Webview: ✨ puts the filter bar in "ask
  mode" (the input holds a description: no validation or completions; Enter
  asks, Esc cancels with `aiCancel`), and results reuse the suggestion dropdown
  (mode `ai`). Picking one fills the bar without applying it. The host posts
  `aiAvailable` after init and on `lm.onDidChangeChatModels` or setting changes.
  No model, consent denied (`LanguageModelError` NoPermissions/Blocked) or
  `pcapViewer.ai.enabled: false` hide the action. A failed or cancelled request
  only shows a short message; the action stays, since those are usually
  transient. `@pcap` (package.json `chatParticipants`) is registered only if
  `vscode.chat.createChatParticipant` exists, and answers with validated filters
  plus `pcapViewer.applyFilter` buttons.
- **Explaining packets** (`src/aiExplain.ts` pure, `FilterAssistant.explain` in
  `src/ai.ts`, `src/commands/ai.ts`): the one AI feature that **sends packet
  data**, so it is gated by `pcapViewer.ai.allowPacketData` (default false,
  `scope: application` so a workspace can't enable it) with a one-time modal
  consent (`PACKET_DATA_CONSENT`, which states the limits and is unit-tested
  against them) that saves the setting. The row menu's _Ask Copilot About This
  Packet…_ / _…About N Selected Packets…_ (shown only when `aiAvailable`) posts
  `askAboutPackets`; the host runs `workbench.action.chat.open` with
  `{query: "@pcap /explain 1-3 7"}` (`explainQuery`), falling back to a direct
  `vscode.lm` request streamed into an untitled Markdown editor when the chat
  API or command is missing or refuses. `/explain` (a `chatParticipants`
  command) parses leading frames/ranges then a question (`parseExplainArgs`);
  no frames = the selection. The backend supplies rows (`list_packets
{frames, inView: false}`: displayed or not) and `packet_detail` trees. The
  prompt (`buildExplainPrompt`) holds the question, current filter, the row
  (column titles) and each tree as indented labels, capped by `EXPLAIN_LIMITS`
  (8 packets, 250 lines, depth 10, 160 chars/line, 48k chars overall: the tree
  budget halves until it fits). **No raw bytes by default**: field `value`s are
  never used, the hex dump only with `pcapViewer.ai.allowPacketBytes` (256
  bytes/packet), and byte dumps in labels (`isByteDump`: hex strings of ≥ 8
  bytes, payload fields) become "[N bytes not sent]". The prompt says the
  data is untrusted. The answer streams as Markdown; ```filter blocks
  (`extractFilters`) are validated with tshark and become _Apply filter_
  buttons, plus _Go to packet N_ for each packet explained.
- **Capture summary** (`src/aiSummary.ts` pure, `FilterAssistant.summarize`,
  `@pcap /summary`, _PCAP: Summarize Capture with Copilot_): seven backend
  requests in parallel (`capture_info`, `stats` phs, conv tcp/udp, endpoints
  ip, expert, io; a failed one is listed as "not available") feed
  `buildSummaryPrompt`, capped by `SUMMARY_LIMITS` (top 15 rows by bytes, 40
  protocol rows, 20 expert groups, IO merged into 12 buckets, 80 chars per
  cell, 24k chars: row counts halve until it fits, then a hard cut). **Never
  packet contents**, but conversations/endpoints hold addresses and names, so
  it is gated by `pcapViewer.ai.allowCaptureStatistics` (application scope,
  default false; `allowPacketData` implies it) with a one-time modal
  (`STATISTICS_CONSENT` in `aiConsent.ts`, unit-tested against
  `SUMMARY_LIMITS`, `ANOMALY_LIMITS` and `TOOL_LIMITS`). The prompt says the
  data is untrusted, to answer only from it and to say what can't be
  determined. Refused while indexing or capturing. The answer streams
  (`streamAnswer`); ```filter blocks go through `validate_filter`
  (`validFilters`) and become _Apply filter_ buttons. The command opens the
  chat with `summaryQuery()`, else streams into a Markdown editor
  (`answerInEditor`). A refused consent answers in chat with an _Open Setting_ button.
- **Anomaly explanations** (`src/aiAnomaly.ts` pure, `explainAnomaly`,
  `@pcap /anomaly`): panels never call the model; they post `askCopilot` to
  their panel host, which runs `pcapViewer.askAboutAnomaly {kind, rows |
stream, sessionId}`. The query stays short: expert rows (sanitized by
  `statsPanel.expertRows`) are kept host-side in `expertSelections` (20) and
  referenced as `expert #N`; streams go by number (`stream N`), and the
  participant fetches `tcp_graph` itself (`parseAnomalyArgs`; plain text =
  overview of the errors and warnings, `notableExpertRows`). Expert: up to 10
  rows with 5 frames each, plus conversation rows (type from the rows'
  protocols; a `frame.number in {…}` pass (`framesFilter`) finds the
  conversations, whose own filters, OR'd, give their whole rows). TCP:
  `tcpFacts` over every point (bytes/data packets/retransmission rate/zero
  windows (not SYNs)/window range per direction, RTT ms min/median/max) plus
  `downsamplePoints` (≤ 200: notable points first, both ends, evenly spread,
  capture order) as CSV. Same consent, streaming, filters and editor fallback
  as the summary. The panels show the button only when `ai` is in their init
  (`aiAvailable()`).
- **Language model tools** (`src/aiTools.ts` pure, `src/lmTools.ts`,
  package.json `languageModelTools` generated from `PCAP_TOOLS`, checked by a
  unit test): `pcap_count`, `pcap_stats` (phs/conv/endpoints/expert/io, 25
  rows), `pcap_capture_info`, `pcap_field_search` (20 fields, no consent) and
  `pcap_list_packets` (≤ 20 rows, `allowPacketData`); the others need
  `allowCaptureStatistics`, else they answer `notAllowed(need)` ("Not allowed:
  ask the user to enable …"). Every filter is validated first; counting uses
  backend `count_matches {filter, limit}` (filter LRU and saved index, never
  `_install_view`), so tools never change the view; rows come from
  `list_packets {frames, inView: false}`. `engines.vscode` stays 1.90:
  `toolsRuntime()` detects `lm.registerTool` and the part classes and declares
  their types locally; without them `@pcap` suggests filters as before.
  `runToolLoop` (fake-model unit tests) sends messages as parts, runs each
  call, stops at `TOOL_LIMITS.maxCalls` (8) or `timeLimitMs` (90 s) with a
  final round without tools, and is cancellable (the host adds a hard
  deadline 30 s later). Cited filters (validated, ≤ 5) become buttons. The
  default `@pcap` route uses the loop when tools exist and statistics are
  allowed (asking once); tools invoked by other participants use the active
  capture's backend.
- **Get Started walkthrough** (`contributes.walkthroughs` id `gettingStarted`,
  pages in `media/walkthrough/`): Python, TShark, open a capture, filter,
  analyze, AI. The setup steps complete on context keys
  `pcapViewer.pythonFound`/`tsharkFound`, set by _PCAP: Check Python and
  TShark_ (`pcapViewer.checkEnvironment`: `checkEnvironment` = `findPython`
  then a short-lived backend's `initialize`, which locates tshark; returns the
  status, `{quiet: true}` shows nothing) and by every capture load
  (`setEnvironmentContext`: a load proves both, a pythonPath/tsharkPath
  failure clears them). `pcapViewer.captureOpened` and
  `pcapViewer.filterApplied` complete the next two. A load that fails for a
  missing tool calls `offerSetupHelp` (_Setup Guide_ opens the walkthrough by
  `<publisher>.<name>#gettingStarted`, download page, settings). _PCAP: Open
  Sample Capture_ copies `media/sample.pcapng` to
  `globalStorageUri/samples/` first, so a comment saved in place never writes
  into the installed extension. A unit test checks that every step's command
  links, setting links, media and completion events exist.
- **Releases** (`scripts/release.mjs`, `.github/workflows/release.yml`):
  `CHANGELOG.md` keeps `## Unreleased` on top, entries grouped under
  `### Added` / `### Changed` / `### Fixed`, one line or two each, ending in
  the PR link `[#N]` whose definition sits at the end of the same `##`
  section (the release notes are cut per section); `prepare <version>` moves it
  under `## <version> — <date>` and bumps `package.json` (a regex, keeping
  its formatting); versions are plain x.y.z (the Marketplace has no semver
  pre-releases). A `v*` tag (or a manual run on one) calls `ci.yml`
  (`workflow_call`) first, then `check <tag>` (tag = package.json version,
  and CHANGELOG notes exist), `vsce package`, `gh release create` with the
  notes (or `upload --clobber` when the release exists), then
  `vsce publish --skip-duplicate` and `ovsx publish` (pinned, via npx: pnpm
  would refuse its install scripts), each skipped with a notice when its
  secret (`VSCE_PAT`, `OVSX_PAT`) is missing. CI uploads the `.vsix` as an
  artifact. Marketplace details: `icon` (PNG: vsce refuses SVG icons),
  `galleryBanner`, categories, keywords; README badges from img.shields.io
  (Marketplace version and installs, Open VSX version and downloads, CI on
  `main`: vsce only accepts SVGs from trusted badge services); the README's
  hero is `demo.gif`, recorded by `scripts/screenshots.js` (`recordDemo`:
  PNG frames → `encodeGif` with the dev dependencies `pngjs` and `gifenc`,
  one palette, unchanged pixels transparent, ~350 KB); README images are relative (vsce
  rewrites them to `…/raw/HEAD/…`, i.e. the default branch, which must be
  `main`), so `media/screenshots/` is not packaged. **History**: 0.3.0 was
  never tagged; v0.4.0 made the GitHub release, but the Marketplace refused
  the display name (see _Name_), so 0.4.1 is the first Marketplace/Open VSX
  version. A tag that reached a store is never moved: the next patch version
  ships instead. The maintainer pushes tags; a Claude Code session can push
  branches (`dev`, its `claude/…` branch) but not tags (the proxy refuses
  them and the API's ref writes), so it prepares the release PR and hands
  over the tag commands. A
  failed run is retried with _Re-run failed jobs_ (the Windows unit job once
  hit mocha's 2 s timeout on a 30 ms synchronous test; the re-run passed).
  **Branches**: `main` (default) holds released code only; work lands on
  `dev` (directly or through PRs into `dev`, Dependabot's too). A release is
  `release:prepare` on `dev`, a `dev` → `main` PR, then the tag on the merge
  commit. Claude Code sessions commit and push to `dev`; a CHANGELOG entry
  without a PR links its commit (`[abc1234]`), added in a follow-up commit.
- **Remote windows and trust** (`extensionKind: ["workspace"]`, `remote.ts`):
  the extension host, backend, tshark and dumpcap all run on the remote
  machine (WSL, SSH, containers), where workspace files are `file:` URIs, so
  paths work unchanged and live capture uses the remote's interfaces.
  `whereLabel(vscode.env.remoteName)` names the machine in setup messages
  (`environmentSummary(status, where)`, `offerSetupHelp`: "install it
  there"). `revealFile` replaces `revealFileInOS`, which can't open a remote
  folder: remotely the Explorer view for workspace files, else _Copy Path_
  (`revealHow`; `preferExplorer` keeps the dissectors folder in the Explorer
  locally too). A document whose scheme isn't `file:` (Live Share `vsls:`,
  zip or virtual file systems) never starts a backend: `load()` shows
  `notOnDisk` with _Open a Copy_ (`pcapViewer.openCopy`: read through
  `workspace.fs` into a new unsaved capture). `capabilities.virtualWorkspaces`
  is `limited` for that reason. `capabilities.untrustedWorkspaces` is
  `limited` with `restrictedConfigurations` pythonPath, tsharkPath,
  luaScripts and dissectorsFolder: in Restricted Mode VS Code only returns
  their user values, so a repository can't choose the programs or Lua that
  run (a unit test keeps the list). The smoke test opens a capture from a
  read-only `pcaptest:` file system provider and its copy.
- **Navigation and customisation** (Wireshark-like; all over the _current view_,
  i.e. the filter and sort order, which only the backend knows in full):
  - _Find Packet_ is backend `find_packet`. It turns the search into a display
    filter (`navigation.find_expression`: string → `frame contains "…"`, or
    case-insensitive `frame matches "(?i)<re-escaped>"`; hex →
    `frame contains aa:bb:cc`, a single byte as `"\xaa"`). The filter is
    validated, run once and cached in the filter LRU. Matches go into a
    one-byte-per-frame bitmap, then view order is walked from the selection,
    wrapping around. The `marked` mode walks the marks instead. **Where
    text is looked for** (`in`, Wireshark's choice; `string` and `regex`
    modes only): `bytes` (default) is the display filter above (`regex` =
    `frame matches "…"`, tshark's PCRE2, `(?i)` unless case-sensitive);
    `list` tests the row store's Source…Info cells plus the custom `columns`
    the webview sends (as shown: resolved names; not No. or Time), joined by
    newlines, in chunks (`LIST_FIND_CHUNK`), no tshark; `details` runs one
    `tshark -V` pass with the usual dissection options and tests each
    packet's text (`navigation.details_blocks`: a packet starts at its
    `Frame N:` line; labels unindented, generated fields' brackets removed,
    since the PDML tree shows none). Both use `navigation.text_matcher`
    (substring with casefold, or a Python regex with `re.MULTILINE`) and
    cache a FrameIndex in the filter LRU under a key starting with NUL
    (`\0find\0in\0mode\0case\0value\0columns…`, never a filter
    expression; not saved with the index). Progress `phase: "find"`. The
    webview's `#find-in` select appears for string/regex; after a details
    hit `state.findMatch` makes `revealFindMatch` (from `showDetail`, or at
    once when that packet is already shown) select the first tree node
    whose label matches (`lib.findTreeMatch`, the browser's RegExp; a
    Python-only pattern simply selects nothing).
  - _Conversation stepping_ is backend `neighbor_frame`: `tcp.stream`/
    `udp.stream` columns, extracted once into the row store, else the unordered
    Source/Destination pair. It reads cells in chunks along the view and
    doesn't wrap.
  - _Marks_ live in the backend (`mark_packets`/`unmark_all`, per session,
    not persisted). Rows carry `marked`; the webview patches its cached pages
    instead of refetching. _Export marked_ uses `export` with `marked: true`:
    `frame.number in {…}` with ranges compressed, split into chunks when the
    filter would exceed `MAX_FILTER_ARG` (16k characters, under Windows'
    32767-character command line), and the chunks joined with `mergecap -a`.
  - _Ignored packets_ (Ctrl+D, `ignore_packets`/`unignore_all`, toggled like
    marks; `_ignored`, per session) stay in every view: rows carry `ignored`
    (dimmed, no rule color, `aria-description` "Ignored"), filters and sorts
    are unchanged. tshark has no ignore option and re-dissecting without
    them would renumber frames, so it is not Wireshark's "not dissected":
    `_without_ignored(flt)` adds `navigation.exclusion_filter` (`!(frame.number
== 2 || (frame.number >= 4 && frame.number <= 6))`: no commas, which
    `-z io,stat` would split its filter list on) to every statistics tap,
    the expert summary (cached per exclusion) and filter-based exports;
    marked/selected exports and CSV/JSON drop them from their frame lists
    (`_chosen_frames`: "Every one of the … is ignored"). More than
    `MAX_FILTER_ARG` of exclusion is an InvalidParamsError ("unignore some").
    Follow, flow/TCP graphs, VoIP, Export Objects, find and AI tools still
    see them. The webview refreshes the expert indicator after each change.
  - _Times_ are formatted by the backend when `list_packets` gets `timeFormat`
    (and `timeRef`). Plain relative time uses the index pass's column; every
    other format uses `frame.time_epoch`, extracted once, parsed to integer ns.
    "Since previous displayed" is since the previous packet _of the filter_ in
    capture order (bisect in `view.matched`), like Wireshark's
    `frame.time_delta_displayed` but for our filter (tshark's field only knows
    the unfiltered pass). It is a property of the packet, whatever the sort,
    which is what lets the Time column sort by it. There is one time reference; its row shows `*REF*` in every format. The format
    and reference are part of the webview's page cache key.
  - _Multi-selection_ lives in the webview as a `Set` of frame numbers
    (`state.selection`, empty when one row is selected) plus the focused row
    (`selectedIndex`/`selectedFrame`, the detail pane). Click selects one row;
    Ctrl/Cmd+click toggles; Shift+click and Shift+arrows select from the
    anchor (the last plain or Ctrl click) and take frames for rows not loaded
    from `view_frames {offset, limit}`. Ctrl+A can't be a keybinding: VS Code's
    webview doesn't stop the key, so Chromium selects the page's text, and
    VS Code's Select All runs `execCommand("selectAll")` in the webview (found
    in real VS Code; a package.json binding didn't win). Both fire a cancelable
    `selectstart` on `<body>` (in an input the target is the input): the
    webview cancels it and selects the view via `view_frames` (deduplicated,
    since both can arrive). _PCAP: Select All Packets_ has no key. Limits:
    `MAX_SELECTION` (1M frames) and 100k rows per copy. A new filter drops the
    selection; a new sort keeps it (same frames). Right-click inside the
    selection keeps it and the menu acts on all of it: mark (Ctrl+M: mark all
    unless all are marked), copy rows (TSV of the visible columns in view
    order: cached pages, else `view_frames {frames}` for the order then
    `list_packets {frames}` in chunks), copy frame numbers, _Export Selected
    Packets…_ (`export` with `frames`, the same chunked `frame.number in {…}`
    path as marked packets; CSV/JSON can export the selected rows). Ctrl+C
    arrives as a `copy` event (VS Code runs `execCommand("copy")` in the
    webview). The host learns the selection from `selection {frame, frames}`.
  - _Frame links_: after a detail loads, the webview asks `field_types` (exact
    catalogue lookups) for the tree's field names once, and `FT_FRAMENUM`
    fields become links. The back/forward history covers jumps (links, go to,
    find, marks, conversation, first/last), not arrow keys. The same lookup
    gives `state.related` (`lib.relatedFrames`: frame → kind by field name,
    `relatedKind`; a specific kind beats "related"): `list.js` draws a
    Codicon `span.related-mark` (absolutely positioned, after the cells, so
    `children[i]` stay cells) at the No. cell's left and an
    `aria-description` on those rows; `clearDetail` empties it. A one-pass
    detail dissects up to the packet only (`-c N`), so forward references
    (`http.response_in`) only appear with two-pass details (small captures,
    see _Detail_); otherwise only earlier packets get marks.
  - _Keys_: the webview handles keys VS Code leaves to a focused webview
    (Ctrl+F, F3, Ctrl+Home/End, Esc). Keys VS Code binds globally even then
    (Ctrl+M, Ctrl+T, Ctrl+,, Ctrl+Shift+N/B, and Alt+Left, which is Back on
    Windows) are package.json keybindings scoped to the viewer
    (`… && !sideBarFocus && !panelFocus && !inputFocus`). They send a
    `command` message and the webview ignores the raw key, so nothing runs
    twice.
  - _Columns_: `pcapViewer.columnLayout` holds `{order, hidden}` by column id
    (`number`…`info`, `custom:<field>`), and `lib.layoutColumns` maps visible
    columns to cell indexes. `pcapViewer.columns` is now resource-scoped, so
    _Apply as Column_, rename and remove write for the capture's folder.
    `lib.cellFilter` builds cell filters (ip/ipv6/eth by address form; none for
    Time or Info). `lib.formatBytesAs` has the bytes-pane copy formats.
- **Commands menu** (☰ `#filter-menu` after `#filter-clear`; `commandMenu.ts`,
  `main.js` `commandsMenu`): the list is built from package.json
  (`context.extension.packageJSON`: `contributes.commands` plus the first
  `contributes.keybindings` entry per command, `buildCommandMenu`), so a new
  command appears by itself; `GROUP_OF` gives its heading (Filters, Packets,
  Statistics, Export, Capture, Editing, Dissectors, AI, Other; "Packets" was
  added for navigation, marks, time reference and comments; a unit test fails
  when a command has no explicit heading, and category "PCAP Statistics"
  falls back to Statistics) and `REQUIRES` what it needs (selection, marks,
  filter, capturing, ai). `EXCLUDED_COMMANDS` names what is left out and why
  (only `savedFilters`: the ★ button in the same bar). **Foldable groups**:
  `lib.commandMenuRows` turns the groups into rows (a heading per group,
  then the commands of open groups; while searching every matching group is
  open and its heading is a plain label, `foldable: false`). Headings are
  `menuitem`s with `aria-expanded` and `data-group` (commands keep
  `data-id`); groups start folded and the open ones persist in the webview
  state (`state.menuGroups`, `persist()`). Enter/click toggles a heading, →
  opens it (again: into it), ← on a command goes to its heading and on an
  open heading folds it; ←/→ move the caret instead while searching. The host posts
  `commands` on "ready", before the capture loads (Reload and Show Log help
  when it fails), and `runCommand {id}` is accepted only for an id in that
  list (`runMenuCommand`: anything else is logged and ignored); it calls
  `activate()` first, since commands act on `provider.activeSession`, then
  `executeCommand`. **Disabled, not hidden**: an entry whose requirement isn't
  met (`lib.commandUnavailable`, from webview state) stays listed, dimmed,
  `aria-disabled`, with the reason as its tooltip and in the hint line; click
  and Enter do nothing, so the menu always shows everything there is.
  Keyboard: the button opens on click, Enter or Space (native button) and ↓;
  focus goes to the filter box and stays there: typing filters
  (`lib.filterCommands`: every word in title, heading or category), ↑/↓ wrap,
  Home/End jump (`aria-activedescendant` on the box), Enter runs, Esc or Tab
  close and give the focus back to the button, as does running an entry; a
  click outside or the window losing focus closes it without moving focus.
  The box's keydown handler stops propagation, so the viewer's own keys
  (Ctrl+F, F3…) don't fire while typing. Key bindings are shown per platform
  (`lib.formatKeybinding`: "Ctrl+Shift+N", or the `mac` binding as "⌘⇧N";
  macOS is detected from the webview's navigator, which is the local machine
  even in a remote window). `.command-menu` reuses `.context-menu`; its
  colors fall back to system colors when a theme variable is missing. The
  filter bar wraps (`flex-wrap`, `#filter-field` 14em minimum), so on a
  narrow editor the buttons go to a second line instead of squeezing the
  input (e2e test at 320/480/800 px).
- **Icons** are Codicons, VS Code's icon font (`@vscode/codicons`, pinned dev
  dependency). vsce packages with `--no-dependencies`, so
  `scripts/sync-codicons.mjs` (`pnpm run codicons`, run by `make update`)
  copies `codicon.css`, `codicon.ttf` and both licenses into
  `src/webview/codicons/` (inside every webview's `localResourceRoots`; in
  `.prettierignore`; `-text` in `.gitattributes`, as the LICENSE files are
  CRLF), and `test/scripts/codicons.test.mjs` fails when the copy differs from
  the installed package. The editor (`{{codiconsUri}}`) and `panelHtml` link
  the stylesheet before `base.css`; the CSP's `font-src cspSource` allows
  the font (fonts load in CORS mode: the test harness sends
  `Access-Control-Allow-Origin: *` like VS Code's resource server, and
  `codiconFontLoaded` checks the editor and the panels). Icons are
  `<span class="codicon codicon-NAME" aria-hidden="true">` built with
  `icon(name)` (main.js and each panel script), so buttons carry an
  `aria-label`. Checkable context-menu items (`showMenu`'s third element) are
  `menuitemcheckbox` with a check icon. Text symbols remain only inside text
  (● in `<option>`s and marked rows, ⚠ in a table cell, → in labels).
- **ARIA structure** (checked by axe, see _Accessibility checks_): the
  packet list's `#list-viewport` is the `grid` (`aria-multiselectable`,
  `aria-rowcount` = rows + 1) and owns the header row outside it
  (`aria-owns="list-header"`, `aria-rowindex` 1, `columnheader` cells with
  `aria-sort`); pooled rows are `row` with `aria-rowindex` (index + 2) and
  `aria-selected`, cells `gridcell`. The splitters are focusable
  `separator`s with `aria-valuenow` (10–90, the pane's percentage): arrow
  keys move them by 2, Home/End to the limits (`layout.js`). The detail and
  bytes panes are labelled regions. The flow graph's scroller is a `listbox`
  whose SVG is `role="none"`; rows are `option`s (`aria-selected`,
  `aria-posinset`/`setsize` over the whole view) and `aria-activedescendant`
  follows the selected one. The VoIP call flow is a labelled `group` of
  `button` rows named by their visible text (label in name).
- **High contrast** (`body.vscode-high-contrast`, `-high-contrast-light`): HC
  themes define no hover/selection/secondary-button fills, so the selected
  packet and tree node used to be invisible. base.css defines `--hc-active`
  and `--hc-border` and the button rules; the last sections of styles.css and
  panel.css outline their lists. `--hc-active` (=
  `--vscode-contrastActiveBorder`) solid for selected/pressed/active, dashed
  on hover, 2 px when the list or tree has focus (and for the focused row of a
  multi-selection), menu entries with `menu-selectionBorder`, popups bordered
  with `--hc-border` (`contrastBorder`); the zebra stripes go. Hover rules
  carry an id selector's specificity through `:is()`, so buttons have their
  own `:not(:focus-visible):hover` rule (the focus outline wins). The flow
  graph's rows are SVG: `stroke` instead of outline. `node
scripts/screenshots.js --theme light|hc --out <dir>` renders Light Modern
  and Dark High Contrast for checking (the default run also writes the
  README's `viewer-light.png`).
- **Shared stylesheet and tokens** (`src/webview/base.css`): the editor loads
  codicon.css, base.css, styles.css; the panels codicon.css, base.css,
  panel.css (no longer the viewer's styles.css; the panels e2e test checks the
  list). base.css holds the design tokens (spacing `--space-1…6` = 2, 4, 6, 8,
  12, 16 px; `--control-pad-y` 3 px / `-sm` 1 px; `--radius` 2 px,
  `--radius-toolbar` 5 px; `--text-xs` 11 px for chart labels, `--text-sm`
  0.9em, `--text-lg` 1.15em; `--mono`, `--mono-size`, `--row-height`,
  `--border`, `--shadow`) and the controls both use: buttons (primary,
  `.secondary`, `.icon`, `.link`, disabled), text/search/number inputs,
  selects and textareas, focus outlines, `.hidden`, `.visually-hidden`, and
  the high-contrast tokens. Paddings, margins, gaps, radii and font sizes in
  styles.css and panel.css use the tokens; add a token rather than a new
  literal. **Icon buttons** look like VS Code's toolbar actions: no border or
  fill, `toolbar-hoverBackground` on hover, `toolbar-activeBackground` while
  pressed or `aria-pressed` (plus `inputOption-activeBorder`), 5 px corners.
  **Indent guides** in the detail tree: main.js sets `--depth` on each row;
  `.node-row` indents by `--depth × --tree-indent` (14 px) and paints one
  1 px line per level as a `background-image` (a repeating gradient at 7–8 px
  of each 14 px step, under the parent's chevron) sized to the indent, so the
  hover/selection rules set `background-color` only. The lines use
  `tree-inactiveIndentGuidesStroke`, and `tree-indentGuidesStroke` while the
  tree is hovered or focused (VS Code's default "onHover").
- **Protocol**: JSON-RPC 2.0 framing (`"jsonrpc": "2.0"`), LSP-style
  cancellation code -32800; app codes in `backend/pcap_backend/protocol.py`
  and mirrored in `src/backendClient.ts` (`ErrorCodes`; -32011 unsupported format,
  -32012 still indexing or still filtering). `open` returns the
  initial `filterId`; every `list_packets` result carries the current one so
  the webview drops stale pages.

## Performance notes (test/perf/bench.py, 1M synthetic packets, 146 MB)

With `-o tcp.analyze_sequence_numbers:FALSE`: open 29–36 s (first rows after
0.5 s with streaming, colored; +2 s with the 14 default coloring rules; reopening from the saved index 0.01 s, 104 MB;
closed at ~500k and reopened: the 501,575 saved rows after 0.2 s, caught up
after 18.6 s, done after 36.7 s, i.e. a resume shows rows at once but saves
no tshark time), filter 26 s
(first matches after 0.5 s when streaming), page
fetch < 1 ms, sort 0.6 s, detail of last frame 20–26 s (quick view of any
frame 0.25–0.3 s with a 300-packet window), backend RSS 125 MB,
tshark 225 MB. With TCP analysis on, the synthetic file (512 replayed flows)
makes tshark super-linear (filter 165 s for 1M vs 4.5 s for 100k); real
captures are not expected to behave like that. Sorting streams one column from
the row store and sorts indices with a stable key list (no per-row tuples):
this took the backend from 710 MB to 125 MB peak.

## Status

Implemented: steps 1–7 of the brief (foundation, packet list with paging /
virtualization / sorting / custom columns, detail tree + hex with two-way
highlighting, display filters with validation, autocomplete, history, saved
filters, apply-as-filter, follow TCP/UDP/TLS/HTTP stream, and statistics
panels: conversations, endpoints, protocol hierarchy, IO graph, expert info,
capture properties).

Also step 6: Lua dissector commands (new from template, reload with error
check, open folder, reload offer on save) and a Decode As UI plus rule manager.

Step 7: coloring rules (defaults, Colorize with Filter, toggle), export
(pcapng/pcap, CSV/JSON packet list, packet bytes), CHANGELOG, packaging.

Beyond the brief: navigation and customisation, multi-select, AI help for
filters and explaining packets, a quick view for late packets in huge files,
streaming open and filters with saved indexes, TLS decryption with a key log,
export of packet dissections, merging captures, a coloring rules editor,
Export Objects, name resolution, packet comments, the flow graph and TCP
stream graphs, live capture and capture editing, AI capture summaries,
anomaly explanations and `@pcap` tools, and publishing: a release workflow,
Marketplace details, and the Get Started walkthrough. Then resumable indexing
with a progress bar, VoIP analysis (SIP calls, RTP streams, audio), the ☰
commands menu, HTTP/DNS/packet length/service response time statistics,
filter buttons, and Import from Hex Dump. Then foldable ☰ menu groups,
per-capture Lua dissectors, and Open File in PCAP Lens for files of any name.
Then Show TShark Plugins and README instructions for Wireshark plugins.
Then theme-aware packet colors, Codicons and high-contrast support.
Then a shared stylesheet with design tokens, toolbar-style icon buttons and
tree indent guides. Released 0.4.0 (GitHub only), then renamed to PCAP Lens for
0.4.1, the first Marketplace version. 0.5.0: Python 3.12+ and Install
Python. Since: the backend, viewer and editor split into modules, coverage
and axe-core checks with the ARIA fixes they found, and protocol preferences.
0.6.0 released. Then BER record files as packets, and the packet diagram:
0.7.0 released. Then Wireshark's expert indicator in the status bar,
related-packet marks, Conversation Filter and Colorize Conversation, and
ignored packets: 0.8.0. Then two-pass details for small captures and
Compare Packets: 0.9.0.
Then Follow Stream search, Filter Out This Stream, HTTP/2, QUIC and WebSocket
streams, and more "show as" views: 0.10.0.
Then Find Packet in the packet list and details, and by regular expression:
0.10.1.
