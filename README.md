# anvilkit-job-codegen-supervisor

The trusted supervisor of the AnvilKit codegen Job class (architecture DD-03 §4–§6 in `anvilkit-services`): the entrypoint of the codegen Job container, which supervises one launch, drops privileges for every candidate it starts, stops and confirms every candidate process, and either observes and finalizes the fixed, non-paid qualification task (`anvilkit-codegen` image, profiles `codegen-fixed-v1` and `harness-wiring-dev-v1`) or serves the trusted team coordinator of [`anvilkit-job-codegen-team`](https://github.com/ancyloce/anvilkit-job-codegen-team), whose image builds this repository's sources through a named `supervisor` build context.

Go module `github.com/ancyloce/anvilkit-job-codegen-supervisor`. It links no other repository: not the contracts' Go module (its `jobschema` package embeds the job profiles, which pin this image's own digest), and no service.

## Processes

- **Supervisor** (`anvilkit-codegen-supervisor`, UID 0 in its container with SETUID, SETGID and SETPCAP only): parses the launch envelope, loads the trusted resources from the explicit read-only agent directory (`/anvilkit/agent/resources.json`, nothing is discovered), closes the verdict tree, stages the protected inputs, waits for the execution scope from the access sidecar (`trusted.sock`), loads handle-bound inputs through it (P13-04) and launches the candidate through its own trampoline (`candidate-exec`): keepcaps off, bounding set emptied, supplementary groups cleared, real/effective/saved GID and UID set to 10001, inheritable and ambient sets cleared, `no_new_privs` set, every descriptor but 0–2 closed, all verified from `/proc/thread-self/status` before `execve`. Any failure denies execution (exit code 111, reported as an infrastructure failure).
- **Stop and confirmation** (one path for every ending): the supervisor holds no CAP_KILL and cannot signal a UID 10001 process itself, so whenever candidate execution ends — the leader exited, the candidate's or the team's bound, the launch's cancellation, the coordinator's end — it runs a helper (`candidate-stop`) through the same privilege drop that kills the process group and every descendant on the supervisor's parent chain (new sessions and groups included). The supervisor is a child subreaper, reaps, and confirms from its own read of `/proc` that nothing of the candidate runs before anything observes, answers or seals; a stop that cannot be confirmed fails the launch.
- **Fixed task** (`anvilkit-codegen-candidate`, UID 10001): writes the fixed result and probes the boundary it observes. The observer snapshots the output into the verdict tree, decides the verdict from the bytes, rechecks the trusted resources; the finalizer transfers result and evidence through the sidecar and submits the manifest twice (acceptance must be idempotent).
- **Team mode** (`anvilkit-codegen-supervisor team`, the entrypoint of `codegen-team-dev-v1`): the supervisor starts the trusted coordinator (`team.coordinator`, its own identity, stderr in the verdict tree) and serves the process protocol below on its stdio; each round runs the reviewed coder program (`team.coder`) as the candidate. The coordinator's end, the team's bound (`team.timeout`) and the launch's cancellation end a running round through the stop path; once the coordinator ended, every descendant of the supervisor — the coordinator's own children included — is stopped and confirmed before its result is read. A protocol violation stops the coordinator and fails the launch.

## Process protocol

The protocol's single source is the contracts repository (`anvilkit-agent-contracts`, `jobs/codegen/protocol.schema.json`, `urn:anvilkit:codegen-protocol:v1`, with its fixtures); `internal/protocol/contract/` holds verbatim copies with their digests in `SOURCE`, refreshed and verified by `tools/sync-protocol.sh [--check] <contracts-checkout>`. Newline-delimited JSON, one UTF-8 object per line of at most 65536 bytes:

| Direction | Message | Members |
|---|---|---|
| coordinator → supervisor | `run-candidate` | `protocolVersion` 1, `requestId` (strictly increasing), `round` (1–64, strictly increasing), `roundDir` (`<workspace>/round/<round>`, a real directory of the coordinator's identity, not group/other-writable) |
| supervisor → coordinator | `candidate-ended` | `protocolVersion`, `requestId`, `round`, `stop` (`exited`, `timeout`, `canceled`), `exit` (null when a signal ended the leader; `signal` then names it), `descendantsStopped`, `startedAt`, `endedAt` |
| supervisor → coordinator | `refused` | `protocolVersion`, `requestId`, `round`, `code` (`ROUND_NOT_NEW`, `ROUND_DIR_INVALID`, `TEAM_ENDED`; final for the launch: `CANDIDATE_NOT_RUN`, `STOP_NOT_ESTABLISHED`), `reason` |
| coordinator → supervisor (file `team/result.json`) | `teamResult` | `protocolVersion`, `outcome` (kind, failure code, detail, round), `verdict`, `failureCode`, `stageId`, `existing`, `counters`, `calls`, `error` |

Every line is decoded strictly: one object, no duplicate or unknown member, no null (but a signaled leader's `exit`), no trailing data. Anything else — a diagnostic line included — is a violation. `internal/protocol`'s tests hold the codec to the copy: constants, enumerations, patterns, member sets and every fixture's outcome.

## Packages

| Package | Responsibility |
|---|---|
| `cmd/anvilkit-codegen-supervisor` | Subcommand dispatch, configuration, signals: assembly only |
| `cmd/anvilkit-codegen-candidate` | The fixed non-paid candidate task and its boundary probes |
| `internal/config` | The koanf configuration snapshot: defaults < `config.yaml` < the launch facts of the environment (nothing else from the environment) |
| `internal/launch` | The launch envelope and the inputs it binds (protected fixtures, handle-bound loads), each verified against its digest |
| `internal/supervisor` | Orchestration: the launch prelude, the fixed task's observer and finalizer, the team flow and its protocol service, the trusted resources, the termination message |
| `internal/process` | Linux process operations: trampoline, stop helper, subreaper, reaping, `/proc` confirmation, one `Run` path for every candidate execution |
| `internal/privdrop` | The privilege drop and the supervisor's capability checks |
| `internal/protocol` | The process protocol codec and its contract copy |
| `internal/sidecar` | The access sidecar's trusted socket (one request per connection) |

## Layout and configuration

| Path | Mount | Owner and mode |
|---|---|---|
| `/workspace` | emptyDir | root `1777`; `/workspace/input` root `0755` (protected inputs); `/workspace/w` created and owned by the candidate; `/workspace/round/<n>` the coordinator's round inputs |
| `/anvilkit/verdict` | emptyDir | root `0700`: snapshot, verdict, evidence, manifest, candidate logs, `team/` |
| `/run/anvilkit` | emptyDir, read-only here | the sidecar's `sockets/` (`10002:0` `0711`) with `trusted.sock` and `candidate.sock` |
| `/anvilkit/agent`, `/anvilkit/fixtures`, `/etc/anvilkit/anvilkit-codegen` | image | root `0700`, `0600` files |

`config.yaml` (root-owned in the image) holds every path, identity and bound; the `team` section names the coordinator and coder programs, the reviewed `team.yaml`, the contracts directory and the coordinator's bound. The launch facts come only from `ANVILKIT_LAUNCH_ID`, `ANVILKIT_ATTEMPT_ID` and `ANVILKIT_LAUNCH_ENVELOPE`; any other `ANVILKIT_CODEGEN_` variable is refused. The supervisor refuses to run with anything but the reviewed capability set; host process tests start it through `supervisor-exec -- <program>`, which constrains every thread exactly as the container runtime does.

## Verification

```sh
GOWORK=off go build ./... && GOWORK=off go vet ./... && test -z "$(gofmt -l .)"
sudo env "PATH=$PATH" GOWORK=off ANVILKIT_REQUIRE_ROOT_TESTS=1 go test -count=1 ./...   # as root: real UID 10001 processes
sh tools/sync-protocol.sh --check <anvilkit-agent-contracts checkout>
docker build -t anvilkit-codegen .                                                    # the fixed-task image from this repository alone
```

The harness tests run the supervisor through `supervisor-exec` and cover the fixed flow, the stop at the bound, on cancellation and after a leader that exits before its descendants (new sessions and groups), an unconfirmable stop, and in team mode the team bound, cancellation, the coordinator's death mid-round, descendants gone before the answer, refused rounds and directories, and protocol violations. They need a root caller and `/tmp` (world-traversable); without root they skip unless `ANVILKIT_REQUIRE_ROOT_TESTS` is set. CI (`.github/workflows/ci.yml`) runs the same from this repository alone; its protocol job needs the contracts commit that holds the protocol (`CONTRACTS_REF`). No sandbox, gVisor or runtime qualification follows from these tests.
