package process

import (
	"fmt"
	"os"
	"strconv"

	"github.com/ancyloce/anvilkit-job-codegen-supervisor/internal/privdrop"
)

// TrampolineCommand is the supervisor's own subcommand that performs the
// privilege drop and executes the candidate:
// "candidate-exec --uid U --gid G --dir D -- program [args...]".
const TrampolineCommand = "candidate-exec"

// SupervisorExecCommand is the development subcommand that starts a
// program with the reviewed supervisor capability set for the whole
// process: "supervisor-exec -- program [args...]".
const SupervisorExecCommand = "supervisor-exec"

// PrivdropDenied is the trampoline's exit code when the drop failed: the
// candidate never ran, which the supervisor reports as an infrastructure
// failure rather than a candidate outcome.
const PrivdropDenied = 111

// trampolineArgs are the arguments of the supervisor executable that make
// it the trampoline into program as the candidate identity.
func trampolineArgs(uid, gid uint32, dir, program string, args ...string) []string {
	return append([]string{TrampolineCommand, "--uid", strconv.FormatUint(uint64(uid), 10), "--gid", strconv.FormatUint(uint64(gid), 10), "--dir", dir, "--", program}, args...)
}

// Trampoline is the candidate-exec subcommand: it parses its arguments and
// performs the drop; it returns only when the drop or the exec failed, with
// PrivdropDenied.
func Trampoline(args []string) int {
	var uid, gid uint64
	var dir, program string
	var rest []string
	var err error
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--uid", "--gid", "--dir":
			if i+1 >= len(args) {
				err = fmt.Errorf("%s needs a value", args[i])
				break
			}
			switch args[i] {
			case "--uid":
				uid, err = strconv.ParseUint(args[i+1], 10, 32)
			case "--gid":
				gid, err = strconv.ParseUint(args[i+1], 10, 32)
			default:
				dir = args[i+1]
			}
			i++
		case "--":
			if i+1 < len(args) {
				program, rest = args[i+1], args[i+2:]
			}
			i = len(args)
		default:
			err = fmt.Errorf("unexpected argument %q", args[i])
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "candidate-exec:", err)
			return PrivdropDenied
		}
	}
	if program == "" {
		fmt.Fprintln(os.Stderr, "candidate-exec: no program")
		return PrivdropDenied
	}
	if err := privdrop.Exec(privdrop.Target{UID: uint32(uid), GID: uint32(gid), Dir: dir, Program: program, Args: rest, Env: os.Environ()}); err != nil {
		fmt.Fprintln(os.Stderr, "candidate-exec: privilege drop refused:", err)
	}
	return PrivdropDenied
}

// SupervisorExec is the supervisor-exec subcommand. Outside a Job
// container (host process tests) it is how the supervisor is started so
// that every thread of it holds SETUID, SETGID and SETPCAP and nothing
// else, exactly as the Job template grants; a container runtime bounds
// the Job's supervisor the same way and never needs it. It returns only
// when the exec failed.
func SupervisorExec(args []string) int {
	if len(args) < 2 || args[0] != "--" {
		fmt.Fprintln(os.Stderr, "supervisor-exec: usage: supervisor-exec -- program [args...]")
		return 2
	}
	err := privdrop.ExecAsSupervisor(args[1], args[2:], os.Environ())
	fmt.Fprintln(os.Stderr, "supervisor-exec:", err)
	return 2
}
