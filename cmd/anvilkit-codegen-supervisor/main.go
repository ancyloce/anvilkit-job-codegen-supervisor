// anvilkit-codegen-supervisor is the trusted entrypoint of the codegen Job
// (DD-03 §4–§6): supervisor, observer and finalizer of one launch. Invoked
// as "anvilkit-codegen-supervisor candidate-exec ..." it is the
// privilege-drop trampoline that becomes the candidate; as
// "anvilkit-codegen-supervisor candidate-stop ..." (always reached through
// that trampoline) it is the stop of the candidate's processes from inside
// the candidate identity; as "anvilkit-codegen-supervisor supervisor-exec
// -- program ..." it starts a program with the reviewed supervisor
// capability set for the whole process, which development harnesses
// outside a Job container use to run the supervisor as a container
// runtime would. As "anvilkit-codegen-supervisor team" (the entrypoint the
// team profile pins) it runs the P12 team flow instead of the fixed task:
// the mode is the reviewed profile's, never an environment variable's.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ancyloce/anvilkit-job-codegen-supervisor/internal/config"
	"github.com/ancyloce/anvilkit-job-codegen-supervisor/internal/process"
	"github.com/ancyloce/anvilkit-job-codegen-supervisor/internal/supervisor"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case process.TrampolineCommand:
			os.Exit(process.Trampoline(os.Args[2:]))
		case process.StopCommand:
			os.Exit(process.Stop(os.Args[2:]))
		case process.SupervisorExecCommand:
			os.Exit(process.SupervisorExec(os.Args[2:]))
		}
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.Load()
	if err != nil {
		log.Error("configuration rejected", "error", err.Error())
		os.Exit(2)
	}
	if len(os.Args) > 1 {
		if os.Args[1] != supervisor.TeamCommand || len(os.Args) > 2 {
			log.Error("unknown arguments", "args", os.Args[1:])
			os.Exit(2)
		}
		cfg.Team.Enabled = true
		if err := cfg.Validate(); err != nil {
			log.Error("configuration rejected", "error", err.Error())
			os.Exit(2)
		}
	}
	self, err := os.Executable()
	if err != nil {
		log.Error("executable path", "error", err.Error())
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	s := &supervisor.Supervisor{Config: cfg, Log: log, Self: self, Now: time.Now}
	os.Exit(s.Run(ctx))
}
