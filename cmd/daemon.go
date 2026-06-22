package cmd

import (
	"fmt"
	"os"

	"proxy_ob/internal"
)

func parseConfig() (*internal.Config, error) {
	cfg, err := internal.Parse(os.Args[1:])
	if err != nil {
		return nil, err
	}
	if cfg.Daemon {
		daemonize()
	}
	initLogging(cfg.Verbose)
	return cfg, nil
}

func daemonize() {
	args := make([]string, 0, len(os.Args))
	for _, a := range os.Args {
		if a != "-d" && a != "--daemon" {
			args = append(args, a)
		}
	}

	logFile, err := os.OpenFile("proxy_ob.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "daemon: cannot open log file: %v\n", err)
		os.Exit(1)
	}

	attr := &os.ProcAttr{
		Files: []*os.File{nil, logFile, logFile},
		Sys:   daemonSysProcAttr(),
	}

	proc, err := os.StartProcess(os.Args[0], args, attr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "daemon: %v\n", err)
		os.Exit(1)
	}

	pidFile := "proxy_ob.pid"
	os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", proc.Pid)), 0644)

	fmt.Fprintf(os.Stderr, "daemon started, pid: %d, log: proxy_ob.log, pid file: %s\n", proc.Pid, pidFile)
	proc.Release()
	os.Exit(0)
}
