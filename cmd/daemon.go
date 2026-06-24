package cmd

import (
	"fmt"
	"os"
	"path/filepath"

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

// resolveDaemonPath 选择 daemon 文件（日志/PID）所在目录。
// 优先级：~/.proxy_ob/ > 系统临时目录。
func resolveDaemonPath(filename string) string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dir := filepath.Join(home, ".proxy_ob")
		if err := os.MkdirAll(dir, 0755); err == nil {
			return filepath.Join(dir, filename)
		}
	}
	return filepath.Join(os.TempDir(), filename)
}

func daemonize() {
	args := make([]string, 0, len(os.Args))
	for _, a := range os.Args {
		if a != "-d" && a != "--daemon" {
			args = append(args, a)
		}
	}

	exe, err := os.Executable()
	if err != nil {
		exe = os.Args[0]
	}

	logPath := resolveDaemonPath("proxy_ob.log")
	pidPath := resolveDaemonPath("proxy_ob.pid")

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "daemon: cannot open log file %s: %v\n", logPath, err)
		os.Exit(1)
	}

	attr := &os.ProcAttr{
		Files: []*os.File{nil, logFile, logFile},
		Sys:   daemonSysProcAttr(),
	}

	proc, err := os.StartProcess(exe, args, attr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "daemon: %v\n", err)
		os.Exit(1)
	}

	os.WriteFile(pidPath, fmt.Appendf(nil, "%d\n", proc.Pid), 0644)

	fmt.Fprintf(os.Stderr, "daemon started, pid: %d, log: %s, pid file: %s\n", proc.Pid, logPath, pidPath)
	proc.Release()
	os.Exit(0)
}
