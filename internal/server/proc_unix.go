//go:build unix

package server

import (
	"os"
	"os/exec"
	"syscall"
)

func shellArgv(command string) []string { return []string{"/bin/sh", "-c", command} }

func setProcAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killTree sends SIGKILL to the command's whole process group.
func killTree(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

// terminateTree sends SIGTERM to the command's whole process group.
func terminateTree(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
}

// copyOwner gives f the owner and group of fi (best effort; needs root for other users).
func copyOwner(f *os.File, fi os.FileInfo) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		_ = f.Chown(int(st.Uid), int(st.Gid))
	}
}
