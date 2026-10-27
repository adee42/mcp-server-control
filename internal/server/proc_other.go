//go:build !unix

package server

import (
	"os"
	"os/exec"
)

// The server targets Linux; these fallbacks only exist so it builds and its tests run
// on a Windows development machine.

func shellArgv(command string) []string { return []string{"cmd.exe", "/C", command} }

func setProcAttrs(*exec.Cmd) {}

func killTree(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}

func terminateTree(cmd *exec.Cmd) error { return killTree(cmd) }

func copyOwner(*os.File, os.FileInfo) {}
