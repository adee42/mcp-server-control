//go:build !linux

package server

import "github.com/adee42/mcp-server-control/internal/api"

// addPlatformInfo only has a Linux implementation; elsewhere /v1/info reports the basics.
func addPlatformInfo(*api.Info) {}
