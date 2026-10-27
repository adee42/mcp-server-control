package server

import (
	"net/http"
	"os"
	"runtime"

	"github.com/adee42/mcp-server-control/internal/api"
)

func (s *Server) handleInfo(r *http.Request, k *Key) (any, error) {
	info := api.Info{
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		CPUs:      runtime.NumCPU(),
		KeyName:   k.Name,
		KeyScopes: k.Scopes,
	}
	info.Hostname, _ = os.Hostname()
	addPlatformInfo(&info)
	return info, nil
}
