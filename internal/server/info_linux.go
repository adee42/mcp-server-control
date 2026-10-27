package server

import (
	"bufio"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/adee42/mcp-server-control/internal/api"
)

// realFS are filesystem types reported as disks; pseudo filesystems are skipped.
var realFS = []string{"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "vfat", "exfat", "ntfs", "ntfs3", "reiserfs", "jfs", "nfs", "nfs4", "cifs"}

func addPlatformInfo(info *api.Info) {
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		info.Kernel = strings.TrimSpace(string(b))
	}
	info.Distro = osRelease()
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			info.UptimeSeconds, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(b))
		for i := 0; i < 3 && i < len(f); i++ {
			info.Load[i], _ = strconv.ParseFloat(f[i], 64)
		}
	}
	info.MemTotalBytes, info.MemAvailBytes = memInfo()
	info.Disks = disks()
}

func osRelease() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "PRETTY_NAME="); ok {
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}

func memInfo() (total, avail uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			total = v * 1024
		case "MemAvailable:":
			avail = v * 1024
		}
	}
	return total, avail
}

func disks() []api.Disk {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []api.Disk
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 || !slices.Contains(realFS, fields[2]) {
			continue
		}
		dev, mount := fields[0], unescapeMount(fields[1])
		if seen[dev] {
			continue // bind mounts and btrfs subvolumes report the same device
		}
		var st syscall.Statfs_t
		if err := syscall.Statfs(mount, &st); err != nil {
			continue
		}
		seen[dev] = true
		out = append(out, api.Disk{
			Mount:      mount,
			FSType:     fields[2],
			TotalBytes: st.Blocks * uint64(st.Bsize),
			FreeBytes:  st.Bavail * uint64(st.Bsize),
		})
	}
	return out
}

// unescapeMount decodes the octal escapes (\040 for space) used in /proc/mounts.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
