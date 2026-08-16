// Package paths 负责路径解析：可执行文件目录、配置文件、数据文件等。
// 关键约定：一切路径以"可执行文件真实所在目录"为锚点，与工作目录无关。
package paths

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/zcrv5/potlite/internal/config"
)

// ExeDir 返回可执行文件真实所在目录（解析符号链接）。
func ExeDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	// Linux 下 os.Executable 读 /proc/self/exe 已解析符号链接；保险起见再解析一次
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return filepath.Dir(exe), nil
}

// ConfigPath potlite.config 的路径（固定放程序所在目录）。
func ConfigPath() (string, error) {
	dir, err := ExeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "potlite.config"), nil
}

// DataDir 计算数据目录：auto → /root 可写则 /root，否则程序目录；显式配置必须是绝对路径（S2 路径校验）。
func DataDir(cfg *config.Config) (string, error) {
	if cfg.DataDir != "" && cfg.DataDir != "auto" {
		if !filepath.IsAbs(cfg.DataDir) {
			return "", fmt.Errorf("data.dir 必须是绝对路径（当前值 %q）", cfg.DataDir)
		}
		return cfg.DataDir, nil
	}
	if isWritable("/root") {
		return "/root", nil
	}
	return ExeDir()
}

func isWritable(dir string) bool {
	probe := filepath.Join(dir, ".potlite-write-test")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(probe)
	return true
}

// 数据文件路径（相对数据目录）。
func BansFile(dir string) string      { return filepath.Join(dir, "potlite.bans") }

// BansBakFile 名单备份文件路径：放程序所在目录（与锁文件一致，支持自动回滚）。
func BansBakFile() (string, error) {
	exeDir, err := ExeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(exeDir, "potlite.bans.bak"), nil
}
func WhitelistFile(dir string) string { return filepath.Join(dir, "potlite.whitelist") }
func CSVFile(dir string) string       { return filepath.Join(dir, "potlite.log.csv") }
func DebugLogFile(dir string) string  { return filepath.Join(dir, "potlite.debug.log") }
// LockFile 单实例锁文件路径：放程序所在目录（锁与程序绑定，而非数据目录）。
func LockFile() (string, error) {
	exeDir, err := ExeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(exeDir, "potlite.lock"), nil
}
