// Package install 实现 potlite install / uninstall：一键服务化与卸载。
package install

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/zcrv5/potlite/internal/config"
	"github.com/zcrv5/potlite/internal/nftfw"
	"github.com/zcrv5/potlite/internal/paths"
)

const (
	unitPath   = "/etc/systemd/system/potlite.service"
	binLink    = "/usr/local/bin/potlite"
	serviceTag = "potlite"
)

// UnitTemplate 生成 potlite.service 内容。
func UnitTemplate(exePath, dataDir string) string {
	return fmt.Sprintf(`[Unit]
Description=PotLite (轻蜜罐)
After=network.target

[Service]
Type=notify
ExecStart=%s serve
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
WatchdogSec=30
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=%s
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
`, exePath, dataDir)
}

// DoInstall 执行安装：配置检查 → 写 unit → 启用服务 → 建软链 → 输出摘要。
func DoInstall() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("需要 root 权限，请使用 sudo potlite install")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}

	// 配置检查/生成
	cfgPath, err := paths.ConfigPath()
	if err != nil {
		return err
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("配置加载失败: %w", err)
	}
	dataDir, err := paths.DataDir(cfg)
	if err != nil {
		return err
	}

	// 写 unit 文件
	unit := UnitTemplate(exe, dataDir)
	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		return fmt.Errorf("写入 %s 失败: %w", unitPath, err)
	}

	// systemd 操作
	if _, err := exec.LookPath("systemctl"); err == nil {
		run("systemctl", "daemon-reload")
		run("systemctl", "enable", "--now", serviceTag)
	}

	// 软链（幂等刷新）
	if _, err := os.Lstat(binLink); err == nil {
		os.Remove(binLink)
	}
	if err := os.Symlink(exe, binLink); err != nil {
		return fmt.Errorf("创建软链 %s 失败: %w", binLink, err)
	}

	// 摘要
	fmt.Println("PotLite 安装完成：")
	fmt.Printf("  程序:   %s\n", exe)
	fmt.Printf("  配置:   %s\n", cfgPath)
	fmt.Printf("  数据目录: %s\n", dataDir)
	fmt.Printf("  服务:   potlite（systemctl status potlite 查看状态）\n")
	fmt.Printf("  命令:   potlite 已在任意目录可用\n")
	return nil
}

// DoUninstall 执行卸载：停服 → 删 unit → 删软链 → 清内核表 → 输出文件清单。
func DoUninstall() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("需要 root 权限，请使用 sudo potlite uninstall")
	}
	// 停服 + 删 unit
	if _, err := exec.LookPath("systemctl"); err == nil {
		run("systemctl", "disable", "--now", serviceTag)
	}
	os.Remove(unitPath)
	if _, err := exec.LookPath("systemctl"); err == nil {
		run("systemctl", "daemon-reload")
	}
	// 删软链
	os.Remove(binLink)

	// 清内核封禁表（用户拍板：直接清除，不询问）
	if fw, err := nftfw.New(); err == nil {
		fw.RemoveTable()
		fw.Close()
	}

	// 文件清单
	cfgPath, _ := paths.ConfigPath()
	exe, _ := os.Executable()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		cfg = config.Default()
	}
	dataDir, _ := paths.DataDir(cfg)

	fmt.Println("以下为程序产生的所有文件，请自行决定是否删除：")
	fmt.Printf("  [程序]      %s\n", exe)
	fmt.Printf("  [配置]      %s\n", cfgPath)
	files := []struct{ name, path string }{
		{"封禁名单", paths.BansFile(dataDir)},
		{"白名单文件", paths.WhitelistFile(dataDir)},
		{"CSV 日志", paths.CSVFile(dataDir)},
		{"debug 日志", paths.DebugLogFile(dataDir)},
	}
	for _, p := range files {
		if _, err := os.Stat(p.path); err == nil {
			fmt.Printf("  [%s] %s\n", p.name, p.path)
		}
	}
	// 锁文件与名单备份在程序所在目录（不属于数据目录）
	if lp, err := paths.LockFile(); err == nil {
		if _, err := os.Stat(lp); err == nil {
			fmt.Printf("  [锁文件] %s\n", lp)
		}
	}
	if bp, err := paths.BansBakFile(); err == nil {
		if _, err := os.Stat(bp); err == nil {
			fmt.Printf("  [名单备份] %s\n", bp)
		}
	}
	// corrupt 残留
	if matches, _ := filepath.Glob(paths.BansFile(dataDir) + ".corrupt.*"); matches != nil {
		for _, m := range matches {
			fmt.Printf("  [损坏名单备份] %s\n", m)
		}
	}
	return nil
}

func run(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}
