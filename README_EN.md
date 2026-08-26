# PotLite - Lightweight Honeypot

[中文](README.md) | **English**

A zero-dependency, single-binary Go honeypot: any IP that touches a honeypot port gets all its access permanently blocked by the kernel firewall.

***

## Getting Started

### One-Command Install

```bash
mkdir -p /root/potlite && curl -sSL https://github.com/zcrv5/potlite/releases/latest/download/potlite-linux-amd64 -o /root/potlite/potlite && chmod +x /root/potlite/potlite && /root/potlite/potlite install
```

This downloads the latest release, installs it as a systemd service, enables auto-start, and makes the `potlite` command available everywhere.

> **Before installing**
>
> 1. If using Alibaba Cloud / Tencent Cloud, open the honeypot TCP ports in the cloud security group (default 20 ports: 22,21,23,25,110,135,139,143,445,1433,3306,3389,5432,5900,6379,8080,8888,9200,11211,27017). Without this, scan traffic never reaches the honeypot.
> 2. Make sure you have an escape route: after your own IP gets banned, SSH is unreachable (all ports blocked). Use the cloud vendor's VNC/OrcaTerm console to log in and unban.
> 3. Root privileges are required (kernel firewall operations).

### Step-by-Step Install

```bash
# 1. Create program directory
mkdir -p /root/potlite

# 2. Download the binary
curl -sSL https://github.com/zcrv5/potlite/releases/latest/download/potlite-linux-amd64 -o /root/potlite/potlite

# 3. Make it executable
chmod +x /root/potlite/potlite

# 4. Install (generates config, installs systemd service, creates symlink, enables auto-start)
/root/potlite/potlite install

# 5. Uninstall (removes service & symlink, clears kernel bans; prints all data file paths for you to decide)
/root/potlite/potlite uninstall
```

### Verify the Download (optional)

Every release ships an official checksums file to verify the binary has not been tampered with:

```bash
curl -sSL https://github.com/zcrv5/potlite/releases/latest/download/checksums.txt -o /tmp/checksums.txt
cd /root/potlite && grep potlite-linux-amd64 /tmp/checksums.txt | sha256sum -c -
# "potlite: OK" means verification passed
```

***

## Commands

### Built-in Commands

**Install & Manage**

| Command | Description |
| --- | --- |
| `potlite install` | Install as a systemd service |
| `potlite uninstall` | Uninstall (stop service, clear kernel bans, list all generated files) |
| `potlite update` | Check for and auto-upgrade to the latest version |
| `potlite reload` | Reload configuration (hot) |
| `potlite restart` | Restart the service |
| `potlite help` | Show usage |

**Information**

| Command | Description |
| --- | --- |
| `potlite info` | Show runtime information (recommended) |
| `potlite port` | Show listening ports |
| `potlite bancount` | Number of currently banned IPs |
| `potlite stat [N]` | Top N rejected IPs this run (default 10) |
| `potlite stats [N]` | Top N rejected IPs overall (requires logging enabled) |

**IP Operations**

| Command | Description |
| --- | --- |
| `potlite ban <IP>` | Ban an IP |
| `potlite unban <IP>` | Unban an IP |
| `potlite allow <IP[/CIDR]>` | Add to whitelist |
| `potlite disallow <IP[/CIDR]>` | Remove from whitelist |

> All read-only commands (`info`/`stat`/`stats`/`bancount`) support `--json` output for scripting.

### systemctl Commands

| Command | Description |
| --- | --- |
| `systemctl status potlite` | View status (ports and banned count; use `potlite info` for full details) |
| `potlite reload` | Hot-reload config after changes (no service interruption) |
| `systemctl restart potlite` | Restart the service |
| `systemctl stop potlite` | Stop the service |

***

## Configuration

The config file `potlite.config` lives next to the binary (default `/root/potlite/potlite.config`, auto-generated with Chinese comments on first run). After editing, run `potlite reload`.

| Key | Default | Description |
| --- | --- | --- |
| `ports` | 20 common ports | Honeypot listening ports (comma-separated) |
| `ban.days` | 0 | Ban duration in days: 0=permanent; >0 auto-unban after expiry, decimals allowed (0.15=3h36m). Auto-bans in potlite.bans follow a sliding window: expiry = last trigger (new ban / re-access while banned / restart) + ban.days; blacklist groups (online lists / standalone list files) are exempt and permanent |
| `interval.bans` | 1 | Ban list save interval (minutes) |
| `log.level` | 0 | CSV log level: 0=off, 1=on |
| `interval.log` | 10 | Log save interval (minutes) |
| `ddns.domains` | empty | DDNS whitelist domains (comma-separated) |
| `interval.ddns` | 120 | DDNS resolve interval (minutes) |
| `allow.static` | 127.0.0.1/8,::1 | Static whitelist |
| `data.dir` | auto | Data directory (auto = /root if writable, else program dir) |
| `debug.log` | 0 | Debug log switch |
| `firehol.level1` | 0 | FireHOL level1 online blacklist (base list, very low false positives, recommended) |
| `firehol.webserver` | 0 | FireHOL webserver online blacklist (recommended when running web services) |
| `firehol.ipsum3` | 0 | FireHOL ipsum_3 online blacklist (IPs listed by 3+ lists, high quality) |

Three fields are maintained automatically (`latest.version`, `total.rejected`, `total.rejected.base`) — do not edit manually.

FireHOL: set to 1 to enable; the program downloads the list daily at 00:00 from the official FireHOL source (iplists.firehol.org) and saves it as `potlite.bans.firehol.level1` (etc.), effective immediately. Failed downloads keep the previous copy.

### Data Files

| File | Description |
| --- | --- |
| `potlite.bans` | Ban list (one IP/CIDR per line; incrementally saved every `interval.bans`; restored after reboot) |
| `potlite.whitelist` | Whitelist file (generated when DDNS results or manual allows exist) |
| `potlite.log.csv` | CSV log (when `log.level=1`) |
| `potlite.debug.log` | Debug log (when `debug.log=1`) |

### External Blacklists

Drop a file named `potlite.bans` + any suffix (e.g. `potlite.bans2`, `potlite.bans10086`) into the data directory (default `/root/`); the program detects it every `interval.bans` cycle (default 1 minute). Format: one IP or CIDR per line, `#` for comments. Two modes:

**Integrate-once mode**: first line contains `#整合` — entries are merged into the main ban list (only adds, never duplicates), then the source file is deleted:

```
#整合
1.2.3.4
5.6.7.0/24
```

**Blacklist group mode** (default): no `#整合` marker — the file is the source of truth, entries are NOT written into the main file:

- File exists → IPs inside are banned (effective at startup and on file change);
- File modified → only the new content is banned (removed IPs are auto-unbanned);
- File deleted → all its bans are lifted;
- Unchanged files are skipped (no extra overhead).

Example — download a shared blacklist from this repo:

```bash
curl -sSL https://raw.githubusercontent.com/zcrv5/potlite/main/blacklists/potlite.bans2 -o /root/potlite.bans2
```

Takes effect within 1 minute. Program artifacts (`potlite.bans.bak`, `potlite.bans.corrupt.*`) are never misinterpreted.

***

## Features

- **Ban on contact**: any IP touching any honeypot port gets ALL its traffic kernel-blocked (blocked at SYN stage; nmap/masscan half-open scans cannot bypass);
- **All-port, all-protocol ban**: TCP/UDP/ICMP traffic from the banned IP is rejected;
- **IPv6 banned by /64**: the whole subnet is banned, not a single address;
- **Multi-source whitelist**: built-in 127.0.0.1 + local interface IPs + static config + DDNS domains;
- **Persistence**: ban list saved incrementally, auto-restored after reboot (`potlite.bans` only grows, never overwritten);
- **External blacklists**: drop a `potlite.bans`+suffix file — `#整合` first line = integrate-once (source deleted); no marker = group mode (file is source of truth, changes take effect live, deleting the file lifts all bans);
- **Log levels**: `0` = off (default); `1` = CSV (IP, total rejects, first/latest ban time);
- **systemd integration**: one-command service install, live status, SIGHUP hot-reload, crash self-healing.

***

## FAQ

**I accidentally touched a honeypot port and got banned. What now?**

The ban blocks all ports including SSH. Log in via the cloud vendor's VNC/OrcaTerm console and run `potlite unban <your-ip>`. If your egress IP resolves from a DDNS domain, the next resolve cycle adds it to the whitelist (whitelist rules are checked first, access recovers).

**How do I see who is banned?**

`potlite bancount` for the count; `cat potlite.bans` for the list.

**Does uninstall delete my data?**

No. `potlite uninstall` prints all data file paths; deletion is up to you.

***

## Compatibility

Kernel >= 5.4 (all mainstream Linux since 2020): Ubuntu 20.04+, Debian 11+, Rocky/AlmaLinux 9+, Alpine 3.19+, openEuler 22.03+ etc. Kernel 4.x (CentOS 8, Ubuntu 18.04 etc.) degrades automatically; kernels < 4.1 (CentOS 6/7 etc.) are not supported.

***

## Building from Source

Requires Go 1.22+:

```bash
go build -ldflags="-s -w" -o potlite .
```

***

## License

MIT
