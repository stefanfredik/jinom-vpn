package service

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

func stripCIDR(addr string) string {
	ip, _, err := net.ParseCIDR(addr)
	if err != nil {
		if parsed := net.ParseIP(addr); parsed != nil {
			return parsed.String()
		}
		return addr
	}
	return ip.String()
}

type L2TPService struct {
	nsSvc *NamespaceService
	log   *zap.Logger
}

func NewL2TPService(nsSvc *NamespaceService, log *zap.Logger) *L2TPService {
	return &L2TPService{nsSvc: nsSvc, log: log}
}

func (s *L2TPService) Setup(t *tunnel.ResellerTunnel) error {
	s.log.Info("Setting up L2TP/IPSec tunnel",
		zap.String("namespace", t.Namespace),
		zap.String("tunnel", t.Name),
	)

	clientIP := stripCIDR(t.ClientIPAddress)
	octets := strings.Split(clientIP, ".")
	if len(octets) == 4 {
		X := octets[2]
		hostIP := fmt.Sprintf("10.254.%s.1/30", X)
		nsIP := fmt.Sprintf("10.254.%s.2/30", X)
		nsIPNoMask := fmt.Sprintf("10.254.%s.2", X)
		vethHost := fmt.Sprintf("vh-%s", X)
		vethNs := fmt.Sprintf("vn-%s", X)

		runCmd := func(name string, args ...string) error {
			out, err := exec.Command(name, args...).CombinedOutput()
			if err != nil {
				s.log.Warn("Command failed", zap.String("cmd", name), zap.Strings("args", args), zap.Error(err), zap.String("out", string(out)))
				return err
			}
			return nil
		}

		// Clean up any existing veth interface from previous failed attempts
		s.log.Debug("Cleaning up existing veth interface", zap.String("veth_host", vethHost))
		exec.Command("ip", "link", "del", vethHost).CombinedOutput()
		time.Sleep(100 * time.Millisecond)

		// Create new veth interface
		if err := runCmd("ip", "link", "add", vethHost, "type", "veth", "peer", "name", vethNs); err != nil {
			return fmt.Errorf("failed to create veth interface: %w", err)
		}

		// Move veth peer to namespace
		if err := runCmd("ip", "link", "set", vethNs, "netns", t.Namespace); err != nil {
			return fmt.Errorf("failed to move veth to namespace: %w", err)
		}

		// Configure host side veth
		if err := runCmd("ip", "addr", "add", hostIP, "dev", vethHost); err != nil {
			return fmt.Errorf("failed to add host veth address: %w", err)
		}
		if err := runCmd("ip", "link", "set", vethHost, "up"); err != nil {
			return fmt.Errorf("failed to bring up host veth: %w", err)
		}

		// Configure namespace side veth
		if _, err := s.nsSvc.ExecInNS(t.Namespace, "ip", "addr", "add", nsIP, "dev", vethNs); err != nil {
			return fmt.Errorf("failed to add namespace veth address: %w", err)
		}
		if _, err := s.nsSvc.ExecInNS(t.Namespace, "ip", "link", "set", vethNs, "up"); err != nil {
			return fmt.Errorf("failed to bring up namespace veth: %w", err)
		}
		if _, err := s.nsSvc.ExecInNS(t.Namespace, "ip", "route", "add", "default", "via", fmt.Sprintf("10.254.%s.1", X)); err != nil {
			return fmt.Errorf("failed to add default route in namespace: %w", err)
		}

		runCmd("iptables", "-t", "nat", "-A", "PREROUTING", "-s", t.RouterIP, "-p", "udp", "--dport", "500", "-j", "DNAT", "--to-destination", nsIPNoMask+":500")
		runCmd("iptables", "-t", "nat", "-A", "PREROUTING", "-s", t.RouterIP, "-p", "udp", "--dport", "4500", "-j", "DNAT", "--to-destination", nsIPNoMask+":4500")
		runCmd("iptables", "-t", "nat", "-A", "PREROUTING", "-s", t.RouterIP, "-p", "udp", "--dport", "1701", "-j", "DNAT", "--to-destination", nsIPNoMask+":1701")
		runCmd("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", fmt.Sprintf("10.254.%s.0/30", X), "-j", "MASQUERADE")

		runCmd("iptables", "-t", "filter", "-I", "FORWARD", "1", "-d", nsIPNoMask, "-j", "ACCEPT")
		runCmd("iptables", "-t", "filter", "-I", "FORWARD", "1", "-s", nsIPNoMask, "-j", "ACCEPT")
	}

	// Clean up old config files before writing new ones
	connName := fmt.Sprintf("jinom-%s", t.Namespace)
	s.log.Debug("Cleaning up old config files", zap.String("conn_name", connName))
	_ = os.Remove(filepath.Join("/etc/ipsec.d", connName+".conf"))
	_ = os.Remove(filepath.Join("/etc/ipsec.d", connName+".secrets"))
	_ = os.Remove(filepath.Join("/etc/xl2tpd", t.Namespace+".conf"))
	time.Sleep(500 * time.Millisecond)

	if err := s.writeIPSecConfig(t); err != nil {
		return fmt.Errorf("write ipsec config: %w", err)
	}

	if err := s.writeXL2TPDConfig(t); err != nil {
		return fmt.Errorf("write xl2tpd config: %w", err)
	}

	// Reload IPSec configuration to pick up new credentials
	if err := s.reloadIPSec(); err != nil {
		s.log.Warn("Failed to reload ipsec configuration", zap.Error(err))
		// Continue anyway - startIPSec will handle full restart
	}

	if err := s.startIPSec(t.Namespace); err != nil {
		return fmt.Errorf("start ipsec: %w", err)
	}

	if err := s.startXL2TPD(t.Namespace); err != nil {
		return fmt.Errorf("start xl2tpd: %w", err)
	}

	return nil
}

func (s *L2TPService) reloadIPSec() error {
	// Reload IPSec to pick up new configuration without full restart
	out, err := exec.Command("ipsec", "rereadall").CombinedOutput()
	if err != nil {
		s.log.Debug("ipsec rereadall result", zap.Error(err), zap.String("output", string(out)))
		// Not critical, will be handled by full restart
		return nil
	}

	out, err = exec.Command("ipsec", "reload").CombinedOutput()
	if err != nil {
		s.log.Debug("ipsec reload result", zap.Error(err), zap.String("output", string(out)))
		return nil
	}

	s.log.Debug("IPSec configuration reloaded")
	time.Sleep(1 * time.Second)
	return nil
}

func (s *L2TPService) startIPSec(ns string) error {
	out, err := s.nsSvc.ExecInNS(ns, "ipsec", "restart")
	if err != nil {
		return fmt.Errorf("ipsec restart: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	time.Sleep(2 * time.Second)
	return nil
}

func (s *L2TPService) startXL2TPD(ns string) error {
	s.killXL2TPD(ns)

	confPath := filepath.Join("/etc/xl2tpd", fmt.Sprintf("%s.conf", ns))
	pidPath := filepath.Join("/run", fmt.Sprintf("xl2tpd-%s.pid", ns))

	if _, err := os.Stat(confPath); os.IsNotExist(err) {
		return fmt.Errorf("config file not found: %s", confPath)
	}

	cmd := exec.Command("ip", "netns", "exec", ns,
		"xl2tpd", "-c", confPath, "-p", pidPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("exec in %s: %s: %w", ns, strings.TrimSpace(string(out)), err)
	}

	time.Sleep(500 * time.Millisecond)

	if _, err := os.Stat(pidPath); os.IsNotExist(err) {
		s.log.Warn("xl2tpd PID file not created, checking if process is running",
			zap.String("namespace", ns))
	}

	s.log.Info("xl2tpd started", zap.String("namespace", ns), zap.String("pid_file", pidPath))
	return nil
}

func (s *L2TPService) killXL2TPD(ns string) {
	pidPath := filepath.Join("/run", fmt.Sprintf("xl2tpd-%s.pid", ns))
	data, err := os.ReadFile(pidPath)
	if err == nil {
		pidStr := strings.TrimSpace(string(data))
		_, _ = s.nsSvc.ExecInNS(ns, "kill", pidStr)
		_ = os.Remove(pidPath)
		time.Sleep(300 * time.Millisecond)
	}

	// Also kill any lingering xl2tpd using this config
	_, _ = s.nsSvc.ExecInNS(ns, "pkill", "-f", fmt.Sprintf("xl2tpd.*%s.conf", ns))
	time.Sleep(200 * time.Millisecond)
}

func (s *L2TPService) Teardown(t *tunnel.ResellerTunnel) error {
	s.log.Info("Tearing down L2TP/IPSec tunnel",
		zap.String("namespace", t.Namespace),
	)

	s.killXL2TPD(t.Namespace)
	_, _ = s.nsSvc.ExecInNS(t.Namespace, "ipsec", "stop")

	clientIP := stripCIDR(t.ClientIPAddress)
	octets := strings.Split(clientIP, ".")
	if len(octets) == 4 {
		X := octets[2]
		nsIPNoMask := fmt.Sprintf("10.254.%s.2", X)
		vethHost := fmt.Sprintf("vh-%s", X)

		runCmd := func(name string, args ...string) {
			out, err := exec.Command(name, args...).CombinedOutput()
			if err != nil {
				s.log.Warn("Teardown command failed", zap.String("cmd", name), zap.Strings("args", args), zap.Error(err), zap.String("out", string(out)))
			}
		}

		runCmd("iptables", "-t", "nat", "-D", "PREROUTING", "-s", t.RouterIP, "-p", "udp", "--dport", "500", "-j", "DNAT", "--to-destination", nsIPNoMask+":500")
		runCmd("iptables", "-t", "nat", "-D", "PREROUTING", "-s", t.RouterIP, "-p", "udp", "--dport", "4500", "-j", "DNAT", "--to-destination", nsIPNoMask+":4500")
		runCmd("iptables", "-t", "nat", "-D", "PREROUTING", "-s", t.RouterIP, "-p", "udp", "--dport", "1701", "-j", "DNAT", "--to-destination", nsIPNoMask+":1701")
		runCmd("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", fmt.Sprintf("10.254.%s.0/30", X), "-j", "MASQUERADE")

		runCmd("iptables", "-t", "filter", "-D", "FORWARD", "-d", nsIPNoMask, "-j", "ACCEPT")
		runCmd("iptables", "-t", "filter", "-D", "FORWARD", "-s", nsIPNoMask, "-j", "ACCEPT")

		runCmd("ip", "link", "del", vethHost)
	}

	connName := fmt.Sprintf("jinom-%s", t.Namespace)
	_ = os.Remove(filepath.Join("/etc/ipsec.d", connName+".conf"))
	_ = os.Remove(filepath.Join("/etc/ipsec.d", connName+".secrets"))
	_ = os.Remove(filepath.Join("/etc/xl2tpd", t.Namespace+".conf"))

	pidPath := filepath.Join("/run", fmt.Sprintf("xl2tpd-%s.pid", t.Namespace))
	_ = os.Remove(pidPath)

	return nil
}

func (s *L2TPService) writeIPSecConfig(t *tunnel.ResellerTunnel) error {
	connName := fmt.Sprintf("jinom-%s", t.Namespace)

	// IPSec config for L2TP - VPS acts as responder (passive listener)
	// auto=add means don't auto-initiate, wait for MikroTik to connect
	// right=RouterIP specifies which endpoint can connect
	conf := fmt.Sprintf(`conn %s
    authby=secret
    auto=add
    type=transport
    left=%%defaultroute
    leftprotoport=17/1701
    right=%s
    rightprotoport=17/1701
    keyingtries=3
    ikelifetime=28800s
    lifetime=3600s
    ike=aes128-sha1-modp1024,aes128-md5-modp1024,3des-sha1-modp1024!
    esp=aes128-sha1,aes128-md5,3des-sha1!
`, connName, t.RouterIP)

	confPath := filepath.Join("/etc/ipsec.d", connName+".conf")
	if err := os.MkdirAll("/etc/ipsec.d", 0755); err != nil {
		return err
	}
	if err := os.WriteFile(confPath, []byte(conf), 0600); err != nil {
		return err
	}

	secrets := fmt.Sprintf(`%%any %%any : PSK "%s"
`, t.PSK)

	secretsPath := filepath.Join("/etc/ipsec.d", connName+".secrets")
	return os.WriteFile(secretsPath, []byte(secrets), 0600)
}

func (s *L2TPService) writeXL2TPDConfig(t *tunnel.ResellerTunnel) error {
	conf := fmt.Sprintf(`[global]
port = 1701

[lns %s]
ip range = %s
local ip = %s
require chap = yes
refuse pap = yes
require authentication = yes
name = jinom-vpn
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
`, t.Namespace, stripCIDR(t.ClientIPAddress), stripCIDR(t.ServerIPAddress))

	if err := os.MkdirAll("/etc/xl2tpd", 0755); err != nil {
		return err
	}
	confPath := filepath.Join("/etc/xl2tpd", t.Namespace+".conf")
	return os.WriteFile(confPath, []byte(conf), 0600)
}
