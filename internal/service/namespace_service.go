package service

import (
	"fmt"
	"os/exec"

	"go.uber.org/zap"
)

type NamespaceService struct {
	log *zap.Logger
}

func NewNamespaceService(log *zap.Logger) *NamespaceService {
	return &NamespaceService{log: log}
}

func (s *NamespaceService) Create(ns string) error {
	s.log.Info("Creating network namespace", zap.String("namespace", ns))

	if err := run("ip", "netns", "add", ns); err != nil {
		return fmt.Errorf("create namespace %s: %w", ns, err)
	}

	if err := run("ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"); err != nil {
		s.log.Warn("Failed to bring up loopback in namespace", zap.String("ns", ns), zap.Error(err))
	}

	if err := run("ip", "netns", "exec", ns,
		"sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		s.log.Warn("Failed to enable ip_forward in namespace", zap.String("ns", ns), zap.Error(err))
	}

	return nil
}

func (s *NamespaceService) Delete(ns string) error {
	s.log.Info("Deleting network namespace", zap.String("namespace", ns))
	if err := run("ip", "netns", "del", ns); err != nil {
		return fmt.Errorf("delete namespace %s: %w", ns, err)
	}
	return nil
}

func (s *NamespaceService) Exists(ns string) bool {
	err := run("ip", "netns", "exec", ns, "true")
	return err == nil
}

func (s *NamespaceService) ExecInNS(ns string, name string, args ...string) ([]byte, error) {
	cmdArgs := append([]string{"netns", "exec", ns, name}, args...)
	out, err := exec.Command("ip", cmdArgs...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("exec in %s: %s: %w", ns, string(out), err)
	}
	return out, nil
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", string(out), err)
	}
	return nil
}
