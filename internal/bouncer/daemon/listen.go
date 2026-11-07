package daemon

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

const (
	envAgentNetwork      = "AGENT_NETWORK"
	envManagementNetwork = "MANAGEMENT_NETWORK"
	envManagementPort    = "MANAGEMENT_PORT"
)

type listenPlan struct {
	proxy string
	ssh   string
	mgmt  string
	split bool
}

func planListen(cfg *config.Config) (listenPlan, error) {
	agentCIDR := os.Getenv(envAgentNetwork)
	mgmtCIDR := os.Getenv(envManagementNetwork)
	if agentCIDR == "" && mgmtCIDR == "" {
		return listenPlan{proxy: cfg.Listen, ssh: cfg.SSHListen, mgmt: cfg.Listen}, nil
	}
	if agentCIDR == "" || mgmtCIDR == "" {
		return listenPlan{}, fmt.Errorf("both %s and %s must be set", envAgentNetwork, envManagementNetwork)
	}

	agentIP, err := ipInCIDR(agentCIDR)
	if err != nil {
		return listenPlan{}, fmt.Errorf("%s: %w", envAgentNetwork, err)
	}
	mgmtIP, err := ipInCIDR(mgmtCIDR)
	if err != nil {
		return listenPlan{}, fmt.Errorf("%s: %w", envManagementNetwork, err)
	}

	_, proxyPort := config.SplitHostPort(cfg.Listen)
	if proxyPort == "" {
		proxyPort = "8228"
	}
	_, sshPort := config.SplitHostPort(cfg.SSHListen)
	if sshPort == "" {
		sshPort = "8229"
	}
	mgmtPort := os.Getenv(envManagementPort)
	if mgmtPort == "" {
		mgmtPort = proxyPort
	}
	if _, err := strconv.Atoi(mgmtPort); err != nil {
		return listenPlan{}, fmt.Errorf("%s: invalid port %q", envManagementPort, mgmtPort)
	}

	return listenPlan{
		proxy: net.JoinHostPort(agentIP, proxyPort),
		ssh:   net.JoinHostPort(agentIP, sshPort),
		mgmt:  net.JoinHostPort(mgmtIP, mgmtPort),
		split: true,
	}, nil
}

func ipInCIDR(cidr string) (string, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("parse cidr: %w", err)
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", fmt.Errorf("list addresses: %w", err)
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		ip := ipnet.IP.To4()
		if ip == nil {
			ip = ipnet.IP
		}
		if network.Contains(ip) {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("no local address in %s", cidr)
}
