package app

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/miekg/dns"
	"github.com/moolen/nie/internal/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const resolvConfPath = "/etc/resolv.conf"

type resolvedRuntimeConfig struct {
	Interface string
	Upstreams []string
}

type routeDetector interface {
	DefaultRouteInterfaces(context.Context) ([]string, error)
}

type resolvConfReader interface {
	ReadResolvConf() ([]byte, error)
}

type resolverDeps struct {
	routeDetector    routeDetector
	resolvConfReader resolvConfReader
}

func resolveRuntimeConfig(ctx context.Context, cfg config.Config, deps resolverDeps) (resolvedRuntimeConfig, error) {
	resolved := resolvedRuntimeConfig{}

	iface, err := resolveInterface(ctx, cfg, deps.routeDetector)
	if err != nil {
		return resolved, err
	}
	resolved.Interface = iface

	upstreams, err := resolveDNSUpstreams(cfg, deps.resolvConfReader)
	if err != nil {
		return resolved, err
	}
	resolved.Upstreams = upstreams

	return resolved, nil
}

func resolveInterface(ctx context.Context, cfg config.Config, detector routeDetector) (string, error) {
	switch cfg.Interface.Mode {
	case "explicit":
		return cfg.Interface.Name, nil
	case "auto":
		if detector == nil {
			detector = defaultRouteDetector{}
		}
		ifaces, err := detector.DefaultRouteInterfaces(ctx)
		if err != nil {
			return "", fmt.Errorf("resolve interface: %w", err)
		}
		unique := orderedUniqueStrings(ifaces)
		switch len(unique) {
		case 0:
			return "", fmt.Errorf("resolve interface: no IPv4 default route found")
		case 1:
			return unique[0], nil
		default:
			sorted := append([]string(nil), unique...)
			sort.Strings(sorted)
			return "", fmt.Errorf("resolve interface: auto-detect found multiple default-route interfaces: %s", strings.Join(sorted, ", "))
		}
	default:
		return "", fmt.Errorf("resolve interface: unsupported interface mode %q", cfg.Interface.Mode)
	}
}

func resolveDNSUpstreams(cfg config.Config, reader resolvConfReader) ([]string, error) {
	switch cfg.DNS.Upstreams.Mode {
	case "explicit":
		return append([]string(nil), cfg.DNS.Upstreams.Addresses...), nil
	case "auto":
		if reader == nil {
			reader = osResolvConfReader{path: resolvConfPath}
		}
		raw, err := reader.ReadResolvConf()
		if err != nil {
			return nil, fmt.Errorf("resolve dns.upstreams: read %s: %w", resolvConfPath, err)
		}
		clientConfig, err := dns.ClientConfigFromReader(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("resolve dns.upstreams: parse %s: %w", resolvConfPath, err)
		}
		upstreams := make([]string, 0, len(clientConfig.Servers))
		seen := make(map[string]struct{}, len(clientConfig.Servers))
		for _, server := range clientConfig.Servers {
			ip := net.ParseIP(strings.TrimSpace(server))
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.To4() == nil {
				continue
			}
			addr := net.JoinHostPort(ip.String(), "53")
			if _, ok := seen[addr]; ok {
				continue
			}
			seen[addr] = struct{}{}
			upstreams = append(upstreams, addr)
		}
		if len(upstreams) == 0 {
			return nil, fmt.Errorf("resolve dns.upstreams: no usable IPv4 nameservers found in %s", resolvConfPath)
		}
		return upstreams, nil
	default:
		return nil, fmt.Errorf("resolve dns.upstreams: unsupported dns.upstreams mode %q", cfg.DNS.Upstreams.Mode)
	}
}

type defaultRouteDetector struct {
	listRoutes  func(netlink.Link, int) ([]netlink.Route, error)
	linkByIndex func(int) (netlink.Link, error)
}

func (d defaultRouteDetector) DefaultRouteInterfaces(_ context.Context) ([]string, error) {
	listRoutes := d.listRoutes
	if listRoutes == nil {
		listRoutes = netlink.RouteList
	}
	linkByIndex := d.linkByIndex
	if linkByIndex == nil {
		linkByIndex = netlink.LinkByIndex
	}

	routes, err := listRoutes(nil, unix.AF_INET)
	if err != nil {
		return nil, err
	}
	ifaces := make([]string, 0, len(routes))
	for _, route := range routes {
		if route.Dst != nil {
			continue
		}
		if route.LinkIndex > 0 {
			name, err := routeLinkName(linkByIndex, route.LinkIndex)
			if err != nil {
				return nil, err
			}
			ifaces = append(ifaces, name)
		}
		for _, hop := range route.MultiPath {
			if hop == nil || hop.LinkIndex <= 0 {
				continue
			}
			name, err := routeLinkName(linkByIndex, hop.LinkIndex)
			if err != nil {
				return nil, err
			}
			ifaces = append(ifaces, name)
		}
	}
	return ifaces, nil
}

func routeLinkName(linkByIndex func(int) (netlink.Link, error), index int) (string, error) {
	link, err := linkByIndex(index)
	if err != nil {
		return "", fmt.Errorf("lookup route link index %d: %w", index, err)
	}
	if link == nil || link.Attrs() == nil || link.Attrs().Name == "" {
		return "", fmt.Errorf("lookup route link index %d: missing interface name", index)
	}
	return link.Attrs().Name, nil
}

type osResolvConfReader struct {
	path string
}

func (r osResolvConfReader) ReadResolvConf() ([]byte, error) {
	return os.ReadFile(r.path)
}

func orderedUniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
