// Copyright 2017 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"strconv"

	"github.com/containernetworking/cni/pkg/utils"
	"github.com/coreos/go-iptables/iptables"
)

// forwardPorts creates iptables rules to forward traffic from ports on
// If enableSNAT is set, it also creates a masquerading chain that rewrites
// connections to localhost:<port> so they also work.
func forwardPorts(config *PortMapConf, containerIP net.IP, enableSNAT bool) error {
	isV6 := (containerIP.To4() == nil)

	var ipt *iptables.IPTables
	var err error

	if isV6 {
		ipt, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
	} else {
		ipt, err = iptables.NewWithProtocol(iptables.ProtocolIPv4)
	}
	if err != nil {
		return fmt.Errorf("failed to open iptables:", err)
	}

	dnatChain := genDnatChain(config.Name, config.ContainerID)
	dnatRules := dnatRules(config.RuntimeConfig.PortMaps, containerIP)
	if err := dnatChain.setup(ipt, dnatRules); err != nil {
		return fmt.Errorf("unable to setup DNAT", err)
	}

	if enableSNAT {
		snatChain := genSnatChain(config.Name, config.ContainerID, isV6)
		snatRules := snatRules(config.RuntimeConfig.PortMaps, containerIP)
		if err := snatChain.setup(ipt, snatRules); err != nil {
			return fmt.Errorf("unable to setup SNAT", err)
		}
		if !isV6 {
			if err := enableLocalnetRouting(); err != nil {
				return fmt.Errorf("unable to enable route_localnet: %v", err)
			}
		}
	}

	return nil
}

func genDnatChain(netName, containerID string) chain {
	name := utils.FormatChainName("DN-", netName, containerID)
	comment := fmt.Sprintf(`dnat name: "%s" id: "%s"`, netName, containerID)

	return chain{
		name: name,
		entryRule: []string{
			"-m", "addrtype",
			"--dst-type", "LOCAL",
			"-m", "comment",
			"--comment", comment,
			"-j", name},
		entryChains: []string{"PREROUTING", "OUTPUT"},
	}
}

// dnatRules generates the destination NAT rules, one per port, to direct
// traffic from hostip:hostport to podip:podport
func dnatRules(entries []PortMapEntry, containerIP net.IP) [][]string {
	out := make([][]string, 0, len(entries))
	for _, entry := range entries {
		out = append(out, []string{
			"-p", entry.Protocol,
			"--dport", strconv.Itoa(entry.HostPort),
			"-j", "DNAT", "--to-destination",
			fmt.Sprintf("%s:%d", containerIP.String(), entry.ContainerPort),
		})
	}
	return out
}
func genSnatChain(netName, containerID string, isV6 bool) chain {
	name := utils.FormatChainName("SN-", netName, containerID)
	comment := fmt.Sprintf(`snat name: "%s" id: "%s"`, netName, containerID)

	if isV6 {
		return chain{
			name: name,
			entryRule: []string{
				"-s", "::1",
				"!", "-d", "::1",
				"-m", "comment",
				"--comment", comment,
				"-j", name},
			entryChains: []string{"POSTROUTING"},
		}
	} else {
		return chain{
			name: name,
			entryRule: []string{
				"-s", "127.0.0.1",
				"!", "-d", "127.0.0.1",
				"-m", "comment",
				"--comment", comment,
				"-j", name},
			entryChains: []string{"POSTROUTING"},
		}
	}
}

// snatRules sets up masquerading for connections to localhost:hostport,
// rewriting the source so that returning packets are correct.
func snatRules(entries []PortMapEntry, containerIP net.IP) [][]string {
	isV6 := (containerIP.To4() == nil)
	var localhostIP string
	if isV6 {
		localhostIP = "::1"
	} else {
		localhostIP = "127.0.0.1"
	}
	out := make([][]string, 0, len(entries))
	for _, entry := range entries {
		out = append(out, []string{
			"-p", entry.Protocol,
			"-s", localhostIP,
			"-d", containerIP.String(),
			"--dport", strconv.Itoa(entry.ContainerPort),
			"-j", "MASQUERADE",
		})
	}
	return out
}

// enableLocalnetRouting tells the kernel not to treat 127/8 as a martian,
// so that connections to 127.0.0.1:PORT will be forwarded
func enableLocalnetRouting() error {
	routeLocalnetPath := "/proc/sys/net/ipv4/conf/all/route_localnet"
	currValue, err := ioutil.ReadFile(routeLocalnetPath)
	if err != nil {
		return err
	}

	if string(currValue) != "1" {
		if err := ioutil.WriteFile(routeLocalnetPath, []byte("1"), 0); err != nil {
			return err
		}
	}
	return nil
}

// unforwardPorts deletes any iptables rules created by this plugin.
// It should be idempotent - it will not error if the chain does not exist.
func unforwardPorts(config *PortMapConf) error {
	// Teardown v4
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}
	dnatChain := genDnatChain(config.Name, config.ContainerID)
	if err := dnatChain.teardown(ipt); err != nil {
		return fmt.Errorf("could not teardown ipv4 dnat: %v", err)
	}
	snatChain := genSnatChain(config.Name, config.ContainerID, false)
	if err := snatChain.teardown(ipt); err != nil {
		return fmt.Errorf("could not teardown ipv4 snat: %v", err)
	}

	ip6t, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		return err
	}

	if err := dnatChain.teardown(ip6t); err != nil {
		return fmt.Errorf("could not teardown ipv6 dnat: %v", err)
	}
	snatChain = genSnatChain(config.Name, config.ContainerID, true)
	if err := snatChain.teardown(ip6t); err != nil {
		return fmt.Errorf("could not teardown ipv6 snat: %v", err)
	}
	return nil
}
