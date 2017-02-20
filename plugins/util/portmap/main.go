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

// This is a post-setup plugin that establishes port forwarding - using iptables,
// from the host's network interface(s) to a pod's network interface.
//
// It is intended to be used as a chained CNI plugin, and determines the container
// IP from the previous result. If the result includes an IPv6 address, it will
// also be configured. (IPTables will not forward cross-family).
//
// This has one notable limitation: it does not perform any kind of reservation
// of the actual host port. If there is a service on the host, it will have all
// its traffic captured by the container. If another container also claims a given
// port, it will caputure the traffic - it is last-write-wins.
package main

import (
	"encoding/json"
	"fmt"

	"github.com/containernetworking/cni/pkg/skel"
	types "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
)

// PortMapEntry corresponds to a single entry in the port_mappings argument,
// see CONVENTIONS.md
type PortMapEntry struct {
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
	Protocol      string `json:"protocol"`
}

type PortMapConf struct {
	types.NetConf
	NoSNAT        *bool `json:"no_snat,omitempty"`
	RuntimeConfig struct {
		PortMaps []PortMapEntry `json:"port_mappings,omitempty"`
	} `json:"runtime_config,omitempty"`
	PrevResult  *current.Result `json:"prevResult,omitempty"`
	ContainerID string
}

func cmdAdd(args *skel.CmdArgs) error {
	netConf := PortMapConf{}
	if err := json.Unmarshal(args.StdinData, &netConf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	if netConf.PrevResult == nil {
		return fmt.Errorf("must be called as plugin but prevResult empty")
	}

	enableSNAT := (netConf.NoSNAT == nil || *netConf.NoSNAT)

	netConf.ContainerID = args.ContainerID

	// Loop through IPs, setting up forwarding to the first reasonable IP per family
	hasV4 := false
	hasV6 := false
	for _, ip := range netConf.PrevResult.IPs {
		if ip.Version == "6" && hasV6 {
			continue
		} else if ip.Version == "4" && hasV4 {
			continue
		}

		addr := ip.Address.IP
		if addr.IsLoopback() {
			continue
		}

		if err := forwardPorts(&netConf, addr, enableSNAT); err != nil {
			return err
		}

		if ip.Version == "6" {
			hasV6 = true
		} else {
			hasV4 = true
		}
	}

	// Pass through the previous result
	return types.PrintResult(netConf.PrevResult, netConf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	netConf := PortMapConf{}
	if err := json.Unmarshal(args.StdinData, &netConf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}
	netConf.ContainerID = args.ContainerID

	// We don't need to parse out whether or not we're using v6 or snat,
	// deletion is idempotent
	if err := unforwardPorts(&netConf); err != nil {
		return err
	}
	return nil
}

func main() {
	// TODO: bump when 0.5.0 is released
	skel.PluginMain(cmdAdd, cmdDel, version.PluginSupports(version.Current()))
}
