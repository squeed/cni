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

	"github.com/coreos/go-iptables/iptables"
)

type chain struct {
	name        string
	entryRule   []string // the rule that enters this chain
	entryChains []string // the chains to add the entry rule
}

func (c *chain) setup(ipt *iptables.IPTables, rules [][]string) error {
	// Create the chain and add its rules
	if err := ipt.NewChain("nat", c.name); err != nil {
		return err
	}
	for _, rule := range rules {
		if err := ipt.AppendUnique("nat", c.name, rule...); err != nil {
			return err
		}
	}

	// create the entry rules
	for _, entryChain := range c.entryChains {
		if err := prependUnique(ipt, "nat", entryChain, c.entryRule); err != nil {
			return err
		}
	}

	return nil
}

// teardown will delete a chain and all of its entry rules. This will not
// error if the chain does not exist.
func (c *chain) teardown(ipt *iptables.IPTables) error {
	// flush the chain
	// This will succeed *and create the chain* if it does not exist.
	// If the chain doesn't exist, the next checks will fail.
	if err := ipt.ClearChain("nat", c.name); err != nil {
		return err
	}

	for _, entryChain := range c.entryChains {
		exists, err := ipt.Exists("nat", entryChain, c.entryRule...)
		if err != nil {
			return fmt.Errorf("could not check if chain %s has entry rule: %v", entryChain, err)
		}
		if exists {
			if err := ipt.Delete("nat", entryChain, c.entryRule...); err != nil {
				return err
			}
		}
	}

	if err := ipt.DeleteChain("nat", c.name); err != nil {
		return err
	}
	return nil
}

// prependUnique will prepend a rule to a chain, if it does not already exist
func prependUnique(ipt *iptables.IPTables, table, chain string, rule []string) error {
	exists, err := ipt.Exists(table, chain, rule...)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	return ipt.Insert(table, chain, 1, rule...)
}
