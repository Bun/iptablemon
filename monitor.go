package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func rules(table string) (map[string]ChainState, error) {
	var args []string
	if table != "" {
		args = append(args, "-t", table)
	}
	args = append(args, "-L", "-n", "-v", "-x")
	cmd := exec.Command("iptables", args...)
	data, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	return parseTables(strings.Split(string(data), "\n"))
}

func main() {
	table := ""
	if len(os.Args) > 1 {
		table = os.Args[1]
	}

	stats, err := rules(table)
	if err != nil {
		log.Fatal(err)
	}

	for {
		cur, err := rules(table)
		if err != nil {
			log.Fatal(err)
		}

		delta(stats, cur)
		stats = cur
		time.Sleep(2 * time.Second)
	}
}

func delta(left, right map[string]ChainState) {
	for cname, rc := range right {
		lc := left[cname]
		for rule, rrule := range rc {
			lrule := lc[rule]
			dp := rrule.Packets - lrule.Packets
			db := rrule.Bytes - lrule.Bytes
			if dp > 0 || db > 0 {
				log.Printf("%vp %vb | %v %v", dp, db, cname, rule)
			}
		}
	}
}

type (
	RuleState struct {
		Packets uint64 `json:"p"`
		Bytes   uint64 `json:"b"`
	}
	ChainState map[string]RuleState
)

func parseTables(lines []string) (map[string]ChainState, error) {
	chains := make(map[string]ChainState)
	var chain ChainState
	headers := false
	var hv []string
	for _, line := range lines {
		if chain == nil {
			if !strings.HasPrefix(line, "Chain ") {
				return nil, fmt.Errorf("Expected start of chain")
			}
			parts := strings.Split(line, " ")
			chain = make(ChainState)
			chains[parts[1]] = chain
			headers = true
			continue
		} else if len(line) == 0 {
			chain = nil
			continue
		} else if headers {
			headers = false
			hv = splitFields(line, 0)
			if hv[0] != "pkts" || hv[1] != "bytes" {
				return nil, fmt.Errorf("Expected header line")
			}
			continue
		}
		vs := splitFields(line, len(hv))
		rule := strings.Join(vs[2:], " ")
		// TODO: detect if exists, then add
		chain[rule] = RuleState{p(vs[0]), p(vs[1])}
	}
	return chains, nil
}

func p(v string) uint64 {
	n, _ := strconv.ParseUint(v, 10, 64)
	return n
}

func splitFields(line string, max int) (fields []string) {
	start := 0
	started := false
	for i := 0; i < len(line); i++ {
		if line[i] == ' ' {
			if started {
				fields = append(fields, line[start:i])
				started = false
			}
		} else if !started {
			started = true
			start = i
			if max > 0 && len(fields) == max {
				break
			}
		}
	}
	if started {
		fields = append(fields, line[start:])
	}
	return
}
