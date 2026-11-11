package main

import (
	"strconv"
	"strings"
)

// parseCodeList transforma "200,403, 500" em um set {200:true, 403:true, 500:true}.
func parseCodeList(s string) map[int]bool {
	m := make(map[int]bool)
	if s == "" {
		return m
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err == nil {
			m[n] = true
		}
	}
	return m
}

// --mc (match codes) / --fc (filter/hide codes) do ffuf/nmap.
func shouldShow(r Result, mc, fc map[int]bool, verbose bool) bool {
	if r.Error != nil {
		return verbose
	}
	if len(fc) > 0 && fc[r.StatusCode] {
		return false
	}
	if len(mc) > 0 {
		return mc[r.StatusCode]
	}
	return true
}