package main

import (
	"bytes"
	"encoding/base64"
	"regexp"
)

var (
	reLinuxPasswd = regexp.MustCompile(`root:.*?:0:0:`)
	reLinuxShadow = regexp.MustCompile(`root:\$[0-9a-z]\$`)
	reWindowsIni  = regexp.MustCompile(`\[(fonts|extensions|mci extensions)\]`)
	reWindowsBoot = regexp.MustCompile(`\[boot loader\]`)
)

func detectSuccess(category string, body []byte) bool {
	switch category {
	case "linux":
		if reLinuxPasswd.Match(body) || reLinuxShadow.Match(body) {
			return true
		}
	case "windows":
		if reWindowsIni.Match(body) || reWindowsBoot.Match(body) {
			return true
		}
	case "php_wrapper":
		trimmed := bytes.TrimSpace(body)
		if len(trimmed) > 10 {
			decoded, err := base64.StdEncoding.DecodeString(string(trimmed))
			if err == nil && (bytes.Contains(decoded, []byte("<?php")) || bytes.Contains(decoded, []byte("<html"))) {
				return true
			}
		}
		if bytes.Contains(body, []byte("<?php")) {
			return true
		}
	}
	return false
}