package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorBold   = "\033[1m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
)

// disableColors zera os códigos ANSI
func disableColors() {
	colorReset, colorRed, colorGreen, colorYellow = "", "", "", ""
	colorBlue, colorBold, colorCyan, colorGray = "", "", "", ""
}

func printBanner() {
	fmt.Println(colorBold + colorCyan + `
 ____              _    _
|  _ \ _   _ _ __ | | _| |_
| |_) | | | | '_ \| |/ / __|
|  __/| |_| | | | |   <| |_
|_|    \__,_|_| |_|_|\_\\__|

   LFI / File Inclusion Scanner
` + colorReset)
}

func colorForStatus(code int) string {
	switch {
	case code >= 200 && code < 300:
		return colorGreen
	case code >= 300 && code < 400:
		return colorCyan
	case code == 401 || code == 403:
		return colorYellow
	case code >= 400 && code < 500:
		return colorYellow
	case code >= 500:
		return colorRed
	default:
		return colorReset
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func printResult(r Result, done, total int) {
	progress := fmt.Sprintf("[%d/%d]", done, total)
	if r.Error != nil {
		fmt.Printf("%s %s[ERR]%s %-70s %v\n", progress, colorGray, colorReset, truncate(r.Payload.Value, 70), r.Error)
		return
	}
	statusColor := colorForStatus(r.StatusCode)
	tag := ""
	if r.Confirmed {
		tag = colorBold + colorRed + " <-- LFI CONFIRMADO" + colorReset
	}
	fmt.Printf("%s %s[%3d]%s %-70s %6d bytes  (%s)%s\n",
		progress, statusColor, r.StatusCode, colorReset, truncate(r.Payload.Value, 70), r.Length, r.Payload.Category, tag)
}

type SavedResult struct {
	Payload    string `json:"payload"`
	Category   string `json:"category"`
	StatusCode int    `json:"status_code"`
	Length     int64  `json:"length"`
	Confirmed  bool   `json:"confirmed"`
	URL        string `json:"url"`
	Error      string `json:"error,omitempty"`
}

func saveResults(path string, results []Result) error {
	if strings.HasSuffix(strings.ToLower(path), ".json") {
		return saveJSON(path, results)
	}
	return saveTXT(path, results)
}

func saveJSON(path string, results []Result) error {
	var out []SavedResult
	for _, r := range results {
		sr := SavedResult{
			Payload:    r.Payload.Value,
			Category:   r.Payload.Category,
			StatusCode: r.StatusCode,
			Length:     r.Length,
			Confirmed:  r.Confirmed,
			URL:        r.URL,
		}
		if r.Error != nil {
			sr.Error = r.Error.Error()
		}
		out = append(out, sr)
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func saveTXT(path string, results []Result) error {
	var sb strings.Builder
	for _, r := range results {
		status := "ERR"
		if r.Error == nil {
			status = strconv.Itoa(r.StatusCode)
		}
		confirmed := ""
		if r.Confirmed {
			confirmed = " [CONFIRMADO]"
		}
		sb.WriteString(fmt.Sprintf("[%s] %s (%s) - %d bytes%s\n", status, r.Payload.Value, r.Payload.Category, r.Length, confirmed))
	}
	return os.WriteFile(path, []byte(sb.String()), 0644)
}