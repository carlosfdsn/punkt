package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Payload struct {
	Value    string
	Category string
}

// Result é o resultado de uma requisição para um payload.
type Result struct {
	Payload    Payload
	StatusCode int
	Length     int64
	Confirmed  bool
	Error      error
	URL        string
}

// ScanConfig concentra toda a configuração do scan.
type ScanConfig struct {
	BaseURL   string
	Method    string
	ParamName string
	Headers   map[string]string
	Cookie    string
	Body      string
	Timeout   time.Duration
	Insecure  bool
	ProxyURL  string
	Delay     time.Duration
}

func buildClient(cfg ScanConfig) (*http.Client, error) {
	tr := &http.Transport{}
	if cfg.Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	if cfg.ProxyURL != "" {
		proxyURL, err := url.Parse(cfg.ProxyURL)
		if err != nil {
			return nil, err
		}
		tr.Proxy = http.ProxyURL(proxyURL)
	}
	return &http.Client{
		Transport: tr,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func doRequest(client *http.Client, cfg ScanConfig, p Payload) Result {
	res := Result{Payload: p}

	targetURL := cfg.BaseURL
	switch {
	case strings.Contains(targetURL, "FUZZ"):
		targetURL = strings.ReplaceAll(targetURL, "FUZZ", p.Value)
	case cfg.ParamName != "":
		sep := "?"
		if strings.Contains(targetURL, "?") {
			sep = "&"
		}
		targetURL = targetURL + sep + cfg.ParamName + "=" + p.Value
	}
	res.URL = targetURL

	var bodyReader io.Reader
	if cfg.Body != "" {
		bodyStr := strings.ReplaceAll(cfg.Body, "FUZZ", p.Value)
		bodyReader = strings.NewReader(bodyStr)
	}

	req, err := http.NewRequest(cfg.Method, targetURL, bodyReader)
	if err != nil {
		res.Error = err
		return res
	}

	for k, v := range cfg.Headers {
		req.Header.Set(k, strings.ReplaceAll(v, "FUZZ", p.Value))
	}
	if cfg.Cookie != "" {
		req.Header.Set("Cookie", strings.ReplaceAll(cfg.Cookie, "FUZZ", p.Value))
	}
	if cfg.Body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	if cfg.Delay > 0 {
		time.Sleep(cfg.Delay)
	}

	resp, err := client.Do(req)
	if err != nil {
		res.Error = err
		return res
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // limite de 2MB por resposta
	res.StatusCode = resp.StatusCode
	res.Length = int64(len(bodyBytes))
	res.Confirmed = detectSuccess(p.Category, bodyBytes)

	return res
}