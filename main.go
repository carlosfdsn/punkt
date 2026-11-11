package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// headerFlags permite repetir -H várias vezes: -H "Cookie: x" -H "X-Forwarded-For: FUZZ"
type headerFlags map[string]string

func (h headerFlags) String() string { return "" }

func (h *headerFlags) Set(value string) error {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("header inválido, use Nome:Valor -> %s", value)
	}
	if *h == nil {
		*h = make(headerFlags)
	}
	(*h)[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	return nil
}

func main() {
	targetURL := flag.String("u", "", "URL alvo. Use FUZZ onde o payload deve entrar (ex: http://alvo.com/index.php?page=FUZZ)")
	method := flag.String("X", "GET", "Método HTTP (GET, POST)")
	paramName := flag.String("p", "", "Nome do parâmetro GET a injetar, se a URL não tiver FUZZ")
	body := flag.String("b", "", "Corpo da requisição (POST), use FUZZ onde o payload entra")
	cookie := flag.String("c", "", "Cookie a enviar, use FUZZ se quiser injetar no cookie")
	wordlist := flag.String("w", "", "Arquivo de wordlist customizada (um payload por linha). Se vazio, usa a wordlist embutida")
	osTarget := flag.String("os", "all", "SO alvo dos payloads: linux, windows, all")
	level := flag.Int("level", 2, "Nível de profundidade (1=rápido, 2=padrão, 3=agressivo)")
	threads := flag.Int("t", 20, "Número de requisições em paralelo")
	timeoutSec := flag.Int("timeout", 10, "Timeout por requisição em segundos")
	delayMs := flag.Int("delay", 0, "Delay entre requisições (ms), por worker")
	matchCodes := flag.String("mc", "", "Mostrar apenas esses status codes (ex: 200,403). Vazio = mostra tudo")
	filterCodes := flag.String("fc", "", "Ocultar esses status codes (ex: 404,500)")
	outputFile := flag.String("o", "", "Arquivo de saída (.json ou .txt). Se definido, salva automaticamente sem perguntar")
	noSave := flag.Bool("no-save", false, "Não salvar resultado em arquivo e não perguntar")
	insecure := flag.Bool("k", false, "Ignorar verificação de certificado TLS")
	proxy := flag.String("proxy", "", "URL de proxy (ex: http://127.0.0.1:8080)")
	verbose := flag.Bool("v", false, "Mostrar também requisições que não bateram no filtro (ex: erros de rede)")
	noColor := flag.Bool("no-color", false, "Desativa cores no output (recomendado em cmd.exe antigo no Windows)")

	var headers headerFlags
	flag.Var(&headers, "H", "Header customizado 'Nome:Valor' (pode repetir -H várias vezes)")

	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Punkt — scanner de LFI / File Inclusion")
		fmt.Fprintln(os.Stderr, `Uso: punkt -u "http://alvo.com/index.php?page=FUZZ" [opções]`)
		fmt.Fprintln(os.Stderr)
		flag.PrintDefaults()
	}
	flag.Parse()

	if *noColor {
		disableColors()
	}

	if *targetURL == "" {
		fmt.Println(colorRed + "Erro: informe a URL alvo com -u" + colorReset)
		flag.Usage()
		os.Exit(1)
	}

	// aviso se nenhum ponto de injeção foi configurado
	hasFuzz := strings.Contains(*targetURL, "FUZZ") || strings.Contains(*body, "FUZZ") || *paramName != "" || strings.Contains(*cookie, "FUZZ")
	for _, v := range headers {
		if strings.Contains(v, "FUZZ") {
			hasFuzz = true
		}
	}
	if !hasFuzz {
		fmt.Println(colorYellow + "Aviso: nenhum ponto de injeção definido (use FUZZ na URL/corpo/header/cookie, ou -p). O mesmo request será repetido para cada payload." + colorReset)
	}

	printBanner()

	reader := bufio.NewReader(os.Stdin)

	var savePath string
	saveDecidedAtStart := false

	if *outputFile != "" {
		savePath = *outputFile
		saveDecidedAtStart = true
	} else if *noSave {
		saveDecidedAtStart = true
	} else {
		fmt.Print(colorCyan + "Deseja salvar os resultados em um arquivo? (s/N): " + colorReset)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer == "s" || answer == "sim" || answer == "y" || answer == "yes" {
			fmt.Print("Nome do arquivo de saída (ex: resultados.json): ")
			name, _ := reader.ReadString('\n')
			savePath = strings.TrimSpace(name)
			if savePath == "" {
				savePath = "punkt_results.json"
			}
			saveDecidedAtStart = true
		}
	}

	mc := parseCodeList(*matchCodes)
	fc := parseCodeList(*filterCodes)

	payloads := loadPayloads(*wordlist, *osTarget, *level)
	fmt.Printf(colorBlue+"[*] %d payloads carregados. Iniciando scan com %d threads...\n"+colorReset, len(payloads), *threads)
	fmt.Println()

	cfg := ScanConfig{
		BaseURL:   *targetURL,
		Method:    strings.ToUpper(*method),
		ParamName: *paramName,
		Headers:   headers,
		Cookie:    *cookie,
		Body:      *body,
		Timeout:   time.Duration(*timeoutSec) * time.Second,
		Insecure:  *insecure,
		ProxyURL:  *proxy,
		Delay:     time.Duration(*delayMs) * time.Millisecond,
	}

	client, err := buildClient(cfg)
	if err != nil {
		fmt.Println(colorRed + "Erro ao configurar cliente HTTP: " + err.Error() + colorReset)
		os.Exit(1)
	}

	jobs := make(chan Payload, len(payloads))
	resultsCh := make(chan Result, len(payloads))

	var wg sync.WaitGroup
	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				resultsCh <- doRequest(client, cfg, p)
			}
		}()
	}

	for _, p := range payloads {
		jobs <- p
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	var allResults []Result
	confirmedCount := 0
	done := 0
	total := len(payloads)

	for r := range resultsCh {
		done++
		allResults = append(allResults, r)
		if r.Confirmed {
			confirmedCount++
		}
		if shouldShow(r, mc, fc, *verbose) {
			printResult(r, done, total)
		}
	}

	fmt.Println()
	fmt.Printf(colorBold+"[*] Scan finalizado: %d requisições, %d confirmados como vulneráveis.\n"+colorReset, total, confirmedCount)

	sort.Slice(allResults, func(i, j int) bool {
		if allResults[i].Confirmed != allResults[j].Confirmed {
			return allResults[i].Confirmed // confirmados primeiro
		}
		return allResults[i].StatusCode < allResults[j].StatusCode
	})

	if !saveDecidedAtStart {
		fmt.Print(colorCyan + "Deseja salvar os resultados agora? (s/N): " + colorReset)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer == "s" || answer == "sim" || answer == "y" || answer == "yes" {
			fmt.Print("Nome do arquivo de saída (ex: resultados.json): ")
			name, _ := reader.ReadString('\n')
			savePath = strings.TrimSpace(name)
			if savePath == "" {
				savePath = "punkt_results.json"
			}
		}
	}

	if savePath != "" {
		if err := saveResults(savePath, allResults); err != nil {
			fmt.Println(colorRed + "Erro ao salvar: " + err.Error() + colorReset)
		} else {
			fmt.Println(colorGreen + "[+] Resultados salvos em " + savePath + colorReset)
		}
	}
}