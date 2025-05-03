package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/blang/semver"
	"github.com/google/go-github/v53/github"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/robfig/cron/v3"
	"golang.org/x/oauth2"
)

// Version injected at build time
var Version = "dev"

// default constants
const (
	DefaultUpdateInterval = 24 * time.Hour
	HeartbeatInterval     = 30 * time.Second
	certDir               = "/etc/edge-agent/certs"
	metricsAddr           = ":9090"
)

var (
	certPath = filepath.Join(certDir, "client.crt")
	keyPath  = filepath.Join(certDir, "client.key")
	caPath   = filepath.Join(certDir, "ca.crt")
)

// Prometheus metrics
var (
	heartbeatsSent = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "heartbeats_sent_total",
		Help: "Total heartbeats sent.",
	})
	fetchSuccess = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "workflows_fetch_success_total",
		Help: "Successful workflow fetches.",
	})
	fetchErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "workflows_fetch_errors_total",
		Help: "Errors during workflow fetch.",
	})
	jobsScheduled = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "jobs_scheduled",
		Help: "Current number of jobs scheduled.",
	})
)

func init() {
	prometheus.MustRegister(heartbeatsSent, fetchSuccess, fetchErrors, jobsScheduled)
}

// Heartbeat payload
type Heartbeat struct {
	DeviceID string    `json:"device_id"`
	Ts       time.Time `json:"ts"`
}

// registerResp is what /register returns
type registerResp struct {
	CertPem string `json:"cert_pem"`
	CaPem   string `json:"ca_pem"`
}

// Workflow represents a device workflow
type Workflow struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Definition struct {
		Steps []struct {
			Cmd string `json:"cmd"`
		} `json:"steps"`
	} `json:"definition"`
	Schedule   string  `json:"schedule"`
	Recurrence *string `json:"recurrence"` // pointer to allow null
}

// newTLSClient returns an HTTP client configured for (m)TLS
func newTLSClient(loadCA bool) *http.Client {
	cfg := &tls.Config{}
	if loadCA {
		if caPem, err := os.ReadFile(caPath); err == nil {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(caPem)
			cfg.RootCAs = pool
		}
	}
	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		cfg.Certificates = []tls.Certificate{cert}
	}
	cfg.InsecureSkipVerify = cfg.RootCAs == nil
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: cfg},
		Timeout:   5 * time.Second,
	}
}

// selfUpdateLoop periodically checks GitHub for a newer release
func selfUpdateLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		if err := tryUpdate(); err != nil {
			log.Printf("self-update failed: %v", err)
		}
	}
}

// tryUpdate fetches the latest GitHub release, verifies checksum, and swaps the binary
func tryUpdate() error {
	owner := os.Getenv("GITHUB_OWNER")
	repo := os.Getenv("GITHUB_REPO")
	token := os.Getenv("GITHUB_TOKEN")
	if owner == "" || repo == "" || token == "" {
		return nil
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	release, ghResp, err := client.Repositories.GetLatestRelease(ctx, owner, repo)
	if err != nil {
		if ghResp != nil && ghResp.StatusCode == http.StatusNotFound {
			return nil
		}
		return fmt.Errorf("fetch latest release: %w", err)
	}

	latestTag := release.GetTagName()
	currTag := Version

	latestV, err1 := semver.ParseTolerant(latestTag)
	currV, err2 := semver.ParseTolerant(currTag)
	if err1 == nil && err2 == nil {
		if !latestV.GT(currV) {
			return nil
		}
	} else if latestTag == currTag {
		return nil
	}

	execPath, err := os.Executable()
	if err != nil {
		return err
	}
	binName := filepath.Base(execPath)
	assetName := fmt.Sprintf("%s-%s-%s-%s", binName, runtime.GOOS, runtime.GOARCH, latestTag)
	checksumName := assetName + ".sha256"

	var assetURL, checksumURL string
	for _, a := range release.Assets {
		switch a.GetName() {
		case assetName:
			assetURL = a.GetBrowserDownloadURL()
		case checksumName:
			checksumURL = a.GetBrowserDownloadURL()
		}
	}
	if assetURL == "" || checksumURL == "" {
		return fmt.Errorf("assets %q or %q not found", assetName, checksumName)
	}

	sumResp, err := http.Get(checksumURL)
	if err != nil {
		return fmt.Errorf("download checksum: %w", err)
	}
	defer sumResp.Body.Close()
	raw, err := io.ReadAll(sumResp.Body)
	if err != nil {
		return fmt.Errorf("read checksum: %w", err)
	}
	expected := strings.Fields(string(raw))[0]

	binResp, err := http.Get(assetURL)
	if err != nil {
		return fmt.Errorf("download asset: %w", err)
	}
	defer binResp.Body.Close()

	tmp, err := os.CreateTemp("", assetName)
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, binResp.Body); err != nil {
		return fmt.Errorf("save asset: %w", err)
	}
	if err := tmp.Chmod(0o755); err != nil {
		return err
	}

	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek asset: %w", err)
	}
	data, err := io.ReadAll(tmp)
	if err != nil {
		return fmt.Errorf("read asset: %w", err)
	}
	sum := sha256.Sum256(data)
	actual := hex.EncodeToString(sum[:])
	if actual != expected {
		return fmt.Errorf("checksum mismatch: got %s want %s", actual, expected)
	}

	if err := os.Rename(tmp.Name(), execPath); err != nil {
		return fmt.Errorf("replace binary: %w", err)
	}
	log.Printf("self-update: %s → %s; exiting", currTag, latestTag)
	os.Exit(0)
	return nil
}

// enroll generates key, CSR, and calls /register
func enroll(ctx context.Context, deviceID, regURL, token string) error {
	if _, err := os.Stat(certPath); err == nil {
		return nil
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return fmt.Errorf("mkdir certDir: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPem, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: deviceID},
	}, key)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}
	csrPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	payload := map[string]string{"device_id": deviceID, "csr_pem": string(csrPem)}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", regURL+"/register", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Register-Token", token)
	}
	resp, err := newTLSClient(false).Do(req)
	if err != nil {
		return fmt.Errorf("register request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("register failed: status %d", resp.StatusCode)
	}
	var out registerResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("decode register response: %w", err)
	}
	if err := os.WriteFile(certPath, []byte(out.CertPem), 0o644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(caPath, []byte(out.CaPem), 0o644); err != nil {
		return fmt.Errorf("write CA: %w", err)
	}
	log.Print("enrolment succeeded")
	return nil
}

// sendHeartbeat posts a heartbeat and updates metric
func sendHeartbeat(ctx context.Context, api, id string) error {
	hb := Heartbeat{DeviceID: id, Ts: time.Now().UTC()}
	body, _ := json.Marshal(hb)
	req, _ := http.NewRequestWithContext(ctx, "POST", api+"/heartbeat", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if _, err := newTLSClient(true).Do(req); err != nil {
		return err
	}
	heartbeatsSent.Inc()
	return nil
}

// fetchWorkflows retrieves workflows, logs metrics
func fetchWorkflows(ctx context.Context, api, device, token string) ([]Workflow, error) {
	url := fmt.Sprintf("%s/devices/%s/workflows", api, device)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		fetchErrors.Inc()
		return nil, err
	}
	if token != "" {
		req.Header.Set("X-Register-Token", token)
	}
	resp, err := newTLSClient(true).Do(req)
	if err != nil {
		fetchErrors.Inc()
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fetchErrors.Inc()
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var wfs []Workflow
	if err := json.NewDecoder(resp.Body).Decode(&wfs); err != nil {
		fetchErrors.Inc()
		return nil, err
	}
	fetchSuccess.Inc()
	return wfs, nil
}

// runWorkflow executes each step
func runWorkflow(w Workflow) {
	log.Printf("▶ running workflow %d: %s", w.ID, w.Name)
	for _, step := range w.Definition.Steps {
		log.Printf("  • exec: %s", step.Cmd)
		if out, err := exec.Command("sh", "-c", step.Cmd).CombinedOutput(); err != nil {
			log.Printf("    ✗ %v\n%s", err, out)
		} else {
			log.Printf("    ✓ %s", out)
		}
	}
}

// syncJobs reconciles cron entries under mutex
func syncJobs(wfs []Workflow, c *cron.Cron, entryIDs map[int]cron.EntryID, schedules map[int]string, mu *sync.Mutex) {
	mu.Lock()
	defer mu.Unlock()

	active := make(map[int]bool)
	for _, wf := range wfs {
		active[wf.ID] = true

		spec := wf.Schedule
		if wf.Recurrence != nil && *wf.Recurrence != "" {
			if p, err := parseRecurrence(*wf.Recurrence); err == nil {
				spec = p
			} else {
				log.Printf("invalid recurrence for %d: %v", wf.ID, err)
			}
		}

		if spec == "" {
			if id, ok := entryIDs[wf.ID]; ok {
				c.Remove(id)
				delete(entryIDs, wf.ID)
				delete(schedules, wf.ID)
			}
			continue
		}
		if old, ok := schedules[wf.ID]; ok && old == spec {
			continue
		}
		if id, ok := entryIDs[wf.ID]; ok {
			c.Remove(id)
		}
		wfc := wf
		id, err := c.AddFunc(spec, func() { runWorkflow(wfc) })
		if err != nil {
			log.Printf("bad spec for %d: %v", wf.ID, err)
			continue
		}
		entryIDs[wf.ID], schedules[wf.ID] = id, spec
	}

	for id, eid := range entryIDs {
		if !active[id] {
			c.Remove(eid)
			delete(entryIDs, id)
			delete(schedules, id)
		}
	}

	jobsScheduled.Set(float64(len(entryIDs)))
}

// parseRecurrence supports human phrases
func parseRecurrence(r string) (string, error) {
	r = strings.ToLower(strings.TrimSpace(r))
	switch {
	case r == "hourly":
		return "0 * * * *", nil
	case strings.HasPrefix(r, "daily at "):
		parts := strings.SplitN(strings.TrimPrefix(r, "daily at "), ":", 2)
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid time: %s", r)
		}
		return fmt.Sprintf("%s %s * * *", parts[1], parts[0]), nil
	case strings.HasPrefix(r, "weekly on "):
		parts := strings.SplitN(strings.TrimPrefix(r, "weekly on "), " at ", 2)
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid format: %s", r)
		}
		day := strings.ToLower(parts[0][:3])
		dow := map[string]string{"sun": "0", "mon": "1", "tue": "2", "wed": "3", "thu": "4", "fri": "5", "sat": "6"}[day]
		tp := strings.SplitN(parts[1], ":", 2)
		if len(tp) != 2 {
			return "", fmt.Errorf("invalid time: %s", parts[1])
		}
		return fmt.Sprintf("%s %s * * %s", tp[1], tp[0], dow), nil
	default:
		return "", fmt.Errorf("unsupported recurrence: %s", r)
	}
}

func main() {
	// graceful shutdown
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVer {
		fmt.Println(Version)
		return
	}

	// metrics & health
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	go func() {
		log.Printf("metrics/health listening on %s", metricsAddr)
		log.Fatal(http.ListenAndServe(metricsAddr, nil))
	}()

	// conditional self-update
	updateInterval := DefaultUpdateInterval
	if s := os.Getenv("UPDATE_INTERVAL"); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			updateInterval = d
		}
	}
	if os.Getenv("GITHUB_OWNER") != "" && os.Getenv("GITHUB_REPO") != "" && os.Getenv("GITHUB_TOKEN") != "" {
		go selfUpdateLoop(updateInterval)
	}

	// enrollment
	apiURL := getenv("API_URL", "https://localhost:8443")
	regURL := getenv("REGISTER_URL", "https://localhost:8444")
	token := os.Getenv("REGISTER_TOKEN")
	device := getenv("DEVICE_ID", hostname())
	if err := enroll(ctx, device, regURL, token); err != nil {
		log.Fatalf("enroll failed: %v", err)
	}

	// cron scheduler
	parser := cron.NewParser(
		// allow optional seconds (for "@every 20s"), standard 5 fields, and descriptors like "@every"
		cron.SecondOptional |
			cron.Minute |
			cron.Hour |
			cron.Dom |
			cron.Month |
			cron.Dow |
			cron.Descriptor,
	)
	c := cron.New(cron.WithParser(parser))
	c.Start()
	defer c.Stop()

	entryIDs := make(map[int]cron.EntryID)
	schedules := make(map[int]string)
	var mu sync.Mutex

	ticker := time.NewTicker(HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("shutting down")
			return
		case <-ticker.C:
			if err := sendHeartbeat(ctx, apiURL, device); err != nil {
				log.Printf("heartbeat error: %v", err)
			}
			wfs, err := fetchWorkflows(ctx, apiURL, device, token)
			if err != nil {
				log.Printf("fetch error: %v", err)
			} else {
				syncJobs(wfs, c, entryIDs, schedules, &mu)
			}
		}
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}
