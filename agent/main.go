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
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/blang/semver"
	"github.com/google/go-github/v53/github"
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
)

var (
	certPath = filepath.Join(certDir, "client.crt")
	keyPath  = filepath.Join(certDir, "client.key")
	caPath   = filepath.Join(certDir, "ca.crt")
)

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

	// if any are missing, skip self-update
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

	// SemVer comparison
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
	osName := runtime.GOOS
	arch := runtime.GOARCH
	assetName := fmt.Sprintf("%s-%s-%s-%s", binName, osName, arch, latestTag)
	checksumName := assetName + ".sha256"

	var assetURL, checksumURL string
	for _, asset := range release.Assets {
		switch asset.GetName() {
		case assetName:
			assetURL = asset.GetBrowserDownloadURL()
		case checksumName:
			checksumURL = asset.GetBrowserDownloadURL()
		}
	}
	if assetURL == "" || checksumURL == "" {
		return fmt.Errorf("assets %q or %q not found", assetName, checksumName)
	}

	// download & verify checksum
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

	// download binary
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

	// checksum verify
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek asset: %w", err)
	}
	data, err := io.ReadAll(tmp)
	if err != nil {
		return fmt.Errorf("read asset: %w", err)
	}
	digest := sha256.Sum256(data)
	actual := hex.EncodeToString(digest[:])
	if actual != expected {
		return fmt.Errorf("checksum mismatch: got %s want %s", actual, expected)
	}

	// atomic swap & restart
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

// sendHeartbeat posts a heartbeat
func sendHeartbeat(ctx context.Context, api, id string) error {
	hb := Heartbeat{DeviceID: id, Ts: time.Now().UTC()}
	body, _ := json.Marshal(hb)
	req, _ := http.NewRequestWithContext(ctx, "POST", api+"/heartbeat", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := newTLSClient(true).Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// fetchWorkflows retrieves pending workflows using the register token
func fetchWorkflows(ctx context.Context, api, device, token string) ([]Workflow, error) {
	url := fmt.Sprintf("%s/devices/%s/workflows", api, device)
	log.Printf("[agent] fetching workflows: url=%q token=%q", url, token)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("X-Register-Token", token)
	}

	client := newTLSClient(true)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[agent] HTTP error: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	log.Printf("[agent] workflows HTTP status: %d", resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	log.Printf("[agent] workflows raw body: %s", body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch workflows: %s", resp.Status)
	}

	var wfs []Workflow
	if err := json.Unmarshal(body, &wfs); err != nil {
		return nil, err
	}
	log.Printf("[agent] parsed %d workflows", len(wfs))
	return wfs, nil
}

// runWorkflow executes each step locally
func runWorkflow(w Workflow) {
	log.Printf("▶ running workflow %d: %s", w.ID, w.Name)
	for _, step := range w.Definition.Steps {
		log.Printf("  • exec: %s", step.Cmd)
		cmd := exec.Command("sh", "-c", step.Cmd)
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("    ✗ error: %v\n%s", err, out)
		} else {
			log.Printf("    ✓ output: %s", out)
		}
	}
}

// syncJobs reconciles cron entries against the latest workflows
func syncJobs(
	wfs []Workflow,
	c *cron.Cron,
	entryIDs map[int]cron.EntryID,
	schedules map[int]string,
) {
	active := make(map[int]bool)
	for _, wf := range wfs {
		active[wf.ID] = true

		// Determine schedule spec: prefer Recurrence if set, else Schedule
		scheduleSpec := wf.Schedule
		if wf.Recurrence != nil && *wf.Recurrence != "" {
			scheduleSpec = *wf.Recurrence
		}

		// remove any existing job if scheduleSpec is now empty
		if scheduleSpec == "" {
			if id, ok := entryIDs[wf.ID]; ok {
				c.Remove(id)
				delete(entryIDs, wf.ID)
				delete(schedules, wf.ID)
				log.Printf("removed scheduling for workflow %d", wf.ID)
			}
			continue
		}

		// add or update job if new or schedule changed
		if old, ok := schedules[wf.ID]; ok && old == scheduleSpec {
			log.Printf("workflow %d (%s) schedule unchanged, skipping", wf.ID, wf.Name)
			continue
		}

		// remove existing job if schedule changed
		if id, ok := entryIDs[wf.ID]; ok {
			c.Remove(id)
			delete(entryIDs, wf.ID)
			delete(schedules, wf.ID)
			log.Printf("removed scheduling for workflow %d due to schedule change", wf.ID)
		}

		// capture wf for closure
		wfc := wf
		id, err := c.AddFunc(scheduleSpec, func() {
			log.Printf("▶ scheduled run workflow %d: %s", wfc.ID, wfc.Name)
			runWorkflow(wfc)
		})
		if err != nil {
			log.Printf("invalid schedule for workflow %d (%s): %v", wf.ID, scheduleSpec, err)
		} else {
			entryIDs[wf.ID] = id
			schedules[wf.ID] = scheduleSpec
			log.Printf("scheduled workflow %d (%s) with %q", wf.ID, wf.Name, scheduleSpec)
		}
	}

	// remove jobs for workflows that no longer exist
	for id, eid := range entryIDs {
		if !active[id] {
			c.Remove(eid)
			delete(entryIDs, id)
			delete(schedules, id)
			log.Printf("removed scheduling for deleted workflow %d", id)
		}
	}
}

func main() {
	// version flag
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVer {
		fmt.Println(Version)
		return
	}

	// update interval
	updateInterval := DefaultUpdateInterval
	if s := os.Getenv("UPDATE_INTERVAL"); s != "" {
		if d, err := time.ParseDuration(s); err != nil {
			log.Printf("invalid UPDATE_INTERVAL=%q, using default: %v", s, err)
		} else {
			updateInterval = d
		}
	}

	// conditional self-update
	if os.Getenv("GITHUB_OWNER") != "" &&
		os.Getenv("GITHUB_REPO") != "" &&
		os.Getenv("GITHUB_TOKEN") != "" {
		go selfUpdateLoop(updateInterval)
	} else {
		log.Print("self-update disabled (set GITHUB_OWNER, GITHUB_REPO, GITHUB_TOKEN)")
	}

	// core settings
	apiURL := getenv("API_URL", "https://192.168.0.94:8443")
	regURL := getenv("REGISTER_URL", "https://192.168.0.94:8444")
	token := os.Getenv("REGISTER_TOKEN")
	device := getenv("DEVICE_ID", hostname())

	ctx := context.Background()
	if err := enroll(ctx, device, regURL, token); err != nil {
		log.Fatalf("enroll failed: %v", err)
	}

	// set up the cron scheduler
	c := cron.New(cron.WithParser(
		cron.NewParser(
			cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.DowOptional | cron.Descriptor,
		),
	))
	entryIDs := make(map[int]cron.EntryID)
	schedules := make(map[int]string)
	c.Start()
	defer c.Stop()

	ticker := time.NewTicker(HeartbeatInterval)
	defer ticker.Stop()
	for range ticker.C {
		if err := sendHeartbeat(ctx, apiURL, device); err != nil {
			log.Printf("heartbeat error: %v", err)
			continue
		}
		log.Print("heartbeat sent")

		wfs, err := fetchWorkflows(ctx, apiURL, device, token)
		if err != nil {
			log.Printf("fetch workflows error: %v", err)
			continue
		}

		// reconcile our scheduled jobs with the latest workflows
		syncJobs(wfs, c, entryIDs, schedules)
	}
}

// getenv returns the env or fallback
func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// hostname returns os.Hostname()
func hostname() string {
	h, _ := os.Hostname()
	return h
}
