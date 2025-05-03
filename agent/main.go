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
	"net"
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

/* ───────── build-time var ───────── */
var Version = "dev"

/* ───────── constants ───────── */
const (
	DefaultUpdateInterval = 24 * time.Hour
	HeartbeatInterval     = 30 * time.Second
	certDir               = "/etc/edge-agent/certs"

	metricsAddr = ":9090" // Prometheus listener (TLS)
	healthAddr  = "127.0.0.1:8080"
)

var (
	certPath = filepath.Join(certDir, "client.crt")
	keyPath  = filepath.Join(certDir, "client.key")
	caPath   = filepath.Join(certDir, "ca.crt")
)

/* ───────── Prometheus ───────── */
var (
	heartbeatsSent = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "heartbeats_sent_total", Help: "Total heartbeats sent."})
	fetchSuccess = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "workflows_fetch_success_total", Help: "Successful workflow fetches."})
	fetchErrors = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "workflows_fetch_errors_total", Help: "Errors during workflow fetch."})
	jobsScheduled = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "jobs_scheduled", Help: "Current number of cron jobs scheduled."})
	jobsClaimed = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "jobs_claimed_total", Help: "Jobs claimed from the control-plane."})
	jobsSucceeded = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "jobs_succeeded_total", Help: "Jobs finished successfully."})
	jobsFailed = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "jobs_failed_total", Help: "Jobs that failed."})
)

func init() {
	prometheus.MustRegister(
		heartbeatsSent, fetchSuccess, fetchErrors,
		jobsScheduled, jobsClaimed, jobsSucceeded, jobsFailed)
}

/* ───────── payloads ───────── */

type Heartbeat struct {
	DeviceID string    `json:"device_id"`
	Ts       time.Time `json:"ts"`
}

type registerResp struct {
	CertPem string `json:"cert_pem"`
	CaPem   string `json:"ca_pem"`
}

type Workflow struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Definition struct {
		Steps []struct {
			Cmd string `json:"cmd"`
		} `json:"steps"`
	} `json:"definition"`
	Schedule   string  `json:"schedule"`
	Recurrence *string `json:"recurrence"`
}

/* ───── jobs ───── */

type Job struct {
	ID             int                    `json:"id"`
	WorkflowID     int                    `json:"workflow_id"`
	ContainerImage string                 `json:"container_image"`
	State          string                 `json:"state"`
	Payload        map[string]interface{} `json:"payload"`
}

type JobUpdate struct {
	State      string                 `json:"state"`
	Result     map[string]interface{} `json:"result,omitempty"`
	Error      string                 `json:"error,omitempty"`
	StartedAt  *time.Time             `json:"started_at,omitempty"`
	FinishedAt *time.Time             `json:"finished_at,omitempty"`
}

/* ───────── TLS client ───────── */

func newTLSClient(loadCA bool) *http.Client {
	cfg := &tls.Config{}
	if loadCA {
		if caPem, err := os.ReadFile(caPath); err == nil {
			p := x509.NewCertPool()
			p.AppendCertsFromPEM(caPem)
			cfg.RootCAs = p
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

/* ───────── self-update (GitHub) ───────── */

func selfUpdateLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		if err := tryUpdate(); err != nil {
			log.Printf("self-update: %v", err)
		}
	}
}

func tryUpdate() error {
	owner, repo, token := os.Getenv("GITHUB_OWNER"), os.Getenv("GITHUB_REPO"), os.Getenv("GITHUB_TOKEN")
	if owner == "" || repo == "" || token == "" {
		return nil
	}

	ctx := context.Background()
	tc := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
	client := github.NewClient(tc)

	rel, _, err := client.Repositories.GetLatestRelease(ctx, owner, repo)
	if err != nil {
		return err
	}
	latestTag := rel.GetTagName()
	currTag := Version

	latestV, _ := semver.ParseTolerant(latestTag)
	currV, _ := semver.ParseTolerant(currTag)
	if !latestV.GT(currV) {
		return nil
	}

	execPath, _ := os.Executable()
	binName := filepath.Base(execPath)
	assetName := fmt.Sprintf("%s-%s-%s-%s", binName, runtime.GOOS, runtime.GOARCH, latestTag)
	sumName := assetName + ".sha256"

	var binURL, sumURL string
	for _, a := range rel.Assets {
		switch a.GetName() {
		case assetName:
			binURL = a.GetBrowserDownloadURL()
		case sumName:
			sumURL = a.GetBrowserDownloadURL()
		}
	}
	if binURL == "" || sumURL == "" {
		return fmt.Errorf("release assets missing")
	}

	sumRaw, _ := io.ReadAll(must(http.Get(sumURL)).Body)
	expected := strings.Fields(string(sumRaw))[0]

	tmp, _ := os.CreateTemp("", assetName)
	io.Copy(tmp, must(http.Get(binURL)).Body)
	tmp.Chmod(0o755)

	tmp.Seek(0, io.SeekStart)
	data, _ := io.ReadAll(tmp)
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != expected {
		return fmt.Errorf("checksum mismatch")
	}

	if err := os.Rename(tmp.Name(), execPath); err != nil {
		return err
	}

	log.Printf("updated from %s to %s, exec-replacing", currTag, latestTag)
	return syscall.Exec(execPath, os.Args, os.Environ())
}

/* ───────── enrol (mTLS) ───────── */

func enroll(ctx context.Context, deviceID, regURL, token string) error {
	if _, err := os.Stat(certPath); err == nil {
		return nil // already enrolled
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	os.MkdirAll(certDir, 0o700)
	os.WriteFile(keyPath, keyPem, 0o600)

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: deviceID},
	}, key)
	csrPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	body, _ := json.Marshal(map[string]string{"device_id": deviceID, "csr_pem": string(csrPem)})
	req, _ := http.NewRequestWithContext(ctx, "POST", regURL+"/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Register-Token", token)
	resp, err := newTLSClient(false).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("register status %d", resp.StatusCode)
	}
	var out registerResp
	json.NewDecoder(resp.Body).Decode(&out)
	os.WriteFile(certPath, []byte(out.CertPem), 0o644)
	os.WriteFile(caPath, []byte(out.CaPem), 0o644)
	return nil
}

/* ───────── control-plane helpers ───────── */

func sendHeartbeat(ctx context.Context, api, dev string) error {
	hb := Heartbeat{DeviceID: dev, Ts: time.Now().UTC()}
	b, _ := json.Marshal(hb)
	req, _ := http.NewRequestWithContext(ctx, "POST", api+"/heartbeat", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	_, err := newTLSClient(true).Do(req)
	if err == nil {
		heartbeatsSent.Inc()
	}
	return err
}

func claimJob(ctx context.Context, api, dev, tok string) (*Job, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("%s/devices/%s/jobs/next", api, dev), nil)
	req.Header.Set("X-Register-Token", tok)
	resp, err := newTLSClient(true).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusNotFound:
		return nil, nil
	case http.StatusOK:
		var j Job
		if err := json.NewDecoder(resp.Body).Decode(&j); err == io.EOF {
			return nil, nil // empty body → no job
		} else if err != nil {
			return nil, err
		}
		if j.ID == 0 {
			return nil, nil
		}
		return &j, nil
	default:
		return nil, fmt.Errorf("claim status %d", resp.StatusCode)
	}
}

func patchJob(ctx context.Context, api, tok string, id int, upd JobUpdate) error {
	b, _ := json.Marshal(upd)
	req, _ := http.NewRequestWithContext(ctx, "PATCH", fmt.Sprintf("%s/jobs/%d", api, id), bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Register-Token", tok)
	_, err := newTLSClient(true).Do(req)
	return err
}

/* ───── run container PoC ───── */

func runJob(ctx context.Context, api, tok string, j Job) {
	start := time.Now().UTC()
	patchJob(ctx, api, tok, j.ID, JobUpdate{State: "running", StartedAt: &start})

	// pull-policy tweak via env var: DOCKER_PULL=never / always / missing (default)
	pullPolicy := os.Getenv("DOCKER_PULL")
	dockerArgs := []string{"run", "--rm"}
	if pullPolicy == "never" {
		dockerArgs = append(dockerArgs, "--pull=never")
	}
	dockerArgs = append(dockerArgs, j.ContainerImage)

	err := exec.CommandContext(ctx, "docker", dockerArgs...).Run()

	upd := JobUpdate{FinishedAt: ptrTime(time.Now().UTC())}
	if err != nil {
		upd.State, upd.Error = "failed", err.Error()
		jobsFailed.Inc()
	} else {
		upd.State = "succeeded"
		jobsSucceeded.Inc()
	}
	patchJob(ctx, api, tok, j.ID, upd)
}

/* ───── pollWork goroutine ───── */

func pollWork(ctx context.Context, api, dev, tok string) {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			if j, err := claimJob(ctx, api, dev, tok); err != nil {
				log.Printf("pollWork: %v", err)
			} else if j != nil {
				jobsClaimed.Inc()
				go runJob(ctx, api, tok, *j)
			}
		case <-ctx.Done():
			return
		}
	}
}

/* ───── workflow helpers (unchanged) ───── */

func fetchWorkflows(ctx context.Context, api, dev, tok string) ([]Workflow, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("%s/devices/%s/workflows", api, dev), nil)
	req.Header.Set("X-Register-Token", tok)
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

func runWorkflow(w Workflow) {
	log.Printf("▶ workflow %d: %s", w.ID, w.Name)
	for _, s := range w.Definition.Steps {
		out, err := exec.Command("sh", "-c", s.Cmd).CombinedOutput()
		if err != nil {
			log.Printf("✗ %v\n%s", err, out)
		} else {
			log.Printf("✓ %s", out)
		}
	}
}

func syncJobs(wfs []Workflow, c *cron.Cron, ids map[int]cron.EntryID,
	specs map[int]string, mu *sync.Mutex) {

	mu.Lock()
	defer mu.Unlock()
	active := map[int]bool{}

	for _, wf := range wfs {
		active[wf.ID] = true
		spec := wf.Schedule
		if wf.Recurrence != nil && *wf.Recurrence != "" {
			if s, err := parseRecurrence(*wf.Recurrence); err == nil {
				spec = s
			}
		}
		if spec == "" {
			if id, ok := ids[wf.ID]; ok {
				c.Remove(id)
				delete(ids, wf.ID)
				delete(specs, wf.ID)
			}
			continue
		}
		if old, ok := specs[wf.ID]; ok && old == spec {
			continue
		}
		if id, ok := ids[wf.ID]; ok {
			c.Remove(id)
		}
		w := wf
		eid, err := c.AddFunc(spec, func() { runWorkflow(w) })
		if err != nil {
			log.Printf("cron parse %d: %v", wf.ID, err)
			continue
		}
		ids[wf.ID], specs[wf.ID] = eid, spec
	}

	for id, eid := range ids {
		if !active[id] {
			c.Remove(eid)
			delete(ids, id)
			delete(specs, id)
		}
	}
	jobsScheduled.Set(float64(len(ids)))
}

func parseRecurrence(r string) (string, error) {
	r = strings.ToLower(strings.TrimSpace(r))
	switch {
	case r == "hourly":
		return "0 * * * *", nil
	case strings.HasPrefix(r, "daily at "):
		p := strings.TrimPrefix(r, "daily at ")
		return fmt.Sprintf("0 %s * * *", p), nil
	default:
		return "", fmt.Errorf("unsupported recurrence %q", r)
	}
}

/* ───────── main ───────── */

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVer {
		fmt.Println(Version)
		return
	}

	/* metrics listener (TLS) */
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		log.Printf("metrics on %s", metricsAddr)
		log.Fatal(http.ListenAndServe(metricsAddr, nil))
	}()

	/* local health listener (plain HTTP) */
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		ln, _ := net.Listen("tcp", healthAddr)
		log.Printf("healthz on %s", healthAddr)
		http.Serve(ln, mux) //nolint:errcheck
	}()

	apiURL := getenv("API_URL", "https://localhost:8443")
	regURL := getenv("REGISTER_URL", "https://localhost:8444")
	token := os.Getenv("REGISTER_TOKEN")
	device := getenv("DEVICE_ID", hostname())

	/* self-update */
	intv := DefaultUpdateInterval
	if s := os.Getenv("UPDATE_INTERVAL"); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			intv = d
		}
	}
	if os.Getenv("GITHUB_OWNER") != "" && os.Getenv("GITHUB_REPO") != "" && os.Getenv("GITHUB_TOKEN") != "" {
		go selfUpdateLoop(intv)
	}

	if err := enroll(ctx, device, regURL, token); err != nil {
		log.Fatalf("enrol: %v", err)
	}

	go pollWork(ctx, apiURL, device, token)

	parser := cron.NewParser(cron.SecondOptional | cron.Minute | cron.Hour |
		cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	c := cron.New(cron.WithParser(parser))
	c.Start()
	defer c.Stop()

	ids, specs := map[int]cron.EntryID{}, map[int]string{}
	var mu sync.Mutex
	tick := time.NewTicker(HeartbeatInterval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := sendHeartbeat(ctx, apiURL, device); err != nil {
				log.Printf("heartbeat: %v", err)
			}
			if wfs, err := fetchWorkflows(ctx, apiURL, device, token); err != nil {
				log.Printf("workflows: %v", err)
			} else {
				syncJobs(wfs, c, ids, specs, &mu)
			}
		}
	}
}

/* ───────── helpers ───────── */

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
func hostname() string               { h, _ := os.Hostname(); return h }
func ptrTime(t time.Time) *time.Time { return &t }

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
