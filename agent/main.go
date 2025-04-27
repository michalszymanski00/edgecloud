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
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/go-github/v53/github"
)

// Version is injected at build time via ldflags: -X main.Version=$(git describe --tags)
var Version = "dev"

const (
	certDir = "/etc/edge-agent/certs"
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

type registerResp struct {
	CertPem string `json:"cert_pem"`
	CaPem   string `json:"ca_pem"`
}

// newTLSClient returns an HTTP client configured for mTLS
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
	// skip verify only if no CA (first boot)
	cfg.InsecureSkipVerify = cfg.RootCAs == nil
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
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

// tryUpdate fetches the latest GitHub release, verifies checksum, and replaces the binary
func tryUpdate() error {
	owner := os.Getenv("GITHUB_OWNER")
	repo := os.Getenv("GITHUB_REPO")
	if owner == "" || repo == "" {
		return errors.New("GITHUB_OWNER and GITHUB_REPO must be set")
	}
	ctx := context.Background()
	client := github.NewClient(nil)

	release, _, err := client.Repositories.GetLatestRelease(ctx, owner, repo)
	if err != nil {
		return fmt.Errorf("fetch latest release: %w", err)
	}
	latest := release.GetTagName()
	if latest == Version {
		return nil // already up-to-date
	}

	execPath, err := os.Executable()
	if err != nil {
		return err
	}
	binName := filepath.Base(execPath)
	osName := runtime.GOOS
	arch := runtime.GOARCH
	assetName := fmt.Sprintf("%s-%s-%s-%s", binName, osName, arch, latest)
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
	if assetURL == "" {
		return fmt.Errorf("asset %s not found", assetName)
	}
	if checksumURL == "" {
		return fmt.Errorf("checksum %s not found", checksumName)
	}

	// download and read expected checksum
	respSum, err := http.Get(checksumURL)
	if err != nil {
		return fmt.Errorf("download checksum: %w", err)
	}
	defer respSum.Body.Close()
	expBytes, err := io.ReadAll(respSum.Body)
	if err != nil {
		return fmt.Errorf("read checksum: %w", err)
	}
	expected := strings.TrimSpace(string(expBytes))

	// download asset binary
	resp, err := http.Get(assetURL)
	if err != nil {
		return fmt.Errorf("download asset: %w", err)
	}
	defer resp.Body.Close()

	tmp, err := os.CreateTemp("", assetName)
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		return fmt.Errorf("save asset: %w", err)
	}
	if err := tmp.Chmod(0o755); err != nil {
		return err
	}

	// verify checksum
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
		return fmt.Errorf("checksum mismatch: got %s, want %s", actual, expected)
	}

	// atomically replace binary and exit for systemd to restart
	if err := os.Rename(tmp.Name(), execPath); err != nil {
		return fmt.Errorf("replace binary: %w", err)
	}
	log.Printf("self-update succeeded: %s → %s; exiting to restart", Version, latest)
	os.Exit(0)
	return nil
}

// enroll generates key, CSR, and registers with the control-plane
func enroll(ctx context.Context, deviceID, regURL, token string) error {
	if _, err := os.Stat(certPath); err == nil {
		return nil
	}
	// generate private key
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

	// create CSR
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: deviceID}}, key)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}
	csrPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	// prepare payload
	reqBody, err := json.Marshal(map[string]string{"device_id": deviceID, "csr_pem": string(csrPem)})
	if err != nil {
		return fmt.Errorf("marshal CSR payload: %w", err)
	}

	// POST /register
	req, err := http.NewRequestWithContext(ctx, "POST", regURL+"/register", bytes.NewReader(reqBody))
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

	// write returned certs
	if err := os.WriteFile(certPath, []byte(out.CertPem), 0o644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(caPath, []byte(out.CaPem), 0o644); err != nil {
		return fmt.Errorf("write CA: %w", err)
	}

	log.Print("enrolment succeeded")
	return nil
}

// sendHeartbeat posts a heartbeat to the control-plane
func sendHeartbeat(ctx context.Context, api, id string) error {
	hb := Heartbeat{DeviceID: id, Ts: time.Now().UTC()}
	body, _ := json.Marshal(hb)
	req, _ := http.NewRequestWithContext(ctx, "POST", api+"/heartbeat", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	client := newTLSClient(true)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func main() {
	// version flag
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVer {
		fmt.Println(Version)
		return
	}

	// read update interval from env or use default
	interval := 24 * time.Hour
	if s := os.Getenv("UPDATE_INTERVAL"); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			interval = d
		} else {
			log.Printf("invalid UPDATE_INTERVAL, using default: %v", err)
		}
	}

	// start self-update loop
	go selfUpdateLoop(interval)

	apiURL := getenv("API_URL", "https://192.168.101.10:8443")
	regURL := getenv("REGISTER_URL", "https://192.168.101.10:8444")
	token := os.Getenv("REGISTER_TOKEN")
	device := getenv("DEVICE_ID", hostname())

	ctx := context.Background()
	if err := enroll(ctx, device, regURL, token); err != nil {
		log.Fatalf("enrol failed: %v", err)
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if err := sendHeartbeat(ctx, apiURL, device); err != nil {
			log.Printf("heartbeat error: %v", err)
		} else {
			log.Print("heartbeat sent")
		}
	}
}

// helpers
func hostname() string { h, _ := os.Hostname(); return h }
func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
