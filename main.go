package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-routeros/routeros"
)

type Config struct {
	MtHost     string
	MtUser     string
	MtPass     string
	ListTemp   string
	ListPerm   string
	Whitelist  []string
	StateFile  string
	Escalation []int
}

// ----------------------------------------------
// AUTO-SETUP: check & create /opt/htb_blocker
// ----------------------------------------------

func ensureBaseDir(base string) {
	if _, err := os.Stat(base); os.IsNotExist(err) {
		fmt.Printf("⚠️  Folder %s does not exist. Create it? (y/n): ", base)

		var answer string
		fmt.Scanln(&answer)

		answer = strings.ToLower(strings.TrimSpace(answer))
		if answer != "y" && answer != "yes" {
			log.Fatal("❌ Aborted by user.")
		}

		fmt.Println("➡️ Creating folder:", base)
		os.MkdirAll(base, 0755)
	}
}

// ----------------------------------------------
// AUTO-SETUP: If config.env missing → create default
// ----------------------------------------------

func ensureConfig(base string) {
	configPath := filepath.Join(base, "config.env")

	if _, err := os.Stat(configPath); os.IsNotExist(err) {

		fmt.Printf("⚠️  config.env not found. Create default config? (y/n): ")

		var answer string
		fmt.Scanln(&answer)
		answer = strings.ToLower(strings.TrimSpace(answer))
		if answer != "y" {
			log.Fatal("❌ Aborted by user.")
		}

		defaultCfg := `
# MikroTik settings
MT_HOST=192.168.88.1:8728
MT_USER=admin
MT_PASS=yourpassword

# Lists
LIST_TEMP=blocked_attackers
LIST_PERM=blocked_permanent

# Whitelist (comma separated)
WHITELIST=8.8.8.8,192.168.1.0/24

# State file
STATE_FILE=/opt/htb_blocker/state.json

# Escalation (hours)
ESCALATE_1=1
ESCALATE_2=3
ESCALATE_3=7
`
		os.WriteFile(configPath, []byte(defaultCfg), 0644)

		fmt.Println("✅ Default config.env created. Please edit it.")
	}
}
func sanitizeIP(raw string) string {
	// Trim quotes
	raw = strings.Trim(raw, "\"")

	// Split on comma (CSV)
	if strings.Contains(raw, ",") {
		parts := strings.Split(raw, ",")
		raw = parts[0]
	}

	// Remove spaces
	raw = strings.TrimSpace(raw)

	// Validate
	ip := net.ParseIP(raw)
	if ip == nil {
		return ""
	}
	return ip.String()
}

// ----------------------------------------------

func loadConfig(path string) (*Config, error) {
	cfg := &Config{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(raw), "\n")
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}

		parts := strings.SplitN(ln, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		val := parts[1]

		switch key {
		case "MT_HOST":
			cfg.MtHost = val
		case "MT_USER":
			cfg.MtUser = val
		case "MT_PASS":
			cfg.MtPass = val
		case "LIST_TEMP":
			cfg.ListTemp = val
		case "LIST_PERM":
			cfg.ListPerm = val
		case "WHITELIST":
			cfg.Whitelist = strings.Split(val, ",")
		case "STATE_FILE":
			cfg.StateFile = val
		case "ESCALATE_1", "ESCALATE_2", "ESCALATE_3":
			h, _ := strconv.Atoi(val)
			cfg.Escalation = append(cfg.Escalation, h)
		}
	}

	return cfg, nil
}

// ----------------------------------------------

func loadIPsFromCSV(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var ips []string
	s := bufio.NewScanner(f)
	line := 0

	for s.Scan() {
		v := strings.TrimSpace(s.Text())
		if line == 0 {
			line++
			continue
		}
		v = strings.Trim(v, "\"")
		if v != "" {
			ips = append(ips, v)
		}
		line++
	}
	return ips, nil
}

// ----------------------------------------------

func isWhitelisted(ip string, wl []string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}

	for _, entry := range wl {
		entry = strings.TrimSpace(entry)
		if !strings.Contains(entry, "/") {
			if entry == ip {
				return true
			}
			continue
		}
		_, cidr, err := net.ParseCIDR(entry)
		if err == nil && cidr.Contains(p) {
			return true
		}
	}
	return false
}

// ----------------------------------------------

func loadState(path string) (map[string]int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]int), nil
		}
		return nil, err
	}

	var s map[string]int
	json.Unmarshal(raw, &s)
	return s, nil
}

func saveState(path string, s map[string]int) {
	b, _ := json.MarshalIndent(s, "", "  ")
	_ = os.WriteFile(path, b, 0644)
}

// ----------------------------------------------

func getTimeout(count int, hours []int) string {
	if count <= len(hours) {
		return fmt.Sprintf("%02d:00:00", hours[count-1])
	}
	return "0"
}

// ----------------------------------------------

func main() {

	if len(os.Args) < 2 {
		log.Fatal("Usage: ./blocker attackers.csv")
	}

	csvPath := os.Args[1]

	// BASE DIR
	baseDir := "/opt/htb_blocker"

	// --- AUTO SETUP ---
	ensureBaseDir(baseDir)
	ensureConfig(baseDir)

	cfg, err := loadConfig(filepath.Join(baseDir, "config.env"))
	if err != nil {
		log.Fatalf("Config load error: %v", err)
	}

	state, _ := loadState(cfg.StateFile)

	ips, err := loadIPsFromCSV(csvPath)
	if err != nil {
		log.Fatalf("CSV error: %v", err)
	}

	client, err := routeros.Dial(cfg.MtHost, cfg.MtUser, cfg.MtPass)
	if err != nil {
		log.Fatalf("Mikrotik error: %v", err)
	}
	defer client.Close()

	for _, ip := range ips {

		// --- 1) SANITIZE → فقط IP واقعی را نگه داریم ---
		ip = sanitizeIP(ip)
		if ip == "" {
			log.Printf("⚠️ Skipping invalid IP (after sanitize)")
			continue
		}

		// --- 2) Whitelist ---
		if isWhitelisted(ip, cfg.Whitelist) {
			log.Printf("⚪ %s → SKIP (whitelisted)", ip)
			continue
		}

		// --- 3) State update ---
		state[ip]++
		timeout := getTimeout(state[ip], cfg.Escalation)

		// --- 4) Permanent block ---
		if timeout == "0" {
			log.Printf("🚫 %s → Permanent block", ip)

			_, _ = client.RunArgs([]string{
				"/ip/firewall/address-list/add",
				"=list=" + cfg.ListPerm,
				"=address=" + ip,
				"=timeout=0",
			})

			continue
		}

		// --- 5) Temporary (escalated) block ---
		log.Printf("🛡️ %s → attempt %d → timeout %s", ip, state[ip], timeout)

		_, err := client.RunArgs([]string{
			"/ip/firewall/address-list/add",
			"=list=" + cfg.ListTemp,
			"=address=" + ip,
			"=timeout=" + timeout,
		})

		if err != nil {
			log.Printf("❌ Block failed for %s: %v", ip, err)
		}
	}

	saveState(cfg.StateFile, state)
}
