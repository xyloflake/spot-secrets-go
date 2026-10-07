package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var bundleRe = regexp.MustCompile(`(?:vendor~web-player|encore~web-player|web-player)\.[0-9a-f]{4,}\.(?:js|mjs)`)

// 10 minutes for timeout
const timeout = 600 * time.Second

type Secret struct {
	Version int    `json:"version"`
	Secret  string `json:"secret"`
}

type SecretBytes struct {
	Version int   `json:"version"`
	Secret  []int `json:"secret"`
}

type SecretBase32 struct {
	Version int    `json:"version"`
	Secret  string `json:"secret"`
}

type SecretDict map[string][]int

func base32FromBytes(bytes []uint8, secretSauce string) string {
	t, n := 0, 0
	r := ""

	for _, b := range bytes {
		n = (n << 8) | int(b)
		t += 8
		for t >= 5 {
			r += string(secretSauce[(n>>(t-5))&31])
			t -= 5
		}
	}

	if t > 0 {
		r += string(secretSauce[(n<<(5-t))&31])
	}

	return r
}

func cleanBuffer(e string) ([]byte, error) {
	// remove spaces
	e = strings.ReplaceAll(e, " ", "")
	// decode hex string into bytes
	buffer, err := hex.DecodeString(e)
	if err != nil {
		return nil, err
	}
	return buffer, nil
}

func summarise(caps []map[string]interface{}) {
	real := map[string]string{}

	for _, cap := range caps {
		sec, ok := cap["secret"].(string)
		if !ok {
			continue
		}

		var ver int
		switch v := cap["version"].(type) {
		case float64:
			ver = int(v)
		default:
			if obj, ok := cap["obj"].(map[string]interface{}); ok {
				if vv, ok := obj["version"].(float64); ok {
					ver = int(vv)
				}
			}
		}

		if ver == 0 {
			continue
		}

		real[strconv.Itoa(ver)] = sec
	}

	if len(real) == 0 {
		fmt.Println("No real secrets with version.")
		return
	}

	versions := make([]int, 0, len(real))
	for k := range real {
		v, _ := strconv.Atoi(k)
		versions = append(versions, v)
	}
	sort.Ints(versions)

	var formattedData []Secret
	for _, v := range versions {
		formattedData = append(formattedData, Secret{
			Version: v,
			Secret:  real[strconv.Itoa(v)],
		})
	}

	var secretBytes []SecretBytes
	secretDict := make(SecretDict)
	for _, s := range formattedData {
		chars := []int{}
		for _, c := range s.Secret {
			chars = append(chars, int(c))
		}
		secretBytes = append(secretBytes, SecretBytes{
			Version: s.Version,
			Secret:  chars,
		})
		secretDict[strconv.Itoa(s.Version)] = chars
	}

	// Base 32 encoding
	var secretBase32 []SecretBase32
	secretSauce := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

	secretCipherBytes := make([]int, len(secretBytes[len(secretBytes)-1].Secret))
	for i, e := range secretBytes[len(secretBytes)-1].Secret {
		secretCipherBytes[i] = e ^ ((i % 33) + 9)
	}

	joined := ""
	for _, v := range secretCipherBytes {
		joined += fmt.Sprintf("%d", v)
	}

	utf8Bytes := []byte(joined)

	hexStr := ""
	for _, b := range utf8Bytes {
		hexStr += fmt.Sprintf("%02x", b)
	}

	secretBytesClean, err := cleanBuffer(hexStr)
	if err != nil {
		panic(err)
	}

	secretBase32 = append(secretBase32, SecretBase32{
		Version: secretBytes[len(secretBytes)-1].Version,
		Secret:  base32FromBytes(secretBytesClean, secretSauce),
	})

	writeJSONPretty("secrets/secrets.json", formattedData)
	writeJSON("secrets/secretBytes.json", secretBytes)
	writeJSON("secrets/secretDict.json", secretDict)
	writeJSON("secrets/secretBase32.json", secretBase32[0])

	fmt.Println(formattedData)
	fmt.Println(secretBytes)
	fmt.Println(secretDict)
	fmt.Println(secretBase32)
}

func writeJSONPretty(filename string, v interface{}) {
	os.MkdirAll("secrets", 0755)
	data, _ := json.MarshalIndent(v, "", "  ")
	_ = os.WriteFile(filename, data, 0644)
}

func writeJSON(filename string, v interface{}) {
	os.MkdirAll("secrets", 0755)
	data, _ := json.Marshal(v) // compact
	_ = os.WriteFile(filename, data, 0644)
}

// Spotify now declares secrets as object literals ([{secret:'...',version:61}].map(...)),
// which bypass setters on Object.prototype, so the old chromedp hook captured nothing.
// Reading the bundles directly is enough and needs no browser.
var (
	scriptRe   = regexp.MustCompile(`https://open\.spotifycdn\.com/cdn/build/web-player/[^"']+\.js`)
	secretRe   = regexp.MustCompile(`\{secret:(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"),version:(\d+)\}`)
	unescapeRe = regexp.MustCompile(`\\(.)`)
)

const userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"

func fetch(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

func extractSecrets(js string) []map[string]interface{} {
	var caps []map[string]interface{}
	for _, m := range secretRe.FindAllStringSubmatch(js, -1) {
		ver, err := strconv.Atoi(m[3])
		if err != nil {
			continue
		}
		raw := m[1]
		if raw == "" {
			raw = m[2]
		}
		caps = append(caps, map[string]interface{}{
			"secret":  unescapeRe.ReplaceAllString(raw, "$1"),
			"version": float64(ver),
		})
	}
	return caps
}

func grabLive(ctx context.Context) ([]map[string]interface{}, error) {
	fmt.Println("Opening Spotify...")
	html, err := fetch(ctx, "https://open.spotify.com")
	if err != nil {
		return nil, err
	}

	var caps []map[string]interface{}
	seen := map[string]bool{}
	for _, url := range scriptRe.FindAllString(html, -1) {
		if seen[url] || !bundleRe.MatchString(url) {
			continue
		}
		seen[url] = true
		js, err := fetch(ctx, url)
		if err != nil {
			return nil, err
		}
		caps = append(caps, extractSecrets(js)...)
	}

	for _, c := range caps {
		fmt.Printf("Secret(%d): %s\n", int(c["version"].(float64)), c["secret"])
	}
	return caps, nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	caps, err := grabLive(ctx)
	if err != nil {
		log.Fatal("Error:", err)
	}
	summarise(caps)
}
