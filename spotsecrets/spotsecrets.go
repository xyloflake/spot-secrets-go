// Package spotsecrets provides TOTP generation for Spotify's web player API.
//
// It fetches rotating cipher secrets and generates time-based one-time passwords
// needed to obtain web player access tokens from https://open.spotify.com/api/token.
//
// Usage:
//
//	totp, ver, err := spotsecrets.GenerateTOTP()
//	// use totp and ver as query params: ?totp=...&totpServer=...&totpVer=...
package spotsecrets

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const secretsURL = "https://raw.githubusercontent.com/xyloflake/spot-secrets-go/main/secrets/secretDict.json"

// SecretDict maps version strings to cipher byte arrays.
type SecretDict map[string][]int

// FetchSecrets downloads the latest cipher secrets from GitHub.
func FetchSecrets() (SecretDict, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(secretsURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch secrets: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read secrets response: %w", err)
	}

	var result SecretDict
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse secrets JSON: %w", err)
	}
	return result, nil
}

// LatestVersion returns the highest version key and its cipher bytes from a SecretDict.
func LatestVersion(dict SecretDict) (string, []int) {
	var ver string
	maxVer := 0
	for k := range dict {
		v, _ := strconv.Atoi(k)
		if v > maxVer {
			maxVer = v
			ver = k
		}
	}
	return ver, dict[ver]
}

// GenerateTOTP fetches the latest secrets and returns a TOTP code and version string.
func GenerateTOTP() (code string, version string, err error) {
	dict, err := FetchSecrets()
	if err != nil {
		return "", "", err
	}

	ver, cipher := LatestVersion(dict)
	if len(cipher) == 0 {
		return "", "", fmt.Errorf("no cipher bytes found for version %s", ver)
	}

	code, err = ComputeTOTP(cipher)
	if err != nil {
		return "", "", err
	}

	return code, ver, nil
}

// ComputeTOTP generates a 6-digit TOTP code from cipher bytes.
func ComputeTOTP(cipher []int) (string, error) {
	// XOR transform
	transformed := make([]int, len(cipher))
	for t, e := range cipher {
		transformed[t] = e ^ ((t % 33) + 9)
	}

	// Join as string digits, then hex encode
	var sb strings.Builder
	for _, num := range transformed {
		sb.WriteString(strconv.Itoa(num))
	}
	hexStr := hex.EncodeToString([]byte(sb.String()))

	// Decode hex and base32 encode
	hexBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", fmt.Errorf("hex decode failed: %w", err)
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hexBytes)

	// HOTP with 30s interval
	now := time.Now().Unix()
	counter := uint64(math.Floor(float64(now) / 30))

	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("base32 decode failed: %w", err)
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, secretBytes)
	mac.Write(buf)
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff
	otp := truncated % 1000000

	return fmt.Sprintf("%06d", otp), nil
}
