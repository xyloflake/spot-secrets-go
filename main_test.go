package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestExtractSecrets(t *testing.T) {
	js := `let ej=[{secret:',7/*F("rLJ2oxaKL^f+E1xvP@N',version:61},{secret:'OmE{ZA.J^":0FG\\Uz?[@WW',version:60},{secret:"{iOFn;4}<1PFYKPV?5{%u14]M>/V0hDH",version:59}].map(e=>e)`
	want := map[int]string{
		61: `,7/*F("rLJ2oxaKL^f+E1xvP@N`,
		60: `OmE{ZA.J^":0FG\Uz?[@WW`,
		59: `{iOFn;4}<1PFYKPV?5{%u14]M>/V0hDH`,
	}
	got := extractSecrets(js)
	if len(got) != len(want) {
		t.Fatalf("got %d secrets, want %d", len(got), len(want))
	}
	for _, c := range got {
		v := int(c["version"].(float64))
		if c["secret"] != want[v] {
			t.Errorf("v%d: got %q, want %q", v, c["secret"], want[v])
		}
	}
}

// totp mirrors the web player: XOR each char, join the decimals, use that string as the HMAC-SHA1 key.
func totp(secret string, t time.Time) string {
	key := ""
	for i, c := range []byte(secret) {
		key += strconv.Itoa(int(c) ^ (i%33 + 9))
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix()/30))
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	o := sum[len(sum)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[o:o+4])&0x7fffffff)%1000000)
}

// Hits open.spotify.com for real. Skip with: go test -short
func TestLiveSecretGetsToken(t *testing.T) {
	if testing.Short() {
		t.Skip("live test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	caps, err := grabLive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(caps) == 0 {
		t.Fatal("no secrets extracted")
	}
	latest := caps[0]
	for _, c := range caps {
		if c["version"].(float64) > latest["version"].(float64) {
			latest = c
		}
	}
	secret, ver := latest["secret"].(string), int(latest["version"].(float64))
	now := time.Now()

	q := url.Values{
		"reason":      {"init"},
		"productType": {"web-player"},
		"totp":        {totp(secret, now)},
		"totpServer":  {totp(secret, now)},
		"totpVer":     {strconv.Itoa(ver)},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://open.spotify.com/api/token?"+q.Encode(), nil)
	req.Header.Set("User-Agent", userAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("v%d: /api/token returned %s", ver, resp.Status)
	}
	var body struct {
		AccessToken    string `json:"accessToken"`
		TotpVerExpired string `json:"totpVerExpired"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.AccessToken == "" {
		t.Fatalf("v%d: no accessToken", ver)
	}
	if body.TotpVerExpired != "" {
		t.Errorf("v%d: totpVerExpired=%q", ver, body.TotpVerExpired)
	}
}
