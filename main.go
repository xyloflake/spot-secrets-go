package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/chromedp/cdproto/page"
)

var bundleRe = regexp.MustCompile(`(?:vendor~web-player|encore~web-player|web-player)\.[0-9a-f]{4,}\.(?:js|mjs)`)

const timeout = 45 * time.Second

type Secret struct {
	Version int    `json:"version"`
	Secret  string `json:"secret"`
}

type SecretBytes struct {
	Version int   `json:"version"`
	Secret  []int `json:"secret"`
}

type SecretDict map[string][]int

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

	writeJSONPretty("secrets/secrets.json", formattedData)
	writeJSON("secrets/secretBytes.json", secretBytes)
	writeJSON("secrets/secretDict.json", secretDict)

	fmt.Println(formattedData)
	fmt.Println(secretBytes)
	fmt.Println(secretDict)
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

// well guess what, go doesn't have puppeteer stealth
// this just imitates it
const stealth = `(function () {
	// navigator.webdriver
	Object.defineProperty(navigator, 'webdriver', { get: () => false });

	// languages
	Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });

	// plugins
	Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });

	// chrome runtime object
	window.chrome = { runtime: {} };

	// permissions
	const originalQuery = window.navigator.permissions.query;
	window.navigator.permissions.query = (parameters) => (
		parameters.name === 'notifications' ?
			Promise.resolve({ state: Notification.permission }) :
			originalQuery(parameters)
	);

	// WebGL vendor/renderer
	const getParameter = WebGLRenderingContext.prototype.getParameter;
	WebGLRenderingContext.prototype.getParameter = function (param) {
		if (param === 37445) return 'Intel Inc.';
		if (param === 37446) return 'Intel Iris OpenGL Engine';
		return getParameter.call(this, param);
	};
})();`

func grabLive(ctx context.Context) ([]map[string]interface{}, error) {
	hook := `(()=>{if(globalThis.__secretHookInstalled)return;
	globalThis.__secretHookInstalled=true;
	globalThis.__captures=[];
	Object.defineProperty(Object.prototype,'secret',{configurable:true,set:function(v){
		try{__captures.push({secret:v,version:this.version,obj:this});}catch(e){}
		Object.defineProperty(this,'secret',{value:v,writable:true,configurable:true,enumerable:true});}});
	})();`

	var caps []map[string]interface{}

	if err := chromedp.Run(ctx,
		// Apply stealth first
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(stealth).Do(ctx)
			return err
		}),
		// Install hook
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(hook).Do(ctx)
			return err
		}),
	); err != nil {
		return nil, err
	}

	fmt.Println("Opening Spotify...")
	if err := chromedp.Run(ctx,
		chromedp.Navigate("https://open.spotify.com"),
		chromedp.Sleep(3*time.Second),
		chromedp.EvaluateAsDevTools(`globalThis.__captures || []`, &caps),
	); err != nil {
		return nil, err
	}

	for _, c := range caps {
		if s, ok := c["secret"].(string); ok {
			if v, ok := c["version"].(float64); ok {
				fmt.Printf("Secret(%d): %s\n", int(v), s)
			}
		}
	}

	return caps, nil
}


func main() {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		// Headless mode but still needs to look real
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-setuid-sandbox", true),
	)

	ctx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel = chromedp.NewContext(ctx)
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, timeout)
	defer cancel()

	caps, err := grabLive(ctx)
	if err != nil {
		log.Fatal("Error:", err)
	}
	summarise(caps)
}
