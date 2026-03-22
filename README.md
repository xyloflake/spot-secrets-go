# spot-secrets-go
Extracts TOTP secrets from Spotify's web player and updates hourly. Has base32 support unlike other versions. Rewritten in Go for fun.

## As a library

The `spotsecrets` package can be imported to generate TOTP codes for Spotify's `/api/token` endpoint:

```go
import "github.com/xyloflake/spot-secrets-go/spotsecrets"

code, version, err := spotsecrets.GenerateTOTP()
// Use as query params: ?totp={code}&totpServer={code}&totpVer={version}
```

Or fetch secrets and compute TOTP separately:

```go
dict, _ := spotsecrets.FetchSecrets()
ver, cipher := spotsecrets.LatestVersion(dict)
code, _ := spotsecrets.ComputeTOTP(cipher)
```

## As a CLI

The CLI extracts fresh secrets from Spotify's web player using headless Chrome and writes them to `secrets/`:

```bash
go run main.go
```

This is run hourly by the GitHub Actions workflow to keep the secret files up to date.

## Credits
[Original work](https://github.com/misiektoja/spotify_monitor/blob/dev/debug/spotify_monitor_secret_grabber.py) by @misiektoja.
