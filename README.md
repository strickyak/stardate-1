# Stardate

A micro-blogging and note-taking web server in Go serving over HTTPS (with automatic self-signed certificate generation) and optional HTTP, featuring HTTP Basic Authentication (`--pwfile` and/or shared `--pw`), AES-256-GCM encrypted private notes for crypto users, and three editor modes (**Plain Text**, **Markdown**, and embedded **Quill Rich Text**).

## Features

- **Private by Default**:
  - All posts default to **private** (`"is_public": false`). If `"is_public"` is omitted in JSON storage, the note is treated as private.
  - Making a note public requires checking **both** confirmation checkboxes (`public1` and `public2`, labeled `"public note (check both)"`).
  - Displays up to the 100 most recent messages that are either public or authored by the currently logged-in user.
- **Flexible Authentication (`--pwfile` and `--pw`)**:
  - **Per-User JSONL Password File (`--pwfile=FILEPATH.jsonl`)**:
    - Each line is a JSON object with keys `"handle"`, `"display"`, `"pw"`, and/or `"pwhash"`.
    - `"handle"` must be ASCII `[a-z0-9_]+` (case-insensitive, normalized to lowercase).
    - `"display"` (optional, supports Unicode) is used as the user's display/author name on non-crypto logins; falls back to the normalized `"handle"` if omitted.
    - Supports plaintext `"pw"` or salted hash `"pwhash"` (`hex(SHA-256(salt + pw))`).
  - **Shared Password (`--pw=STRING`)**:
    - Optional shared base password for any username. If `--pw` is empty or unspecified, shared-password logins are disabled.
  - **Reliable Logout**: Uses a session logout cookie (`stardate_logout=1`) so logging out persists across page refreshes even if the browser caches Basic Auth credentials.
- **Crypto Users & Symmetric Encryption**:
  - **Enhanced Password Rule**: To log in as a **Crypto User**, the Basic Auth password must be `BasePassword + "/" + AtLeast12AsciiChars` (a literal `/` followed by at least 12 ASCII characters). Any other extra suffix after `BasePassword` is rejected.
  - **Crypto Username**: First 10 hex digits of `SHA-256(salt + username_or_handle + entire_password)`. Crypto logins always use this 10-hex-digit identifier as their display/author name.
  - **Symmetric Crypto Key**: Full 32-byte `SHA-256(username_or_handle + entire_password)` key used to encrypt private notes with **AES-256-GCM** (stored as Base64 in `messages.json`) and decrypt them on the fly when viewed by that crypto user.
  - **No-Cache Protection**: Responses set `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` and `Pragma: no-cache` so browsers do not cache decrypted notes on disk.
- **Three Editor Modes & Server-Side Sanitization**:
  - **Plain Text (`"text"`)**: Standard textarea; HTML-escaped with preserved line breaks.
  - **Markdown (`"markdown"`)**: Monospace Markdown source editor; rendered server-side with `goldmark` (GitHub Flavored Markdown) and sanitized with `bluemonday`.
  - **Rich Text (`"html"`)**: Interactive WYSIWYG **Quill 2.0** editor embedded directly in the Go binary (`//go:embed`, zero external CDN requests) and sanitized server-side with `bluemonday`.
- **In-Place Post Editing**:
  - Logged-in users see an **EDIT** button on any post they authored, allowing them to update content, editor format, and public/private visibility (automatically re-encrypting private notes for crypto users).
- **Timestamps & Stardates**: Every message is stamped with its UTC creation time and calculated Stardate.
- **HTTPS & Optional HTTP**:
  - Generates an in-memory self-signed ECDSA TLS certificate out-of-the-box (or loads/persists PEM files if `--cert` and `--key` are specified).
  - Supports an optional plain HTTP listener (`--http=localhost:8080`) for local testing.
- **JSON API Support**: Append `?format=json` or send `Accept: application/json` to query messages and the current stardate in JSON format.

## Project Structure

```
.
├── cmd/
│   └── stardate/
│       └── main.go              # CLI entrypoint and flag parsing
├── server/
│   ├── assets/
│   │   ├── quill.js             # Embedded Quill 2.0.3 editor script
│   │   └── quill.snow.css       # Embedded Quill Snow theme stylesheet
│   ├── cert.go                  # Self-signed TLS certificate generation & loading
│   ├── cert_test.go             # Certificate unit tests
│   ├── crypto.go                # SHA-256 identity/password hashing & AES-256-GCM encryption
│   ├── crypto_test.go           # Encryption & identity unit tests
│   ├── format.go                # Markdown rendering (goldmark), HTML sanitization (bluemonday), static assets
│   ├── format_test.go           # Rendering, XSS sanitization, Quill, and post editing tests
│   ├── server.go                # HTTPS/HTTP servers, auth, handlers, and UI template
│   ├── server_test.go           # Server integration, auth, and --pwfile tests
│   ├── store.go                 # Thread-safe JSON message persistence, filtering, and updates
│   └── store_test.go            # Message visibility, persistence, and limit unit tests
├── .gitignore
├── go.mod
├── go.sum
└── README.md
```

## Running the Server

### With a JSONL Password File (`--pwfile`)

Create a `users.jsonl` file:

```jsonl
{"handle": "spock", "display": "Spock 🖖", "pw": "llap"}
{"handle": "kirk", "display": "Capt. Kirk", "pwhash": "<hex-sha256-of-salt+password>"}
```

Start the server:

```bash
go run ./cmd/stardate --pwfile=users.jsonl --salt="my-starfleet-salt" -https=:8443
```

### With a Shared Password (`--pw`)

```bash
go run ./cmd/stardate --pw=secretpass --salt="my-starfleet-salt" -https=:8443 --http=localhost:8080
```

### Command-line Options

```bash
go run ./cmd/stardate -help
```

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-https` | `":8443"` | HTTPS server listen address |
| `--http` | `""` | Optional HTTP server listen address for testing (e.g. `--http=localhost:8080`) |
| `--pw` | `""` | Shared password for Basic authentication (if empty, shared-password logins are disabled) |
| `--pwfile` | `""` | Path to JSONL password file (`handle`, `display`, `pw`, `pwhash`) |
| `--salt` | `""` | Salt string for deriving crypto usernames and verifying `pwhash` |
| `--data` | `"messages.json"` | Path to JSON file for persisting messages (empty for in-memory only) |
| `--cert` | `""` | Path to TLS certificate PEM file (if empty, an in-memory self-signed cert is generated) |
| `--key` | `""` | Path to TLS private key PEM file |
| `--hosts` | `"localhost,127.0.0.1,::1"` | Comma-separated hostnames and IPs for generated certificate SANs |

## Usage

### In the Browser

1. Navigate to `https://localhost:8443` (or `http://localhost:8080` if `--http` is enabled).
2. Click **LOGIN** at the top right and enter your Basic Auth credentials:
   - **Standard Login**: `handle:pw` (from `--pwfile`) or `username:shared_pw` (if `--pw` is set). Displays your `"display"` name (if configured) or username/handle.
   - **Crypto Login**: `handle:pw/AtLeast12AsciiChars` (or `username:shared_pw/AtLeast12AsciiChars`). Displays your 10-hex-digit Crypto Username (`SHA-256(salt + handle + entire_password)[:10]`) with a **Crypto** badge, and encrypts all your private notes with AES-256-GCM.
3. Click **New Note**, choose **Plain Text**, **Markdown**, or **Rich Text (Quill)**, and click **Publish**:
   - Leave the checkboxes unchecked to save a **Private** note (visible only to you, and AES-256-GCM encrypted at rest if logged in as a Crypto User).
   - Check **both** `"public note (check both)"` checkboxes to publish a **Public** entry.
4. Click **EDIT** on any of your own posts to modify its content, format, or visibility.

### Command Line / cURL

View recent public messages as JSON:
```bash
curl -k "https://localhost:8443/?format=json"
```

Post a public Markdown entry (requires both `public1=1` and `public2=1`):
```bash
curl -k -u spock:llap \
  -d "format=markdown" \
  -d "content=**Sensor log**: all systems *nominal*." \
  -d "public1=1" -d "public2=1" \
  https://localhost:8443/post
```

Post an encrypted private note as a Crypto User (neither public checkbox checked):
```bash
curl -k -u "spock:llap/vulcan_mind_meld_123" \
  -d "format=markdown" \
  -d "content=Classified Vulcan high command telemetry" \
  https://localhost:8443/post
```

Edit an existing post (`edit_id=1`):
```bash
curl -k -u spock:llap \
  -d "edit_id=1" \
  -d "format=markdown" \
  -d "content=**Sensor log**: updated reading." \
  -d "public1=1" -d "public2=1" \
  https://localhost:8443/post
```

## Testing

Run the full test suite:

```bash
go test -v ./...
```
