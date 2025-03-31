# 403 Bypass Tool

## Overview
This tool is designed to bypass 403 Forbidden restrictions using various header manipulations and path alterations. It automates sending multiple requests with different headers to detect potential misconfigurations in web security.

## Features
- Uses **random User-Agents** to evade detection.
- Implements **custom header payloads** to attempt 403 bypass.
- Supports **port-based bypass techniques**.
- **Concurrent worker threads** for faster execution.
- Ability to **scan multiple targets** using a domains file.
- **Error handling and validation** for cleaner results.
- **Verbose mode** to display detailed errors.

## Installation
1. Install Go if not already installed:  
   ```sh
   sudo apt install golang  # Debian/Ubuntu
   brew install go          # macOS
   choco install golang     # Windows (Chocolatey)
   ```
2. Clone the repository:  
   ```sh
   git clone https://github.com/403-X.git
   cd 403-X
   ```
3. Build the tool:  
   ```sh
   go build -o 403-x
   ```

## Usage
```sh
./403-X -t <target_url> -p <path_to_check> -w <workers> -timeout <seconds> -v
```

### Arguments
| Argument | Description |
|----------|-------------|
| `-t` | Single target URL to check (e.g., `http://example.com`) |
| `-d` | File with domains to check (e.g., `domains.txt`) |
| `-p` | Path to check for bypass attempts (e.g., `admin`) |
| `-w` | Number of concurrent workers (default: 10) |
| `-timeout` | HTTP request timeout (default: 10s) |
| `-v` | Verbose mode for detailed output |

## Example Usage
### Single Target Scan
```sh
./403-X -t http://example.com -p admin -w 10 -timeout 5s
```

### Multiple Domains Scan
```sh
./403-X -d domains.txt -p admin -w 20 -timeout 5s -v
```

## Notes
- Make sure to have a `bypasses.txt` file containing bypass payloads.
- Ensure your target URL is properly formatted (e.g., `http://example.com`).

## Disclaimer
This tool is intended for security testing and educational purposes only. Unauthorized testing on systems you do not own is illegal.

## Author
**Whoamikiddie**