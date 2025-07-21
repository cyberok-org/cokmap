# Cokmap 🚀

**Cokmap** — is a fast network scanner written in Go that identifies services and products on open ports by sending probes from an `nmap-service-probes` -formatted file, following the rules described in [Technique Described](https://nmap.org/book/vscan-technique.html).

## 🔥 Features
- **High-speed  scanning**
- **Fast product detection** via `pm_[YOUR_GOOS].so` plugin
- **Supports nmap-service-probes format** — [details here](https://nmap.org/book/vscan-fileformat.html).
- **Works on Linux and macOS**
- **Flexible configuration**
- **Detailed statistics**

## 🛠️ Installation
### Build from source
1. Ensure Go  is installed **Go** (version 1.24.2+).
2. Clone the repository and build:
    ```bash
    git clone https://github.com/cyberok-org/cokmap.git
    cd cokmap
    go build -o cokmap ./cmd/.
    ```
3. Download the latest `nmap-service-probes`
    ```bash
    curl -O https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes
    ```


**Pre-built releases are available in the [Releases](https://github.com/cyberok-org/cokmap/releases) section.** 

## ⚙️ Usage

### Input file format:
```text
192.168.0.1:8080/tcp
192.168.0.1:443/tcp
192.168.0.1:8080/udp
```
### Example
- Scan a single target:
    ```bash
    echo 192.168.0.1:8080/tcp | ./cokmap -plugin plugin/pm_[YOUR_GOOS].so -n nmap-service-probes -o result.json
    ```
- Scan a list of targets:
    ```bash
    ./cokmap -plugin plugin/pm_[YOUR_GOOS].so  -i targets -n nmap-service-probes -o result.jsonl
    # or
    cat targets | ./cokmap -plugin plugin/pm_[YOUR_GOOS].so  -n nmap-service-probes -o result.jsonl
    ```



## ❓ Help
```text
    ./cokmap [flags]

Flags:
    INPUT:
        -i string Input filename, use - for stdin (default "-") format  ip:port/protocol
    TIMEOUT:
        -crt int Set connection read timeout in seconds (default 5)
        -cst int Set connection send timeout in seconds (default 5)
        -ct int Set connection to host timeout in seconds (default 5)
        -ret int Set regexp match timeout in seconds (default 1)
    RATE-LIMIT:
        -tm int process numbers using during parsing (default 10)
        -tr int process numbers using during scanning (default 10)
    MATCHERS:
        -plugin string Name of product matcher dynamic plugin file (default "../plugin/pm.so")
        -fr bool Enable softmatch parsing (default true)
    PROBES:
        -n string A flat file to store the version detection probes and match strings (default "./nmap-service-probes")
        -n-extra string Extra, golden probes to expand"nmap-service-probes"
        -pc int Sets the count of sending probes by rarity, dont disable others probes by ports, usefull for quickiest runtime (default 5)
        -probes-cfg string ini file for probes specifiations, sets which regular expression have different format, which indicates where need to convert banner
        -use-NULL Use NULL probe in dialer service (default false)
    OUTPUT:
        -o string Output filename, use - for stdout (default "-")
        -v int Output more information during service scanning 0=Error 1=Warning 2=Info 3=Debug
        -sr int Sets the intensity level of a version scan to the specified value (default 7)
        -stat bool Save summary grab results (default true)
        -err-stat bool Save errors summary (default true)
        -p-stat bool Save successful-probes summary (default true)
        -file-stat-name string Save successful-match summary (default "summary_cokmap_result")
        -bs int Output banner limit size: negative int = fullsize, 0 = without banner (default fullsize)
```

## 🛠️ Building custom plugins
For plugin documentation, see [Go Plugin Documentation](https://pkg.go.dev/plugin)

To create custom product matchers, use types defined in [types.go](https://github.com/cyberok-org/cokmap-api/blob/main/types/types.go).
Plugins must implement:
```go
func LoadMatchers(in io.Reader, timeout time.Duration) (types.Matchers, error)
func ExtractProductsFromRunes(matchers types.Matchers, input []rune, ip string) ([]types.HostInfo, []error)
```



## 📄 License

MIT License. Details in [LICENSE](LICENCE.md).
