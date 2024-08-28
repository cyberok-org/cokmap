# cokmap

python version for [nmap_cokmap](https://github.com/nixawk/nmap_vscan) nmap service and application version detection (without nmap installation)
golang version for [nmap_cokmap](https://github.com/RickGray/vscan-go) nmap service and application version detection (without nmap installation)

## Input

 **EXAMPLE**:

- `192.168.0.1:8080/tcp`

- `192.168.0.1:8080/udp`

```text
cokmap can determine security protocol. by port:443 and application layer protocols what can be provided in input - it means what first probes will send like usual to these protocols  what provide high performance products detection

cokmap by default always send security-like packets if security protocol was not defined or excluded (udp,http)
```

**Default is protocol is** `TCP`
 **supported** `UDP/TCP`

**Application layer and external** `http`

## Building

Build:

```text
cd cmd
go build .

./cokmap -n ./nmap-service-probes -i ./example-input  
```

## Usage

```text
Usage:
      ./cokmap [flags]
Flags:
USAGE:
  -h
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
  -r int how mutch retries to dial connection (default 0)
MATCHERS:
  -fr bool Enable softmatch parsing (default true)
PROBES:
  -n string A flat file to store the version detection probes and match strings (default "./nmap-service-probes")
  -nop bool Use NULL probe to probe service only (dafault false)
  -p bool Use all probes after failed filtered probes (dafault false)
  -n-extra string Extra, golden probes to expand"nmap-service-probes"
  -pc int Sets the count of sending probes by rarity, dont disable others probes by ports, usefull for quickiest runtime (default 5)
  -probes-cfg string ini file for probes specifiations, sets which regular expression have different format, which indicates where need to convert banner
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

Specailly, `cokmap` use [NMap](https://github.com/nmap/nmap) cokmap probe file - [nmap-service-probes](https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes) to detect service, you can download and use it directly:

```text
wget https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes -O ./nmap-service-probes

cokmap -n ./nmap-service-probes -h
```

if you want more details about cokmap, see [https://nmap.org/book/cokmap.html](https://nmap.org/book/cokmap.html).

## Example

With [masscan](https://github.com/robertdavidgraham/masscan):

```text
masscan -p1-65535,U:1-65535 --excludefile=blacklist.conf 0.0.0.0/0 | awk -F '/' '{print $1" "$2}' | awk '{print $7":"$4"/"$5}' | cokmap cokmap -n ./nmap-service-probes | jq
```

With [zmap](https://github.com/zmap/zmap):

```text
zmap -p 80 | awk '{print $1":80"}' | cokmap -n ./nmap-service-probes | jq
```
