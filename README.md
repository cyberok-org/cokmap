# Cokmap 🚀

**Cokmap** — это быстрый сетевой сканер, написанный на Go, который определяет протоколы и сервисы на открытых портах, отправляя различные пробы из файла `nmap-service-probes`.

## 🔥 Особенности
- **Высокая скорость** сканирования и определения протоколов и ПО на открытых портах.
- **Поддержка формата nmap-service-probes** — [подробнее о формате](https://nmap.org/book/vscan-fileformat.html).
- **Кросс-платформенность** — работает на Linux и macOS.
- **Гибкие настройки**
- **Детальная статистика**

## ⚙️ Установка
### Сборка из исходников
1. Убедитесь, что у вас установлен **Go** (версия 1.24.2+).
2. Клонируйте репозиторий и собирите:
    ```bash
    git clone https://github.com/cyberok-org/cokmap.git
    cd cokmap
    go build -o cokmap ./cmd/.
    ```
3. Получите актуальную версию `nmap-service-probes`
    ```bash
    curl -O https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes
    ```


**Готовые релизы можно скачать в разделе [Releases](https://github.com/cyberok-org/cokmap/releases).**

## Использование

### Input file format:
```text
192.168.0.1:8080/tcp
192.168.0.1:443/tcp
192.168.0.1:8080/udp
```
### Example
- Сканирование одного таргета:
    ```bash
    echo 192.168.0.1:8080/tcp | ./cokmap -plugin plugin/pm_[YOUR_GOOS].so -n nmap-service-probes -o result.json
    ```
- Сканирование списка таргетов:
    ```bash
    ./cokmap -plugin plugin/pm_[YOUR_GOOS].so  -i targets -n nmap-service-probes -o result.json
    # или
    cat targets | ./cokmap -plugin plugin/pm_[YOUR_GOOS].so  -n nmap-service-probes -o result.json
    ```



## Help
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

## 📄 Лицензия

MIT License. Подробнее в файле [LICENSE](LICENCE.md).