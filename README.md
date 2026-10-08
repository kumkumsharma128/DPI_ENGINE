# DPI Engine (C++17)

A Deep Packet Inspection engine for network captures. It reads one or many `.pcap` files (or watches a
folder for new ones), tracks connections, identifies the application behind each one (YouTube, Facebook, ...)
**even for HTTPS**, applies blocking rules, and writes filtered captures plus a report.

```
pcap files / folder / watch -> PcapReader -> PacketParser -> Flow table -> Classifier -> Rules -> filtered pcaps + report
                                (24+16B hdrs)  Eth/IPv4/TCP/UDP  5-tuple map   SNI/Host/DNS   app/ip/domain
```

## Features
- Hand-written parsers for pcap (both byte orders), Ethernet (+VLAN), IPv4, **IPv6 (including extension headers)**, TCP, UDP. No libpcap needed.
- **Multiple inputs:** files, whole folders, or both in one run.
- **Near real-time watch mode:** processes new `.pcap` files as they appear (works with Wireshark/dumpcap rotating captures).
- **Flow table shared across files:** a connection that starts in one file and continues in the next is one flow.
- Bidirectional flow tracking via a canonical 5-tuple.
- **Site summary:** groups the many domains a browser contacts into a short list of likely-visited sites, and
  separates ads/trackers, browser/OS background traffic and shared assets (fonts, CDNs). Edit the one table in
  `src/sites.cpp` to teach it new domains.
- Classification from TLS ClientHello **SNI**, HTTP `Host:` header and DNS query names.
- Flow-level blocking by app, IP or domain substring.
- Bounds-checked extractors, tested with truncated and random input under ASan/UBSan.
- JSON export of per-flow results (for a dashboard).

## Build
```bash
make            # builds ./dpi_engine (g++ with C++17)
make sample     # generates samples/test_dpi.pcap
make test       # unit tests with sanitizers
```

## Usage
```bash
# one file
./dpi_engine samples/test_dpi.pcap

# one file, block rules, write filtered copy
./dpi_engine samples/test_dpi.pcap --out filtered.pcap --block-app YouTube --block-domain facebook

# many files / a whole folder, filtered copies go into a folder
./dpi_engine captures/ --out-dir filtered/ --block-app TikTok --json report.json

# near real-time: keep watching a folder (Ctrl+C prints the final report)
./dpi_engine --watch captures/ --block-app YouTube

# also print every domain seen (the default output shows the grouped site summary instead)
./dpi_engine mycapture.pcap --all-domains
```

Try the multi-file feature with the sample: `python3 tools/split_pcap.py samples/test_dpi.pcap parts 3` then `./dpi_engine parts/`.

### Capturing with Wireshark for watch mode
Wireshark -> Capture -> Options -> **Output** tab: set a folder and file name, tick "Create a new file
automatically after 10 seconds", and set the output format to **pcap** (not pcapng). Then run
`./dpi_engine --watch /mnt/c/your/capture/folder` inside WSL.

## Reading the site summary
A single page load contacts dozens of servers (images, fonts, ads, analytics), so a raw domain list is long and
misleading. The summary groups domains by site, and anything not tied to one site goes under "Everything else".
"No domain visible" shows how much traffic the engine could not name (mostly QUIC).
Note: "Sites & apps" means *likely visited*. An embedded tracker or login widget can make a site appear even if
the user never opened it, and the category of each domain is a best guess from its name.

## Limitations
- "Near real-time" means it processes finished capture files a few seconds after they are written.
  It does not sniff the network card live and cannot block live traffic.
- A file is treated as finished when its size stops growing; very slow traffic can fool this check.
- Packets before the ClientHello (SYN, handshake) are forwarded because the app is not known yet.
- No QUIC/HTTP3 support. On a real Chrome capture, QUIC was ~58% of packets, so most Google/YouTube traffic shows as
  "Unknown" unless QUIC is disabled in the browser (QUIC Initial packets are encrypted, SNI needs key derivation).
- No TCP reassembly (a ClientHello split across packets is missed); no Encrypted Client Hello.
- IP rules and printing use POSIX `inet_pton`/`inet_ntop` (Linux, macOS, WSL).
- In watch mode the flow table grows without limit (no idle-flow timeout yet).
- Only classic `.pcap`, not `.pcapng`.

## Roadmap
- [ ] Live capture with libpcap (Linux/macOS) and idle-flow timeouts
- [ ] Multi-threaded pipeline (hash(5-tuple) -> worker threads with per-thread flow tables)
- [ ] QUIC Initial packet decryption to read SNI, TCP stream reassembly, rules from a config file
- [ ] Web dashboard for report.json
