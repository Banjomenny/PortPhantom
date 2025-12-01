# Feature Implementation Breakdown for Network Port Scanner

This document maps each required feature to the corresponding implementation in the provided codebase. Each section explains **where** the feature is implemented and **how** it is achieved.

---

## 1. Port Filtering (2 points)
**Where:**  
- Implemented in `parse_arguments()` with the `--display` option.  
- Used in `save_as_csv()` and `save_as_txt()` to filter results.

**How:**  
- Users can specify `--display all`, `--display open`, or `--display closed`.  
- The reporting functions check the state of each port and only include results that match the filter.



---

## 2. Scan Modes (1 point)
**Where:**  
- Implemented in `parse_arguments()` with `--portList` choices (`common`, `range`, `all`, `single`, `wellKnown`, `web`, `database`, `remoteAccess`, `fileShare`, `mail`).  
- Interactive mode (`textual_interface()`) also provides scan type selection.

**How:**  
- Quick scans use predefined sets like `common` or `web`.  
- Thorough scans use `all` (1–65535).  
- Users can tailor scans by selecting the mode.

---

## 3. Custom Port Lists (1 point)
**Where:**  
- Implemented in `parsePort(input)` function.  
- CLI option `-p, --port` allows custom lists.

**How:**  
- Users provide comma-separated ports.  
- The function parses and validates them into integers for scanning.

---

## 4. User-Friendly CLI (1 point)
**Where:**  
- Implemented in `parse_arguments()` using `argparse`.  
- Interactive mode in `textual_interface()` uses `rich` prompts and tables.

**How:**  
- Provides clear options, defaults, and help messages.  
- Interactive mode guides users step-by-step with visual tables.

---

## 5. Support for Scanning Multiple Targets (2 points)
**Where:**  
- Implemented in `getIPaddresses(address, threads)` for CIDR and ranges.  
- Functions `busybeeIFMultipleHosts()` and `busyBeeIFOneHost()` handle threading across multiple hosts.

**How:**  
- Expands CIDR or range notation into host lists.  
- Distributes scanning tasks across threads for simultaneous scanning.

---

## 6. Logging and Reporting (2 points)
**Where:**  
- Implemented in `save_as_csv()`, `save_as_txt()`, and `outputFile()`.

**How:**  
- Results are written to TXT or CSV files.  
- Includes timestamp, target, port mode, and scan results.  
- Provides persistent records for review.

---

## 7. Output Customization (1 point)
**Where:**  
- Controlled by CLI options `-out, --output-to-file` and `-f, --output-format`.  
- Implemented in `outputFile()`.

**How:**  
- Users can choose TXT or CSV format.  
- Filename can be specified or auto-generated.  
- Reports include banners and vulnerabilities when enabled.

---

## 8. Port Range Validation (1 point)
**Where:**  
- Implemented in `getIPaddresses()` for IP ranges.  
- Port validation in `parsePort()` and through dictionaries `common_ports_dict` and `wellKnownPorts`.

**How:**  
- Ensures valid ranges (e.g., octet ≤ 255).  
- Reserved/well-known ports are mapped to services, providing warnings or context.

---

## 9. Service Detection (1 point)
**Where:**  
- Implemented in `scan_port_connect()` with banner grabbing logic.  
- Uses `common_ports_dict` and `wellKnownPorts`.

**How:**  
- Attempts to read banners from services (FTP, SSH, SMTP, HTTP, etc.).  
- Identifies services based on port dictionaries.  
- Returns service name and banner in results.

---

## 10. IP Range Scanning (1 point)
**Where:**  
- Implemented in `getIPaddresses(address, threads)`.

**How:**  
- Supports CIDR notation (`192.168.1.0/24`).  
- Supports range notation (`192.168.1.1-50`).  
- Expands into host lists for scanning.

---

## 11. Security Scanning (2 points)
**Where:**  
- Implemented in `queryCpe()` and `rateVulnerabilities()`.  
- Integrated with `--servicescan` and `--show-vulns`.

**How:**  
- Queries NIST NVD via `nvdlib` using banners or service info.  
- Retrieves CVEs with severity ratings (Low, Medium, High, Critical).  
- Reports vulnerabilities alongside port/service results.  
Example: scanning Telnet (`port 23`) with `--show-vulns` will highlight known CVEs.
---

# Summary
All required features are implemented in the codebase:
- **Filtering, modes, custom lists, CLI, multi-target scanning, logging, output customization, validation, service detection, IP range scanning, and security scanning** are fully supported.  
- The scanner provides a comprehensive, user-friendly, and security-focused tool for network assessments.