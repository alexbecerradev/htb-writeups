# Forensic Investigation Report: backup-secondary

## 1. Executive Summary
An investigation was conducted on the host `backup-secondary` following alerts of unauthorized access. The analysis confirmed a successful compromise via an unauthenticated remote access service, leading to data exfiltration and the establishment of persistence pointing to an external Command and Control (C2) infrastructure.

---

## 2. Initial Access & Exploitation
* **Vulnerability**: The system was accessible via an unencrypted management protocol.
* **Exploitation**: The attacker exploited a known vulnerability (CVE-2026-24061) to gain immediate root-level access.
* **Attacker Source**: Initial commands originated from a local network neighbor at `192.168.72.131`.

---

## 3. Post-Exploitation Activity
### Data Discovery
The attacker performed reconnaissance on the `/opt` directory, identifying a database file containing sensitive financial information: `credit-cards-25-blackfriday.db`.

### Exfiltration Method
Instead of using standard file transfer tools, the attacker utilized a built-in interpreter to spawn a temporary web server:
* **Tool**: Python 3 `http.server`.
* **Port**: 6932.
* **Timestamp**: The file was successfully requested and transferred on **2026-01-27 at 10:49:54 UTC**.

---

## 4. Persistence & C2 Infrastructure
To maintain access, a persistence script (`linper.sh`) was executed. This script configured the system to communicate with an external entity:
* **C2 IP Address**: 91.99.25.54.
* **Mechanism**: Use of system schedulers and service managers to ensure the connection survives a reboot.

---

## 5. Digital Forensics Procedure (Step-by-Step)
To replicate the findings or analyze the exfiltrated data, follow these steps:

1. **Traffic Analysis**: Filter the packet capture for the attacker's temporary server:
   `tcp.port == 6932`.
2. **Object Recovery**: Use Wireshark's "Export Objects" feature for the HTTP protocol to save the `.db` file locally.
3. **Database Analysis**: Open the recovered file in a SQLite-compatible viewer (e.g., DB Browser for SQLite).
4. **Data Validation**: Query the `purchases` table to identify compromised customer records, ensuring the correct interpretation of `INTEGER` fields which may not render properly in plain text streams.
5. **Command Reconstruction**: Follow the TCP Stream of the initial exploitation session to see the exact sequence of commands typed by the attacker.

---

## 6. Recommendations
* Discontinue the use of unencrypted protocols for remote management.
* Implement strict egress filtering to block unauthorized connections to unknown external IPs (C2).
* Encrypt sensitive databases at rest to prevent plain-text exposure during exfiltration.