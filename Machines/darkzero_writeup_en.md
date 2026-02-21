# HackTheBox – DarkZero

**Difficulty:** Hard  
**OS:** Windows  
**Category:** Active Directory  
**Tags:** SMB, MSSQL, Linked Servers, Kerberos, CVE-2024-30088, DCSync

---

## Overview

DarkZero is a hard-difficulty Windows machine focused on Active Directory exploitation. The attack chain involves enumerating SMB shares, leveraging MSSQL linked servers to achieve remote code execution, escalating privileges via a local kernel vulnerability, and finally performing a credential delegation attack to compromise the entire domain.

---

## Reconnaissance

Start with a full port scan to identify exposed services. Pay close attention to ports commonly associated with Windows domain environments such as SMB, MSSQL, Kerberos, and WinRM.

Once the open services are identified, use modern SMB enumeration tools to map the domain and generate host entries for name resolution throughout the assessment.

> **Hint:** Look carefully at the Group Policy Objects stored in SYSVOL. They often reveal sensitive configuration details about the domain environment.

---

## Foothold – SMB Enumeration

Connect to the SYSVOL share using the provided credentials and recursively download all available files. Inside the Group Policy directory structure you will find configuration files that reveal:

- Privilege assignments for key domain groups
- Password policy settings
- Security hardening configurations

Analyzing these files gives you a clear picture of the domain's security posture and which accounts hold elevated privileges.

Use `rpcclient` to enumerate domain users and identify all accounts present on the domain controller.

---

## Database Access – MSSQL

With the credentials in hand, authenticate to the MSSQL service using Windows authentication. Once connected to the database, enumerate the available linked servers.

The environment contains a linked server pointing to a secondary domain controller. This linked server can be abused to:

1. Enable advanced options remotely
2. Enable `xp_cmdshell` on the remote instance
3. Execute operating system commands in the context of the SQL service account

> **Hint:** Linked server attacks allow you to execute queries and commands on remote SQL Server instances using the permissions of the linked server's mapped login.

---

## Remote Code Execution

Using the `xp_cmdshell` capability enabled on the linked server, deliver a reverse shell payload to the target. A staged Meterpreter payload delivered via PowerShell is effective here.

The workflow is:
- Generate a payload using Metasploit's web delivery module
- Host it on a local HTTP server
- Download and execute it from the victim via `xp_cmdshell`

This gives you an initial shell as the SQL service account on the secondary domain controller.

---

## Privilege Escalation – CVE-2024-30088

The target system is vulnerable to **CVE-2024-30088**, a Windows kernel privilege escalation vulnerability affecting Windows Server 2022. This vulnerability allows a local attacker to elevate privileges to `NT AUTHORITY\SYSTEM`.

Before exploiting it, establish persistence using a scheduled task and a registry run key to ensure your shell survives session drops — the exploit tends to kill the current session during execution.

Once persistence is confirmed and a stable session is available, use the Metasploit module for CVE-2024-30088 against your persistent session. A successful exploitation yields a SYSTEM-level Meterpreter session on DC02.

> **Hint:** Always use a **separate session** for the privilege escalation exploit — do not attempt to run it against your primary foothold session.

---

## Credential Capture – Kerberos TGT via Coercion

With SYSTEM privileges on DC02, the next objective is to capture a Kerberos Ticket Granting Ticket (TGT) for the DC01 machine account.

The technique involves:

1. Running **Rubeus** in monitor mode on DC02 to capture incoming Kerberos tickets
2. Coercing DC01 into authenticating to DC02 by triggering a UNC path request via MSSQL's `xp_dirtree`
3. Rubeus intercepts the TGT of `DC01$` as it authenticates

Once captured, convert the Base64-encoded ticket to a `.kirbi` file, then to a `.ccache` file suitable for use with Impacket tools.

> **Important:** Kerberos is time-sensitive. Ensure your attack machine's clock is synchronized with the domain controller to avoid `KRB_AP_ERR_SKEW` errors.

---

## Domain Compromise – DCSync

With a valid Kerberos ticket for the `DC01$` machine account exported to your environment:

```bash
export KRB5CCNAME=admin.ccache
```

Use Impacket's `secretsdump` with Kerberos authentication to perform a **DCSync** attack against DC01. This replicates the domain's credential database, revealing:

- NTLM hashes for all domain accounts
- Kerberos keys (AES-256, AES-128)
- The Administrator's NTLM hash

> **Note:** If you encounter SPN target name validation errors, try dumping specific users with the `-just-dc-user` flag first to confirm the technique works before running a full dump.

---

## Post-Exploitation – Administrator Access

With the Administrator's NTLM hash obtained via DCSync, authenticate to the domain controller using a Pass-the-Hash attack via **Evil-WinRM**:

```bash
evil-winrm -i <TARGET_IP> -u administrator -H <NTLM_HASH>
```

This provides a full interactive shell as the domain Administrator on DC01.

---

## Flags

| Flag | Location |
|------|----------|
| `user.txt` | Administrator's Desktop on DC01 |
| `root.txt` | Administrator's Desktop on DC01 |

---

## Attack Chain Summary

```
Credentials (john.w)
    │
    ├─► SMB SYSVOL Enumeration → GPO Analysis
    │
    ├─► MSSQL Authentication → Linked Server Abuse
    │
    ├─► xp_cmdshell RCE → Meterpreter Shell (svc_sql @ DC02)
    │
    ├─► CVE-2024-30088 → SYSTEM @ DC02
    │
    ├─► Rubeus Monitor + xp_dirtree Coercion → DC01$ TGT Capture
    │
    ├─► Ticket Conversion → DCSync Attack
    │
    └─► Administrator NTLM Hash → Pass-the-Hash → Domain Pwned 🏆
```

---

## Key Techniques & Tools

| Technique | Tool |
|-----------|------|
| SMB Enumeration | `smbclient`, `nxc` |
| Domain User Enumeration | `rpcclient` |
| MSSQL Access | `impacket-mssqlclient` |
| Linked Server Abuse | MSSQL T-SQL |
| Payload Delivery | Metasploit `web_delivery` |
| Privilege Escalation | CVE-2024-30088 (Metasploit) |
| Persistence | Scheduled Task + Registry Run Key |
| TGT Capture | `Rubeus` (monitor mode) |
| Authentication Coercion | `xp_dirtree` via MSSQL |
| Ticket Conversion | `impacket-ticketConverter` |
| DCSync | `impacket-secretsdump` |
| Pass-the-Hash | `evil-winrm` |

---

## Lessons Learned

- **SYSVOL is always worth checking** — Group Policy files can expose privilege configurations and password policies.
- **MSSQL Linked Servers** are a powerful lateral movement vector often overlooked in assessments.
- **Persistence before privilege escalation** — kernel exploits can be unstable; having a fallback shell is essential.
- **Machine account TGTs** can be just as powerful as user account tickets when the machine has domain replication rights.
- **Time synchronization matters** in Kerberos environments — always sync your clock with the DC before using Kerberos-based attacks.
