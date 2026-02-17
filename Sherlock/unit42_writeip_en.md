# HTB Sherlock — Unit42
## Forensic Analysis Guide with Sysmon

---

## Case Overview

This Sherlock simulates incident response on a Windows machine where a user executed a malicious file downloaded from the Internet. The goal is to reconstruct the attack chain by analyzing **Sysmon** (Sysinternals System Monitor) logs exported in `.evtx` format.

The main evidence file is:
```
Microsoft-Windows-Sysmon-Operational.evtx
```

---

## Tools Used

- **PowerShell** — to parse and filter `.evtx` events
- **Windows Event Viewer** — for visual exploration
- **Sysmon** — source of the logs (must be installed on the analyzed system)

---

## Relevant Sysmon Event IDs

| Event ID | Description |
|----------|-------------|
| 1  | Process Create — process started |
| 2  | File Creation Time Changed — Time Stomping |
| 3  | Network Connection — outbound connections |
| 5  | Process Terminated — process ended |
| 11 | File Create — file written to disk |
| 22 | DNS Query — domain name resolution |

---

## General Methodology

### 1. Identify the Malicious Process (Event ID 1)

The entry point is always an **Event ID 1** showing which process was executed, from where, who launched it, and what the parent process was.

Key fields to review:
- `Image` — path of the executable
- `OriginalFileName` — original binary name (may differ from the name on disk)
- `ParentImage` — process that spawned it
- `CommandLine` — execution arguments
- `Hashes` — SHA256/MD5 for VirusTotal lookup

```powershell
Get-WinEvent -Path ".\Microsoft-Windows-Sysmon-Operational.evtx" |
Where-Object { $_.Id -eq 1 } |
ForEach-Object { $_.ToXml() } |
Select-String -Pattern "Image|CommandLine|OriginalFileName"
```

---

### 2. Trace the Download Origin (Event ID 22 — DNS)

To find out which service the malware was downloaded from, look for DNS queries made by the browser just before execution.

```powershell
Get-WinEvent -Path ".\Microsoft-Windows-Sysmon-Operational.evtx" |
Where-Object { $_.Id -eq 22 } |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time      = $_.TimeCreated
        Image     = ($data | Where-Object Name -eq "Image")."#text"
        QueryName = ($data | Where-Object Name -eq "QueryName")."#text"
    }
} | Format-Table -AutoSize
```

> Correlate the malware execution timestamp with prior DNS queries to identify the download domain.

---

### 3. Detect Time Stomping (Event ID 2)

Malware can modify file creation timestamps on dropped files to make them appear older and blend in with legitimate files. Sysmon records this with **Event ID 2**.

Key fields:
- `TargetFilename` — the modified file
- `CreationUtcTime` — the **fake** timestamp applied by the malware
- `PreviousCreationUtcTime` — the **real** original timestamp

```powershell
Get-WinEvent -Path ".\Microsoft-Windows-Sysmon-Operational.evtx" |
Where-Object { $_.Id -eq 2 } |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TargetFile  = ($data | Where-Object Name -eq "TargetFilename")."#text"
        FakeDate    = ($data | Where-Object Name -eq "CreationUtcTime")."#text"
        RealDate    = ($data | Where-Object Name -eq "PreviousCreationUtcTime")."#text"
    }
} | Format-List
```

---

### 4. Files Dropped to Disk (Event ID 11)

**Event ID 11** records every file created on the system. It allows you to identify what files the malware left behind and where.

```powershell
Get-WinEvent -Path ".\Microsoft-Windows-Sysmon-Operational.evtx" |
Where-Object { $_.Id -eq 11 } |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time       = $_.TimeCreated
        Image      = ($data | Where-Object Name -eq "Image")."#text"
        TargetFile = ($data | Where-Object Name -eq "TargetFilename")."#text"
    }
} | Where-Object { $_.Image -like "*<malicious_process>*" } | Format-Table -AutoSize
```

> Replace `<malicious_process>` with the binary name identified in step 1.

---

### 5. Evasion Techniques — Signed Binary Proxy Execution (T1218)

Check whether the malicious process spawns legitimate Windows binaries (such as `msiexec.exe`, `regsvr32.exe`, `rundll32.exe`) to execute its payload covertly. This is detected in **Event ID 1** by reviewing the `ParentImage` field.

This technique is catalogued in MITRE ATT&CK as:
- **T1218** — Signed Binary Proxy Execution

---

### 6. Process Termination (Event ID 5)

**Event ID 5** records when a process ends. Droppers typically self-terminate immediately after completing their work.

```powershell
Get-WinEvent -Path ".\Microsoft-Windows-Sysmon-Operational.evtx" |
Where-Object { $_.Id -eq 5 } |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time  = $_.TimeCreated
        Image = ($data | Where-Object Name -eq "Image")."#text"
    }
} | Where-Object { $_.Image -like "*<malicious_process>*" } | Format-List
```

---

## General Attack Flow

```
User downloads file from Cloud Drive (browser)
        ↓
User manually executes the file (T1204 - User Execution)
        ↓
Malware launches msiexec.exe to install payload (T1218 - Signed Binary Proxy Execution)
        ↓
Malware drops files to disk and applies Time Stomping (T1070.006)
        ↓
Malware self-terminates
        ↓
Backdoor installed and active on the system
```

---

## Analysis Tips

- **Always filter by time window** — correlate events by timestamp to reconstruct the exact chain.
- **Use `Format-List` instead of `Format-Table`** when fields are long to avoid truncation.
- **Event ID 22 (DNS) is key** for identifying external domains contacted by the malware.
- **Search VirusTotal** with the SHA256 hashes from Event ID 1 to confirm whether a binary is malicious.
- **Correlate Event ID 2 and 11** together to understand which files were dropped and which had their timestamps manipulated via Time Stomping.

---

*Analysis performed on Sysmon logs from machine `DESKTOP-887GK2L`, user `CyberJunkie`.*  
*Incident date: 2024-02-14*
