<img width="300" height="168" alt="image" src="https://github.com/user-attachments/assets/72e32e5a-b839-42c9-aa03-3a9a81ab96e4" />


# Threat Hunt Report: Unauthorized TOR Usage

> Portfolio project based on Microsoft Defender for Endpoint telemetry exported from the investigation. All timestamps and observations below were aligned to the supplied screenshots and CSV exports.


## Scenario
Management suspects that a user may be using the TOR browser to bypass network restrictions and generate anonymous outbound traffic. The objective of this hunt is to determine whether TOR artifacts exist on disk, whether TOR-related processes were launched, and whether those processes generated network connections consistent with active TOR usage.

---

## Platforms and Languages Leveraged
- Windows endpoint telemetry
- Microsoft Defender for Endpoint (MDE)
- Kusto Query Language (KQL)
- TOR Browser

---

## High-Level IoC Discovery Plan
- Check `DeviceFileEvents` for TOR-related files, browser profile artifacts, and recent-item shortcuts.
- Check `DeviceProcessEvents` for execution of `firefox.exe` and `tor.exe` from the TOR Browser directory.
- Check `DeviceNetworkEvents` for local proxy activity and outbound connections from `tor.exe` over TOR-related ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table
I reviewed file activity related to the TOR Browser directory and associated artifacts. The results showed multiple TOR profile files being created and modified under the Desktop-based TOR Browser installation path, along with shortcut evidence showing user interaction.
<img width="1157" height="543" alt="Screenshot 2026-03-01 235410" src="https://github.com/user-attachments/assets/51203b5b-fd50-48f1-ac6c-cadc437a3006" />


**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "bigp"
| where FileName contains "tor" or FolderPath contains "Tor Browser"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account
| order by Timestamp desc
```

**MITRE ATT&CK Mapping:**
- **T1204.002 – User Execution: Malicious File**  
  Evidence: TOR Browser files and shortcuts were created in the user context.
- **T1105 – Ingress Tool Transfer**  
  Evidence: TOR-related application files were present on disk and subsequently used.

---

### 2. Searched the `DeviceProcessEvents` Table for `tor.exe`
I isolated `tor.exe` process creation events to validate that the TOR runtime itself executed on the endpoint. The screenshot evidence shows repeated launches of `tor.exe` from the TOR Browser installation path.

<img width="1136" height="428" alt="Screenshot 2026-03-01 235923" src="https://github.com/user-attachments/assets/316520b6-a75c-4965-8e56-700e000000ce" />
That is strong evidence that the TOR runtime fully initialized.


**Query used to locate events:**


```kql
DeviceProcessEvents
| where DeviceName == "bigp"
| where AccountName == "bigp"
| where FileName == "tor.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```


**MITRE ATT&CK Mapping:**
- **T1204.002 – User Execution: Malicious File**  
  Evidence: the user context `bigp` launched `tor.exe` from the TOR Browser directory.
- **T1090.003 – Proxy: Multi-hop Proxy**  
  Evidence: `tor.exe` process execution is consistent with anonymized proxy routing through the TOR network.

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution
I then reviewed broader TOR-related process activity for both `firefox.exe` and `tor.exe`. The screenshots show repeated launches of TOR's bundled Firefox browser from the Desktop installation path, along with recurring `tor.exe` execution.
<img width="1137" height="425" alt="Screenshot 2026-03-01 235931" src="https://github.com/user-attachments/assets/437c2afb-fbd2-417d-bf0a-4d07af4a368d" />


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "bigp"
| where AccountName == "bigp"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```

**MITRE ATT&CK Mapping:**
- **T1071.001 – Application Layer Protocol: Web Protocols**  
  Evidence: the TOR Browser used Firefox-based web processes to generate browser activity.
- **T1090.003 – Proxy: Multi-hop Proxy**  
  Evidence: browser execution is tied to the TOR anonymization workflow.

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections
To validate that TOR execution resulted in actual communications, I reviewed network events initiated by `tor.exe` and `firefox.exe`. The screenshots show both local proxy behavior and outbound connections over ports commonly associated with TOR traffic.
<img width="1876" height="891" alt="Screenshot 2026-03-09 145127" src="https://github.com/user-attachments/assets/c8dc04cc-65f4-48ec-b855-ff25ee0fcae6" />


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "bigp"
| where InitiatingProcessAccountName == "bigp"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150, 80, 443)
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```


**MITRE ATT&CK Mapping:**
- **T1090.003 – Proxy: Multi-hop Proxy**  
  Evidence: repeated outbound connections from `tor.exe` over TOR-associated relay traffic.
- **T1573 – Encrypted Channel**  
  Evidence: TOR-generated traffic used encrypted outbound communications, including HTTPS and relay connections.
- **T1071.001 – Application Layer Protocol: Web Protocols**  
  Evidence: communications leveraged normal web-facing protocols and destinations.

---

## Chronological Event Timeline

1. **`Feb 25, 2026 7:47:19 PM`** — earliest visible `firefox.exe` process creation from the TOR Browser path.  
2. **`Feb 25, 2026 7:48:23 PM`** — earliest visible `tor.exe` process creation from `C:\Users\bigp\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`.  
3. **`Feb 25, 2026 7:48:23 PM`** — `storage-sync-v2.sqlite` created in the TOR Browser profile path.  
4. **`Feb 25, 2026 7:48:41 PM`** — `firefox.exe` attempted a local proxy connection to `127.0.0.1:9150`.  
5. **`Feb 25, 2026 7:52:07 PM`** — `Tor Browser.lnk` created.  
6. **`Feb 25, 2026 7:53:20 PM`** — first visible successful outbound `tor.exe` connections over port `443`.  
7. **`Feb 25, 2026 7:55:20 PM`** — first visible successful outbound `tor.exe` connections over port `9001`.  
8. **`Feb 25, 2026 8:14:36 PM`** — `formhistory.sqlite` created in the TOR Browser profile.  
9. **`Feb 25, 2026 9:39:48 PM`** — `tor-shopping-list.lnk` created in Recent Items, indicating likely user interaction with a TOR-related file.  
10. **`Feb 26, 2026 2:51:08 AM`** — latest visible successful `tor.exe` network connection to `88.99.142.177:9001`.  
11. **`Feb 26, 2026 3:00:54 AM` to `3:00:55 AM`** — late-stage profile file modifications (`storage-sync-v2.sqlite` and `storage.sqlite`) indicate continued TOR Browser profile activity.

---

## MITRE ATT&CK Mapping Summary

| Technique | Name | Where it appears in this project |
|---|---|---|
| T1204.002 | User Execution: Malicious File | File and process evidence showing user-context execution of TOR components |
| T1105 | Ingress Tool Transfer | TOR-related files and browser artifacts present on disk |
| T1071.001 | Application Layer Protocol: Web Protocols | Firefox/TOR browser execution and web-style network communications |
| T1090.003 | Proxy: Multi-hop Proxy | `tor.exe` process execution and relay-style network traffic |
| T1573 | Encrypted Channel | Encrypted outbound connections associated with TOR traffic |

---

## Lessons Learned
This hunt reinforced the value of correlating telemetry across multiple MDE tables instead of relying on a single indicator.

- **File telemetry** showed the TOR Browser profile and shortcuts, which established that the tool existed on disk and was interacted with by the user.
- **Process telemetry** confirmed that both `firefox.exe` and `tor.exe` actually executed from the TOR installation path.
- **Network telemetry** provided the strongest validation by showing local proxy behavior and repeated outbound relay-style connections over ports such as `443`, `80`, `9001`, and `9150`.
- Looking at all three layers together made the investigation defensible: this was not just file presence, but observable execution and network use.

---

## Summary
The telemetry aligns across file, process, and network evidence and supports the conclusion that the user `bigp` actively used the TOR Browser on endpoint `bigp`.

The screenshot-backed evidence shows:
- TOR profile artifacts and shortcuts created and modified on disk
- repeated execution of both `firefox.exe` and `tor.exe` from the TOR Browser directory
- local proxy behavior to `127.0.0.1:9150`
- repeated outbound network connections from `tor.exe`, including successful connections over `443`, `80`, and `9001`

Based on the supplied evidence, this activity is consistent with **successful TOR execution and active TOR network usage**.

---

## Response Recommendation
The supplied dataset confirms TOR activity, but it does not include containment telemetry or case-management evidence showing that the device was isolated or that notifications were sent.

Reasonable follow-on actions would be:
- determine whether TOR usage violates policy
- isolate the endpoint if anonymization tools are prohibited
- preserve relevant telemetry and artifacts
- escalate to the security team or incident handler for review
- investigate how the tool was introduced and whether additional controls are needed

