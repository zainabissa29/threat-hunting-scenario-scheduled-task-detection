# Threat Hunt Report: Scheduled Task & File Transfer

- [Scenario Creation](https://github.com/zainabissa29/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- PowerShell

---

## Scenario

Management suspects a user may be automating the execution of unauthorized processes and moving files in ways that could be used for data exfiltration or persistence.  
This scenario simulates an adversary using scheduled tasks to launch processes, copy executables, and transfer files externally. The goal is to detect evidence of scheduled task creation, suspicious file copies, and outbound web activity that may indicate the start of data theft or persistence actions.

---

### High-Level IoC Discovery Plan

- **Check `DeviceEvents`** for `ScheduledTaskCreated` actions.
- **Check `DeviceFileEvents`** for suspicious file creation or file copies in Temp directories.
- **Check `DeviceNetworkEvents`** for outbound HTTP/HTTPS requests or file downloads.

---

## Steps Taken

### 1. Searched the DeviceEvents Table

Searched for scheduled task creation actions to identify any new scheduled task on the endpoint.

**Query used to locate events:**
```kql
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| project Timestamp, DeviceName, InitiatingProcessAccountName, AdditionalFields
| order by Timestamp desc

```
---


### 2. Searched the DeviceFileEvents Table
Searched for evidence of file copies to the Temp directory, which could indicate attempts to mask persistence or prep for data exfiltration.

**Query used to locate events:**
```kql
DeviceFileEvents
| where FolderPath contains "\\Temp\\"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
| order by Timestamp desc
```
---

### 3. Searched the DeviceNetworkEvents Table
Checked for any outbound HTTP requests to example.com (used in the simulation), which could be a sign of data exfiltration or command-and-control traffic.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where RemoteUrl has "example.com"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemotePort
| order by Timestamp desc
```
---


### Chronological Event Timeline

### 1. Scheduled Task Creation

Timestamp: (Time task was created)

Event: A scheduled task named TestLogTask was created to launch Notepad.

Action: ScheduledTaskCreated event detected.
```powershell
SCHTASKS /Create /SC ONCE /TN "TestLogTask" /TR "notepad.exe" /ST 23:45
```


### 2. File Copy to Temp Directory
Timestamp: (Time file was copied)

Event: Notepad executable copied to user's Temp directory.

Action: File creation event detected in Temp directory.
```powershell
Copy-Item "C:\Windows\System32\notepad.exe" "$env:TEMP\notepad_copy.exe"
```

### 3. Outbound HTTP Download
Timestamp: (Time download occurred)

Event: HTTP download from external site detected.

Action: Outbound network event detected.
```powershell
Invoke-WebRequest -Uri "http://example.com" -OutFile "$env:TEMP\test-download.html"
```

### 4. Cleanup Actions
Timestamp: (Time cleanup executed)

Event: Scheduled task and temporary files deleted, possibly to cover tracks.

Action: ScheduledTaskDeleted and file deletion events detected.
```powershell
SCHTASKS /Delete /TN "TestLogTask" /F
Remove-Item "$env:TEMP\notepad_copy.exe" -Force
Remove-Item "$env:TEMP\test-download.html" -Force
```
---

### Summary
A user on the monitored endpoint executed a sequence of suspicious actions:

* Created a scheduled task to launch Notepad

* Copied Notepad.exe to a Temp directory

* Downloaded a file from an external web address

* Cleaned up artifacts to reduce forensic evidence

This activity chain may represent a proof-of-concept for persistence and data movement techniques that mimic early-stage malware or insider threat activity.
Detection of each step using Microsoft Defender for Endpoint ensures that these behaviors are visible and can be responded to.

### Response Taken
* The endpoint was flagged for further review.

* Security team notified and additional monitoring was enabled for the user account.

* No evidence of actual data exfiltration was detected beyond the simulation file.

