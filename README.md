# Threat Hunt Report: Scheduled Task & File Transfer

- [Scenario Creation](https://github.com/zainabissa29/threat-hunting-scenario-scheduled-task-detection/blob/main/threat-hunting-scenario-scheduled-task-detection-event-creation.md)

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

A review of the DeviceEvents table was performed to identify any new or potentially unauthorized tasks on the endpoint. During this analysis, it was observed that the user "zeemakay" on the device named "zee" created a scheduled task at 2025-09-24T18:34:25.095864Z. This event was successfully captured as a "ScheduledTaskCreated" record in Microsoft Defender for Endpoint, confirming both the creation of the task and the accuracy of monitoring on the endpoint

**Query used to locate events:**
```kql
DeviceEvents
| where  DeviceName == "zee"
| where ActionType == "ScheduledTaskCreated"
| project Timestamp, DeviceName, ActionType,InitiatingProcessAccountName, InitiatingProcessAccountDomain
| order by Timestamp desc


```
<img width="1193" height="472" alt="image" src="https://github.com/user-attachments/assets/e66d838d-2977-4fd4-a838-2f0ea3f1b653" />

---


### 2. Searched the DeviceFileEvents Table
A review of the DeviceFileEvents table was conducted to identify any suspicious file copy operations that might indicate attempts to mask persistence or facilitate data exfiltration on the endpoint. During this analysis, it was observed that the user "zeemakay" on the device named "zee" initiated the copying of the file "notepad_copy.exe" to a temporary folder at 2025-09-24T18:34:42.4063458Z. This activity was successfully captured in Microsoft Defender for Endpoint, confirming the occurrence of the file copy event and demonstrating the system’s ability to monitor file movement within user directories.

**Query used to locate events:**
```kql
DeviceFileEvents
| where DeviceName == "zee"
| where  FileName contains "notepad"
| where FolderPath contains "Temp"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
| order by Timestamp desc


```
<img width="1195" height="561" alt="image" src="https://github.com/user-attachments/assets/b6c1e6cf-ae45-4ac3-9c3d-511c631189c7" />

---

### 3. Searched the DeviceNetworkEvents Table
A review of the DeviceNetworkEvents table was conducted to detect any outbound network activity that could indicate file downloads or communication with external sites. During this analysis, it was observed that the user "zeemakay" on the device named "zee" successfully established an HTTP connection (port 80) to "example.com" at 2025-09-24T18:35:08.236484Z. This action was captured as a "ConnectionSuccess" event in Microsoft Defender for Endpoint, confirming both the outbound web activity and the effectiveness of the network monitoring in place.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "zee"
| where ActionType == "ConnectionSuccess" and RemotePort == "80"
| where RemoteUrl has "example.com"
| project Timestamp, DeviceName, ActionType,InitiatingProcessAccountName, RemoteUrl, RemotePort
| order by Timestamp desc
```
<img width="1245" height="427" alt="image" src="https://github.com/user-attachments/assets/440d7884-5ea5-41f6-a1f6-dae1bc8d2438" />

### 4. Searched for File and Task Deletion Events

A review of the DeviceFileEvents and DeviceEvents tables was conducted to confirm that cleanup activities, including the deletion of the scheduled task and temporary files, were performed as intended. This review focused on the removal of the file "notepad_copy.exe" and "test-download.html" from the Temp directory, as well as the deletion of the scheduled task "TestLogTask." These actions are expected to generate "FileDeleted" and "ScheduledTaskDeleted" records, respectively, which further validate the completion of the simulation and the reliability of endpoint monitoring.

**Query used to locate events:**

```kql

DeviceFileEvents
| where DeviceName == "zee"
| where FileName in~ ("notepad_copy.exe", "test-download.html")
| where FolderPath contains "Temp"
| where ActionType == "FileDeleted"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessAccountName
| order by Timestamp desc
```
<img width="1188" height="574" alt="image" src="https://github.com/user-attachments/assets/a21e1b97-b9ca-4746-97b7-e22b0c17ba0f" />


```kql
DeviceEvents
| where DeviceName == "zee"
| where ActionType == "ScheduledTaskDeleted"
| project Timestamp, DeviceName, ActionType, InitiatingProcessAccountName, AdditionalFields
| order by Timestamp desc

```
<img width="1168" height="523" alt="image" src="https://github.com/user-attachments/assets/d2060eae-5dc2-428c-b331-f45bd8b6f04d" />

---

### Chronological Event Timeline

### 1. Scheduled Task Creation

Timestamp: 2025-09-24T18:34:25.095864Z

Event: A scheduled task named ```TestLogTask``` was created to launch Notepad.

Action: ScheduledTaskCreated event detected.



### 2. File Copy to Temp Directory
Timestamp: 2025-09-24T18:34:42.4063458Z

Event: Notepad executable copied to user's Temp directory.

Action: File creation event detected in Temp directory.


### 3. Outbound HTTP Download
Timestamp: 2025-09-24T18:35:08.236484Z

Event: HTTP download from external site detected.

Action: Outbound network event detected.


### 4. Cleanup Actions
Timestamp: 2025-09-24T18:35:17.845266Z

Event: Scheduled task and temporary files deleted, possibly to cover tracks.

Action: ScheduledTaskDeleted and file deletion events detected.

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

