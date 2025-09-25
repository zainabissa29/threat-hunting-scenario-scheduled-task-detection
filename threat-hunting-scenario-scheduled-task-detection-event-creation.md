# Threat Event (Scheduled Task & File Transfer)
**Scheduled Task Creation and Outbound File Transfer**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Create a scheduled task that launches Notepad after a short delay:

    ```SCHTASKS /Create /SC ONCE /TN "TestLogTask" /TR "notepad.exe" /ST 23:45‎```
 
2. Copy the Notepad executable to the user’s Temp directory:

   ```Copy-Item "C:\Windows\System32\notepad.exe" "$env:TEMP\notepad_copy.exe"‎```‎

3. Establish an outbound HTTP connection by downloading a file from the internet:

   ```Invoke-WebRequest -Uri "http://example.com" -OutFile "$env:TEMP\test-download.html"‎```‎

4.  Clean up by deleting the scheduled task and copied files:
   
    ```
    SCHTASKS /Delete /TN "TestLogTask" /F‎‎
    Remove-Item "$env:TEMP\notepad_copy.exe" -Force
    ‎‎‎Remove-Item "$env:TEMP\test-download.html" -Force
---
   ## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table|
| **Purpose**|Used to detect scheduled task creation and deletion.

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefile-table|
| **Purpose**|Used to detect file copy and file removal activity in Temp or user directories.

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**|Purpose	Used to detect outbound HTTP/HTTPS connections from user activity.
---

## Related Queries

```kql
// Detect scheduled task creation
DeviceEvents
| where  DeviceName == "zee"
| where ActionType == "ScheduledTaskCreated"
| project Timestamp, DeviceName, ActionType,InitiatingProcessAccountName, InitiatingProcessAccountDomain
| order by Timestamp desc

// Detect file copy to TEMP directory
DeviceFileEvents
| where DeviceName == "zee"
| where  FileName contains "notepad"
| where FolderPath contains "Temp"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
| order by Timestamp desc

// Detect outbound HTTP download activity
DeviceNetworkEvents
| where DeviceName == "zee"
| where ActionType == "ConnectionSuccess" and RemotePort == "80"
| where RemoteUrl has "example.com"
| project Timestamp, DeviceName, ActionType,InitiatingProcessAccountName, RemoteUrl, RemotePort
| order by Timestamp desc


// Detect Scheduled task deletion
DeviceEvents
| where ActionType == "ScheduledTaskDeleted"
| where DeviceName == "zee"
| where InitiatingProcessAccountName == "zeemakay"
| project Timestamp, DeviceName, ActionType, InitiatingProcessAccountName, AdditionalFields
| order by Timestamp desc

//Detect File Deletions in Temp Directory
DeviceFileEvents
| where DeviceName == "zee"
| where FileName in~ ("notepad_copy.exe", "test-download.html")
| where FolderPath contains "Temp"
| where ActionType == "FileDeleted"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessAccountName
| order by Timestamp desc

```


---

## Created By:
- **Author Name**: Zainab Issa
- **Author Contact**: https://www.linkedin.com/in/zainabissa-cybersecurity/
- **Date**: September 24, 2025


## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

## Additional Notes:
- **None**

---
## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `September  24, 2025`  | `Zainab Issa `
