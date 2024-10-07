<h1>Incident Response: Possible Lateral Movement - Excessive Password Reset</h1>

- <b>This tutorial outlines the configuration of performing incident response for excessive password reset using Microsoft Sentinel and Log Analytics Workspace</b>

<h2>Environments and Technologies Used</h2>

- <b>Microsoft Azure</b> 
- <b>Microsoft Sentinel</b>
- <b>Log Analytics Workspace</b>

<h2>Operating Systems</h2>

- <b>Windows 10</b>

<h2>Configuration Steps</h2>

![image](https://github.com/user-attachments/assets/e8f0bcd6-6667-4bc6-8b80-506526f3fe40)
- <b>Navigate to Microsoft Sentinel and click a CUSTOM: Possible Lateral Movement - Excessive Password Reset incident</b>
- <b>Set Owner: Ryan Justin De Jesus, Status: Active, Severity: Medium</b>
- <b>Click view full details</b>

![image](https://github.com/user-attachments/assets/9e29d727-127b-4200-a292-e0786ddaa4bf)
- <b>Click activity log and observe the activity log</b>

![image](https://github.com/user-attachments/assets/aa7d9edd-7758-454c-8eb1-5263ad7a35f0)
- <b>Click the IP Address and observe the geolocation information</b>

![image](https://github.com/user-attachments/assets/4b383e24-b8de-4a23-8f42-48ca76a12541)
- <b>Investigate and determine the scope</b>

![image](https://github.com/user-attachments/assets/1f4d1ef8-4c71-4cd7-a793-ec64cfc9fa13)
- <b>Click the IP Address and observe the related event</b>
- <b>This specific incident is related to 11+ events</b>

![image](https://github.com/user-attachments/assets/1e18bc35-099b-454b-bc99-ca9417c8398e)
- <b>More Information is presented in the Log Analytics Workspace from this query:</b>

``` 
let GetIPRelatedAlerts = (v_IP_Address: string) {
    SecurityAlert
    | summarize arg_max(TimeGenerated, *) by SystemAlertId
    | extend entities = todynamic(Entities)
    | mv-expand entities
    | project-rename entity=entities
    | where entity['Type'] == 'ip' and entity['Address'] =~ v_IP_Address
    | project-away entity
};
GetIPRelatedAlerts(@'13.93.155.8')
```

```
SecurityEvent
| where EventID == 4625
| where IpAddress == '13.93.155.8'
```
 
![image](https://github.com/user-attachments/assets/399fa37f-d5d9-4108-b80f-4d43a8dff8ea)
- <b>Based on the results, I will conclude this as a True Positive - Suspicious Activity due to the results containing multiple failed authentication attempts by the same user account or from the same IP address, further suggesting malicious intent.

## Incident Management Playbook 
- <b>Incident Description</b>
    - This incident involves observation of potential brute force attempts against a Linux Syslog.

- <b>Initial Response Actions</b>
    - Verify the authenticity of the alert or report.
    - Immediately isolate the machine and change the password of the affected user
    - Identify the origin of the attacks and determine if they are attacking or involved with anything else
    - Determine how and when the attack occurred
        - Are the NSGs not being locked down? If so, check other NSGs
    - Assess the potential impact of the incident.
        - What type of account was it? Permissions?

- <b>Containment and Recovery</b>

![image](https://github.com/user-attachments/assets/86ee1b28-092f-4490-b5b1-c0bc58562da9)
- <b>Lock down the NSG assigned to that VM/Subnet, either entirely, or to allow only necessary traffic</b>

![image](https://github.com/user-attachments/assets/0f43e8a9-e329-405e-9467-d57dbbd165ab)
- <b>Reset the affected user’s password</b>
