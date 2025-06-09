
# Devices Exposed to the Internet

## Overview

A threat hunt investigation was conducted regarding a sudden rapid decrease in network speed in a local area network (LAN) working environment. Coordinated and sophisticated attacks seem rather unlikely and may point to endpoint activity within the internal network. The primary tool here used was **Microsoft Defender for Endpoint (MDE)**, while leveraging Kusto Query Language (KQL) to query detailed threat hunting logs to identify large files downloaded, port scans, and numerous failed connection attempts. The findings below highlight the importance of implementing safeguards that will flag any suspicious behaviour from inside the network.


---

## 1. Preparation

### Scenario:

During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources.

Currently, the traffic originating from the local area network (LAN) is allowed by all endpoints. Applications such as Powershell and others can be used freely by those in the working environment. There are suspicions that a user(s) may be downloading extremely large files or conducting port scans on the internal network. 

### Hypothesis:

During the time the devices were unknowingly exposed to the internet, it’s possible that someone could have actually brute-force logged into some of them since some of the older devices do not have account lockout configured for excessive failed login attempts.

Because VMs were placed in a shared services cluster, it's possible that these VMs were exposed to the internet. This would have given attackers a chance to attempt any brute-force login attacks because the older devices are not configured have their accounts locked after numerous, unsuccessful login attempts. If successful, these attacks would've given threat actors access to the shared environment, which would allow the threat actor to perform lateral movement across the network. 

## 2. Data Collection
  
### Action:

Gather relevant data from logs, network traffic, and endpoints.

Ensure the relevant tables contain recent logs:

```kql
- DeviceInfo
- DeviceLogonEvents
```

#### Initial Findings:

The account `windows-target-1` has been facing the internet for several days now.


```kql
DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == true
| order by Timestamp desc
```

![image](https://github.com/user-attachments/assets/b91b0980-50e7-4f66-8745-6b0480450f0d)

![image](https://github.com/user-attachments/assets/8c1d52b6-b996-4b58-a0b8-a1d5051b3cb2)

![image](https://github.com/user-attachments/assets/332f33fd-3797-472c-a9db-a06d276c1623)


Last internet facing time was `2025-06-09T11:06:17.2711518Z`.


![image](https://github.com/user-attachments/assets/8df57b34-61bf-461c-96ea-8250da868221)


---

## 3. Data Analysis

### Findings

Several bad actors have been discovered attempting to log into the target machine.
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, DeviceName, RemoteIP
| order by Attempts
```

![image](https://github.com/user-attachments/assets/118cc71a-2bd2-422c-9011-1490e67f2d9c)

We then checked to see if the top 5 IP addresses that failed to login the most were able to successfully login.

```kql
let AttemptedIPs = dynamic(["45.135.232.96", "185.39.19.71", "109.205.213.154", "118.107.45.60", "194.180.49.127"]);
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(AttemptedIPs)
```

![image](https://github.com/user-attachments/assets/86d5e234-e993-48a8-a84d-a5bf9d63dc7a)

The only successful remote/network logons in the past 30 days was for the `labuser` account (2 times).

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
```
![image](https://github.com/user-attachments/assets/48468c7b-e8d7-4907-9d34-ee756869c5d5)

There were zero (0) failed logons for the `labuser` account, indicating that a brute force attempt for this account didn't take place, and a 1-time password guess is unlikely.

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "labuser"
```
![image](https://github.com/user-attachments/assets/c9c7a14d-2733-4aa5-97dd-f3de82c86078)

We checked all of the successful login IP addresses for the `labuser` account to see if any of them were unusual or from an unexpected location. All were normal. 

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```

![image](https://github.com/user-attachments/assets/a9d2fcbd-aa61-46e0-b58d-d6901906660e)


Though the device was exposed to the internet and clear brute force attempts took place, there's no evidence of any brute force success or unauthorised access from the legitimate account `labuser`. 




## 4. Investigation

**Suspicious Activity Origin**: An endpoint within the 10.0.0.0/16 network, specifically the Windows VM `win-vm-mde` (IP: 10.0.0.137), initiated unusual activity causing a significant network slowdown, as observed by the networking team on June 09, 2025.

**Potential Reconnaissance**: The sequential scanning of IP addresses within the 10.0.0.0/16 network indicates an attempt to gather information about the internal network, possibly as a precursor to further attacks or to map the environment (T1595.001: Scanning IP Blocks).

**Discovery via Port Scanning**: The device conducted a port scan, systematically targeting sequential ports on other hosts within the LAN, as detected by numerous failed connection attempts in Microsoft Defender for Endpoint logs (T1046: Network Service Discovery), likely to identify vulnerable systems or services.

**PowerShell Execution**: A PowerShell script named `portscan.ps1` was executed on `win-vm-mde` at `2025-06-08T16:29:40.1687498Z`, just before the port scan began, leveraging PowerShell’s capabilities to automate the scanning process (T1059.001: PowerShell).

**Unexpected User Account Usage**: The `portscan.ps1` script was launched by the user `ylavnu`, an action that was unexpected and not authorized by administrators, suggesting possible misuse of user credentials or compromised account
    
    
### MITRE ATT&CK TTPs

1. **Tactic: Reconnaissance (TA0043)** 
    
    - **Technique: Scanning IP Blocks (T1595.001)** Adversaries scan IP blocks to identify targets, often as a precursor to attacks. The scans were done on targeted hosts within the 10.0.0.0/16 network, as seen in failed connection attempts.
 
2. **Tactic: Execution (TA0002)** 
    
    - **Technique: PowerShell (T1059.001)** Adversaries use PowerShell to execute commands or scripts, often for malicious purposes, due to its legitimate use and powerful capabilities. The KQL query on `DeviceProcessEvents` identified `portscan.ps1`, a PowerShell script, launched at `2025-06-08T16:29:40.1687498Z`, just before the port scan.
        
        
3. **Tactic: Privilege Escalation (TA0004)** 
    
    - **Technique: Valid Accounts (T1078)**  Adversaries use legitimate credentials (e.g., compromised or misused) to execute actions. The `portscan.ps1` script was executed by the user `ylavnu`, which was unexpected and not authorised by administrators.
  
4. **Tactic: Discovery (TA0007)** 
    
    - **Technique: Network Service Discovery (T1046)** Adversaries use port scanning to identify open ports and services on target hosts within the network. The KQL query on `DeviceNetworkEvents` revealed that the failed connection attempts from `10.0.0.137` targeted ports in a sequential and chronological pattern, focusing on commonly used ports. This behavior strongly indicates a methodical port scan conducted around `2025-06-08T16:30:19.4145359Z`.

---

## 5. Response

### Actions Taken
- Immediately isolated the compromised VM from the network to prevent further scanning or lateral movement.

- Performed a thorough malware scan and forensic investigation to identify persistence mechanisms or additional malicious activity.

- Investigate why the user `ylavnu` launched the PowerShell script and tighten controls on privileged account access to prevent misuse.

- Configured the firewall to block suspicious outbound or inbound traffic from the endpoint, especially unusual or sequential port connection attempts.

- Deployed IDS/IPS solutions that can detect and block port scanning and other reconnaissance activities in real-time.

## 6. Improvement

### Prevention:
- **Network Segmentation and Egress Controls**: Segment the internal network to limit lateral movement and reconnaissance scope. Implement network egress filtering to block unauthorized scanning and connection attempts within the LAN.
- **PowerShell Restrictions**: Place PowerShell into Constrained Language Mode, reducing risk of executing malicious scripts.
- **Real-Time Alerting**: Use Endpoint Detection and Response (EDR) tools and Intrusion Detection/Prevention Systems (IDS/IPS) to monitor for suspicious PowerShell executions and sequential port scanning activity. Configure alerts for unusual user activity, especially involving scripting or network scanning.

### Threat Hunting:
- Use KQL queries to detect PowerShell scripts related to port scanning or network reconnaissance, focusing on command lines invoking TCP connection attempts or scanning utilities.
- Correlate  `DeviceNetworkEvents` and `DeviceProcessEvents` to identify processes (like portscan.ps1) that precede or coincide with sequential failed connection attempts, indicating scanning behavior.
- Regularly audit changes to user privileges especially unauthorised privilege escalations or scripting capabilities by users like `ylavnu`.
- Establish normal user and network behavior baselines to detect deviations such as unusual PowerShell usage or network scanning patterns originating from endpoints.

---

## Conclusion

Port scanning is one of the most common techniques used to assess a target’s security posture. Sequential and chronological scanning patterns are relatively straightforward to detect. Maintaining continuous monitoring through firewalls and IDS/IPS solutions is critical to prevent threat actors from gaining a foothold. Fortunately, in this case, the connection attempts were unsuccessful, and the opportunity to exploit any open ports was effectively thwarted.


