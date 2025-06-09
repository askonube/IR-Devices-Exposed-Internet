
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

Because VMs were placed in a shared services cluster, it's possible that these VMs were exposed to the internet. This would have given attackers a chance to attempt any brute-force login attacks as the older devices are not configured have their accounts locked after numerous, unsuccessful login attempts. If successful, these attacks would've given threat actors access to the shared environment, which would allow the threat actor to perform lateral movement across the network. 

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

**Suspicious Activity Origin**: The VM `windows-target-1` was exposed to the public internet for several days, resulting in multiple failed login attempts from external IP addresses, indicating potential brute-force attack activity against this internet-facing host.

**Potential Brute-Froce Login Attempts**: Numerous failed login attempts from external IPs were observed targeting the exposed VM, consistent with brute-force techniques aimed at gaining unauthorized access (T1110: Brute Force). Despite these attempts, no successful brute-force login was detected for the legitimate account `labuser`.

**Risk of Initial Access and Lateral Movement**: If any brute-force attempts had succeeded, attackers could have gained initial access to the shared services environment, which includes critical infrastructure such as DNS, Domain Services, and DHCP. This access could facilitate lateral movement within the network to expand control (T1021: Remote Services).

**Legitimate Account Behaviour**: The account "labuser" successfully logged in twice via network logons in the past 30 days, with no failed attempts and all logins originating from expected IP addresses, confirming no malicious activity or compromise associated with this account.
    
### MITRE ATT&CK TTPs

1. **Tactic: Initial Access (TA0001)** 
    
    - **Technique: Brute Force (T1110)** Adversaries attempt to gain access by guessing credentials, often targeting systems without account lockout mechanisms. Logs from `DeviceLogonEvents` show multiple failed login attempts (ActionType == "LogonFailed") from external IPs (e.g., 45.135.232.96, 185.39.19.71) targeting "windows-target-1," consistent with brute-force behavior.

2. **Tactic: Credential Access (TA0006)** 
    
    - **Technique: Brute Force (T1110)** The repeated failed login attempts indicate attempts to acquire valid credentials through brute force.
        
        
3. **Tactic: Initial Access (TA0001)** 
    
    - **Technique: Exploit Public-Facing Application (T1190)** Adversaries may exploit vulnerabilities in internet-facing applications to gain initial access. The VM "windows-target-1," hosting critical services (DNS, DHCP, Domain Services), was exposed to the internet (IsInternetFacing == true until 2025-06-09T11:06:17.2711518Z), making it a potential target for exploitation. While no direct evidence of application-specific exploits (e.g., CVEs or anomalous service behavior) was found in the logs, the internet exposure of these services increases the risk of such attacks, particularly if unpatched or misconfigured.
  
4. **Tactic: Lateral Movement (TA0008)** 
    
    - **Technique: Remote Services (T1021)** Successful compromise of the exposed VM could enable attackers to move laterally through the shared services cluster.

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


