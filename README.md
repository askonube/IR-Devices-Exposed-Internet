
# Devices Exposed to the Internet

## Overview

This threat investigation highlights the reality of having devices exposed to the internet. In the modern world, internet connectivity has become a necessity for operations. However, this level of access to information and resources also leaves many hosts exposed to potential threats. Newer, updated, and more advanced devices are typically configured with security controls to mitigate common threats, whereas older devices often do not receive the same level of security configuration or updates. As a result, when these older devices are connected to the local network — especially if misconfigured or left unconfigured — they remain vulnerable and relatively defenceless against attacks.

---

## 1. Preparation

### Scenario:

During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources.

Currently, the traffic originating from the local area network (LAN) is allowed by all endpoints. Applications such as Powershell and others can be used freely by those in the working environment. There are suspicions that a user(s) may be downloading extremely large files or conducting port scans on the internal network. 

### Hypothesis:

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

There were zero (0) failed logons for the `labuser` account, indicating that a brute force attempt for this account didn't take place, and a one-time password guess is unlikely.

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "labuser"
```
![image](https://github.com/user-attachments/assets/c9c7a14d-2733-4aa5-97dd-f3de82c86078)

We checked all of the successful login IP addresses for the `labuser` account to see if any of them were unusual or from an unexpected location. The IP address corresponded to their accurate location and was deemed safe. 

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
- Immediately restrict internet exposure by limiting or removing public internet-facing configuration of the VM `windows-target-1` unless absolutely necessary.

- Implement firewall rules or network security groups (NSGs), if operating in a cloud environment, to restrict inbound traffic to only trusted IP addresses or networks.
  
- Implement strong, unique passwords and enable multi-factor authentication (MFA) for all user accounts.

- Enable account lockout policies after a configurable number of failed login attempts to mitigate brute-force attacks.

- Continuously monitor login attempts and network traffic for abnormal patterns

- Utilise intrusion detection/prevention systems (IDS/IPS) and endpoint protection tools to detect and block malicious activity

- Apply the principle of least privilege for accounts and services to minimise potential damage from compromised credentials.

## 6. Improvement

### Prevention:
- **Reduce Internet Exposure**: Limit or eliminate direct internet-facing access to critical VMs such as windows-target-1. Use VPNs, jump servers, or Just-in-Time (JIT) access to securely control remote connectivity.
- **Implement Account Lockout Policies**: Configure account lockout thresholds to block accounts after a set number of failed login attempts.
- **Enforce Strong Authentication**: Require complex passwords and enable multi-factor authentication (MFA) for all user accounts, especially those with remote access privileges.
- **Least Privilege Access**: Apply the principle of least privilege to user accounts and service permissions to minimize risk if credentials are compromised.

### Threat Hunting:
-  Continuously analyze authentication logs for patterns of failed login attempts from external IPs to detect brute-force activity early.
- Investigate accounts with multiple failed attempts followed by successful logins to identify potential credential compromise.
- Regularly review and inventory VMs exposed to the internet. Prioritize threat hunting on these assets due to higher risk exposure.
- Hunt for unusual remote service usage or authentication events within the shared services cluster that may indicate lateral movement attempts.
- Integrate external threat intelligence feeds to identify known malicious IP addresses attempting access and proactively block them.
- Establish normal login and network behavior baselines for critical accounts like labuser to quickly spot anomalies.

---

## Conclusion

Brute-force attacks will continue to be a mainstay in the modern cyber threat landscape. The vast trove of exposed credentials and stolen password lists will arm threat actors for the foreseeable future. Implementing security measures such as account lockout policies, multi-factor authentication, complex passwords, and the principle of least privilege are currently considered the absolute baseline standards for protecting against threat actors. Adopting basic security hygiene is essential to prevent businesses of all sizes from falling victim to common, yet effective, attacks.


