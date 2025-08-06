# Goal
Detect and respond to ransomware attacks conducted by the DEV-0270/PHOSPHORUS actor by monitoring their specific tactics, techniques, and procedures (TTPs), including vulnerability exploitation, the use of Living-off-the-Land Binaries (LOLBins), and other unique activities.

# Categorization
These attacks are categorized as Ransomware / Nation-State Actor. The specific tactics used include:
* Initial Access
* Discovery
* Credential Access
* Persistence
* Privilege Escalation
* Defense Evasion
* Lateral Movement
* Impact

# Strategy Abstract
This strategy will function as follows:

* Data Collection: Record process and command-line data from Windows hosts using endpoint detection tooling.

* IOC Hunting: Perform searches and correlations for specific Indicators of Compromise (IOCs) and TTPs associated with DEV-0270, such as the reg command for WDigest, the use of rundll32.exe and comsvcs.dll for MiniDump, and the creation of new user accounts with specific names and passwords.

* Anomaly Identification: Detect unusual activity from LOLBins like powershell.exe, net.exe, and wmic.exe.

* Actioning: If a match is found, raise an alert for further investigation.

# Technical Context
DEV-0270 is an opportunistic actor known for exploiting newly disclosed vulnerabilities, such as ProxyLogon in Exchange and CVE-2018-13379 in Fortinet. They also use native system binaries (LOLBins) to evade detection.

- Credential Access: The actor modifies the registry to enable WDigest (```
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f```), which then allows them to use rundll32.exe and comsvcs.dll to dump credentials from LSASS into an ssasl.dmp file.

- Persistence: The actor creates a new user account, often named DefaultAccount with the password P@ssw0rd1234. They also enable RDP access and use Scheduled Tasks to download and run a modified dllhost.exe as a reverse proxy.

- Lateral Movement: The actor uses RDP and the Impacket's WMIExec toolkit to move through the network and deploy their tools.

- Impact: They use the native BitLocker tool or DiskCryptor (for workstations) to encrypt drives, rendering the hosts inoperable, and then demand a ransom.


# Blind Spots and Assumptions
This strategy relies on the following assumptions:

Endpoint detection tooling (EDR) like Microsoft 365 Defender is correctly functioning on the system.

Process execution and command-line events are being recorded and forwarded to a security system (SIEM).

The attacker uses the documented TTPs and does not use more sophisticated obfuscation techniques that would defeat the detection queries.

Blind spots will occur if:

The endpoint detection tooling is tampered with or disabled.

The attacker uses a method that does not generate a specific command-line footprint.


# False Positives
Some false positives may occur due to the use of LOLBins, which are also frequently used by system administrators for routine tasks. Examples include:

An administrator running net user or reg commands for legitimate administrative purposes.

Management scripts running PowerShell commands to configure systems.

# Validation
Validation can be performed by running a few of the following commands on a test host (in an isolated environment):

Credential Access: Run the reg command to enable WDigest (```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 1 /f```) and verify if a detection alert is triggered.

Persistence: Attempt to create a new user with the known name and password (net user DefaultAccount P@ssw0rd1234 /add) and observe if an alert is generated.


# Priority
High. Given that this threat has the potential to cause significant financial and operational impact from a ransomware attack, any alerts should be treated with high priority.


# Response
1. In the event that this alert is triggered, the following response procedures are recommended:

2. Apply Mitigation: Immediately apply patches for Exchange Server (ProxyLogon) and Fortinet vulnerabilities if the host is vulnerable.

3. Isolate Host: Immediately isolate the infected host from the network to prevent lateral movement.

4. Investigate:
** Check for any newly created or modified user accounts, especially DefaultAccount.
** Examine the process activity that triggered the alert, including the process chain, user, and full command line.
** Use the hunting queries provided by Microsoft (e.g., in Microsoft Sentinel or Microsoft 365 Defender) to search for other TTPs across your network.
