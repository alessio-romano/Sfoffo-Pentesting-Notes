# Enumerating Attack Vectors

## **Helpful Tools**

**Miscellaneous:**

* [**Ghostpack Compiled Binaries**](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)
* [**UAC (User Account Control) Bypasses**](https://github.com/hfiref0x/UACME)
* [**Impacket Tools**](https://github.com/fortra/impacket/tree/master/examples)
* [**NetCat for Windows**](https://github.com/int0x33/nc.exe/)

**Exploit Suggesters:**

* [**winPEAS**](https://github.com/carlospolop/PEASS-ng/releases): Windows local Privilege Escalation Awesome Script.
* [**Seatbelt**](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries): C# local privilege escalation checks.
* [**PowerUp**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1): PowerShell script for finding common Windows privilege escalation vectors that rely on misconfigurations.
* [**SharpUp**](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries): C# version of PowerUp .
* [**JAWS**](https://github.com/411Hall/JAWS/tree/master): PowerShell script for enumerating privilege escalation vectors written in PowerShell 2.0 .
* [**Watson**](https://github.com/rasta-mouse/Watson): .NET tool to enumerate missing KBs and suggest exploits.
* [**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng)
* **Metasploit Local Exploit Suggester**: `use post/multi/recon/local_exploit_suggester` on a backgrounded meterpreter sessions .

**Credentials:**

* [**LaZagne**](https://github.com/AlessandroZ/LaZagne/releases/): Retrieve passwords stored on a local machine from Windows password storage mechanisms and many different sources.
* [**MimiKatz**](https://github.com/ParrotSec/mimikatz): Extract credentials, perform PtH, PtT, craft golden tickets and more.
* [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher): PowerShell tool to find and decrypt saved session information for remote access tools.

***

## **Enumerating Windows Protection**

* Check Windows Defender status: `Get-MpComputerStatus`
* List AppLocker rules: `Get-AppLockerPolicy -Effective \| select -ExpandProperty RuleCollections`
* Test AppLocker policy: `Get-AppLockerPolicy -Local \| Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone`

***

## **Processes, Jobs, Scheduled Tasks**

* Dislpay all running processes (PowerShell): `Get-Process`
* List named pipes: `pipelist.exe /accepteula`
* List named pipes with PowerShell: `gci \\.\pipe\`
* Review permissions on a named pipe: `accesschk.exe /accepteula \\.\Pipe\lsass -v`
* Display running processes: `tasklist /svc`
* Enumerate scheduled tasks: `schtasks /query /fo LIST /v`
* Get ACLs for a specific scheduled task:\
  `icacls C:\Users\dude\Desktop\example.exe`
* Enumerate scheduled tasks with PowerShell: `Get-ScheduledTask \| select TaskName,State`
* Enumerate all Unquoted Service Paths: `wmic service get name,displayname,pathname,startmode \| findstr /i "auto" \| findstr /i /v "c:\windows\\" \| findstr /i /v """`

***

## **Kernel and OS**

* Display all environment variables: `set`
* View detailed system configuration information: `systeminfo`
* Get patches and updates: `wmic qfe`
* Get installed programs: `wmic product get name`
* Get Installed programs in PowerShell: `Get-WmiObject -Class Win32_Product \| select Name, Version`
* Enumerate computer description field: `Get-WmiObject -Class Win32_OperatingSystem \| select Description`

***

## **Registries**

* Query for always install elevated registry key (1): `reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer`
* Query for always install elevated registry key (2): `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`
* Find PuTTY clear-text credentials: `reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Session\`

***

## **Users and Groups**

* Get logged-in users: `query user`
* Get current user: `echo %USERNAME%`
* View current user privileges: `whoami /priv`
* View current user group information: `whoami /groups`
* Get all system user: `net user`
* Get all system groups: `net localgroup`
* View details about a group: `net localgroup administrators`
* Get password policy: `net accounts`
* Check permissions on a directory: `.\accesschk64.exe /accepteula -s -d C:\Scripts\`
* Check local user description field: `Get-LocalUser`
* Run commands as another user (requires their password): `runas /user:backupadmin cmd`

***

## **Network-Related**

* Display active network connections: `netstat -ano`
* Get interface, IP address and DNS information: `ipconfig /all`
* Review ARP table: `arp -a`
* Review routing table: `route print`

***

## **Installed Applications**

check installed applications:\
`Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`

check installed applications (alternative):\
`Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`

***

## **Credential Hunting**

* Search common configuration files containing the word "password":\
  `findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml`
* Searching file contents for a string: `findstr /spin "password" *.*`
* Search file contents with PowerShell:\
  `select-string -Path C:\Users\htb-student\Documents\*.txt -Pattern password`
* Search for file extensions:\
  `dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*`
* Search for file extensions (alternative):\
  `Get-ChildItem -Path C:\ -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue`
* Search for file extensions using PowerShell:\
  `Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore`
* List `cmdkey` saved credentials (in memory): `cmdkey /list`
* Run SessionGopher to extract credentials:\
  `Import-Module .\SessionGopher.ps1` → `Invoke-SessionGopher -Target WINLPE-SRV01`
* Retrieve saved Chrome credentials: `.\SharpChrome.exe logins /unprotect`
* Search Chrome Dictionary Files containing passwords:\
  `gc 'C:\Users\username\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' \| Select-String password`
* Read the PowerShell History File: `gc (Get-PSReadLineOption).HistorySavePath`
* Retrieve saved wireless passwords: `netsh wlan show profile WIFINAME key=clear`
* Enumerate unattended installation files (files named `unattend.xml`) which may contain passwords, which are stored in plaintext or base64
* Enumerate `.kdbx` KeePass files and extract credentials using `python2.7 keepass2john.py file.kdbx`, followed by `hashcat -m 13400`
* Extract clipboard (copy-paste) data: `git clone https://github.com/inguardians/Invoke-Clipboard/blob/master/Invoke-Clipboard.ps1`
* Search current user's history file content (PowerShell): `Get-History`
* Find all accessible PowerShell history files: `foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}`
* Display a user's specific history file's content:\
  `type C:\Users\{USERNAME}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
* Retrieve password from Windows Sticky Notes:\
  `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`
