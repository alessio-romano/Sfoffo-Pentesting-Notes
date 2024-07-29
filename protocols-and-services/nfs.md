# NFS

## **Introduction**

> * Network File System (NFS) is a network file system developed by Sun Microsystems and has the same purpose as SMB.
> * Its purpose is to access file systems over a network as if they were local. However, it uses an entirely different protocol.
> * NFS' default port is 2049 TCP

***

## **Basic Enumeration & Interaction**

> * When footprinting NFS, the TCP ports 111 and 2049 are essential.
> * We can also get information about the NFS service and the host via RPC (2049)

<table><thead><tr><th width="256">Command</th><th>Description</th></tr></thead><tbody><tr><td>Use nmap scripts to find connected NFS shares names</td><td>sudo nmap --script nfs* &#x3C;IP> -sV -p111,2049</td></tr><tr><td>Show Available shares on target IP</td><td>showmount -e &#x3C;IP></td></tr><tr><td>Mount (locally) an available share</td><td>sudo mount -t nfs &#x3C;IP>:/target-NFS/ /your-target-dir -o nolock</td></tr><tr><td>Unmount a previously mounted share</td><td>sudo umount ./target-dir</td></tr></tbody></table>
