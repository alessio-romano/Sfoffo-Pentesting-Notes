# Capabilities Abuse

## What are Capabilities?

> * Linux capabilities are a security feature in the Linux operating system that allows specific privileges to be granted to processes, allowing them to perform specific actions that would otherwise be restricted.
> * Linux capabilities provide a subset of the available root privileges to a process. This effectively breaks up root privileges into smaller and distinctive units. Each of these units can then be independently be granted to processes.
> * One common vulnerability is using capabilities to grant privileges to processes that are not adequately sandboxed or isolated from other processes, allowing us to escalate their privileges and gain access to sensitive information or perform unauthorized actions.
> * Another potential vulnerability is the misuse or overuse of capabilities, which can result in processes having more privileges than they need.

***

## Capabilities Enumeration

* Enumerate all capabilities:\
  `find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;`
* Enumerate a specific binary's capabilities: `getcap /usr/bin/binaryname`

***

## Capability Values

| Capability Values | Desciption                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `+ep`             | This value grants the effective and permitted privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows but does not allow it to perform any actions that are not allowed by the capability.                                                                                                                                                    |
| `+ei`             | This value grants sufficient and inheritable privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows and child processes spawned by the executable to inherit the capability and perform the same actions.                                                                                                                                    |
| `+p`              | This value grants the permitted privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows but does not allow it to perform any actions that are not allowed by the capability. This can be useful if we want to grant the capability to the executable but prevent it from inheriting the capability or allowing child processes to inherit it. |

***

## Interesting Capabilities

* `CAP_SETUID`: Allows a process to set its effective user ID, which can be used to gain the privileges of another user, including the root user.
* `CAP_SETGID`: Allows to set its effective group ID, which can be used to gain the privileges of another group, including the root group.
* `cap_sys_admin`: Allows to perform actions with administrative privileges, such as modifying system files or changing system settings.
* `cap_sys_chroot`: Allows to change the root directory for the current process, allowing it to access files and directories that would otherwise be inaccessible.
* `cap_sys_ptrace`: Allows to attach to and debug other processes, potentially allowing it to gain access to sensitive information or modify the behavior of other processes.
* `cap_sys_nice`: Allows to raise or lower the priority of processes, potentially allowing it to gain access to resources that would otherwise be restricted.
* `cap_sys_time`: Allows to modify the system clock, potentially allowing it to manipulate timestamps or cause other processes to behave in unexpected ways.
* `cap_sys_resource`: Allows to modify system resource limits, such as the maximum number of open file descriptors or the maximum amount of memory that can be allocated.
* `cap_sys_module`: Allows to load and unload kernel modules, potentially allowing it to modify the operating system's behavior or gain access to sensitive information.
* `cap_net_bind_service`: Allows to bind to network ports, potentially allowing it to gain access to sensitive information or perform unauthorized actions.
