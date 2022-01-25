# KernelCorridor

KernelCorridor is a Windows kernel module, which provides a variaty of utilities implmented at pure kernel level and exposes them to user mode application.

By KernelCorridor, your user mode application can accesss critical system resouces directly, making it possible to bypass anti virus software, anti cheat solustion, or some of the Windows security mechenism.

## Avaliable Interfaces

+ Read/Write a process's virtual memory.
+ Create a user thread in target process.
+ Toggle a process protection field, to make it a ppl process or disable the ppl.
+ Change a process's handle's access rights.
+ Delete a file which is currently occupied.
+ Trigger a Blue Screen of Death
+ Toggle the system's driver signature enforcement (DSE) setting.
+ Call a set of windows API under kernel mode, such as OpenProcess, SetInformationProcess, QueueUserAPC.
