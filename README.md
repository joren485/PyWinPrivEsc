RunAsSystem
======================

Privilege escalation Admin > SYSTEM, the PsExec way. 

This script will (if run with admin privs) give you a command prompt with as NT AUTHORITY\SYSTEM.

Dependencies:
 - Pywin32 (Only for the Pywin32 version, the ctypes version works out of the box)


UACBypass
======================

(semi-)Privilege escalation User > Admin.

Also disables your UAC, and dumps the SAM, SECURITY and SYSTEM files to C:\Temp\.
