runassystem
===========

The psexec way of executing a command with SYSTEM. This is script that will escalate Administrator privileges to SYSTEM privileges.

This script will (if run with admin privs) give you a command prompt with as NT AUTHORITY\SYSTEM.

TODO: 
 1) Replace Pywin32 with, Ctypes
 2) Combine with ProcessHollowing, for stealth malware executing as SYSTEM


Dependencies:
 - Pywin32
