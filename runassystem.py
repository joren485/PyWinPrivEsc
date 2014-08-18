import win32api, win32pdh, win32process,win32security, win32con, pywintypes, win32profile

def EnablePrivilege(privilegeStr):
    PyhCP = win32security.OpenProcessToken(win32api.GetCurrentProcess(), priv_flags)
    privilege_id = win32security.LookupPrivilegeValue(None, privilegeStr)
    print privilege_id
    old_privs = win32security.AdjustTokenPrivileges(PyhCP, False, [(privilege_id, win32security.SE_PRIVILEGE_ENABLED)])

def procids():
    """Returns a list with all running processes and their pids."""
    #each instance is a process, you can have multiple processes w/same name
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
            hq = win32pdh.OpenQuery() # initializes the query handle 
            path = win32pdh.MakeCounterPath( (None,'process',instance, None, inum,'ID Process') )
            counter_handle=win32pdh.AddCounter(hq, path) 
            win32pdh.CollectQueryData(hq) #collects data for the counter 
            type, val = win32pdh.GetFormattedCounterValue(counter_handle, win32pdh.PDH_FMT_LONG)
            proc_ids.append((instance,str(val)))
            win32pdh.CloseQuery(hq) 
 
    return [int(pid[1]) for pid in proc_ids]

def GetLocalSystemProcessToken():
    systemsid = win32security.ConvertSidToStringSid(win32security.LookupAccountName(None, "nt authority\\system")[0])

    PROCESS_QUERY_INFORMATION = win32con.PROCESS_QUERY_INFORMATION
    tokenprivs = (win32con.TOKEN_QUERY | win32con.TOKEN_READ | win32con.TOKEN_IMPERSONATE | win32con.TOKEN_QUERY_SOURCE | win32con.TOKEN_DUPLICATE | win32con.TOKEN_ASSIGN_PRIMARY | win32con.TOKEN_EXECUTE)

    for pid in procids():
        try:
            PyhProcess = win32api.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)

            PyhToken = win32security.OpenProcessToken(PyhProcess, tokenprivs)
            sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(PyhToken, win32security.TokenUser)[0])
            if sid == systemsid:
                win32api.CloseHandle(PyhProcess)
                return PyhToken
            win32api.CloseHandle(PyhToken)
            win32api.CloseHandle(PyhProcess)

        except pywintypes.error,e :
            print str(e)


priv_flags = win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY

EnablePrivilege(win32security.SE_DEBUG_NAME)

PyhToken = GetLocalSystemProcessToken()
PyhTokendupe = win32security.DuplicateTokenEx(PyhToken, win32security.SecurityImpersonation, win32con.MAXIMUM_ALLOWED, win32security.TokenPrimary, TokenAttributes=None)
win32api.CloseHandle(PyhToken)

privilege_id = win32security.LookupPrivilegeValue(None, win32security.SE_ASSIGNPRIMARYTOKEN_NAME)
print privilege_id
old_privs = win32security.AdjustTokenPrivileges(PyhTokendupe, False, [(privilege_id, win32security.SE_PRIVILEGE_ENABLED)])

privilege_id = win32security.LookupPrivilegeValue(None, win32security.SE_INCREASE_QUOTA_NAME)
print privilege_id
old_privs = win32security.AdjustTokenPrivileges(PyhTokendupe, False, [(privilege_id, win32security.SE_PRIVILEGE_ENABLED)])

EnablePrivilege(win32security.SE_IMPERSONATE_NAME)

win32security.ImpersonateLoggedOnUser(PyhTokendupe)

##EnablePrivilege(win32security.SE_ASSIGNPRIMARYTOKEN_NAME)
##EnablePrivilege(win32security.SE_INCREASE_QUOTA_NAME)


si = win32process.STARTUPINFO()
si.wShowWindow = win32con.SW_SHOW
si.dwFlags = win32con.STARTF_USESHOWWINDOW

dwFlags = win32process.CREATE_NEW_CONSOLE
    
##check if elevated
print "Elevated: " + str(win32security.GetTokenInformation(PyhTokendupe, win32security.TokenElevationType) == True)
print "Token user: " + win32security.ConvertSidToStringSid(win32security.GetTokenInformation(PyhTokendupe, win32security.TokenUser)[0])
print "SYTEM SID: " + win32security.ConvertSidToStringSid(win32security.LookupAccountName(None, "nt authority\\system")[0])
print "Running as: " + win32api.GetUserName()
print win32security.GetTokenInformation(PyhTokendupe, win32security.TokenPrivileges)


win32process.CreateProcessAsUser(
                                PyhTokendupe,
                                r"C:\Windows\System32\cmd.exe",
                                None,
                                None,
                                None,
                                True,
                                dwFlags,
                                None,
                                None,
                                si)
