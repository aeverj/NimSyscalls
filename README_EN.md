# NimSysCalls
This nim application get a clean copy of ntdll from a new process in a suspended state.We can use it to execute shellcode by direct system calls.

# Introduction
1. Create a new process in a suspended state
2. Get the ntdll base address
3. Copy clean ntdll from the new process and kill it
4. Save syscallStub from clean copy of ntdll
5. Invoke the syscall

# How to use it
1. Clone this repository
2. Update which functions you required in `functions.txt`
3. Run `python3 NimSysCalls.py` to generate the inline assembly (syscalls.nim) file - example in the repo.
4. Compile and run it.
# Example
```cmd
>> nim c -d:strip --opt:size -d:release -f -r example.nim
[*] Create process notepad.exe
[*] Read clean copy of ntdll from notepad.exe and kill the process
[*] Get export function from clean copy of ntdll
[*] Start create C:\Users\pw.log
[*] Syscall code: 85
[*] NtCreateFile return: 0
[*] Create file C:\Users\pw.log success
```
# Credits
- [Peruns-Fart](https://github.com/plackyhacker/Peruns-Fart.git)
- [NimlineWhispers2](https://github.com/ajpc500/NimlineWhispers2)