# NimSysCalls
从挂起进程内存中获取干净的ntdll副本，使用syscall绕过AV/EDR


简体中文说明 | [English README](https://github.com/aeverj/NimSyscalls/blob/master/README_EN.md)
# 介绍
1. 创建一个挂起的进程
2. 获取ntdll的基址
3. 从挂起的进程中获取ntdll内容复制到本进程
4. 保存syscall的调用代码
5. 执行syscall调用

# 如何使用
1. 下载仓库到本地
2. 将需要syscall调用的函数写到 `functions.txt`文件中
3. 执行 `python3 NimSysCalls.py` 生成一个`syscalls.nim`文件
4. 编译并执行，例子在`example.nim`.
# 实例
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
# 引用
- [Peruns-Fart](https://github.com/plackyhacker/Peruns-Fart.git)
- [NimlineWhispers2](https://github.com/ajpc500/NimlineWhispers2)