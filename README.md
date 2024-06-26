# NtStrace

frida-stalker based system call tracer on windows(x64).

```
[483]NtWaitForWorkViaWorkerFactory
test.exe!0x7ff91fbaf262
[35]NtQueryVirtualMemory
test.exe!0x7ff91fbaf262
[35]NtQueryVirtualMemory
test.exe!0x7ff91fbaf262
[35]NtQueryVirtualMemory
test.exe!0x7ff91fbb06d2
[199]NtCreateThreadEx
[+] Following thread 17876
test.exe!0x7ff91fbb06d2
[7]NtDeviceIoControlFile
[+] Unfollowing thread 17876
test.exe!0x7ff91fbaeee2
[7]NtDeviceIoControlFile
test.exe!0x7ff91fbaeee2
[7]NtDeviceIoControlFile
[+] Unfollowing thread 6344
[+] Unfollowing thread 6124
```

It can also accurately identify types that cover up system calls, such as the project below.  
https://github.com/passthehashbrowns/hiding-your-syscalls

<img width="272" alt="img" src="https://user-images.githubusercontent.com/96031346/220208613-9c7a165e-1f69-48c1-9c8f-8334f304be3e.png">



# Usage

```
frida -l tracer.js app.exe
```

# License

## iostrace

The original software is available at  
https://github.com/sh1ma/iostrace.
