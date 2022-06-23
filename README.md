## Section Mapping Process Injection modified with SysWhisper2 (sw2-secinject): Cobalt Strike BOF

This project is for SysWhisper2 **practice purpose** and heavily relies on https://github.com/apokryptein/secinject

- <del>Failed to implement RtlCreateUserThread since syscall cannot be found using SW2
- ^Replaced with NtCreateThreadEx
- Currently, this is only implemented for x64 processes.

### How to Make
```
git clone https://github.com/ScriptIdiot/sw2-secinject.git
cd sw2-secinject/src
make
```

### How to Use
#### Injecting Beacon
```
sw2-sec-inject PID LISTENER-NAME
```

![image](https://user-images.githubusercontent.com/21979646/175093085-b24d36dc-4659-4e2a-8b33-20187eedc254.png)


#### Injecting Other Shellcode
```
sw2-sec-shinject PID /path/to/bin
```

![image](https://user-images.githubusercontent.com/21979646/175093429-a17e1bcf-2101-450c-b783-1bd7b04fd8f5.png)


### Code References
https://github.com/apokryptein/secinject

https://github.com/Sh0ckFR/InlineWhispers2





