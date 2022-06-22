#pragma once
#include <windows.h>

#if _WIN64

#define ZwCreateSection NtCreateSection
__asm__("NtCreateSection: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x00A546E87 \n\
call SW2_GetSyscallNumber \n\
add rsp, 0x28 \n\
mov rcx, [rsp +8] \n\
mov rdx, [rsp+16] \n\
mov r8, [rsp+24] \n\
mov r9, [rsp+32] \n\
mov r10, rcx \n\
syscall \n\
ret \n\
");

#define ZwMapViewOfSection NtMapViewOfSection
__asm__("NtMapViewOfSection: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x0168835D9 \n\
call SW2_GetSyscallNumber \n\
add rsp, 0x28 \n\
mov rcx, [rsp +8] \n\
mov rdx, [rsp+16] \n\
mov r8, [rsp+24] \n\
mov r9, [rsp+32] \n\
mov r10, rcx \n\
syscall \n\
ret \n\
");

#define ZwUnmapViewOfSection NtUnmapViewOfSection
__asm__("NtUnmapViewOfSection: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x008A0263D \n\
call SW2_GetSyscallNumber \n\
add rsp, 0x28 \n\
mov rcx, [rsp +8] \n\
mov rdx, [rsp+16] \n\
mov r8, [rsp+24] \n\
mov r9, [rsp+32] \n\
mov r10, rcx \n\
syscall \n\
ret \n\
");

#define ZwClose NtClose
__asm__("NtClose: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x07A2B4377 \n\
call SW2_GetSyscallNumber \n\
add rsp, 0x28 \n\
mov rcx, [rsp +8] \n\
mov rdx, [rsp+16] \n\
mov r8, [rsp+24] \n\
mov r9, [rsp+32] \n\
mov r10, rcx \n\
syscall \n\
ret \n\
");

#endif