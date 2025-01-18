# Anti-Cheat Detection Vectors

This document catalogs known detection vectors used by major anti-cheat systems,
based on our research and public disclosures.

## Overview

| Vector | EAC | BattlEye | Vanguard | GameGuard |
|--------|-----|----------|----------|-----------|
| Memory Scanning | Yes | Yes | Yes | Yes |
| Module Enumeration | Yes | Yes | Yes | Yes |
| Handle Validation | Yes | Yes | Yes | No |
| Driver Stack Check | Yes | No | Yes | No |
| Syscall Monitoring | Yes | Partial | Yes | No |
| Thread Inspection | No | Yes | Partial | Yes |
| Timing Analysis | No | Yes | No | Yes |
| Hypervisor-based | No | No | Yes | No |
| Debug Detection | Yes | Yes | Yes | Yes |
| Code Integrity | Yes | Yes | Yes | Partial |
| Stack Walking | Partial | Yes | Yes | No |
| Registry Monitoring | No | No | Yes | No |

## Memory Scanning

All major anti-cheat systems perform periodic memory scans of the game process.

**EAC**: Scans all committed regions with PAGE_EXECUTE_* protections.
Uses signature-based detection with an encrypted, periodically updated
signature database downloaded from their servers.

**BattlEye**: Known to scan both executable and non-executable regions.
Uses a mix of pattern matching and heuristic analysis. The BEClient DLL
performs user-mode scans while the BEDaisy driver monitors kernel objects.

**Vanguard**: Kernel-level scanning via the vgk.sys driver. Scans are
performed from kernel mode, making them harder to intercept or redirect.
Can scan physical memory directly, bypassing user-mode protections.

## Module Enumeration

Anti-cheat systems maintain a list of expected modules and flag unknown ones.

**Detection methods:**
- Walking the PEB InMemoryOrderModuleList
- Using NtQueryInformationProcess
- NtQueryVirtualMemory with MemoryMappedFilenameInformation
- Kernel-mode MmGetFileNameForAddress
- Walking the VAD (Virtual Address Descriptor) tree

**Evasion considerations:**
- PEB unlinking only hides from user-mode PEB walks
- VAD-based detection requires kernel-mode countermeasures
- Manual mapping avoids module list entries but leaves
  memory regions with no backing file

## Handle Validation

Process handles opened to the game process are monitored.

**EAC**: Monitors ObRegisterCallbacks to intercept handle creation.
Strips PROCESS_VM_READ and PROCESS_VM_WRITE access from unauthorized handles.

**BattlEye**: Periodically enumerates all system handles via
NtQuerySystemInformation(SystemHandleInformation) and checks for
handles to the game process from non-whitelisted processes.

**Vanguard**: Blocks handle access at the kernel level using
ObRegisterCallbacks. Running at boot, it can intercept handles
before any user-mode code executes.

## Syscall Monitoring

Some anti-cheats hook or monitor system calls.

**EAC**: Hooks several ntdll functions in user mode. Known to check
for ntdll modifications by comparing against a clean copy from disk.

**Vanguard**: Operates at ring-0 with a kernel driver loaded at boot.
Can intercept syscalls via MSR hooks or page-level interception.

## Timing Analysis

**BattlEye**: Uses RDTSC and QueryPerformanceCounter to detect
debugging and single-stepping. Measures execution time of critical
code paths to detect breakpoints or instrumentation.

## Hypervisor Detection

**Vanguard**: Includes hypervisor detection via CPUID leaf 1 (ECX.31)
and timing-based VM exit detection. Also checks for known hypervisor
vendor strings.

## References

1. EasyAntiCheat documentation (public)
2. BattlEye developer documentation
3. Various security research publications on anti-cheat internals
4. Riot Games Vanguard technical blog posts
5. Windows Internals, 7th Edition (Russinovich et al.)
