# Sentinel

**Anti-Cheat Evasion & Game Security Research Framework**

Sentinel is a C/C++ framework for studying anti-cheat detection mechanisms, understanding their internals, and researching evasion techniques. Built over seven years of hands-on research into Windows internals, kernel-mode security, and game protection systems.

> This project is intended for **security research and education only**. See [SECURITY.md](SECURITY.md) for responsible use guidelines.

## Architecture

The framework is organized into modular layers:

- **Core Layer** - types, error codes, platform detection, privilege management
- **Process Module** - hollowing, DLL injection, PEB hiding, handle manipulation
- **Memory Module** - pattern scanning (with SIMD), protection, allocation, integrity
- **Driver Module** - kernel driver loading, manual mapping, IOCTL communication
- **Signature Module** - scanning, generation, binary mutation
- **Detection Module** - anti-cheat analysis, syscall hook detection, timing attacks
- **Utilities** - logging, crypto (XOR, RC4, FNV-1a), PE file parsing

## Detection Vector Coverage

| Anti-Cheat | User-Mode | Kernel-Mode | Process | Driver |
|------------|-----------|-------------|---------|--------|
| Easy Anti-Cheat | Yes | Yes | EasyAntiCheat.exe | EasyAntiCheat.sys |
| BattlEye | Yes | Yes | BEService.exe | BEDaisy.sys |
| Riot Vanguard | Yes | Yes | vgc.exe | vgk.sys |
| XIGNCODE3 | Yes | Yes | xhunter1.sys | xhunter1.sys |
| nProtect GameGuard | Yes | Partial | GameMon.des | npggsvc.sys |

### Detection Capabilities

| Technique | EAC | BattlEye | Vanguard |
|-----------|-----|----------|----------|
| Memory Scanning | Detected | Detected | Detected |
| Module Enumeration | Detected | Detected | Detected |
| Handle Monitoring | Detected | Detected | Detected |
| Syscall Hooks | Detected | Partial | Detected |
| Driver Integrity | Detected | - | Detected |
| Timing Analysis | - | Detected | - |
| Hypervisor | - | - | Detected |

## Quick Start

### Build

    cmake -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build --config Release

### Usage Examples

See the `examples/` directory for complete working examples:

- **basic_scan.cpp** - Pattern scanning with IDA-style signatures
- **driver_comm.cpp** - Kernel driver communication

## Tools

### sig_scan - Signature Scanner

    sig_scan --pattern "48 89 5C 24 ? 57 48 83 EC 20" target.dll
    sig_scan signatures.db target.exe

### ac_probe - Anti-Cheat Probe

Identifies running anti-cheat systems and analyzes their detection posture, including syscall hooks, ntdll integrity, timing analysis, and platform security features.

## Modules

### Process Module

- **Hollowing**: Create suspended process, unmap original image, write payload, patch PEB, resume
- **Injection**: LoadLibrary, manual DLL mapping, thread hijack via context manipulation
- **Hiding**: PEB list unlinking (all three lists), PE header zeroing, module name spoofing
- **Handle**: NtQuerySystemInformation handle enumeration, remote handle closing, duplication

### Memory Module

- **Scanner**: IDA-style pattern matching with wildcard support and SSE4.2 SIMD acceleration (2-5x speedup)
- **Protection**: VirtualProtectEx wrappers, region enumeration, atomic protected writes
- **Allocator**: Near-address allocation (within +/-2GB for relative jumps), code cave discovery
- **Integrity**: CRC32-based code integrity monitoring of executable sections

### Driver Module

- **Loader**: Service Control Manager based driver loading/unloading
- **Mapper**: Manual PE mapping with relocation processing (DIR64, HIGHLOW). VBS/HVCI-aware
- **Communication**: IOCTL-based user-kernel channel with structured protocol

### Signature Module

- **Scanner**: Signature database with file persistence and bulk scanning
- **Generator**: Auto-generate patterns from function prologues, wildcarding relative offsets
- **Mutator**: Polymorphic NOP sleds (1-5 byte variants), junk instruction insertion

### Detection Module

- **Analyzer**: Fingerprints running anti-cheat by process name and driver enumeration
- **Syscall**: Inline hook detection (JMP, MOV RAX, FF 25), ntdll integrity verification
- **Timing**: RDTSC debugger detection, CPUID VM exit timing, QPC consistency checks

## Research Background

Key areas of study behind this framework:

- **Windows kernel internals**: PEB/TEB structures, VAD trees, handle tables, object manager, system call dispatching
- **PE file format**: Headers, sections, imports/exports, relocations, TLS, exception handling
- **x86/x64 architecture**: Instruction encoding, memory paging, MSRs, VT-x/AMD-V
- **Anti-cheat techniques**: Memory scanning heuristics, kernel callback registration, hypervisor-based monitoring

Findings from this research have been responsibly disclosed to anti-cheat vendors.

## Platform Support

| Platform | Status |
|----------|--------|
| Windows 10/11 x64 | Full support |
| Windows 10 x86 | Partial (no driver module) |
| Linux | Stub implementations |

## Build Options

| Option | Default | Description |
|--------|---------|-------------|
| SENTINEL_BUILD_TOOLS | ON | Build standalone tools |
| SENTINEL_BUILD_EXAMPLES | ON | Build example programs |
| SENTINEL_BUILD_TESTS | ON | Build unit tests |

## Responsible Use

This framework exists to advance the understanding of game security. Use it only on systems you own or have authorization to test, for legitimate security research, and in compliance with all applicable laws. **Never** use this to create cheats or circumvent protections on live services.

## Contact

Need custom anti-cheat research, detection analysis, or enterprise licensing?

- **Email:** [contact@bypasscore.com](mailto:contact@bypasscore.com)
- **Telegram:** [@bypasscore](https://t.me/bypasscore)
- **Web:** [bypasscore.com](https://bypasscore.com)

## Support

Help keep BypassCore open-source and independent.

| Network | Address |
|---------|---------|
| **Polygon** | `0xd0f38b51496bee61ea5e9e56e2c414b607ab011a` |
| **Ethereum** | `0xd0f38b51496bee61ea5e9e56e2c414b607ab011a` |
| **BSC** | `0xd0f38b51496bee61ea5e9e56e2c414b607ab011a` |
| **Arbitrum** | `0xd0f38b51496bee61ea5e9e56e2c414b607ab011a` |
| **Optimism** | `0xd0f38b51496bee61ea5e9e56e2c414b607ab011a` |
| **Avalanche** | `0xd0f38b51496bee61ea5e9e56e2c414b607ab011a` |

USDT / USDC / ETH / BNB accepted on all networks.

## License

MIT License. See [LICENSE](LICENSE) for details.
