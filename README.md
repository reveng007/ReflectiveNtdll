# ReflectiveNtdll
A POC Dropper focusing EDR evasion, NTDLL Unhooking followed by loading ntdll in-memory, which is present as shellcode (using pe2shc by @hasherezade). Payload encryption via SystemFucntion033 NtApi and No new thread via Fiber
