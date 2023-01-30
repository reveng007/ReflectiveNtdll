### :exclamation: A Small personal WeekEnd Project POC form my side. Completely Free and Open Source. Doesn't belong to my Company's Asset!

# ReflectiveNtdll
1. A POC Dropper focusing EDR evasion (***Self-Injecting dropper***). Again thanks to [Sektor7](https://institute.sektor7.net/) by [Reenzo](https://twitter.com/SEKTOR7net)
2. NTDLL Unhooking from implant Process.
3. Followed by loading of ntdll in-memory ([BYONtdll](https://steve-s.gitbook.io/0xtriboulet/unholy-unhooking/unholy-unhooking-frbyodll)), which is present as shellcode (using [pe2shc](https://github.com/hasherezade/pe_to_shellcode) by [@hasherezade](https://twitter.com/hasherezade)).
4. Evasion via ***In-memory Payload encryption*** via [SystemFucntion033](https://www.redteam.cafe/red-team/shellcode-injection/inmemory-shellcode-encryption-and-decryption-using-systemfunction033) NtApi. It performs RC4 encryption and decryption in-memory, which ***erradicates*** "_On Injection_"  shellcode detection, as in case of normal shellcode injection, encrypted payload is decrypted just before mapping those raw shellcode in process memeory, at that particular moment, the AV trigger happens. But in this case, no chance of that as decryption occurs when it is already mapped in process memory :wink:
5. Shellcode Execution via No new thread technique via [Fiber](https://www.ired.team/offensive-security/code-injection-process-injection/executing-shellcode-with-createfiber).

### DrawBack of this POC:
To make it work in all release versions of 

### Building the Executable:
```
1. Get the shellcode from Havoc C2 (Or any C2) [Tested Against Havoc C2 only!]

2. Use (in linux/ gitbash prompt) to get header file containing shellcode : xxd -i shellcode.bin > shellcode.h

3. Then copy the 'shellcode.h' to 'Encrypt_shellcode folder':

4. Use compile.bat to create the executable to encrypt the shellcode.h and will return shellcode.bin file (remember to edit the shellcode.h file with unsigned char named "shellcode")

5. Then: ".\encrypt.exe shellcode.h" => You will get a bin file which is encrypted.

6. Now again, (in linux/ gitbash prompt) to get header file containing encrypted shellcode : xxd -i enc_shellcode.bin > enc_shellcode.h (remember to edit the shellcode.h file with unsigned char named "enc_shellcode")

7. Now to get the shellcode version of ntdll: .\pe2shc.exe .\win10_ntdll_22H2_19045_2486.dll .\win10_ntdll_22H2_19045_2486.bin
(I tested in these versions only: win10_ntdll_22H2_19045_2486 and win11-ntdll_22H2_22621-1105)
8. Again, (in linux/ gitbash prompt) to get header file containing ntdll shellcode : xxd -i win10_ntdll_22H2_19045_2486.bin > win10_ntdll_22H2_19045_2486.h

9. Move those two header file to "ReflectiveNtdll" folder

10. Run: .\compile.bat
```

### Demo:

![ReflectiveNtdll](https://user-images.githubusercontent.com/61424547/215466427-b19b37de-4141-4b27-80ce-e2d93bf908ac.gif)

Video Link: https://drive.google.com/file/d/11lPBx2pYpy0_wr3lzVUeDziELdT-DAlK/view?usp=share_link

### Internal Findings:
1. Bypassing [Get-InjectedThread.ps1](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2) by [@jaredcatkinson](https://twitter.com/jaredcatkinson?lang=en):

I used CreateThread not CreateRemoteThread, to run shellcode version of ntdll in-memory!

According to [Get-InjectedThread.ps1](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2):

![image](https://user-images.githubusercontent.com/61424547/215455307-fc3bea35-4c21-4ec2-8359-6d377a5b6532.png)

No CreateThread is mentioned!

![image](https://user-images.githubusercontent.com/61424547/215441788-5bb0beff-ec9c-4d80-8162-c539263e8abf.png)

2. Bypassing [DefenderCheck](https://github.com/matterpreter/DefenderCheck): by [@matterpreter](https://twitter.com/matterpreter)

![image](https://user-images.githubusercontent.com/61424547/215447444-41e1819e-9196-4d56-bd45-d5bfec1d627a.png)

3. AntiScan.me Scan:

![image](https://user-images.githubusercontent.com/61424547/215460913-ec1e4100-ca54-4b99-befb-a08469965ae6.png)

4. [Capa](https://github.com/mandiant/capa) Scan:

![image](https://user-images.githubusercontent.com/61424547/215458741-6c714c4e-c7b0-413b-98f4-60adce771652.png)

5. [Moneta](https://github.com/forrest-orr/moneta) Scan: 

![image](https://user-images.githubusercontent.com/61424547/215459656-45d2608b-28c1-4c47-a734-979cad5c7cb4.png)

As we have loaded ntdll.dll in-memory and also the implant is not signed!

6. [Pe-sieve](https://github.com/hasherezade/pe-sieve) Scan:

```diff
PS C:\Users\HP\Desktop\Tools\DefenseTools> .\pe-sieve64.exe /pid 26744 /shellc /data 3
PID: 26744
Output filter: no filter: dump everything (default)
Dump mode: autodetect (default)
[-] Could not set debug privilege
[*] Using raw process!
[*] Scanning: C:\Users\HP\Desktop\Windows\MaldevTechniques\3.Evasions\ReflectiveNtdll\implant.exe
[*] Scanning: C:\Windows\System32\ntdll.dll
[*] Scanning: C:\Windows\System32\kernel32.dll
[*] Scanning: C:\Windows\System32\KERNELBASE.dll
[*] Scanning: C:\Windows\System32\advapi32.dll
[*] Scanning: C:\Windows\System32\msvcrt.dll
[*] Scanning: C:\Windows\System32\sechost.dll
[*] Scanning: C:\Windows\System32\rpcrt4.dll
[*] Scanning: C:\Windows\System32\cryptsp.dll
[*] Scanning: C:\Windows\System32\bcrypt.dll
[*] Scanning: C:\Windows\System32\bcryptprimitives.dll
[*] Scanning: C:\Windows\System32\crypt32.dll
[*] Scanning: C:\Windows\System32\ucrtbase.dll
[*] Scanning: C:\Windows\System32\mscoree.dll
[*] Scanning: C:\Windows\System32\oleaut32.dll
[*] Scanning: C:\Windows\System32\msvcp_win.dll
[*] Scanning: C:\Windows\System32\combase.dll
[*] Scanning: C:\Windows\System32\user32.dll
[*] Scanning: C:\Windows\System32\win32u.dll
[*] Scanning: C:\Windows\System32\gdi32.dll
[*] Scanning: C:\Windows\System32\gdi32full.dll
[*] Scanning: C:\Windows\System32\imm32.dll
[*] Scanning: C:\Windows\System32\shell32.dll
[*] Scanning: C:\Windows\System32\winhttp.dll
[*] Scanning: C:\Windows\System32\IPHLPAPI.DLL
[*] Scanning: C:\Windows\System32\wkscli.dll
[*] Scanning: C:\Windows\System32\netapi32.dll
[*] Scanning: C:\Windows\System32\samcli.dll
[*] Scanning: C:\Windows\System32\srvcli.dll
[*] Scanning: C:\Windows\System32\netutils.dll
[*] Scanning: C:\Windows\System32\sspicli.dll
[*] Scanning: C:\Windows\System32\nsi.dll
[*] Scanning: C:\Windows\System32\dhcpcsvc.dll
[*] Scanning: C:\Windows\System32\ws2_32.dll
[*] Scanning: C:\Windows\System32\webio.dll
[*] Scanning: C:\Windows\System32\mswsock.dll
[*] Scanning: C:\Windows\System32\winnsi.dll
[*] Scanning: C:\Windows\System32\schannel.dll
[*] Scanning: C:\Windows\System32\mskeyprotect.dll
[*] Scanning: C:\Windows\System32\ntasn1.dll
[*] Scanning: C:\Windows\System32\ncrypt.dll
[*] Scanning: C:\Windows\System32\ncryptsslp.dll
[*] Scanning: C:\Windows\System32\msasn1.dll
[*] Scanning: C:\Windows\System32\rsaenh.dll
[*] Scanning: C:\Windows\System32\CRYPTBASE.dll
[*] Scanning: C:\Windows\System32\gpapi.dll
[*] Scanning: C:\Windows\System32\dpapi.dll
[*] Scanning: C:\Windows\System32\dnsapi.dll
Scanning workingset: 328 memory regions.
[*] Workingset scanned in 2500 ms
[+] Report dumped to: process_26744
[*] Dumped module to: C:\Users\HP\Desktop\Tools\DefenseTools\\process_26744\234daa50000.shc as VIRTUAL
[*] Dumped module to: C:\Users\HP\Desktop\Tools\DefenseTools\\process_26744\234daa61000.shc as VIRTUAL
[*] Dumped module to: C:\Users\HP\Desktop\Tools\DefenseTools\\process_26744\234dabc0000.dll as UNMAPPED
[+] Dumped modified to: process_26744
[+] Report dumped to: process_26744
---
PID: 26744
---
SUMMARY:

Total scanned:      48
Skipped:            0
-
Hooked:             0
Replaced:           0
Hdrs Modified:      0
IAT Hooks:          0
-Implanted:          3
-Implanted PE:       2
-Implanted shc:      1
Unreachable files:  0
Other:              0
-
-Total suspicious:   3
---
```

7. [PEBear](https://github.com/hasherezade/pe-bear) View: IAT Table

![image](https://user-images.githubusercontent.com/61424547/215467783-9adff000-8285-4692-b14e-8100e62ddf9e.png)

Suspicious usage of WinApi is removed from IAT

### Also thanks to:
1. [@Jean_Maes_1994](https://twitter.com/Jean_Maes_1994) for enlightening me, regarding the internals of EDR and other suggestions.
2. [@D1rkMtr](https://twitter.com/D1rkMtr/) for having a spontenious discussion on ImplantDev.
3. [@_winterknife_](https://twitter.com/_winterknife_) for his [Wraith](https://github.com/slaeryan/AQUARMOURY/tree/master/Wraith) Project.
4. [@peterwintrsmith](https://twitter.com/peterwintrsmith) for enlightening me, regarding the internals of `ntdll.dll` hooking by EDR.
