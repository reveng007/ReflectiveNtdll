@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp encrypt.cpp /link /OUT:encrypt.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
del *.obj
