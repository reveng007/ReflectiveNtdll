@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp implant.cpp /link /OUT:implant.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
del implant.obj
