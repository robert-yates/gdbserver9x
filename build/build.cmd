@echo off
cls
set TOOLCHAIN_DIR=D:\main\software\Microsoft Visual Studio 6.0
set COMPILER="%TOOLCHAIN_DIR%\VC98\bin\CL.EXE"
set LINKER="%TOOLCHAIN_DIR%\VC98\bin\LINK.EXE"
set LIBSDIR=%TOOLCHAIN_DIR%\VC98\Lib
set INCLUDEDIR=%TOOLCHAIN_DIR%\VC98\Include

set INCLUDE=%INCLUDEDIR%
set LIB=%LIBSDIR%

if not exist "%TOOLCHAIN_DIR%\VC98\bin\MSPDB60.DLL" (
    copy "%TOOLCHAIN_DIR%\Common\MSDev98\Bin\MSPDB60.DLL" "%TOOLCHAIN_DIR%\VC98\bin\MSPDB60.DLL"
)

%COMPILER% /ML /W3 /GX /Ox /Ob2 /Oy /GF /G6 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /Fo"./" /Fd"./" /FD /c "../main.c" "../server.c" "../context.c" "../utils.c" "../gdb.c" "../debugger.c"
%LINKER% /OPT:REF /RELEASE kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /subsystem:console /incremental:no /pdb:"./gdbserver9x.pdb" /machine:I386 /out:"./gdbserver9x.exe" ".\main.obj" ".\server.obj" ".\context.obj" ".\utils.obj" ".\gdb.obj" ".\debugger.obj"



