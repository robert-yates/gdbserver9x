# gdbserver9x

# Info

`gdbserver9x` is a very hacked together gdbserver implementation for debugging 32bits exes on old windows machines. It works best with [BinaryNinja's](https://binary.ninja/) `GDP RSP` adapter. Tested on Windows 98SE, Windows 2000-SP4 and Windows XP-SP3

## Building

The tested toolchain is Microsoft Visual Studio 6.0 / Visual C++ 6.0
targeting 32-bit x86 Windows.

A helper script is available at `build\build.cmd`. Update `TOOLCHAIN_DIR` in
that script to match your Visual Studio 6.0 installation, then run it from the
`build` directory:

```bat
cd build
build.cmd
```

The script compiles the C sources and writes `gdbserver9x.exe` into `build`.
If you use another compatible toolchain, compile the project as a Win32 console
program and link against Winsock 2 (`ws2_32.lib`) plus the normal Win32 system
libraries.

## Usage

```text
gdbserver9x.exe HOST:PORT PROGRAM [ARGS...]
```

Example:

```bat
gdbserver9x.exe 0.0.0.0:31337 C:\targets\hello.exe arg1 arg2
```

To enable verbose packet and debugger logging, set `GDBLOG` before launching:

```bat
set GDBLOG=1
gdbserver9x.exe 0.0.0.0:31337 C:\targets\hello.exe
```

```bat
set GDBRESTART=1
```

will restart the server on exit

## Limitations

- Only 32-bit Windows debuggees are in scope.
- The server launches a new process; it does not attach to an existing process.
- While the debuggee is running, the main loop waits for the next Windows debug
  event and does not process arbitrary incoming RSP packets.
- Hardware breakpoints and watchpoints, are not currently implemented.

## History

v1.0  
  - inital release not battle tested  

v1.1  
  - allows round trip debugging via `GDBRESTART` var  
  - allows register writes  
  - allows memory writes  
  
v1.2  
  - fix deadlock when reading module list on windows 2000  
  
have fun  
/yates.