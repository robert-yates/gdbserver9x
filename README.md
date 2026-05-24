# gdbserver9x

# Info

`gdbserver9x` is a very hacked together gdbserver implementation for debugging 32bits exes on old windows machines. It works best with [BinaryNinja's](https://binary.ninja/) `GDP RSP` adapter. Tested on Windows 98SE and Windows XP-SP3
## Status

It implements the basics needed for practical 32-bit process debugging on old Windows machines, with a focus on keeping the code simple enough to build with the Visual C++ 6.0 toolchain.

Implemented support includes:

- Launching a target process under the Windows debugging API.
- GDB RSP packet framing, checksums, and no-ack mode.
- Basic process, host, thread, and register queries.
- Memory reads and memory region queries.
- Continue and single-step requests.
- Software breakpoints via `Z0` and `z0`.
- Thread listing and thread selection.
- Module/library metadata used by Binary Ninja and LLDB-style adapters.

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

## Limitations

- Only 32-bit Windows debuggees are in scope.
- The server launches a new process; it does not attach to an existing process.
- While the debuggee is running, the main loop waits for the next Windows debug
  event and does not process arbitrary incoming RSP packets.
- Hardware breakpoints, watchpoints, and general memory writes are not currently
  implemented.

have fun  
/yates.