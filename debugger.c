#include "context.h"
#include "windows.h"
#include "stdio.h"
#include "stdlib.h"

int wait_for_interesting_stop();
void add_thread(DWORD tid, HANDLE hThread);
void remove_thread(DWORD tid);
DWORD exception_to_signal(DWORD code);
DWORD reg_by_index(CONTEXT* c, int n, int* ok);
int find_bp_by_addr(DWORD addr);
int alloc_bp_slot();
int write_debuggee_byte(DWORD addr, BYTE value);
int read_debuggee_byte(DWORD addr, BYTE* value);
void maybe_flush_icache(LPCVOID addr, SIZE_T len);
int get_context_for_current(CONTEXT* ctx);
int set_context_for_current(CONTEXT* ctx);
int handle_possible_swbreak_hit(void);
void make_stop_reply(char* out, int outsz);
void patch_breakpoints_out_of_memory_read(DWORD addr, BYTE* buf, DWORD len);
DWORD get_first_section_rva_from_file(const char* path);
void populate_module_sections_from_pe(struct modules* m);
static void invalidate_thread_caches(void);

int launch_debuggee(const char* cmdline) {

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    char exe_path[MAX_PATH];
    const char* p;
    const char* exe_end;
    size_t exe_len;

    if (!cmdline || !cmdline[0]) {
        printf("[launch_debuggee]: empty cmdline\n");
        return 0;
    }

    p = cmdline;
    while (*p == ' ' || *p == '\t')
        p++;
    exe_end = p;
    while (*exe_end && *exe_end != ' ' && *exe_end != '\t')
        exe_end++;
    exe_len = (size_t)(exe_end - p);
    if (exe_len >= sizeof(exe_path))
        exe_len = sizeof(exe_path) - 1;
    memcpy(exe_path, p, exe_len);
    exe_path[exe_len] = '\0';

    GetFullPathName(exe_path, sizeof(g_ctx.mod.exec_file), g_ctx.mod.exec_file, NULL);

    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    if (!CreateProcess(NULL, (LPSTR)cmdline, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) {
        printf("[launch_debuggee]: CreateProcess failed: %lu\n", GetLastError());
        return 0;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return wait_for_interesting_stop();
}

int wait_for_interesting_stop() {
    DEBUG_EVENT ev;
    DWORD cont = 0;

    for (;;) {
        if (!WaitForDebugEvent(&ev, INFINITE)) {
            printf("WaitForDebugEvent failed: %lu\n", GetLastError());
            return 0;
        }

        g_ctx.dbg.last_event = ev;
        g_ctx.dbg.have_pending_event = 1;
        g_ctx.dbg.current_tid = ev.dwThreadId;

        switch (ev.dwDebugEventCode) {
            case CREATE_PROCESS_DEBUG_EVENT: {
                printf("[debugger]: CREATE_PROCESS_DEBUG_EVENT pid=%lu tid=%lu\n", ev.dwProcessId, ev.dwThreadId);
                g_ctx.mod.modules_changed = 1;
                g_ctx.dbg.process_id = ev.dwProcessId;
                g_ctx.dbg.process_handle = ev.u.CreateProcessInfo.hProcess;
                g_ctx.mod.main_module_base = (DWORD)ev.u.CreateProcessInfo.lpBaseOfImage;
                add_thread(ev.dwThreadId, ev.u.CreateProcessInfo.hThread);
                CloseHandle(ev.u.CreateProcessInfo.hFile);
                cont = DBG_CONTINUE;
                break;
            }

            case CREATE_THREAD_DEBUG_EVENT: {
                printf("[debugger]: CREATE_THREAD_DEBUG_EVENT pid=%lu tid=%lu\n", ev.dwProcessId, ev.dwThreadId);
                add_thread(ev.dwThreadId, ev.u.CreateThread.hThread);
                cont = DBG_CONTINUE;
                break;
            }

            case EXIT_THREAD_DEBUG_EVENT: {
                printf("[debugger]: EXIT_THREAD_DEBUG_EVENT pid=%lu tid=%lu\n", ev.dwProcessId, ev.dwThreadId);
                remove_thread(ev.dwThreadId);
                cont = DBG_CONTINUE;
                break;
            }

            case LOAD_DLL_DEBUG_EVENT: {
                printf("[debugger]: LOAD_DLL_DEBUG_EVENT pid=%lu tid=%lu\n", ev.dwProcessId, ev.dwThreadId);
                g_ctx.mod.modules_changed = 1;
                CloseHandle(ev.u.LoadDll.hFile);
                cont = DBG_CONTINUE;
                break;
            }

            case UNLOAD_DLL_DEBUG_EVENT: {
                printf("[debugger]: UNLOAD_DLL_DEBUG_EVENT pid=%lu tid=%lu\n", ev.dwProcessId, ev.dwThreadId);
                g_ctx.mod.modules_changed = 1;
                cont = DBG_CONTINUE;
                break;
            }
            case OUTPUT_DEBUG_STRING_EVENT: {
                printf("[debugger]: OUTPUT_DEBUG_STRING_EVENT pid=%lu tid=%lu\n", ev.dwProcessId, ev.dwThreadId);
                cont = DBG_CONTINUE;
                break;
            }

            case EXIT_PROCESS_DEBUG_EVENT: {
                printf("[debugger]: EXIT_PROCESS_DEBUG_EVENT pid=%lu tid=%lu\n", ev.dwProcessId, ev.dwThreadId);
                g_ctx.dbg.last_signal = 0;
                return 1;
            }

            case EXCEPTION_DEBUG_EVENT: {
                printf("[debugger]: EXCEPTION_DEBUG_EVENT pid=%lu tid=%lu code=0x%08lx\n", ev.dwProcessId, ev.dwThreadId,
                       ev.u.Exception.ExceptionRecord.ExceptionCode);
                g_ctx.dbg.last_stop_was_breakpoint = 0;
                g_ctx.dbg.last_stop_was_single_step = (ev.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP);

                if (ev.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
                    printf("[debugger]: Hit breakpoint at EIP=0x%08lx\n", ev.u.Exception.ExceptionRecord.ExceptionAddress);
                    if (handle_possible_swbreak_hit()) {
                        printf("[debugger]: Handled breakpoint hit at 0x%08lx\n", ev.u.Exception.ExceptionRecord.ExceptionAddress);
                        g_ctx.dbg.last_signal = 5; /* SIGTRAP */
                        return 1;
                    }
                    printf("[debugger]: Unhandled breakpoint at 0x%08lx\n", ev.u.Exception.ExceptionRecord.ExceptionAddress);
                }

                g_ctx.dbg.last_signal = exception_to_signal(ev.u.Exception.ExceptionRecord.ExceptionCode);
                printf("[debugger]: Mapped exception code 0x%08lx to signal %lu\n", ev.u.Exception.ExceptionRecord.ExceptionCode,
                       g_ctx.dbg.last_signal);
                return 1;
            }

            default: {
                fprintf(stdout, "[debugger]: UNKNOWN_EVENT %lu pid=%lu tid=%lu\n", ev.dwDebugEventCode, ev.dwProcessId, ev.dwThreadId);
                ExitProcess(-1);
            }
        }

        g_ctx.dbg.have_pending_event = 0;
        invalidate_thread_caches();
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
    }
}

void set_pc_if_present(const char* pkt) {
    CONTEXT c;
    DWORD addr;

    if (pkt[1] == 0)
        return;

    addr = strtoul(pkt + 1, NULL, 16);

    if (get_context_for_current(&c)) {
        c.Eip = addr;
        set_context_for_current(&c);
    }
}

int handle_possible_swbreak_hit(void) {
    CONTEXT c;
    DWORD bp_addr;
    int idx;

    if (!get_context_for_current(&c))
        return 0;

    bp_addr = c.Eip - 1;

    idx = find_bp_by_addr(bp_addr);
    if (idx < 0 || !g_ctx.dbg.bps[idx].inserted)
        return 0;

    /*
       Restore original instruction byte.
    */
    if (!write_debuggee_byte(bp_addr, g_ctx.dbg.bps[idx].original_byte))
        return 0;

    g_ctx.dbg.bps[idx].inserted = 0;
    g_ctx.dbg.inserted_bp_count--;

    /*
       Rewind EIP so the frontend sees execution stopped at the
       breakpoint address, not one byte after it.
    */
    c.Eip = bp_addr;
    set_context_for_current(&c);

    g_ctx.dbg.last_stop_was_breakpoint = 1;
    return 1;
}

int find_bp_at_current_eip(void) {
    CONTEXT c;

    if (!get_context_for_current(&c))
        return -1;

    return find_bp_by_addr(c.Eip);
}

int ensure_bp_temporarily_removed(int idx) {
    if (idx < 0)
        return 1;

    if (!g_ctx.dbg.bps[idx].used)
        return 1;

    if (!g_ctx.dbg.bps[idx].inserted)
        return 1;

    if (!write_debuggee_byte(g_ctx.dbg.bps[idx].addr, g_ctx.dbg.bps[idx].original_byte))
        return 0;

    g_ctx.dbg.bps[idx].inserted = 0;
    g_ctx.dbg.inserted_bp_count--;
    return 1;
}

int reinsert_bp(int idx) {
    if (idx < 0)
        return 1;

    if (!g_ctx.dbg.bps[idx].used)
        return 1;

    if (g_ctx.dbg.bps[idx].inserted)
        return 1;

    if (!write_debuggee_byte(g_ctx.dbg.bps[idx].addr, 0xCC))
        return 0;

    g_ctx.dbg.bps[idx].inserted = 1;
    g_ctx.dbg.inserted_bp_count++;
    return 1;
}

int continue_pending_event(DWORD status) {
    if (!g_ctx.dbg.have_pending_event)
        return 1;

    invalidate_thread_caches();

    if (!ContinueDebugEvent(g_ctx.dbg.last_event.dwProcessId, g_ctx.dbg.last_event.dwThreadId, status)) {
        printf("ContinueDebugEvent failed: %lu\n", GetLastError());
        return 0;
    }

    g_ctx.dbg.have_pending_event = 0;
    return 1;
}

HANDLE find_thread(DWORD tid) {
    int i;
    for (i = 0; i < g_ctx.dbg.thread_count; ++i) {
        if (g_ctx.dbg.threads[i].tid == tid)
            return g_ctx.dbg.threads[i].hThread;
    }
    return NULL;
}

static void invalidate_thread_caches(void) {
    g_ctx.dbg.cached_ctx_tid = 0;
    g_ctx.dbg.cached_g_reply_valid = 0;
}

int get_context_for_current(CONTEXT* ctx) {
    HANDLE ht;

    if (g_ctx.dbg.cached_ctx_tid != 0 && g_ctx.dbg.cached_ctx_tid == g_ctx.dbg.current_tid) {
        memcpy(ctx, &g_ctx.dbg.cached_ctx, sizeof(*ctx));
        return 1;
    }

    ht = find_thread(g_ctx.dbg.current_tid);

    if (!ht)
        return 0;

    memset(ctx, 0, sizeof(*ctx));
    ctx->ContextFlags = CONTEXT_FULL | CONTEXT_SEGMENTS;

    if (!GetThreadContext(ht, ctx)) {
        printf("GetThreadContext failed tid=%lu err=%lu\n", g_ctx.dbg.current_tid, GetLastError());
        return 0;
    }

    memcpy(&g_ctx.dbg.cached_ctx, ctx, sizeof(*ctx));
    g_ctx.dbg.cached_ctx_tid = g_ctx.dbg.current_tid;

    return 1;
}

int set_context_for_current(CONTEXT* ctx) {
    HANDLE ht = find_thread(g_ctx.dbg.current_tid);

    if (!ht)
        return 0;

    if (!SetThreadContext(ht, ctx)) {
        printf("SetThreadContext failed tid=%lu err=%lu\n", g_ctx.dbg.current_tid, GetLastError());
        return 0;
    }

    memcpy(&g_ctx.dbg.cached_ctx, ctx, sizeof(*ctx));
    g_ctx.dbg.cached_ctx_tid = g_ctx.dbg.current_tid;
    g_ctx.dbg.cached_g_reply_valid = 0;

    return 1;
}

void read_all_registers(char* out, int outsz) {
    CONTEXT c;
    char* p;
    int n;

    if (g_ctx.dbg.cached_g_reply_valid && g_ctx.dbg.cached_g_reply_tid == g_ctx.dbg.current_tid) {
        strcpy(out, g_ctx.dbg.cached_g_reply);
        return;
    }

    if (!get_context_for_current(&c)) {
        strcpy(out, "E01");
        return;
    }

    /*
       Register order:
       eax ebx ecx edx edi esi ebp esp eip eflags cs fs gs ss ds es
    */
    p = out;
    p = append_u32_le(p, c.Eax);
    p = append_u32_le(p, c.Ebx);
    p = append_u32_le(p, c.Ecx);
    p = append_u32_le(p, c.Edx);
    p = append_u32_le(p, c.Edi);
    p = append_u32_le(p, c.Esi);
    p = append_u32_le(p, c.Ebp);
    p = append_u32_le(p, c.Esp);
    p = append_u32_le(p, c.Eip);
    p = append_u32_le(p, c.EFlags);
    p = append_u32_le(p, c.SegCs);
    p = append_u32_le(p, c.SegFs);
    p = append_u32_le(p, c.SegGs);
    p = append_u32_le(p, c.SegSs);
    p = append_u32_le(p, c.SegDs);
    p = append_u32_le(p, c.SegEs);

    *p = 0;

    n = (int)(p - out);
    if (n < (int)sizeof(g_ctx.dbg.cached_g_reply)) {
        memcpy(g_ctx.dbg.cached_g_reply, out, n + 1);
        g_ctx.dbg.cached_g_reply_tid = g_ctx.dbg.current_tid;
        g_ctx.dbg.cached_g_reply_valid = 1;
    }
}

void read_one_register(const char* pkt, char* out, int outsz) {
    CONTEXT c;
    int n, ok;
    DWORD v;
    char* p = out;

    n = (int)strtoul(pkt + 1, NULL, 16);

    if (!get_context_for_current(&c)) {
        strcpy(out, "E01");
        return;
    }

    v = reg_by_index(&c, n, &ok);
    if (!ok) {
        strcpy(out, "xxxxxxxx");
        return;
    }

    p = append_u32_le(p, v);
    *p = 0;
}

void add_thread(DWORD tid, HANDLE hThread) {
    if (g_ctx.dbg.thread_count >= MAX_THREADS)
        return;

    g_ctx.dbg.threads[g_ctx.dbg.thread_count].tid = tid;
    g_ctx.dbg.threads[g_ctx.dbg.thread_count].hThread = hThread;
    g_ctx.dbg.thread_count++;

    if (g_ctx.dbg.current_tid == 0)
        g_ctx.dbg.current_tid = tid;
}

void remove_thread(DWORD tid) {
    int i;

    for (i = 0; i < g_ctx.dbg.thread_count; ++i) {
        if (g_ctx.dbg.threads[i].tid != tid)
            continue;

        if (i != g_ctx.dbg.thread_count - 1)
            g_ctx.dbg.threads[i] = g_ctx.dbg.threads[g_ctx.dbg.thread_count - 1];

        g_ctx.dbg.thread_count--;
        memset(&g_ctx.dbg.threads[g_ctx.dbg.thread_count], 0, sizeof(g_ctx.dbg.threads[g_ctx.dbg.thread_count]));

        if (g_ctx.dbg.current_tid == tid)
            g_ctx.dbg.current_tid = g_ctx.dbg.thread_count > 0 ? g_ctx.dbg.threads[0].tid : 0;

        return;
    }
}

DWORD exception_to_signal(DWORD code) {
    switch (code) {
        case EXCEPTION_BREAKPOINT:
        case EXCEPTION_SINGLE_STEP:
            return 5; /* SIGTRAP */
        case EXCEPTION_ACCESS_VIOLATION:
            return 11; /* SIGSEGV */
        case EXCEPTION_ILLEGAL_INSTRUCTION:
            return 4; /* SIGILL */
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:
            return 8; /* SIGFPE */
        default:
            return 5;
    }
}

int insert_sw_breakpoint(DWORD addr, DWORD kind) {
    int idx;
    BYTE b;

    (void)kind;

    idx = find_bp_by_addr(addr);

    if (idx >= 0) {
        if (g_ctx.dbg.bps[idx].inserted)
            return 1;

        if (!write_debuggee_byte(addr, 0xCC))
            return 0;

        g_ctx.dbg.bps[idx].inserted = 1;
        g_ctx.dbg.inserted_bp_count++;
        return 1;
    }

    idx = alloc_bp_slot();
    if (idx < 0)
        return 0;

    if (!read_debuggee_byte(addr, &b))
        return 0;

    if (!write_debuggee_byte(addr, 0xCC))
        return 0;

    {
        BYTE check = 0;
        if (read_debuggee_byte(addr, &check))
            printf("[bp]: insert addr=0x%08lx orig=0x%02x readback=0x%02x\n", addr, b, check);
        else
            printf("[bp]: insert addr=0x%08lx orig=0x%02x readback=FAILED\n", addr, b);
    }

    g_ctx.dbg.bps[idx].used = 1;
    g_ctx.dbg.bps[idx].addr = addr;
    g_ctx.dbg.bps[idx].original_byte = b;
    g_ctx.dbg.bps[idx].inserted = 1;
    g_ctx.dbg.inserted_bp_count++;

    return 1;
}

int remove_sw_breakpoint(DWORD addr) {
    int idx;

    idx = find_bp_by_addr(addr);
    if (idx < 0) {
        return 1;
    }

    if (g_ctx.dbg.bps[idx].inserted) {
        if (!write_debuggee_byte(addr, g_ctx.dbg.bps[idx].original_byte))
            return 0;

        g_ctx.dbg.inserted_bp_count--;
    }

    memset(&g_ctx.dbg.bps[idx], 0, sizeof(g_ctx.dbg.bps[idx]));
    return 1;
}

void read_memory_packet(const char* pkt, char* out, int outsz) {
    DWORD addr;
    DWORD len;
    const char* comma;
    BYTE buf[1024];
    SIZE_T got = 0;
    DWORD i;
    char* p = out;

    comma = strchr(pkt, ',');
    if (!comma) {
        strcpy(out, "E22");
        return;
    }

    addr = strtoul(pkt + 1, NULL, 16);
    len = strtoul(comma + 1, NULL, 16);

    if (len > sizeof(buf))
        len = sizeof(buf);

    if (!ReadProcessMemory(g_ctx.dbg.process_handle, (LPCVOID)addr, buf, len, &got)) {
        strcpy(out, "E14");
        return;
    }

    patch_breakpoints_out_of_memory_read(addr, buf, (DWORD)got);

    for (i = 0; i < got && (p + 2) < (out + outsz); ++i)
        p = append_hex_byte(p, buf[i]);

    *p = '\0';
}

int read_debuggee_byte(DWORD addr, BYTE* out) {
    SIZE_T got = 0;

    if (!ReadProcessMemory(g_ctx.dbg.process_handle, (LPCVOID)addr, out, 1, &got))
        return 0;

    return got == 1;
}

int write_debuggee_byte(DWORD addr, BYTE value) {
    SIZE_T written = 0;

    if (!WriteProcessMemory(g_ctx.dbg.process_handle, (LPVOID)addr, &value, 1, &written))
        return 0;

    if (written != 1)
        return 0;

    maybe_flush_icache((LPCVOID)addr, 1);

    return 1;
}

int find_bp_by_addr(DWORD addr) {
    int i;

    for (i = 0; i < MAX_BREAKPOINTS; ++i) {
        if (g_ctx.dbg.bps[i].used && g_ctx.dbg.bps[i].addr == addr) {
            printf("Found breakpoint slot %d for address 0x%08lx\n", i, addr);
            return i;
        }
    }

    return -1;
}

int alloc_bp_slot(void) {
    int i;

    for (i = 0; i < MAX_BREAKPOINTS; ++i) {
        if (!g_ctx.dbg.bps[i].used)
            return i;
    }

    return -1;
}

DWORD reg_by_index(CONTEXT* c, int n, int* ok) {
    *ok = 1;

    switch (n) {
        case 0:
            return c->Eax;
        case 1:
            return c->Ebx;
        case 2:
            return c->Ecx;
        case 3:
            return c->Edx;
        case 4:
            return c->Edi;
        case 5:
            return c->Esi;
        case 6:
            return c->Ebp;
        case 7:
            return c->Esp;
        case 8:
            return c->Eip;
        case 9:
            return c->EFlags;
        case 10:
            return c->SegCs;
        case 11:
            return c->SegFs;
        case 12:
            return c->SegGs;
        case 13:
            return c->SegSs;
        case 14:
            return c->SegDs;
        case 15:
            return c->SegEs;
        default:
            *ok = 0;
            return 0;
    }
}

typedef BOOL(WINAPI* PFN_FLUSH_INSTRUCTION_CACHE)(HANDLE, LPCVOID, SIZE_T);
void maybe_flush_icache(LPCVOID addr, SIZE_T len) {
    HMODULE k32;
    PFN_FLUSH_INSTRUCTION_CACHE pFlush;

    k32 = GetModuleHandle("KERNEL32.DLL");
    if (!k32)
        return;

    pFlush = (PFN_FLUSH_INSTRUCTION_CACHE)GetProcAddress(k32, "FlushInstructionCache");

    if (pFlush)
        pFlush(g_ctx.dbg.process_handle, addr, len);
}

void set_single_step_flag(void) {
    CONTEXT c;

    if (get_context_for_current(&c)) {
        c.EFlags |= 0x100; /* x86 trap flag */
        set_context_for_current(&c);
    }
}

void clear_single_step_flag(void) {
    CONTEXT c;

    if (g_ctx.dbg.last_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
        g_ctx.dbg.last_event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
        return;
    }

    if (get_context_for_current(&c)) {
        c.EFlags &= ~0x100;
        set_context_for_current(&c);
    }
}

int step_over_breakpoint_for_continue(void) {
    int idx;

    idx = find_bp_at_current_eip();
    if (idx < 0) {
        if (!continue_pending_event(DBG_CONTINUE))
            return 0;

        return 1;
    }

    if (!ensure_bp_temporarily_removed(idx))
        return 0;

    set_single_step_flag();

    if (!continue_pending_event(DBG_CONTINUE))
        return 0;

    if (!wait_for_interesting_stop())
        return 0;

    clear_single_step_flag();

    /*
       Expected stop: EXCEPTION_SINGLE_STEP.
       If something else happened, report it to the frontend instead
       of swallowing it.
    */
    if (g_ctx.dbg.last_event.dwDebugEventCode != EXCEPTION_DEBUG_EVENT ||
        g_ctx.dbg.last_event.u.Exception.ExceptionRecord.ExceptionCode != EXCEPTION_SINGLE_STEP) {
        reinsert_bp(idx);
        return 2; /* real stop happened */
    }

    if (!reinsert_bp(idx))
        return 0;

    /*
       Swallow the internal single-step event.
       The caller will continue again and wait for a real stop.
    */
    if (!continue_pending_event(DBG_CONTINUE))
        return 0;

    return 1;
}

int step_once_for_frontend(char* reply, int replysz) {
    int idx;

    idx = find_bp_at_current_eip();

    if (idx >= 0) {
        if (!ensure_bp_temporarily_removed(idx)) {
            strcpy(reply, "E01");
            return 1;
        }
    }

    set_single_step_flag();

    if (!continue_pending_event(DBG_CONTINUE)) {
        strcpy(reply, "E01");
        return 1;
    }

    if (!wait_for_interesting_stop()) {
        strcpy(reply, "E02");
        return 1;
    }

    clear_single_step_flag();

    if (idx >= 0)
        reinsert_bp(idx);

    make_stop_reply(reply, replysz);
    return 1;
}

void add_or_update_module(DWORD base, DWORD size, const char* path) {
    int i;
    int idx = -1;

    for (i = 0; i < g_ctx.mod.mod_count; ++i) {
        if (g_ctx.mod.mods[i].base == base) {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        if (g_ctx.mod.mod_count >= MAX_MODULES)
            return;

        idx = g_ctx.mod.mod_count++;
        memset(&g_ctx.mod.mods[idx], 0, sizeof(g_ctx.mod.mods[idx]));
    }

    g_ctx.mod.mods[idx].base = base;
    g_ctx.mod.mods[idx].size = size ? size : 0x1000;

    if (path && path[0]) {
        strncpy(g_ctx.mod.mods[idx].path, path, MAX_MODULE_PATH - 1);
        g_ctx.mod.mods[idx].path[MAX_MODULE_PATH - 1] = '\0';
    }

    populate_module_sections_from_pe(&g_ctx.mod.mods[idx]);

    // printf("[modules]: module base=0x%08lx sections=%d path=%s\n",
    //        g_ctx.mod.mods[idx].base,
    //        g_ctx.mod.mods[idx].section_count,
    //        g_ctx.mod.mods[idx].path);
}

void make_bn_maps_path(const char* win_path, char* out, int outsz) {
    int i, j;

    if (!win_path || !win_path[0]) {
        strncpy(out, "/unknown", outsz - 1);
        out[outsz - 1] = 0;
        return;
    }

    /*
       Binary Ninja's GDB adapter expects the maps path field to begin
       with '/', so turn:

           C:\WINDOWS\SYSTEM32\KERNEL32.DLL

       into:

           /C:/WINDOWS/SYSTEM32/KERNEL32.DLL
    */
    j = 0;

    if (j < outsz - 1)
        out[j++] = '/';

    for (i = 0; win_path[i] && j < outsz - 1; ++i) {
        char c = win_path[i];

        if (c == '\\')
            c = '/';

        out[j++] = c;
    }

    out[j] = 0;
}

int refresh_modules_from_toolhelp(void);
void build_proc_maps(void) {
    int i;
    char* p = g_ctx.mod.maps_buf;
    char* end = g_ctx.mod.maps_buf + sizeof(g_ctx.mod.maps_buf);

    if (g_ctx.mod.modules_changed) {
        refresh_modules_from_toolhelp();
        g_ctx.mod.modules_changed = 0;
    }

    for (i = 0; i < g_ctx.mod.mod_count; ++i) {
        DWORD start = g_ctx.mod.mods[i].base;
        DWORD finish = g_ctx.mod.mods[i].base + g_ctx.mod.mods[i].size;
        char maps_path[512];

        if (p >= end - 512)
            break;

        make_bn_maps_path(g_ctx.mod.mods[i].path, maps_path, sizeof(maps_path));

        p += sprintf(p, "%08lx-%08lx r-xp 00000000 00:00 0 %s\n", start, finish, maps_path);
    }

    g_ctx.mod.maps_len = (int)(p - g_ctx.mod.maps_buf);

    printf("[modules]: generated /proc/maps:\n%.*s\n", g_ctx.mod.maps_len, g_ctx.mod.maps_buf);
}

int refresh_modules_from_toolhelp(void) {
    HANDLE snap;
    MODULEENTRY32 me;

    g_ctx.mod.mod_count = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, g_ctx.dbg.process_id);
    if (snap == INVALID_HANDLE_VALUE) {
        printf("[modules]: CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
        return 0;
    }

    memset(&me, 0, sizeof(me));
    me.dwSize = sizeof(me);

    if (!Module32First(snap, &me)) {
        printf("[modules]: Module32First failed: %lu\n", GetLastError());
        CloseHandle(snap);
        return 0;
    }

    do {
        /*
            MODULEENTRY32:
              modBaseAddr = base
              modBaseSize = image size
              szExePath   = path
              szModule    = short name
        */
        add_or_update_module((DWORD)me.modBaseAddr, (DWORD)me.modBaseSize, me.szExePath[0] ? me.szExePath : me.szModule);

        me.dwSize = sizeof(me);
    } while (Module32Next(snap, &me));

    CloseHandle(snap);
    return 1;
}

int handle_qxfer_exec_file(const char* pkt, char* reply, int replysz) {
    const char* prefix = "qXfer:exec-file:read:";
    const char* p;
    const char* annex;
    char annex_buf[64];
    char* endptr;
    unsigned long offset;
    unsigned long length;
    unsigned long n;
    unsigned long path_len;

    if (strncmp(pkt, prefix, strlen(prefix)) != 0) {
        reply[0] = '\0';
        return 1;
    }

    /*
        Format:
            qXfer:exec-file:read:annex:offset,length

        Common:
            qXfer:exec-file:read::0,2001e

        With pid annex:
            qXfer:exec-file:read:50e0:0,2001e
    */
    p = pkt + strlen(prefix);

    annex = p;
    p = strchr(annex, ':');
    if (!p) {
        strcpy(reply, "E22");
        return 1;
    }

    if ((p - annex) >= sizeof(annex_buf)) {
        strcpy(reply, "E22");
        return 1;
    }

    memcpy(annex_buf, annex, p - annex);
    annex_buf[p - annex] = 0;

    /*
        For a single-process stub:
          empty annex -> current process
          pid annex   -> accept only our pid, or ignore and return current
    */
    if (annex_buf[0] != '\0') {
        unsigned long requested_pid = strtoul(annex_buf, NULL, 16);

        if (requested_pid != 0 && requested_pid != g_ctx.dbg.process_id) {
            /*
                Unknown process.
                Empty response means unsupported/no data.
            */
            reply[0] = '\0';
            return 1;
        }
    }

    p++; /* now points at offset,length */

    offset = strtoul(p, &endptr, 16);
    if (*endptr != ',') {
        strcpy(reply, "E22");
        return 1;
    }

    length = strtoul(endptr + 1, NULL, 16);

    path_len = (unsigned long)strlen(g_ctx.mod.exec_file);

    if (offset >= path_len) {
        strcpy(reply, "l");
        return 1;
    }

    n = path_len - offset;

    if (n > length)
        n = length;

    if (n > (unsigned long)(replysz - 2))
        n = replysz - 2;

    reply[0] = ((offset + n) >= path_len) ? 'l' : 'm';
    memcpy(reply + 1, g_ctx.mod.exec_file + offset, n);
    reply[1 + n] = '\0';

    return 1;
}

void build_libraries_xml(void) {
    int i, j;
    char* p = g_ctx.mod.libraries_xml;
    char* end = g_ctx.mod.libraries_xml + sizeof(g_ctx.mod.libraries_xml);

    refresh_modules_from_toolhelp();

    p += sprintf(p, "<library-list>");

    for (i = 0; i < g_ctx.mod.mod_count; ++i) {
        char module_path[512];

        if (p >= end - 512)
            break;

        make_lldb_module_path(g_ctx.mod.mods[i].path, module_path, sizeof(module_path));

        p += sprintf(p, "<library name=\"");
        xml_escape_append(&p, end, module_path);
        p += sprintf(p, "\">");

        /*
           Important:
           Emit the PE header VA first, then each real PE section VA.
        */
        for (j = 0; j < g_ctx.mod.mods[i].section_count; ++j) {
            if (p >= end - 64)
                break;

            p += sprintf(p, "<section address=\"0x%08lx\"/>", g_ctx.mod.mods[i].section_va[j]);
        }

        p += sprintf(p, "</library>");
    }

    p += sprintf(p, "</library-list>");

    g_ctx.mod.libraries_xml_len = (int)(p - g_ctx.mod.libraries_xml);
}

const char* find_module_path_for_addr(DWORD addr) {
    int i;

    refresh_modules_from_toolhelp();

    for (i = 0; i < g_ctx.mod.mod_count; ++i) {
        DWORD start = g_ctx.mod.mods[i].base;
        DWORD end = g_ctx.mod.mods[i].base + g_ctx.mod.mods[i].size;

        if (addr >= start && addr < end)
            return g_ctx.mod.mods[i].path;
    }

    return NULL;
}

void patch_breakpoints_out_of_memory_read(DWORD addr, BYTE* buf, DWORD len) {
    int i;
    int remaining;

    if (g_ctx.dbg.inserted_bp_count == 0)
        return;

    remaining = g_ctx.dbg.inserted_bp_count;

    for (i = 0; i < MAX_BREAKPOINTS && remaining > 0; ++i) {
        DWORD off;

        if (!g_ctx.dbg.bps[i].used || !g_ctx.dbg.bps[i].inserted)
            continue;

        remaining--;

        if (g_ctx.dbg.bps[i].addr < addr)
            continue;

        off = g_ctx.dbg.bps[i].addr - addr;

        if (off < len)
            buf[off] = g_ctx.dbg.bps[i].original_byte;
    }
}

DWORD get_first_section_rva_from_file(const char* path) {
    HANDLE h;
    DWORD got;
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS32 nt;
    IMAGE_SECTION_HEADER sh;
    LONG nt_off;

    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (h == INVALID_HANDLE_VALUE)
        return 0x1000;

    if (!ReadFile(h, &dos, sizeof(dos), &got, NULL) || got != sizeof(dos)) {
        CloseHandle(h);
        return 0x1000;
    }

    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(h);
        return 0x1000;
    }

    nt_off = dos.e_lfanew;
    SetFilePointer(h, nt_off, NULL, FILE_BEGIN);

    if (!ReadFile(h, &nt, sizeof(nt), &got, NULL) || got != sizeof(nt)) {
        CloseHandle(h);
        return 0x1000;
    }

    if (nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.NumberOfSections == 0) {
        CloseHandle(h);
        return 0x1000;
    }

    /*
        Move to first section header.
    */
    SetFilePointer(h, nt_off + FIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader, NULL,
                   FILE_BEGIN);

    if (!ReadFile(h, &sh, sizeof(sh), &got, NULL) || got != sizeof(sh)) {
        CloseHandle(h);
        return 0x1000;
    }

    CloseHandle(h);

    return sh.VirtualAddress ? sh.VirtualAddress : 0x1000;
}

void populate_module_sections_from_pe(struct modules* m) {
    HANDLE h;
    DWORD got;
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS32 nt;
    IMAGE_SECTION_HEADER sh;
    DWORD i;
    LONG sec_off;

    m->section_count = 0;

    /*
       Synthetic PE/COFF header section.
       This is the important one for Binary Ninja's LLDB adapter.
    */
    m->section_va[m->section_count++] = m->base;

    h = CreateFileA(m->path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (h == INVALID_HANDLE_VALUE) {
        printf("[modules]: failed to open module file %s (%lu)\n", m->path, GetLastError());
        return;
    }

    if (!ReadFile(h, &dos, sizeof(dos), &got, NULL) || got != sizeof(dos))
        goto done;

    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
        goto done;

    SetFilePointer(h, dos.e_lfanew, NULL, FILE_BEGIN);

    if (!ReadFile(h, &nt, sizeof(nt), &got, NULL) || got != sizeof(nt))
        goto done;

    if (nt.Signature != IMAGE_NT_SIGNATURE)
        goto done;

    sec_off = dos.e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader;

    SetFilePointer(h, sec_off, NULL, FILE_BEGIN);

    for (i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
        if (!ReadFile(h, &sh, sizeof(sh), &got, NULL) || got != sizeof(sh))
            break;

        if (m->section_count >= MAX_MODULE_SECTIONS)
            break;

        if (sh.VirtualAddress != 0) {
            m->section_va[m->section_count] = m->base + sh.VirtualAddress;
            m->section_count++;
        }
    }

done:
    CloseHandle(h);
}
