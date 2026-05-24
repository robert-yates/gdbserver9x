#include "context.h"
#include "windows.h"
#include "main.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

void handle_qxfer_features(const char* pkt, char* reply, int replysz);
void make_stop_reply(char* out, int outsz);
int parse_z0_packet(const char* pkt, DWORD* addr, DWORD* kind);
int handle_vfile_packet(const char* pkt, char* reply, int replysz);
int parse_B_packet(const char* pkt, DWORD* addr, char* mode);
int handle_qFileLoadAddress(const char* pkt, char* reply, int replysz);
int handle_qxfer_libraries(const char* pkt, char* reply, int replysz);
int handle_qMemoryRegionInfo(const char* pkt, char* reply, int replysz);
int do_continue_common(char* reply, int replysz);
int parse_thread_id_token(const char* in, const char** end_out, DWORD* tid_out);
int parse_vcont_resume_action(const char* pkt, DWORD fallback_tid, char* action_out, DWORD* action_tid_out);

int parse_thread_id_token(const char* in, const char** end_out, DWORD* tid_out) {
    const char* p;
    char* end_hex;
    char* end_dec;
    DWORD tid_hex;
    DWORD tid_dec;

    p = in;

    if (*p == 'p') {
        p++;

        if (p[0] == '-' && p[1] == '1') {
            p += 2;
        } else {
            (void)strtoul(p, &end_hex, 16);
            if (end_hex == p)
                return 0;
            p = end_hex;
        }

        if (*p != '.')
            return 0;

        p++;
    }

    if (p[0] == '-' && p[1] == '1') {
        *tid_out = 0;
        *end_out = p + 2;
        return 1;
    }

    tid_hex = strtoul(p, &end_hex, 16);
    if (end_hex == p)
        return 0;

    if (tid_hex == 0) {
        *tid_out = 0;
        *end_out = end_hex;
        return 1;
    }

    tid_dec = strtoul(p, &end_dec, 10);

    if (find_thread(tid_hex)) {
        *tid_out = tid_hex;
        *end_out = end_hex;
        return 1;
    }

    if (end_dec == end_hex && tid_dec != 0 && find_thread(tid_dec)) {
        *tid_out = tid_dec;
        *end_out = end_hex;
        return 1;
    }

    if (g_ctx.dbg.thread_count == 1) {
        printf("Thread id '%.*s' did not match a known thread; using only thread %lu\n", (int)(end_hex - p), p,
               g_ctx.dbg.threads[0].tid);
        *tid_out = g_ctx.dbg.threads[0].tid;
        *end_out = end_hex;
        return 1;
    }

    return 0;
}

int parse_vcont_resume_action(const char* pkt, DWORD fallback_tid, char* action_out, DWORD* action_tid_out) {
    const char* p;
    char default_action = 0;
    char selected_action = 0;
    DWORD selected_tid = 0;
    char any_thread_action = 0;
    DWORD any_thread_tid = 0;

    if (strncmp(pkt, "vCont;", 6) != 0)
        return 0;

    p = pkt + 5;

    while (*p == ';') {
        char act;
        DWORD tid = 0;
        int has_tid = 0;
        const char* q;
        const char* end;

        p++;
        if (*p == '\0')
            return 0;

        act = *p++;
        if (act != 'c' && act != 's')
            return 0;

        q = p;
        if (*q == ':') {
            q++;
            if (!parse_thread_id_token(q, &end, &tid))
                return 0;
            has_tid = 1;
            q = end;
        }

        if (*q != '\0' && *q != ';')
            return 0;

        if (has_tid) {
            if (any_thread_action == 0) {
                any_thread_action = act;
                any_thread_tid = tid;
            }

            if (tid == fallback_tid) {
                selected_action = act;
                selected_tid = tid;
            }
        } else {
            default_action = act;
        }

        p = q;
    }

    if (selected_action == 0)
        selected_action = default_action;

    if (selected_action == 0 && any_thread_action != 0) {
        selected_action = any_thread_action;
        selected_tid = any_thread_tid;
    }

    if (selected_action == 0)
        return 0;

    *action_out = selected_action;
    *action_tid_out = selected_tid;
    return 1;
}

int handle_packet(const char* pkt_in, char* reply, int replysz) {
    char pktbuf[MAX_PACKET];
    char* pkt;
    DWORD saved_tid;
    DWORD suffix_tid = 0;
    int suffix_result;
    int had_packet_thread_override = 0;
    int keep_selected_tid = 0;
    int result = PACKET_NOT_HANDLED;

#define RETURN_HANDLE_PACKET(v)                                                                                                       \
    do {                                                                                                                              \
        result = (v);                                                                                                                 \
        goto done;                                                                                                                    \
    } while (0)

    reply[0] = '\0';

    strncpy(pktbuf, pkt_in, sizeof(pktbuf) - 1);
    pktbuf[sizeof(pktbuf) - 1] = '\0';
    pkt = pktbuf;

    saved_tid = g_ctx.dbg.current_tid;

    suffix_result = strip_thread_suffix(pkt, &suffix_tid);

    if (suffix_result < 0) {
        strcpy(reply, "E01");
        RETURN_HANDLE_PACKET(1);
    }

    if (suffix_result > 0 && suffix_tid != 0) {
        had_packet_thread_override = 1;
        g_ctx.dbg.current_tid = suffix_tid;
        printf("Temporarily switched to thread %lu for packet '%s'\n", suffix_tid, pkt);
    }

    // ---------------------------------------------------------------------------------
    if (strncmp(pkt, "qSupported", 10) == 0) {
        strcpy(reply, "PacketSize=1f00;"
                      "QStartNoAckMode+;"
                      "QThreadSuffixSupported+;"
                      "QListThreadsInStopReply+;"
                      "qXfer:features:read+;"
                      "qXfer:exec-file:read+;"
                      "swbreak+");
        RETURN_HANDLE_PACKET(PACKET_HANDLED);
    }
    // ---------------------------------------------------------------------------------
    if (strcmp(pkt, "QThreadSuffixSupported") == 0) {
        g_ctx.rsp.thread_suffix_supported = 1;
        strcpy(reply, "OK");
        RETURN_HANDLE_PACKET(1);
    }
    if (strcmp(pkt, "QListThreadsInStopReply") == 0) {
        g_ctx.rsp.list_threads_in_stop_reply = 1;
        strcpy(reply, "OK");
        RETURN_HANDLE_PACKET(1);
    }
    if (strcmp(pkt, "qVAttachOrWaitSupported") == 0) {
        reply[0] = '\0';
        RETURN_HANDLE_PACKET(1);
    }
    if (strcmp(pkt, "QEnableErrorStrings") == 0) {
        reply[0] = '\0';
        RETURN_HANDLE_PACKET(1);
    }
    if (strcmp(pkt, "qOffsets") == 0) {
        reply[0] = '\0';
        RETURN_HANDLE_PACKET(1);
    }
    if (strcmp(pkt, "qStructuredDataPlugins") == 0) {
        strcpy(reply, "[]");
        RETURN_HANDLE_PACKET(1);
    }
    if (strcmp(pkt, "qShlibInfoAddr") == 0) {
        reply[0] = '\0';
        RETURN_HANDLE_PACKET(1);
    }
    if (strcmp(pkt, "qSymbol::") == 0) {
        strcpy(reply, "OK");
        RETURN_HANDLE_PACKET(1);
    }
    if (pkt[0] == 'x') {
        reply[0] = '\0';
        RETURN_HANDLE_PACKET(1);
    }
    if (strcmp(pkt, "!") == 0) {
        strcpy(reply, "OK");
        RETURN_HANDLE_PACKET(1);
    }
    // ---------------------------------------------------------------------------------
    if (strcmp(pkt, "qHostInfo") == 0) {
        char* p = reply;

        p += sprintf(p, "triple:");
        p = append_hex_string(p, "i686-pc-windows-msvc");

        p += sprintf(p, ";ptrsize:4;"
                        "watchpoint_exceptions_received:after;"
                        "endian:little;"
                        "os_version:4.10;"
                        "hostname:");

        p = append_hex_string(p, "WIN98");
        *p++ = ';';
        *p = '\0';

        RETURN_HANDLE_PACKET(1);
    }
    if (strcmp(pkt, "qProcessInfo") == 0) {
        char* p = reply;

        p += sprintf(p,
                     "pid:%lx;"
                     "parent-pid:0;"
                     "real-uid:ffffffff;"
                     "real-gid:ffffffff;"
                     "effective-uid:ffffffff;"
                     "effective-gid:ffffffff;"
                     "triple:",
                     g_ctx.dbg.process_id);

        p = append_hex_string(p, "i386-pc-windows");

        p += sprintf(p, ";ostype:windows;"
                        "endian:little;"
                        "ptrsize:4;");

        RETURN_HANDLE_PACKET(1);
    }
    // ---------------------------------------------------------------------------------
    if (strcmp(pkt, "vCont?") == 0) {
        strcpy(reply, "vCont;c;s");
        RETURN_HANDLE_PACKET(1);
    }
    // ---------------------------------------------------------------------------------
    if (strcmp(pkt, "?") == 0) {
        make_stop_reply(reply, replysz);
        RETURN_HANDLE_PACKET(PACKET_HANDLED);
    }
    if (pkt[0] == 'c') {
        set_pc_if_present(pkt);
        keep_selected_tid = 1;
        RETURN_HANDLE_PACKET(do_continue_common(reply, replysz));
    }
    if (strncmp(pkt, "vCont;", 6) == 0) {
        char action = 0;
        DWORD action_tid = 0;

        if (!parse_vcont_resume_action(pkt, g_ctx.dbg.current_tid, &action, &action_tid)) {
            strcpy(reply, "E01");
            RETURN_HANDLE_PACKET(1);
        }

        if (action_tid != 0) {
            g_ctx.dbg.current_tid = action_tid;
            printf("Selected vCont thread %lu for packet '%s'\n", action_tid, pkt);
        }

        keep_selected_tid = 1;
        if (action == 's') {
            RETURN_HANDLE_PACKET(step_once_for_frontend(reply, replysz));
        }

        RETURN_HANDLE_PACKET(do_continue_common(reply, replysz));
    }
    if (pkt[0] == 's') {
        set_pc_if_present(pkt);
        RETURN_HANDLE_PACKET(step_once_for_frontend(reply, replysz));
    }
    // ---------------------------------------------------------------------------------
    if (strncmp(pkt, "qXfer:features:read:", 20) == 0) {
        handle_qxfer_features(pkt, reply, replysz);
        RETURN_HANDLE_PACKET(PACKET_HANDLED);
    }
    // ---------------------------------------------------------------------------------
    if (pkt[0] == 'p') {
        read_one_register(pkt, reply, replysz);
        RETURN_HANDLE_PACKET(PACKET_HANDLED);
    }
    if (strcmp(pkt, "g") == 0) {
        read_all_registers(reply, replysz);
        return PACKET_HANDLED;
    }
    // ---------------------------------------------------------------------------------
    if (strncmp(pkt, "qFileLoadAddress:", 17) == 0) {
        RETURN_HANDLE_PACKET(handle_qFileLoadAddress(pkt, reply, replysz));
    }
    // ---------------------------------------------------------------------------------
    if ((pkt[0] == 'Z' || pkt[0] == 'z') && pkt[1] == '0' && pkt[2] == ',') {
        DWORD addr, kind;
        int ok;

        if (!parse_z0_packet(pkt, &addr, &kind)) {
            strcpy(reply, "E22");
            RETURN_HANDLE_PACKET(1);
        }

        if (pkt[0] == 'Z')
            ok = insert_sw_breakpoint(addr, kind);
        else
            ok = remove_sw_breakpoint(addr);

        strcpy(reply, ok ? "OK" : "E14");
        RETURN_HANDLE_PACKET(1);
    }
    // ---------------------------------------------------------------------------------
    if (strcmp(pkt, "qfThreadInfo") == 0) {
        int i;
        char* p = reply;

        if (g_ctx.dbg.thread_count == 0) {
            strcpy(reply, "l");
            RETURN_HANDLE_PACKET(PACKET_HANDLED);
        }

        *p++ = 'm';
        for (i = 0; i < g_ctx.dbg.thread_count; ++i) {
            if (i)
                *p++ = ',';
            p += sprintf(p, "%lx", g_ctx.dbg.threads[i].tid);
        }
        RETURN_HANDLE_PACKET(PACKET_HANDLED);
    }
    if (strcmp(pkt, "qsThreadInfo") == 0) {
        strcpy(reply, "l");
        RETURN_HANDLE_PACKET(PACKET_HANDLED);
    }
    if (strcmp(pkt, "jThreadsInfo") == 0) {
        int i;
        char* p = reply;

        p += sprintf(p, "[");

        for (i = 0; i < g_ctx.dbg.thread_count; ++i) {
            if (i)
                p += sprintf(p, ",");

            p += sprintf(p,
                         "{"
                         "\"tid\":%lu,"
                         "\"name\":\"Thread %lx\""
                         "}",
                         (unsigned long)g_ctx.dbg.threads[i].tid, (unsigned long)g_ctx.dbg.threads[i].tid);
        }

        p += sprintf(p, "]");
        RETURN_HANDLE_PACKET(1);
    }
    if (pkt[0] == 'H') {
        DWORD tid;

        if (pkt[2] == '-' || pkt[2] == '0' || pkt[2] == '\0') {
            strcpy(reply, "OK");
            RETURN_HANDLE_PACKET(1);
        }

        tid = strtoul(pkt + 2, NULL, 16);

        if (find_thread(tid)) {
            printf("Switching to thread %lu\n", tid);
            g_ctx.dbg.current_tid = tid;
            strcpy(reply, "OK");
        } else {
            strcpy(reply, "E01");
        }

        RETURN_HANDLE_PACKET(1);
    }
    // ---------------------------------------------------------------------------------
    if (strncmp(pkt, "qMemoryRegionInfo:", 18) == 0) {
        RETURN_HANDLE_PACKET(handle_qMemoryRegionInfo(pkt, reply, replysz));
    }
    // ---------------------------------------------------------------------------------
    if (pkt[0] == 'm') {
        read_memory_packet(pkt, reply, replysz);
        RETURN_HANDLE_PACKET(PACKET_HANDLED);
    }
    // ---------------------------------------------------------------------------------
    // IDA's ctrl+f2
    if (pkt[0] == 'k') {
        TerminateProcess(g_ctx.dbg.process_handle, 0);
        ExitProcess(0);
    }
    // ---------------------------------------------------------------------------------
    if (strncmp(pkt, "vFile:", 6) == 0) {
        return handle_vfile_packet(pkt, reply, replysz);
    }
    // ---------------------------------------------------------------------------------
    // This lets IDA read the module name
    if (strncmp(pkt, "qXfer:exec-file:read:", 21) == 0) {
        return handle_qxfer_exec_file(pkt, reply, replysz);
    }
    // ---------------------------------------------------------------------------------
    // ---------------------------------------------------------------------------------
    // ---------------------------------------------------------------------------------

done:
    if (had_packet_thread_override && !keep_selected_tid) {
        g_ctx.dbg.current_tid = saved_tid;
    }

#undef RETURN_HANDLE_PACKET
    return result;
}

int do_continue_common(char* reply, int replysz) {
    int r;

    r = step_over_breakpoint_for_continue();

    if (r == 0) {
        strcpy(reply, "E01");
        return 1;
    }

    if (r == 2) {
        make_stop_reply(reply, replysz);
        return 1;
    }

    if (!wait_for_interesting_stop()) {
        strcpy(reply, "E02");
        return 1;
    }

    make_stop_reply(reply, replysz);
    return 1;
}

int handle_qMemoryRegionInfo(const char* pkt, char* reply, int replysz) {
    DWORD addr;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T got;
    char perms[4];
    char* p;
    const char* path;

    if (strncmp(pkt, "qMemoryRegionInfo:", 18) != 0)
        return 0;

    addr = strtoul(pkt + 18, NULL, 16);

    got = VirtualQueryEx(g_ctx.dbg.process_handle, (LPCVOID)addr, &mbi, sizeof(mbi));

    if (got == 0) {
        strcpy(reply, "E01");
        return 1;
    }

    protect_to_permissions(mbi.Protect, perms);

    p = reply;

    p += sprintf(p, "start:%lx;size:%lx;permissions:%s;", (DWORD)mbi.BaseAddress, (DWORD)mbi.RegionSize, perms);

    path = find_module_path_for_addr(addr);
    if (path && path[0]) {
        char posix_path[512];

        // make_posix_win_path(path, posix_path, sizeof(posix_path));
        make_lldb_module_path(path, posix_path, sizeof(posix_path));
        printf("PATH: %s\n", posix_path);

        p += sprintf(p, "name:");
        p = append_hex_string(p, posix_path);
        *p++ = ';';
        *p = '\0';
    }

    return 1;
}

int handle_qFileLoadAddress(const char* pkt, char* reply, int replysz) {
    char requested[512];
    int i;

    if (strncmp(pkt, "qFileLoadAddress:", 17) != 0)
        return 0;

    if (!decode_hex_string_all(pkt + 17, requested, sizeof(requested))) {
        strcpy(reply, "E22");
        return 1;
    }

    printf("[qFileLoadAddress]: '%s'\n", requested);

    refresh_modules_from_toolhelp();

    for (i = 0; i < g_ctx.mod.mod_count; ++i) {
        char posix_path[512];
        char lldb_path[512];

        /*
            posix_path:
                /D:/main/code/HelloWorld9x.exe

            lldb_path:
                D:/main/code/HelloWorld9x.exe
        */
        make_posix_win_path(g_ctx.mod.mods[i].path, posix_path, sizeof(posix_path));
        make_lldb_module_path(g_ctx.mod.mods[i].path, lldb_path, sizeof(lldb_path));

        if (same_module_path(requested, g_ctx.mod.mods[i].path) || same_module_path(requested, posix_path) ||
            same_module_path(requested, lldb_path)) {

            sprintf(reply, "00000000%08lx", g_ctx.mod.mods[i].base);
            return 1;
        }
    }

    strcpy(reply, "E01");
    return 1;
}

int parse_z0_packet(const char* pkt, DWORD* addr, DWORD* kind) {
    char* end;

    /*
       Format:
           Z0,401041,1
           z0,401041,1
    */

    if (!(pkt[0] == 'Z' || pkt[0] == 'z'))
        return 0;

    if (pkt[1] != '0' || pkt[2] != ',')
        return 0;

    *addr = strtoul(pkt + 3, &end, 16);
    if (*end != ',')
        return 0;

    *kind = strtoul(end + 1, NULL, 16);
    return 1;
}

void make_stop_reply(char* out, int outsz) {
    CONTEXT c;
    char* p = out;
    char* end = out + outsz;

    if (outsz <= 0)
        return;

    out[0] = '\0';

    if (g_ctx.dbg.last_event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
        sprintf(out, "W%02lx", g_ctx.dbg.last_event.u.ExitProcess.dwExitCode & 0xff);
        return;
    }

    p += sprintf(p, "T%02lxthread:%lx;", g_ctx.dbg.last_signal & 0xff, g_ctx.dbg.current_tid);

    if (g_ctx.dbg.last_stop_was_breakpoint) {
        p += sprintf(p, "swbreak:;");
    } else if (g_ctx.dbg.last_stop_was_single_step) {
        // p += sprintf(p, "reason:trace;");
    }

    if (get_context_for_current(&c)) {
        p += sprintf(p, "08:");
        p = append_u32_le(p, c.Eip);
        *p++ = ';';
        *p = '\0';

        p += sprintf(p, "07:");
        p = append_u32_le(p, c.Esp);
        *p++ = ';';
        *p = '\0';
    }
}

// clang-format off
const char g_target_xml[] =
    "<target>"
      "<architecture>i386</architecture>"
      "<endian>little</endian>"
      "<feature name=\"org.gnu.gdb.i386.core\">"
        "<reg name=\"eax\" bitsize=\"32\" regnum=\"0\"/>"
        "<reg name=\"ebx\" bitsize=\"32\" regnum=\"1\"/>"
        "<reg name=\"ecx\" bitsize=\"32\" regnum=\"2\"/>"
        "<reg name=\"edx\" bitsize=\"32\" regnum=\"3\"/>"
        "<reg name=\"edi\" bitsize=\"32\" regnum=\"4\"/>"
        "<reg name=\"esi\" bitsize=\"32\" regnum=\"5\"/>"
        "<reg name=\"ebp\" bitsize=\"32\" regnum=\"6\"/>"
        "<reg name=\"esp\" bitsize=\"32\" regnum=\"7\"/>"
        "<reg name=\"eip\" bitsize=\"32\" regnum=\"8\"/>"
        "<reg name=\"eflags\" bitsize=\"32\" regnum=\"9\"/>"
        "<reg name=\"cs\" bitsize=\"32\" regnum=\"10\"/>"
        "<reg name=\"fs\" bitsize=\"32\" regnum=\"11\"/>"
        "<reg name=\"gs\" bitsize=\"32\" regnum=\"12\"/>"
        "<reg name=\"ss\" bitsize=\"32\" regnum=\"13\"/>"
        "<reg name=\"ds\" bitsize=\"32\" regnum=\"14\"/>"
        "<reg name=\"es\" bitsize=\"32\" regnum=\"15\"/>"
      "</feature>"
    "</target>";
// clang-format on

void handle_qxfer_features(const char* pkt, char* reply, int replysz) {
    const char* prefix = "qXfer:features:read:";
    const char* p;
    const char* annex;
    const char* offstr;
    const char* lenstr;
    char annex_buf[128];
    unsigned long offset;
    unsigned long length;
    unsigned long xml_len;
    unsigned long remain;
    unsigned long n;

    if (strncmp(pkt, prefix, strlen(prefix)) != 0) {
        reply[0] = 0;
        return;
    }

    p = pkt + strlen(prefix);

    /*
       Format now:
           target.xml:offset,length
    */

    annex = p;
    p = strchr(annex, ':');
    if (!p) {
        strcpy(reply, "E22");
        return;
    }

    if ((p - annex) >= sizeof(annex_buf)) {
        strcpy(reply, "E22");
        return;
    }

    memcpy(annex_buf, annex, p - annex);
    annex_buf[p - annex] = 0;

    offstr = p + 1;
    p = strchr(offstr, ',');
    if (!p) {
        strcpy(reply, "E22");
        return;
    }

    lenstr = p + 1;

    offset = strtoul(offstr, NULL, 16);
    length = strtoul(lenstr, NULL, 16);

    if (strcmp(annex_buf, "target.xml") != 0) {
        reply[0] = 0; /* unknown XML annex */
        printf(reply, "[warning]: qXfer:features:read: - EAnnex '%s' not found", annex_buf);
        return;
    }

    xml_len = (unsigned long)strlen(g_target_xml);

    if (offset >= xml_len) {
        strcpy(reply, "l");
        return;
    }

    remain = xml_len - offset;
    n = remain;

    if (n > length)
        n = length;

    if (n > (unsigned long)(replysz - 2))
        n = replysz - 2;

    // l = final chunk, m = ask again with larger offset
    reply[0] = ((offset + n) >= xml_len) ? 'l' : 'm';

    memcpy(reply + 1, g_target_xml + offset, n);
    reply[1 + n] = 0;
}

int is_proc_maps_path(const char* path) {
    const char* p;

    if (strncmp(path, "/proc/", 6) != 0)
        return 0;

    p = strrchr(path, '/');
    if (!p)
        return 0;

    return strcmp(p, "/maps") == 0;
}

int handle_vfile_packet(const char* pkt, char* reply, int replysz) {

    if (strcmp(pkt, "vFile:setfs:0") == 0) {
        strcpy(reply, "F0");
        return 1;
    }

    if (strncmp(pkt, "vFile:open:", 11) == 0) {
        char filename[512];
        const char* after;

        if (!decode_hex_string_until_comma(pkt + 11, filename, sizeof(filename), &after)) {
            strcpy(reply, "F-1,16"); /* EINVAL-ish */
            return 1;
        }

        printf("[vFile]: open '%s'\n", filename);

        if (is_proc_maps_path(filename)) {
            build_proc_maps();
            g_ctx.mod.maps_fd_open = 1;
            sprintf(reply, "F%x", FAKE_MAPS_FD);
            return 1;
        }

        strcpy(reply, "F-1,2"); /* ENOENT */
        return 1;
    }

    if (strncmp(pkt, "vFile:pread:", 12) == 0) {
        unsigned long fd, count, offset;
        const char* p;
        int n;
        char* out;

        /*
            Format:
              vFile:pread:fd,count,offset
        */
        fd = strtoul(pkt + 12, (char**)&p, 16);
        if (*p != ',') {
            strcpy(reply, "F-1,16");
            return 1;
        }

        count = strtoul(p + 1, (char**)&p, 16);
        if (*p != ',') {
            strcpy(reply, "F-1,16");
            return 1;
        }

        offset = strtoul(p + 1, NULL, 16);

        printf("[vFile]: pread fd=%lu count=%lu offset=%lu\n", fd, count, offset);

        if (fd != FAKE_MAPS_FD || !g_ctx.mod.maps_fd_open) {
            strcpy(reply, "F-1,9"); /* EBADF */
            return 1;
        }

        if (offset >= (unsigned long)g_ctx.mod.maps_len) {
            strcpy(reply, "F0;");
            return 1;
        }

        n = g_ctx.mod.maps_len - (int)offset;

        if ((unsigned long)n > count)
            n = (int)count;

        if (n > 1024)
            n = 1024;

        out = reply;
        out += sprintf(out, "F%x;", n);

        append_escaped_binary(out, reply + replysz - 1, (const unsigned char*)(g_ctx.mod.maps_buf + offset), n);

        return 1;
    }

    if (strncmp(pkt, "vFile:close:", 12) == 0) {
        unsigned long fd = strtoul(pkt + 12, NULL, 16);

        printf("[vFile]: close fd=%lu\n", fd);

        if (fd == FAKE_MAPS_FD) {
            g_ctx.mod.maps_fd_open = 0;
            strcpy(reply, "F0");
            return 1;
        }

        strcpy(reply, "F-1,9");
        return 1;
    }

    reply[0] = 0;
    return 1;
}

int strip_thread_suffix(char* pkt, DWORD* tid_out) {
    char* s;
    char* id_start;
    const char* end;
    DWORD tid;

    /*
        Examples:
            p0;thread:567c;
            g;thread:567c;

        After this:
            p0;thread:567c; -> p0
            g;thread:567c;  -> g
    */

    s = strstr(pkt, ";thread:");
    if (!s)
        return 0; /* no suffix */

    id_start = s + 8; /* strlen(";thread:") */

    if (!parse_thread_id_token(id_start, &end, &tid))
        return -1;

    if (*end != ';')
        return -1;

    *s = '\0';

    if (tid_out)
        *tid_out = tid;

    return 1;
}
