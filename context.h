
#ifndef CONTEXT_H
#define CONTEXT_H

#ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <winsock2.h>


extern int do_logging;
extern int do_restart;
int gdb_log_printf(const char* fmt, ...);

#define printf gdb_log_printf

#define PACKET_NOT_HANDLED 0
#define PACKET_HANDLED 1

#define MAX_PACKET 8192
#define MAX_THREADS 64

struct thread {
    DWORD tid;
    HANDLE hThread;
};

#define MAX_BREAKPOINTS 128
struct breakpoints {
    int used;
    DWORD addr;
    BYTE original_byte;
    int inserted;
};

#define MAX_MODULES 128
#define MAX_MODULE_PATH 260
#define MAX_MODULE_SECTIONS 32
#define MAPS_BUF_SIZE 16384
#define FAKE_MAPS_FD 3
struct modules {
    DWORD base;
    DWORD size;
    int section_count;
    DWORD section_va[MAX_MODULE_SECTIONS]; /* absolute VAs */
    char path[MAX_MODULE_PATH];
};

#define MAX_VFILES 16
#define VFILE_FD_BASE 100
struct vfile_slot {
    int in_use;
    HANDLE handle;
};

#define LIBRARIES_XML_SIZE 16384

struct rsp_context {
    SOCKET client;
    int wsa_started;
    char pkt[MAX_PACKET];
    char reply[MAX_PACKET];
    int no_ack;
    int thread_suffix_supported;
    int list_threads_in_stop_reply;
};

struct dbg_context {
    DWORD process_id;
    HANDLE process_handle;
    int thread_count;
    struct thread threads[MAX_THREADS];
    DWORD current_tid;
    DWORD last_signal;
    DEBUG_EVENT last_event;
    int have_pending_event;
    int process_exited;
    DWORD exit_code;
    struct breakpoints bps[MAX_BREAKPOINTS];
    int inserted_bp_count;
    int last_stop_was_breakpoint;
    int last_stop_was_single_step;

    /*
       cached_ctx_tid == 0 means the slot is empty. While the debuggee is
       stopped its registers cannot change, so any consumer asking for the
       same thread can reuse the cached CONTEXT instead of issuing another
       GetThreadContext syscall.
    */
    CONTEXT cached_ctx;
    DWORD cached_ctx_tid;

    /*
       Pre-formatted hex reply for the 'g' (read all registers) packet,
       valid until the next continue or any SetThreadContext.
    */
    char cached_g_reply[160];
    DWORD cached_g_reply_tid;
    int cached_g_reply_valid;
};

struct module_context {
    struct modules mods[MAX_MODULES];
    int mod_count;
    char maps_buf[MAPS_BUF_SIZE];
    int maps_len;
    int maps_fd_open;
    struct vfile_slot vfiles[MAX_VFILES];
    char exec_file[MAX_MODULE_PATH];
    char libraries_xml[LIBRARIES_XML_SIZE];
    int libraries_xml_len;
    DWORD main_module_base;
    int modules_changed;
};

struct context {
    struct rsp_context rsp;
    struct dbg_context dbg;
    struct module_context mod;
};

extern struct context g_ctx;

// utils
int hexval(int c);
void put_hex_byte(char* out, unsigned char b);
char* append_hex_byte(char* p, unsigned char b);
char* append_u32_le(char* p, DWORD v);
int decode_hex_string_until_comma(const char* in, char* out, int outsz, const char** after);
char* append_escaped_binary(char* p, char* end, const unsigned char* buf, int len);
char* append_hex_string(char* p, const char* s);
int stricmp_slash_insensitive(const char* a, const char* b);
int decode_hex_string_all(const char* in, char* out, int outsz);
void xml_escape_append(char** pp, char* end, const char* s);
void make_posix_win_path(const char* win_path, char* out, int outsz);
void protect_to_permissions(DWORD protect, char* out);
void make_proc_maps_path(const char* win_path, char* out, int outsz);
void make_lldb_module_path(const char* win_path, char* out, int outsz);
void normalize_module_query_path(const char* in, char* out, int outsz);
int same_module_path(const char* a, const char* b);

#endif
