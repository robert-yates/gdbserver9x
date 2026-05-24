

void context_init();

int start_server(const char* host, unsigned short port);
int recv_packet(char* out, int outsz);
int send_packet(const char* payload);
int handle_packet(const char* pkt, char* reply, int replysz);

int launch_debuggee(const char* cmdline);
void read_memory_packet(const char* pkt, char* out, int outsz);
void read_all_registers(char* out, int outsz);
void read_one_register(const char* pkt, char* out, int outsz);
int continue_pending_event(DWORD status);
int step_over_breakpoint_for_continue(void);
int handle_possible_swbreak_hit(void);
int wait_for_interesting_stop();
int insert_sw_breakpoint(DWORD addr, DWORD kind);
int remove_sw_breakpoint(DWORD addr);
void set_pc_if_present(const char* pkt);
int get_context_for_current(CONTEXT* ctx);
void make_stop_reply(char* out, int outsz);
int step_once_for_frontend(char* reply, int replysz);
void build_proc_maps(void);
int handle_qxfer_exec_file(const char* pkt, char* reply, int replysz);
HANDLE find_thread(DWORD tid);
int refresh_modules_from_toolhelp(void);
void make_posix_win_path(const char* win_path, char* out, int outsz);
void build_libraries_xml(void);
const char* find_module_path_for_addr(DWORD addr);
int set_context_for_current(CONTEXT* ctx);
int strip_thread_suffix(char* pkt, DWORD* tid_out);
