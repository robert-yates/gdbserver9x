#include "stdio.h"
#include "stdlib.h"

#define WIN32_LEAN_AND_MEAN
#include "context.h"
#include "windows.h"
#include "main.h"
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

static void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s HOST:PORT PROGRAM [ARGS...]\n", prog);
}

int core(int argc, char** argv) {
    char host[64];
    unsigned short port;
    const char* host_port;
    const char* colon;
    size_t host_len;
    char cmdline[1024];
    int i;
    size_t used;
    int rc = 1;
    int debuggee_started = 0;

    context_init();

    if (argc < 3) {
        print_usage(argv[0]);
        goto done;
    }

    host_port = argv[1];
    colon = strrchr(host_port, ':');
    if (!colon || colon == host_port) {
        fprintf(stderr, "Bad HOST:PORT argument: '%s'\n", host_port);
        print_usage(argv[0]);
        goto done;
    }

    host_len = (size_t)(colon - host_port);
    if (host_len >= sizeof(host)) {
        fprintf(stderr, "Host name too long\n");
        goto done;
    }
    memcpy(host, host_port, host_len);
    host[host_len] = '\0';

    {
        int p = atoi(colon + 1);
        if (p <= 0 || p > 65535) {
            fprintf(stderr, "Bad port: '%s'\n", colon + 1);
            goto done;
        }
        port = (unsigned short)p;
    }

    cmdline[0] = '\0';
    used = 0;
    for (i = 2; i < argc; ++i) {
        const char* tok = argv[i];
        int needs_quotes = (strchr(tok, ' ') != NULL) && tok[0] != '"';
        size_t tok_len = strlen(tok);
        size_t need = tok_len + (i > 2 ? 1 : 0) + (needs_quotes ? 2 : 0) + 1;

        if (used + need >= sizeof(cmdline)) {
            fprintf(stderr, "Command line too long\n");
            goto done;
        }

        if (i > 2)
            cmdline[used++] = ' ';
        if (needs_quotes)
            cmdline[used++] = '"';
        memcpy(cmdline + used, tok, tok_len);
        used += tok_len;
        if (needs_quotes)
            cmdline[used++] = '"';
        cmdline[used] = '\0';
    }

    if (!start_server(host, port)) {
        fprintf(stderr, "Failed to start server.\n");
        goto done;
    }

    if (!launch_debuggee(cmdline)) {
        fprintf(stderr, "Debuggee did not start cleanly; not entering the GDB command loop.\n");
        goto done;
    }
    debuggee_started = 1;

    while (recv_packet(g_ctx.rsp.pkt, sizeof(g_ctx.rsp.pkt))) {

        printf("-------------------------------\n");
        printf("GDB: %s\n", g_ctx.rsp.pkt);

        if (strcmp(g_ctx.rsp.pkt, "QStartNoAckMode") == 0) {
            send_packet("OK");
            g_ctx.rsp.no_ack = 1;
            printf("RSP: OK\n");
            continue;
        }

        if (handle_packet(g_ctx.rsp.pkt, g_ctx.rsp.reply, sizeof(g_ctx.rsp.reply)) == PACKET_NOT_HANDLED) {
            fprintf(stderr, "Couldnt handle packet: strict aborting: %s\n", g_ctx.rsp.pkt);
            break;
        }

        printf("RSP: %s\n", g_ctx.rsp.reply);

        if (g_ctx.rsp.pkt[0] == 'k')
            break;

        send_packet(g_ctx.rsp.reply);
    }

    fprintf(stdout, "GDB Server exiting.\n");
    rc = 0;

done:
    if (debuggee_started || g_ctx.dbg.process_handle)
        cleanup_debuggee(1);
    stop_server();
    return rc;
}

int main(int argc, char** argv) {

    fprintf(stdout, "gdbserver9x - version 1.2.20062026\n");

    do_logging = (getenv("GDBLOG") != NULL);
    do_restart = (getenv("GDBRESTART") != NULL);

    for (;;) {
        int rc = core(argc, argv);

        if (rc != 0 || !do_restart)
            return rc;

        fprintf(stdout, "Restarting gdbserver.\n");
    }
}
