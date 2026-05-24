#define WIN32_LEAN_AND_MEAN
#include "context.h"
#include "windows.h"
#include "stdio.h"
#include <winsock2.h>

int start_server(const char* host, unsigned short port) {

    WSADATA wsa;
    SOCKET s;
    struct sockaddr_in a;
    int yes = 1;
    unsigned long bind_addr;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[start_server]: WSAStartup failed\n");
        return 0;
    }

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        printf("[start_server]: socket failed\n");
        return 0;
    }

    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));

    if (!host || !host[0] || strcmp(host, "*") == 0 || strcmp(host, "0.0.0.0") == 0) {
        bind_addr = htonl(INADDR_ANY);
    } else {
        bind_addr = inet_addr(host);
        if (bind_addr == INADDR_NONE) {
            fprintf(stderr, "[start_server]: invalid host '%s'\n", host);
            closesocket(s);
            return 0;
        }
    }

    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = bind_addr;
    a.sin_port = htons(port);

    if (bind(s, (struct sockaddr*)&a, sizeof(a)) == SOCKET_ERROR) {
        fprintf(stderr, "[start_server]: bind failed\n");
        closesocket(s);
        return 0;
    }

    if (listen(s, 1) == SOCKET_ERROR) {
        fprintf(stderr, "[start_server]: listen failed\n");
        closesocket(s);
        return 0;
    }

    fprintf(stdout, "Listening on port %u...\n", port);

    g_ctx.rsp.client = accept(s, NULL, NULL);
    closesocket(s);

    if (g_ctx.rsp.client == INVALID_SOCKET) {
        fprintf(stderr, "accept failed\n");
        return 0;
    }

    {
        int nodelay = 1;
        setsockopt(g_ctx.rsp.client, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));
    }

    fprintf(stdout, "GDB connected.\n");

    return 1;
}

static char s_recv_buf[4096];
static int s_recv_len = 0;
static int s_recv_pos = 0;

int recv_char(void) {
    if (s_recv_pos >= s_recv_len) {
        int r = recv(g_ctx.rsp.client, s_recv_buf, sizeof(s_recv_buf), 0);
        if (r <= 0)
            return -1;
        s_recv_len = r;
        s_recv_pos = 0;
    }
    return (unsigned char)s_recv_buf[s_recv_pos++];
}

int send_all(const char* buf, int len) {
    int sent = 0;
    while (sent < len) {
        int r = send(g_ctx.rsp.client, buf + sent, len - sent, 0);
        if (r <= 0)
            return 0;
        sent += r;
    }
    return 1;
}

int send_packet_len(const char* payload, int len) {
    /*
       Assemble $payload#XX into one buffer and send in a single call,
       so Nagle never sees a partial frame.
    */
    static char buf[MAX_PACKET + 8];
    unsigned char sum = 0;
    int i;
    int total;

    if (payload == NULL) {
        payload = "";
        len = 0;
    }

    if (len > MAX_PACKET)
        len = MAX_PACKET;

    buf[0] = '$';
    for (i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)payload[i];
        buf[1 + i] = (char)c;
        sum += c;
    }

    buf[1 + len] = '#';
    put_hex_byte(&buf[1 + len + 1], sum);
    total = 1 + len + 3;

    return send_all(buf, total);
}

int send_packet(const char* payload) {
    if (payload == NULL)
        return send_packet_len("", 0);

    return send_packet_len(payload, (int)strlen(payload));
}

int recv_packet(char* out, int outsz) {
    int c, c1, c2;
    unsigned char sum, got;
    int n;

again:
    do {
        c = recv_char();
        if (c < 0)
            return 0;
    } while (c != '$');

    sum = 0;
    n = 0;

    for (;;) {
        c = recv_char();
        if (c < 0)
            return 0;

        if (c == '#')
            break;

        if (n < outsz - 1)
            out[n++] = (char)c;

        sum += (unsigned char)c;
    }

    out[n] = 0;

    c1 = recv_char();
    c2 = recv_char();
    if (c1 < 0 || c2 < 0)
        return 0;

    got = (unsigned char)((hexval(c1) << 4) | hexval(c2));

    if (got != sum) {
        if (!g_ctx.rsp.no_ack) {
            send_all("-", 1);
        }
        goto again;
    }

    if (!g_ctx.rsp.no_ack) {
        send_all("+", 1);
    }
    return 1;
}
