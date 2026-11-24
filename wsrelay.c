// VG Metro (c) авторы — онлайн-мод 2.7, ретранслятор по WebSocket.
// Один файл: Windows (TCC, локальный тест) и Linux (gcc, Render). Порт = $PORT или 10000.
// Пересылает бинарные сообщения "VGN*" всем остальным игрокам.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include "vgsock.h"
#define SOCK_STREAM 1
#define SOL_SOCKET 0xffff
#define SO_REUSEADDR 4
int __stdcall listen(SOCKET, int);
SOCKET __stdcall accept(SOCKET, struct sockaddr*, int*);
int __stdcall recv(SOCKET, char*, int, int);
int __stdcall send(SOCKET, const char*, int, int);
int __stdcall closesocket(SOCKET);
int __stdcall setsockopt(SOCKET, int, int, const char*, int);
#define BADSOCK ((SOCKET)~0)
static int would_block(void) { return WSAGetLastError() == 10035; }
static void nap(void) { Sleep(2); }
static void set_nb(SOCKET s) { unsigned long one = 1; ioctlsocket(s, FIONBIO, &one); }
static unsigned long ms(void) { return GetTickCount(); }
#define SENDFL 0
#else
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
typedef int SOCKET;
#define BADSOCK (-1)
#define closesocket close
static int would_block(void) { return errno == EAGAIN || errno == EWOULDBLOCK; }
static void nap(void) { usleep(2000); }
static void set_nb(SOCKET s) { fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK); }
static unsigned long ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000UL + t.tv_nsec / 1000000; }
#define SENDFL MSG_NOSIGNAL
#endif

// ---- SHA1 + base64 для рукопожатия ----
static unsigned rol(unsigned x, int c) { return (x << c) | (x >> (32 - c)); }
static void sha1_blk(unsigned* h, const unsigned char* p) {
    unsigned w[80], a, b, c, d, e, t;
    for (int i = 0; i < 16; i++) w[i] = (unsigned)p[4*i] << 24 | (unsigned)p[4*i+1] << 16 | (unsigned)p[4*i+2] << 8 | p[4*i+3];
    for (int i = 16; i < 80; i++) w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];
    for (int i = 0; i < 80; i++) {
        unsigned f, k;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; } else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; } else { f = b ^ c ^ d; k = 0xCA62C1D6; }
        t = rol(a, 5) + f + e + k + w[i]; e = d; d = c; c = rol(b, 30); b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}
static void sha1(const unsigned char* m, size_t n, unsigned char out[20]) {
    unsigned h[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 }; unsigned char blk[64]; size_t i = 0;
    for (; i + 64 <= n; i += 64) sha1_blk(h, m + i);
    size_t r = n - i; memset(blk, 0, 64); memcpy(blk, m + i, r); blk[r] = 0x80;
    if (r >= 56) { sha1_blk(h, blk); memset(blk, 0, 64); }
    unsigned long long bits = (unsigned long long)n * 8; for (int j = 0; j < 8; j++) blk[63 - j] = (unsigned char)(bits >> (8 * j));
    sha1_blk(h, blk);
    for (int j = 0; j < 20; j++) out[j] = (unsigned char)(h[j / 4] >> (24 - 8 * (j % 4)));
}
static void b64(const unsigned char* s, int n, char* o) {
    const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; int j = 0;
    for (int i = 0; i < n; i += 3) {
        unsigned v = s[i] << 16 | (i + 1 < n ? s[i+1] << 8 : 0) | (i + 2 < n ? s[i+2] : 0);
        o[j++] = t[v >> 18 & 63]; o[j++] = t[v >> 12 & 63]; o[j++] = i + 1 < n ? t[v >> 6 & 63] : '='; o[j++] = i + 2 < n ? t[v & 63] : '=';
    }
    o[j] = 0;
}
static void ws_accept(const char* key, char* out) {
    char buf[256]; unsigned char d[20]; snprintf(buf, sizeof buf, "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
    sha1((unsigned char*)buf, strlen(buf), d); b64(d, 20, out);
}

// ---- клиенты ----
#define MAXC 256
typedef struct { SOCKET s; int used, ws, closing; unsigned char in[8192]; int inlen; unsigned char out[65536]; int outlen; double tokens; unsigned long last; } Cl;
static Cl cl[MAXC]; static int nws;

static void drop(Cl* c) { if (c->used) { closesocket(c->s); if (c->ws) nws--; c->used = 0; printf("- ушёл, игроков %d\n", nws); fflush(stdout); } }
static void qout(Cl* c, const void* p, int n) { if (c->outlen + n > (int)sizeof c->out) { c->closing = 2; return; } memcpy(c->out + c->outlen, p, n); c->outlen += n; }
static void qframe(Cl* c, int op, const unsigned char* p, int n) {
    unsigned char h[4]; int hl;
    h[0] = 0x80 | op; if (n < 126) { h[1] = n; hl = 2; } else { h[1] = 126; h[2] = n >> 8; h[3] = n & 255; hl = 4; }
    qout(c, h, hl); qout(c, p, n);
}
static void flush(Cl* c) {
    while (c->outlen) {
        int r = send(c->s, (const char*)c->out, c->outlen, SENDFL);
        if (r <= 0) { if (r < 0 && would_block()) return; c->closing = 2; return; }
        memmove(c->out, c->out + r, c->outlen - r); c->outlen -= r;
    }
}
static char* findi(char* h, const char* n) { size_t l = strlen(n); for (; *h; h++) { size_t i = 0; while (i < l && h[i] && (h[i] | 32) == (n[i] | 32)) i++; if (i == l) return h; } return 0; }

static void http(Cl* c) {
    c->in[c->inlen < (int)sizeof c->in ? c->inlen : (int)sizeof c->in - 1] = 0;
    char* end = strstr((char*)c->in, "\r\n\r\n");
    if (!end) { if (c->inlen >= (int)sizeof c->in - 1) c->closing = 2; return; }
    char* k = findi((char*)c->in, "sec-websocket-key:");
    if (k) {
        k += 18; while (*k == ' ') k++; char key[64]; int i = 0; while (k[i] && k[i] != '\r' && i < 63) { key[i] = k[i]; i++; } key[i] = 0;
        char acc[64], resp[256]; ws_accept(key, acc);
        int n = snprintf(resp, sizeof resp, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", acc);
        qout(c, resp, n); c->ws = 1; nws++; printf("+ игрок, игроков %d\n", nws); fflush(stdout);
        int used = (int)(end + 4 - (char*)c->in); memmove(c->in, c->in + used, c->inlen - used); c->inlen -= used;
    } else {
        char body[160], resp[400]; int bl = snprintf(body, sizeof body, "VG Metro (c) authors - online mod 2.7 relay. players online: %d\n", nws);
        int n = snprintf(resp, sizeof resp, "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", bl, body);
        qout(c, resp, n); c->closing = 1;
    }
}
static void frames(Cl* c, int me) {
    for (;;) {
        if (c->inlen < 2) return;
        unsigned char* b = c->in; int op = b[0] & 15, masked = b[1] & 128; unsigned long len = b[1] & 127; int off = 2;
        if (len == 126) { if (c->inlen < 4) return; len = b[2] << 8 | b[3]; off = 4; }
        else if (len == 127) { c->closing = 2; return; }
        if (len > 4096) { c->closing = 2; return; }
        int mo = masked ? 4 : 0; if (c->inlen < off + mo + (int)len) return;
        unsigned char* p = b + off + mo;
        if (masked) for (unsigned long i = 0; i < len; i++) p[i] ^= b[off + (i & 3)];
        if (op == 8) { qframe(c, 8, 0, 0); c->closing = 1; }
        else if (op == 9) qframe(c, 10, p, len);
        else if (op == 2 && len >= 8 && len <= 512 && !memcmp(p, "VGN", 3)) {
            unsigned long t = ms(); c->tokens += (t - c->last) * 0.06; c->last = t; if (c->tokens > 80) c->tokens = 80;
            if (c->tokens >= 1) { c->tokens -= 1;
                for (int i = 0; i < MAXC; i++) if (i != me && cl[i].used && cl[i].ws && !cl[i].closing) qframe(&cl[i], 2, p, len); }
        }
        int used = off + mo + len; memmove(c->in, c->in + used, c->inlen - used); c->inlen -= used;
    }
}

int main(void) {
    { char a[64]; ws_accept("dGhlIHNhbXBsZSBub25jZQ==", a); printf("self-test %s\n", strcmp(a, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") ? "FAIL" : "ok"); }
#ifdef _WIN32
    WSADATA w; WSAStartup(0x202, &w);
#else
    signal(SIGPIPE, SIG_IGN);
#endif
    int port = getenv("PORT") ? atoi(getenv("PORT")) : 10000;
    SOCKET ls = socket(AF_INET, SOCK_STREAM, 0); int one = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof one);
    struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_port = htons(port);
    if (bind(ls, (struct sockaddr*)&a, sizeof a) || listen(ls, 64)) { printf("bind/listen fail on %d\n", port); return 1; }
    set_nb(ls);
    printf("VG Metro (c) авторы, онлайн-мод 2.7 — WebSocket relay на порту %d\n", port); fflush(stdout);
    unsigned long tping = ms();
    for (;;) {
        SOCKET s;
        while ((s = accept(ls, 0, 0)) != BADSOCK) {
            int i = 0; while (i < MAXC && cl[i].used) i++;
            if (i == MAXC) { closesocket(s); continue; }
            set_nb(s); setsockopt(s, 6, 1, (const char*)&one, sizeof one);
            memset(&cl[i], 0, sizeof cl[i]); cl[i].s = s; cl[i].used = 1; cl[i].tokens = 80; cl[i].last = ms();
        }
        int ping = ms() - tping > 25000; if (ping) tping = ms();
        for (int i = 0; i < MAXC; i++) {
            Cl* c = &cl[i]; if (!c->used) continue;
            if (!c->closing) {
                int r = recv(c->s, (char*)c->in + c->inlen, sizeof c->in - 1 - c->inlen, 0);
                if (r == 0 || (r < 0 && !would_block())) { drop(c); continue; }
                if (r > 0) { c->inlen += r; if (!c->ws) http(c); if (c->ws) frames(c, i); }
                if (ping && c->ws) qframe(c, 9, 0, 0);
            }
            flush(c);
            if (c->closing == 2 || (c->closing == 1 && !c->outlen)) drop(c);
        }
        nap();
    }
}
