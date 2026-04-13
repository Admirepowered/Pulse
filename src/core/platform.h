#ifndef PLATFORM_H
#define PLATFORM_H

#if defined(_WIN32) || defined(WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>

#define PLATFORM_IS_WINDOWS 1

static inline int platform_init_network(void) {
    WSADATA wsa_data;
    return WSAStartup(MAKEWORD(2, 2), &wsa_data);
}

static inline void platform_cleanup_network(void) {
    WSACleanup();
}

#else

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define PLATFORM_IS_WINDOWS 0

typedef int SOCKET;

#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif

#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif

#ifndef SD_BOTH
#define SD_BOTH SHUT_RDWR
#endif

#ifndef closesocket
#define closesocket close
#endif

#ifndef WSAGetLastError
#define WSAGetLastError() (errno)
#endif

#ifndef _stricmp
#define _stricmp strcasecmp
#endif

#ifndef _strnicmp
#define _strnicmp strncasecmp
#endif

static inline int platform_init_network(void) {
    return 0;
}

static inline void platform_cleanup_network(void) {
}

#endif

#endif
