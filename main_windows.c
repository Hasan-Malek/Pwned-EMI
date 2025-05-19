#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <direct.h>
#include <io.h>
#include <errno.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

#define DEFAULT_FTP_PORT 2221
#define TIMEOUT_SEC 2
#define DEBUG 1
#define MAX_BUFFER 4096
#define MAX_FILES 4096
#define MAX_DIRS 4096
#define MAX_LISTING_BUFFER (MAX_BUFFER * 32)
#define MAX_PATH 260

#define DEBUG_PRINT(fmt, ...)                             \
    do {                                                  \
        if (DEBUG)                                        \
            fprintf(stderr, "[DEBUG] " fmt, ##__VA_ARGS__); \
    } while (0)

char *get_ip_from_interface(const char *interface)
{
    static char ip[INET_ADDRSTRLEN];
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
    int iterations = 0;
    DWORD dwRetVal = 0;

    do {
        pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(outBufLen);
        if (pAddresses == NULL) {
            fprintf(stderr, "Memory allocation failed for IP_ADAPTER_ADDRESSES\n");
            return NULL;
        }

        dwRetVal = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            free(pAddresses);
            pAddresses = NULL;
        } else {
            break;
        }
        iterations++;
    } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (iterations < 3));

    if (dwRetVal == NO_ERROR) {
        pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            if (strcmp(pCurrAddresses->AdapterName, interface) == 0) {
                PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;
                if (pUnicast && pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                    struct sockaddr_in *sa_in = (struct sockaddr_in *)pUnicast->Address.lpSockaddr;
                    inet_ntop(AF_INET, &(sa_in->sin_addr), ip, INET_ADDRSTRLEN);
                    free(pAddresses);
                    DEBUG_PRINT("IP of %s: %s\n", interface, ip);
                    return ip;
                }
            }
            pCurrAddresses = pCurrAddresses->Next;
        }
    } else {
        fprintf(stderr, "GetAdaptersAddresses failed with error: %lu\n", dwRetVal);
    }

    if (pAddresses) free(pAddresses);
    return NULL;
}

int scan_host(const char *ip, int port)
{
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in addr;
    fd_set fdset;
    struct timeval tv;
    u_long mode = 1;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID subsidies) {
        fprintf(stderr, "Socket creation failed: %d\n", WSAGetLastError());
        return 0;
    }

    ioctlsocket(sock, FIONBIO, &mode);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    connect(sock, (struct sockaddr *)&addr, sizeof(addr));

    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    tv.tv_sec = TIMEOUT_SEC;
    tv.tv_usec = 0;

    if (select((int)sock + 1, NULL, &fdset, NULL, &tv) == 1) {
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&so_error, &len);
        if (so_error == 0) {
            closesocket(sock);
            return 1;
        }
    }

    closesocket(sock);
    return 0;
}

int parse_pasv_response(const char *response, char *ip, int *port)
{
    const char *paren = strchr(response, '(');
    if (!paren)
        return 0;

    int h1, h2, h3, h4, p1, p2;
    if (sscanf(paren, "(%d,%d,%d,%d,%d,%d)", &h1, &h2, &h3, &h4, &p1, &p2) != 6)
        return 0;

    snprintf(ip, INET_ADDRSTRLEN, "%d.%d.%d.%d", h1, h2, h3, h4);
    *port = p1 * 256 + p2;
    return 1;
}

typedef struct {
    char **filenames;
    int file_count;
    char **dirnames;
    int dir_count;
} FileList;

void free_file_list(FileList *list)
{
    for (int i = 0; i < list->file_count; i++)
        free(list->filenames[i]);
    free(list->filenames);
    for (int i = 0; i < list->dir_count; i++)
        free(list->dirnames[i]);
    free(list->dirnames);
    list->file_count = 0;
    list->dir_count = 0;
}

void parse_directory_listing(const char *listing, FileList *list)
{
    list->filenames = malloc(MAX_FILES * sizeof(char *));
    list->dirnames = malloc(MAX_DIRS * sizeof(char *));
    list->file_count = 0;
    list->dir_count = 0;

    char *copy = strdup(listing);
    if (!copy) {
        DEBUG_PRINT("Failed to allocate memory for listing copy\n");
        return;
    }

    char *line = strtok(copy, "\n");
    while (line && (list->file_count < MAX_FILES || list->dir_count < MAX_DIRS)) {
        if (strlen(line) == 0) {
            line = strtok(NULL, "\n");
            continue;
        }

        DEBUG_PRINT("Parsing line: %s\n", line);

        char *filename = NULL;
        char *ptr = line;
        while (*ptr) {
            while (*ptr == ' ' || *ptr == '\t') ptr++;
            if (*ptr == '\0') break;
            filename = ptr;
            while (*ptr && *ptr != ' ' && *ptr != '\t') ptr++;
        }

        if (filename && strlen(filename) > 0) {
            char *end = filename + strlen(filename) - 1;
            while (end > filename && (*end == ' ' || *end == '\t'))
                *end-- = '\0';

            int is_dir = (line[0] == 'd');
            if (is_dir && (strcmp(filename, ".") != 0 && strcmp(filename, "..") != 0)) {
                if (list->dir_count < MAX_DIRS) {
                    list->dirnames[list->dir_count] = strdup(filename);
                    DEBUG_PRINT("Parsed directory: %s\n", filename);
                    list->dir_count++;
                }
            } else if (!is_dir && list->file_count < MAX_FILES) {
                list->filenames[list->file_count] = strdup(filename);
                DEBUG_PRINT("Parsed file: %s\n", filename);
                list->file_count++;
            }
        } else {
            DEBUG_PRINT("No filename found in line: %s\n", line);
        }
        line = strtok(NULL, "\n");
    }
    free(copy);
    DEBUG_PRINT("Total files parsed: %d, directories: %d\n", list->file_count, list->dir_count);
}

int mkdir_recursive(const char *path)
{
    char tmp[MAX_PATH];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (tmp[len - 1] == '\\' || tmp[len - 1] == '/')
        tmp[len - 1] = '\0';

    for (p = tmp + 1; *p; p++) {
        if (*p == '\\' || *p == '/') {
            *p = '\0';
            if (_mkdir(tmp) != 0 && errno != EEXIST) {
                fprintf(stderr, "mkdir failed for %s: %d\n", tmp, GetLastError());
                return -1;
            }
            *p = '\\';
        }
    }
    if (_mkdir(tmp) != 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir failed for %s: %d\n", tmp, GetLastError());
        return -1;
    }
    return 0;
}

int connect_with_timeout(SOCKET sock, struct sockaddr *addr, socklen_t addrlen, int timeout_sec)
{
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    int res = connect(sock, addr, addrlen);
    if (res == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
        fd_set fdset;
        struct timeval tv;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;
        if (select((int)sock + 1, NULL, &fdset, NULL, &tv) > 0) {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&so_error, &len);
            if (so_error == 0) {
                mode = 0;
                ioctlsocket(sock, FIONBIO, &mode);
                return 0;
            }
        }
        WSASetLastError(WSAETIMEDOUT);
    }
    return -1;
}

int download_file(SOCKET control_sock, const char *filename, const char *dest_path)
{
    char buffer[MAX_BUFFER];
    int bytes;
    SOCKET data_sock = INVALID_SOCKET;
    struct sockaddr_in data_addr;
    FILE *file = NULL;
    int success = 0;

    send(control_sock, "PASV\r\n", 6, 0);
    bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes <= 0) {
        printf("[-] No response to PASV command\n");
        goto cleanup;
    }
    buffer[bytes] = '\0';
    DEBUG_PRINT("PASV response: %s\n", buffer);

    char data_ip[INET_ADDRSTRLEN];
    int data_port;
    if (!parse_pasv_response(buffer, data_ip, &data_port)) {
        printf("[-] Failed to parse PASV response\n");
        goto cleanup;
    }

    data_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (data_sock == INVALID_SOCKET) {
        fprintf(stderr, "data socket: %d\n", WSAGetLastError());
        goto cleanup;
    }

    data_addr.sin_family = AF_INET;
    data_addr.sin_port = htons(data_port);
    inet_pton(AF_INET, data_ip, &data_addr.sin_addr);

    if (connect_with_timeout(data_sock, (struct sockaddr *)&data_addr, sizeof(data_addr), TIMEOUT_SEC) < 0) {
        fprintf(stderr, "data connect: %d\n", WSAGetLastError());
        goto cleanup;
    }

    char retr_cmd[256];
    snprintf(retr_cmd, sizeof(retr_cmd), "RETR %s\r\n", filename);
    send(control_sock, retr_cmd, strlen(retr_cmd), 0);
    bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes <= 0 || strncmp(buffer, "150", 3) != 0) {
        printf("[-] Failed to start file transfer for %s\n", filename);
        goto cleanup;
    }

    char filepath[MAX_PATH];
    snprintf(filepath, sizeof(filepath), "%s\\%s", dest_path, filename);
    file = fopen(filepath, "wb");
    if (!file) {
        fprintf(stderr, "fopen %s: %d\n", filepath, GetLastError());
        goto cleanup;
    }

    while ((bytes = recv(data_sock, buffer, sizeof(buffer), 0)) > 0) {
        if (fwrite(buffer, 1, bytes, file) != bytes) {
            printf("[-] Error writing to file %s\n", filepath);
            goto cleanup;
        }
    }
    if (bytes < 0) {
        fprintf(stderr, "data recv: %d\n", WSAGetLastError());
        goto cleanup;
    }

    bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes > 0 && strncmp(buffer, "226", 3) == 0) {
        success = 1;
        printf("[+] Successfully downloaded %s\n", filename);
    } else {
        printf("[-] Transfer not completed for %s\n", filename);
    }

cleanup:
    if (file) fclose(file);
    if (data_sock != INVALID_SOCKET) closesocket(data_sock);
    return success;
}

int list_directory(SOCKET control_sock, char *listing_buffer, int max_size)
{
    char buffer[MAX_BUFFER];
    int bytes;
    SOCKET data_sock = INVALID_SOCKET;
    struct sockaddr_in data_addr;
    int listing_pos = 0;

    send(control_sock, "PASV\r\n", 6, 0);
    bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes <= 0) {
        printf("[-] No response to PASV command\n");
        return 0;
    }
    buffer[bytes] = '\0';
    DEBUG_PRINT("PASV response: %s\n", buffer);

    char data_ip[INET_ADDRSTRLEN];
    int data_port;
    if (!parse_pasv_response(buffer, data_ip, &data_port)) {
        printf("[-] Failed to parse PASV response\n");
        return 0;
    }

    data_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (data_sock == INVALID_SOCKET) {
        fprintf(stderr, "data socket: %d\n", WSAGetLastError());
        return 0;
    }

    data_addr.sin_family = AF_INET;
    data_addr.sin_port = htons(data_port);
    inet_pton(AF_INET, data_ip, &data_addr.sin_addr);

    if (connect_with_timeout(data_sock, (struct sockaddr *)&data_addr, sizeof(data_addr), TIMEOUT_SEC) < 0) {
        fprintf(stderr, "data connect: %d\n", WSAGetLastError());
        closesocket(data_sock);
        return 0;
    }

    send(control_sock, "LIST\r\n", 6, 0);
    bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("[Response to 'LIST' (control)] %s\n", buffer);
    }

    printf("[Directory Listing]\n");
    while ((bytes = recv(data_sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes] = '\0';
        printf("%s", buffer);
        if (listing_pos + bytes < max_size) {
            strncpy(listing_buffer + listing_pos, buffer, bytes);
            listing_pos += bytes;
        } else {
            DEBUG_PRINT("Listing buffer overflow, truncating\n");
            break;
        }
    }
    if (bytes < 0) {
        fprintf(stderr, "data recv: %d\n", WSAGetLastError());
    }
    closesocket(data_sock);

    bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("[Completion Response] %s\n", buffer);
    }

    return 1;
}

int download_directory(SOCKET control_sock, const char *remote_dir, const char *local_base_path, const char *relative_path)
{
    char buffer[MAX_BUFFER];
    int bytes;

    char cwd_cmd[256];
    snprintf(cwd_cmd, sizeof(cwd_cmd), "CWD %s\r\n", remote_dir);
    send(control_sock, cwd_cmd, strlen(cwd_cmd), 0);
    bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("[Response to 'CWD %s'] %s\n", remote_dir, buffer);
        if (strncmp(buffer, "250", 3) != 0) {
            printf("[-] Failed to change to directory %s\n", remote_dir);
            return 0;
        }
    } else {
        printf("[-] No response to CWD command\n");
        return 0;
    }

    char local_path[MAX_PATH];
    if (relative_path[0] == '\0')
        snprintf(local_path, sizeof(local_path), "%s", local_base_path);
    else
        snprintf(local_path, sizeof(local_path), "%s\\%s", local_base_path, relative_path);

    struct stat st;
    if (_stat(local_path, &st) != 0) {
        if (mkdir_recursive(local_path) != 0) {
            fprintf(stderr, "mkdir_recursive failed\n");
            return 0;
        }
        printf("[*] Created local directory: %s\n", local_path);
    }

    char listing_buffer[MAX_LISTING_BUFFER] = {0};
    if (!list_directory(control_sock, listing_buffer, MAX_LISTING_BUFFER)) {
        return 0;
    }

    FileList list = {NULL, 0, NULL, 0};
    DEBUG_PRINT("Raw listing buffer for %s:\n%s\n", remote_dir, listing_buffer);
    parse_directory_listing(listing_buffer, &list);

    for (int i = 0; i < list.file_count; i++) {
        printf("[*] Downloading %s/%s...\n", relative_path, list.filenames[i]);
        char file_path[256];
        snprintf(file_path, sizeof(file_path), "%s", list.filenames[i]);

        if (download_file(control_sock, file_path, local_path)) {
            printf("[+] Successfully downloaded %s\n", file_path);
        } else {
            printf("[-] Failed to download %s\n", file_path);
        }
    }

    for (int i = 0; i < list.dir_count; i++) {
        char new_remote_dir[256];
        char new_relative_path[256];
        if (relative_path[0] == '\0') {
            snprintf(new_remote_dir, sizeof(new_remote_dir), "%s", list.dirnames[i]);
            snprintf(new_relative_path, sizeof(new_relative_path), "%s", list.dirnames[i]);
        } else {
            snprintf(new_remote_dir, sizeof(new_remote_dir), "%s/%s", relative_path, list.dirnames[i]);
            snprintf(new_relative_path, sizeof(new_relative_path), "%s/%s", relative_path, list.dirnames[i]);
        }

        printf("[*] Entering directory %s\n", new_remote_dir);
        download_directory(control_sock, new_remote_dir, local_base_path, new_relative_path);

        send(control_sock, "CWD ..\r\n", 8, 0);
        bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            printf("[Response to 'CWD ..'] %s\n", buffer);
        }
    }

    free_file_list(&list);
    return 1;
}

int login_ftp(SOCKET control_sock)
{
    char buffer[MAX_BUFFER];
    int bytes;

    const char *user_cmd = "USER anonymous\r\n";
    send(control_sock, user_cmd, strlen(user_cmd), 0);
    bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("[Response to 'USER anonymous'] %s\n", buffer);
        DEBUG_PRINT("USER response: %s\n", buffer);
        if (strncmp(buffer, "230", 3) != 0 && strncmp(buffer, "331", 3) != 0) {
            printf("[-] Anonymous login not supported\n");
            return 0;
        }
    } else {
        printf("[-] No response to USER command\n");
        return 0;
    }

    if (strncmp(buffer, "331", 3) == 0) {
        const char *pass_cmd = "PASS anonymous@example.com\r\n";
        send(control_sock, pass_cmd, strlen(pass_cmd), 0);
        bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            printf("[Response to 'PASS'] %s\n", buffer);
            DEBUG_PRINT("PASS response: %s\n", buffer);
            if (strncmp(buffer, "230", 3) != 0) {
                printf("[-] Password login failed\n");
                return 0;
            }
        } else {
            printf("[-] No response to PASS command\n");
            return 0;
        }
    }
    return 1;
}

void interact_with_ftp(const char *ip, int port, FileList *file_list)
{
    SOCKET control_sock = INVALID_SOCKET;
    struct sockaddr_in server_addr;
    char buffer[MAX_BUFFER];
    int bytes;

    control_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (control_sock == INVALID_SOCKET) {
        fprintf(stderr, "control socket: %d\n", WSAGetLastError());
        return;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server_addr.sin_addr);

    if (connect(control_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "control connect: %d\n", WSAGetLastError());
        closesocket(control_sock);
        return;
    }

    bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("[FTP Banner from %s] %s\n", ip, buffer);
        DEBUG_PRINT("Banner: %s\n", buffer);
    } else {
        printf("[-] Failed to receive FTP banner\n");
        closesocket(control_sock);
        return;
    }

    if (!login_ftp(control_sock)) {
        closesocket(control_sock);
        return;
    }

    char listing_buffer[MAX_LISTING_BUFFER] = {0};
    if (list_directory(control_sock, listing_buffer, MAX_LISTING_BUFFER)) {
        DEBUG_PRINT("Raw listing buffer:\n%s\n", listing_buffer);
        parse_directory_listing(listing_buffer, file_list);
    }

    const char *cmds[] = {"SYST\r\n", "FEAT\r\n", "PWD\r\n", "STAT\r\n"};
    for (int i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
        send(control_sock, cmds[i], strlen(cmds[i]), 0);
        bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            printf("[Response to '%s'] %s\n", cmds[i], buffer);
        }
    }

    send(control_sock, "QUIT\r\n", 6, 0);
    bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("[Response to 'QUIT'] %s\n", buffer);
    }

    closesocket(control_sock);
}

int main(int argc, char *argv[])
{
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }

    const char *interface = "{YOUR_ADAPTER_GUID}"; // Replace with adapter GUID or name
    int port = DEFAULT_FTP_PORT;

    if (argc > 1)
        interface = argv[1];
    if (argc > 2)
        port = atoi(argv[2]);

    char *local_ip = get_ip_from_interface(interface);
    if (!local_ip) {
        fprintf(stderr, "Failed to get IP from interface %s\n", interface);
        WSACleanup();
        return 1;
    }

    char ip_prefix[INET_ADDRSTRLEN];
    char *last_dot = strrchr(local_ip, '.');
    if (!last_dot) {
        fprintf(stderr, "Invalid IP format: %s\n", local_ip);
        WSACleanup();
        return 1;
    }

    strncpy(ip_prefix, local_ip, last_dot - local_ip);
    ip_prefix[last_dot - local_ip] = '\0';

    char target_ip[INET_ADDRSTRLEN];
    printf("[*] Scanning subnet: %s.1 - %s.254\n", ip_prefix, ip_prefix);

    FileList file_list = {NULL, 0, NULL, 0};
    int ftp_found = 0;
    for (int i = 1; i <= 254; i++) {
        snprintf(target_ip, sizeof(target_ip), "%s.%d", ip_prefix, i);

        if (strcmp(target_ip, local_ip) == 0)
            continue;

        if (scan_host(target_ip, port)) {
            printf("[+] FTP service found on %s:%d\n", target_ip, port);
            interact_with_ftp(target_ip, port, &file_list);
            ftp_found = 1;
            break;
        }
    }

    if (ftp_found) {
        printf("\n[DEBUG] Files to copy: %d, Directories: %d\n", file_list.file_count, file_list.dir_count);
        if (file_list.file_count > 0 || file_list.dir_count > 0) {
            char choice[10];
            printf("\nDo you want to copy all data (files and directories) to your computer? (y/n): ");
            if (fgets(choice, sizeof(choice), stdin) != NULL) {
                choice[strcspn(choice, "\n")] = '\0';
                if (strcmp(choice, "y") == 0 || strcmp(choice, "Y") == 0) {
                    char dest_path[MAX_PATH];
                    printf("Enter destination folder path (e.g., C:\\ftp_data): ");
                    if (fgets(dest_path, sizeof(dest_path), stdin) != NULL) {
                        dest_path[strcspn(dest_path, "\n")] = '\0';

                        struct stat st;
                        if (_stat(dest_path, &st) != 0) {
                            if (mkdir_recursive(dest_path) != 0) {
                                fprintf(stderr, "mkdir_recursive failed\n");
                                free_file_list(&file_list);
                                WSACleanup();
                                return 1;
                            }
                            printf("[*] Created folder: %s\n", dest_path);
                        } else if (!_S_ISDIR(st.st_mode)) {
                            printf("[-] %s is not a directory\n", dest_path);
                            free_file_list(&file_list);
                            WSACleanup();
                            return 1;
                        }

                        SOCKET control_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                        if (control_sock == INVALID_SOCKET) {
                            fprintf(stderr, "control socket: %d\n", WSAGetLastError());
                            free_file_list(&file_list);
                            WSACleanup();
                            return 1;
                        }

                        struct sockaddr_in server_addr;
                        server_addr.sin_family = AF_INET;
                        server_addr.sin_port = htons(port);
                        inet_pton(AF_INET, target_ip, &server_addr.sin_addr);

                        if (connect(control_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
                            fprintf(stderr, "control connect: %d\n", WSAGetLastError());
                            closesocket(control_sock);
                            free_file_list(&file_list);
                            WSACleanup();
                            return 1;
                        }

                        char buffer[MAX_BUFFER];
                        int bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
                        if (bytes <= 0) {
                            printf("[-] Failed to receive FTP banner\n");
                            closesocket(control_sock);
                            free_file_list(&file_list);
                            WSACleanup();
                            return 1;
                        }

                        if (!login_ftp(control_sock)) {
                            closesocket(control_sock);
                            free_file_list(&file_list);
                            WSACleanup();
                            return 1;
                        }

                        printf("[*] Starting recursive download from /\n");
                        download_directory(control_sock, "/", dest_path, "");

                        send(control_sock, "QUIT\r\n", 6, 0);
                        closesocket(control_sock);
                    }
                }
            }
        } else {
            printf("[*] No files or directories found to copy\n");
        }
    } else {
        printf("[*] No FTP servers found\n");
    }

    free_file_list(&file_list);
    printf("[*] Scan complete.\n");
    WSACleanup();
    return 0;
}