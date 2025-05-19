/*
    Bypass EMI Locked Phone for Data Transfer
    by : HM
    GitHub: https://github.com/Hasan-Malek
    Linkedin: https://linkedin.com/in/hasan-malek-125036297
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <sys/select.h>
#include <net/if.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>

// ANSI color codes
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_RESET   "\x1b[0m"
#define COLOR_BOLD    "\x1b[1m"
#define COLOR_UNDERLINE "\x1b[4m"

#define DEFAULT_FTP_PORT 2221
#define TIMEOUT_SEC 2
#define MAX_RETRIES 3
#define DEBUG 1
#define MAX_BUFFER 4096
#define MAX_FILES 4096
#define MAX_DIRS 4096
#define MAX_LISTING_BUFFER (MAX_BUFFER * 32)

#define DEBUG_PRINT(fmt, ...) \
    do { if (DEBUG) fprintf(stderr, COLOR_CYAN "[DEBUG] " fmt COLOR_RESET, ##__VA_ARGS__); } while (0)

void print_banner() {
    printf(COLOR_MAGENTA);
    printf("██████╗ ██╗    ██╗███╗   ██╗███████╗██████╗     ███████╗███╗   ███╗██╗\n");
    printf("██╔══██╗██║    ██║████╗  ██║██╔════╝██╔══██╗    ██╔════╝████╗ ████║██║\n");
    printf("██████╔╝██║ █╗ ██║██╔██╗ ██║█████╗  ██║  ██║    █████╗  ██╔████╔██║██║\n");
    printf("██╔═══╝ ██║███╗██║██║╚██╗██║██╔══╝  ██║  ██║    ██╔══╝  ██║╚██╔╝██║╚═╝\n");
    printf("██║     ╚███╔███╔╝██║ ╚████║███████╗██████╔╝    ███████╗██║ ╚═╝ ██║██╗\n");
    printf("╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝╚══════╝╚═════╝     ╚══════╝╚═╝     ╚═╝╚═╝\n");
    printf(COLOR_RESET);
    printf(COLOR_BOLD COLOR_CYAN "\n Pwned EMI v2.0 - Enhanced Edition\n By: HM (github.com/Hasan-Malek)\n" COLOR_RESET);
    printf(COLOR_YELLOW " ---------------------------------------------\n" COLOR_RESET);
    printf(" Features:\n");
    printf(" - Bypass EMI Locked Phone for Data Transfer\n");
    printf(" - Recursive directory downloading\n");
    printf(" - FTP server fingerprinting\n");
    printf(" - Progress indicators\n");
    printf(COLOR_YELLOW " ---------------------------------------------\n\n" COLOR_RESET);
}

void print_timestamp() {
    time_t now;
    time(&now);
    printf(COLOR_BLUE "[%s] " COLOR_RESET, ctime(&now));
}

void print_success(const char *msg) {
    printf(COLOR_GREEN "[+] %s\n" COLOR_RESET, msg);
}

void print_error(const char *msg) {
    printf(COLOR_RED "[-] %s\n" COLOR_RESET, msg);
}

void print_warning(const char *msg) {
    printf(COLOR_YELLOW "[!] %s\n" COLOR_RESET, msg);
}

void print_info(const char *msg) {
    printf(COLOR_CYAN "[*] %s\n" COLOR_RESET, msg);
}

void print_debug(const char *msg) {
    if (DEBUG) printf(COLOR_MAGENTA "[DEBUG] %s\n" COLOR_RESET, msg);
}

int has_forbidden_extension(const char *filename) {
    const char *forbidden_extensions[] = {".nomedia", ".thumb", ".dmp"};
    int num_forbidden = sizeof(forbidden_extensions) / sizeof(forbidden_extensions[0]);
    char *lower_filename = strdup(filename);
    
    if (!lower_filename) return 0;

    for (char *p = lower_filename; *p; p++) *p = tolower(*p);

    for (int i = 0; i < num_forbidden; i++) {
        if (strstr(lower_filename, forbidden_extensions[i])) {
            free(lower_filename);
            return 1;
        }
    }
    free(lower_filename);
    return 0;
}

char *get_ip_from_interface() {
    static char ip[INET_ADDRSTRLEN];
    struct ifaddrs *ifaddr, *ifa;
    struct sockaddr_in *sa;

    if (getifaddrs(&ifaddr) == -1) {
        print_error("getifaddrs failed");
        return NULL;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;

        sa = (struct sockaddr_in *)ifa->ifa_addr;
        inet_ntop(AF_INET, &(sa->sin_addr), ip, INET_ADDRSTRLEN);

        if (strncmp(ip, "192.168.", 8) == 0) {
            DEBUG_PRINT("Selected interface %s with IP: %s", ifa->ifa_name, ip);
            freeifaddrs(ifaddr);
            return ip;
        }
    }

    freeifaddrs(ifaddr);
    DEBUG_PRINT("No interface with 192.168.x.x address found");
    return NULL;
}

int scan_host(const char *ip, int port) {
    int sock;
    struct sockaddr_in addr;
    fd_set fdset;
    struct timeval tv;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return 0;
    }

    fcntl(sock, F_SETFL, O_NONBLOCK);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    connect(sock, (struct sockaddr *)&addr, sizeof(addr));

    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    tv.tv_sec = TIMEOUT_SEC;
    tv.tv_usec = 0;

    if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error == 0) {
            close(sock);
            return 1;
        }
    }

    close(sock);
    return 0;
}

int parse_pasv_response(const char *response, char *ip, int *port) {
    const char *paren = strchr(response, '(');
    if (!paren) return 0;

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

void free_file_list(FileList *list) {
    for (int i = 0; i < list->file_count; i++)
        free(list->filenames[i]);
    free(list->filenames);
    for (int i = 0; i < list->dir_count; i++)
        free(list->dirnames[i]);
    free(list->dirnames);
    list->file_count = 0;
    list->dir_count = 0;
}

void parse_directory_listing(const char *listing, FileList *list) {
    list->filenames = malloc(MAX_FILES * sizeof(char *));
    list->dirnames = malloc(MAX_DIRS * sizeof(char *));
    list->file_count = 0;
    list->dir_count = 0;

    char *copy = strdup(listing);
    if (!copy) {
        DEBUG_PRINT("Failed to allocate memory for listing copy");
        return;
    }

    char *line = strtok(copy, "\n");
    while (line && (list->file_count < MAX_FILES || list->dir_count < MAX_DIRS)) {
        if (strlen(line) == 0) {
            line = strtok(NULL, "\n");
            continue;
        }

        DEBUG_PRINT("Parsing line: %s", line);

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
                    DEBUG_PRINT("Parsed directory: %s", filename);
                    list->dir_count++;
                }
            }
            else if (!is_dir && list->file_count < MAX_FILES) {
                if (!has_forbidden_extension(filename)) {
                    list->filenames[list->file_count] = strdup(filename);
                    DEBUG_PRINT("Parsed file: %s", filename);
                    list->file_count++;
                } else {
                    DEBUG_PRINT("Skipped file with forbidden extension: %s", filename);
                }
            }
        } else {
            DEBUG_PRINT("No filename found in line: %s", line);
        }
        line = strtok(NULL, "\n");
    }
    free(copy);
    DEBUG_PRINT("Total files parsed: %d, directories: %d", list->file_count, list->dir_count);
}

int mkdir_recursive(const char *path, mode_t mode) {
    char tmp[512];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = '\0';

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

int connect_with_timeout(int sock, struct sockaddr *addr, socklen_t addrlen, int timeout_sec) {
    fcntl(sock, F_SETFL, O_NONBLOCK);
    int res = connect(sock, addr, addrlen);
    if (res < 0 && errno == EINPROGRESS) {
        fd_set fdset;
        struct timeval tv;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;
        if (select(sock + 1, NULL, &fdset, NULL, &tv) > 0) {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
            if (so_error == 0) {
                fcntl(sock, F_SETFL, 0);
                return 0;
            }
        }
        errno = ETIMEDOUT;
    }
    return -1;
}

int download_file(int control_sock, const char *filename, const char *dest_path) {
    char buffer[MAX_BUFFER];
    int bytes;
    int data_sock = -1;
    struct sockaddr_in data_addr;
    FILE *file = NULL;
    int success = 0;
    int retry_count = 0;

retry:
    send(control_sock, "PASV\r\n", 6, 0);
    bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes <= 0) {
        print_error("No response to PASV command");
        goto cleanup;
    }
    buffer[bytes] = '\0';
    DEBUG_PRINT("PASV response: %s", buffer);
    if (strncmp(buffer, "227", 3) != 0) {
        print_error("Invalid PASV response");
        goto cleanup;
    }

    char data_ip[INET_ADDRSTRLEN];
    int data_port;
    if (!parse_pasv_response(buffer, data_ip, &data_port)) {
        print_error("Failed to parse PASV response");
        goto cleanup;
    }

    data_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (data_sock < 0) {
        perror("data socket");
        goto cleanup;
    }

    data_addr.sin_family = AF_INET;
    data_addr.sin_port = htons(data_port);
    inet_pton(AF_INET, data_ip, &data_addr.sin_addr);

    if (connect_with_timeout(data_sock, (struct sockaddr *)&data_addr, sizeof(data_addr), TIMEOUT_SEC) < 0) {
        perror("data connect");
        goto cleanup;
    }

    char retr_cmd[256];
    snprintf(retr_cmd, sizeof(retr_cmd), "RETR %s\r\n", filename);
    send(control_sock, retr_cmd, strlen(retr_cmd), 0);
    bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes <= 0) {
        print_error("No response to RETR command");
        goto cleanup;
    }
    buffer[bytes] = '\0';
    if (strncmp(buffer, "150", 3) != 0) {
        if (strncmp(buffer, "550", 3) == 0) {
            print_warning("Permission denied, skipping");
            success = 0;
            goto cleanup;
        }
        print_error("Failed to start file transfer");
        goto cleanup;
    }

    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/%s", dest_path, filename);
    file = fopen(filepath, "wb");
    if (!file) {
        perror("fopen");
        goto cleanup;
    }

    size_t total_bytes = 0;
    while ((bytes = recv(data_sock, buffer, sizeof(buffer), 0)) > 0) {
        if (fwrite(buffer, 1, bytes, file) != bytes) {
            print_error("Error writing to file");
            goto cleanup;
        }
        total_bytes += bytes;
        printf("\rDownloading %s: %zu bytes", filename, total_bytes);
        fflush(stdout);
    }
    printf("\n");
    if (bytes < 0) {
        perror("data recv");
        goto cleanup;
    }

    bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes > 0 && strncmp(buffer, "226", 3) == 0) {
        success = 1;
        print_success("Transfer completed successfully");
    } else {
        print_error("Transfer not completed");
    }

cleanup:
    if (file) fclose(file);
    if (data_sock >= 0) close(data_sock);
    if (!success && retry_count < MAX_RETRIES && strncmp(buffer, "550", 3) != 0) {
        retry_count++;
        print_warning("Retrying download...");
        sleep(1);
        goto retry;
    }
    return success;
}

int list_directory(int control_sock, char *listing_buffer, int max_size) {
    char buffer[MAX_BUFFER];
    int bytes;
    int data_sock = -1;
    struct sockaddr_in data_addr;
    int listing_pos = 0;

    send(control_sock, "PASV\r\n", 6, 0);
    bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes <= 0) {
        print_error("No response to PASV command");
        return 0;
    }
    buffer[bytes] = '\0';
    DEBUG_PRINT("PASV response: %s", buffer);
    if (strncmp(buffer, "227", 3) != 0) {
        print_error("Invalid PASV response");
        return 0;
    }

    char data_ip[INET_ADDRSTRLEN];
    int data_port;
    if (!parse_pasv_response(buffer, data_ip, &data_port)) {
        print_error("Failed to parse PASV response");
        return 0;
    }

    data_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (data_sock < 0) {
        perror("data socket");
        return 0;
    }

    data_addr.sin_family = AF_INET;
    data_addr.sin_port = htons(data_port);
    inet_pton(AF_INET, data_ip, &data_addr.sin_addr);

    if (connect_with_timeout(data_sock, (struct sockaddr *)&data_addr, sizeof(data_addr), TIMEOUT_SEC) < 0) {
        perror("data connect");
        close(data_sock);
        return 0;
    }

    send(control_sock, "LIST\r\n", 6, 0);
    bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes <= 0 || strncmp(buffer, "150", 3) != 0) {
        if (bytes > 0 && strncmp(buffer, "550", 3) == 0) {
            print_warning("Permission denied for directory listing");
            close(data_sock);
            return 0;
        }
        print_error("Failed to start directory listing");
        close(data_sock);
        return 0;
    }

    printf(COLOR_BOLD COLOR_BLUE "\nDirectory Listing:\n" COLOR_RESET);
    while ((bytes = recv(data_sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes] = '\0';
        printf("%s", buffer);
        if (listing_pos + bytes < max_size) {
            strncpy(listing_buffer + listing_pos, buffer, bytes);
            listing_pos += bytes;
        } else {
            DEBUG_PRINT("Listing buffer overflow, truncating");
            break;
        }
    }
    if (bytes < 0) {
        perror("data recv");
        close(data_sock);
        return 0;
    }
    listing_buffer[listing_pos] = '\0';
    close(data_sock);

    bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes <= 0 || strncmp(buffer, "226", 3) != 0) {
        print_error("Directory listing not completed");
        return 0;
    }

    return 1;
}

int download_directory(int control_sock, const char *remote_dir, const char *local_base_path, const char *relative_path) {
    char buffer[MAX_BUFFER];
    int bytes;

    char cwd_cmd[256];
    snprintf(cwd_cmd, sizeof(cwd_cmd), "CWD %s\r\n", remote_dir);
    send(control_sock, cwd_cmd, strlen(cwd_cmd), 0);
    bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        DEBUG_PRINT("Response to 'CWD %s': %s", remote_dir, buffer);
        if (strncmp(buffer, "250", 3) != 0) {
            if (strncmp(buffer, "550", 3) == 0) {
                print_warning("Permission denied for directory");
                return 0;
            }
            print_error("Failed to change directory");
            return 0;
        }
    } else {
        print_error("No response to CWD command");
        return 0;
    }

    char local_path[512];
    if (relative_path[0] == '\0')
        snprintf(local_path, sizeof(local_path), "%s", local_base_path);
    else
        snprintf(local_path, sizeof(local_path), "%s/%s", local_base_path, relative_path);

    struct stat st;
    if (stat(local_path, &st) != 0) {
        if (mkdir_recursive(local_path, 0755) != 0) {
            perror("mkdir_recursive");
            return 0;
        }
        print_info("Created local directory");
    }

    char listing_buffer[MAX_LISTING_BUFFER] = {0};
    if (!list_directory(control_sock, listing_buffer, MAX_LISTING_BUFFER)) {
        return 0;
    }

    FileList list = {NULL, 0, NULL, 0};
    DEBUG_PRINT("Raw listing buffer:\n%s", listing_buffer);
    parse_directory_listing(listing_buffer, &list);

    for (int i = 0; i < list.file_count; i++) {
        printf(COLOR_YELLOW "\n[*] Downloading %s/%s..." COLOR_RESET, relative_path, list.filenames[i]);
        if (download_file(control_sock, list.filenames[i], local_path)) {
            print_success("Download completed");
        } else {
            print_error("Download failed");
        }
    }

    for (int i = 0; i < list.dir_count; i++) {
        char new_remote_dir[512];
        char new_relative_path[512];
        if (relative_path[0] == '\0') {
            snprintf(new_remote_dir, sizeof(new_remote_dir), "%s", list.dirnames[i]);
            snprintf(new_relative_path, sizeof(new_relative_path), "%s", list.dirnames[i]);
        } else {
            snprintf(new_remote_dir, sizeof(new_remote_dir), "%s/%s", relative_path, list.dirnames[i]);
            snprintf(new_relative_path, sizeof(new_relative_path), "%s/%s", relative_path, list.dirnames[i]);
        }

        printf(COLOR_BOLD COLOR_BLUE "\n[*] Entering directory %s" COLOR_RESET, new_remote_dir);
        download_directory(control_sock, new_remote_dir, local_base_path, new_relative_path);

        send(control_sock, "CWD ..\r\n", 8, 0);
        bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            DEBUG_PRINT("Response to 'CWD ..': %s", buffer);
        }
    }

    free_file_list(&list);
    return 1;
}

int login_ftp(int control_sock) {
    char buffer[MAX_BUFFER];
    int bytes;

    const char *user_cmd = "USER anonymous\r\n";
    send(control_sock, user_cmd, strlen(user_cmd), 0);
    bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        DEBUG_PRINT("USER response: %s", buffer);
        if (strncmp(buffer, "230", 3) != 0 && strncmp(buffer, "331", 3) != 0) {
            print_error("Anonymous login not supported");
            return 0;
        }
    } else {
        print_error("No response to USER command");
        return 0;
    }

    if (strncmp(buffer, "331", 3) == 0) {
        const char *pass_cmd = "PASS anonymous@example.com\r\n";
        send(control_sock, pass_cmd, strlen(pass_cmd), 0);
        bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            DEBUG_PRINT("PASS response: %s", buffer);
            if (strncmp(buffer, "230", 3) != 0) {
                print_error("Password login failed");
                return 0;
            }
        } else {
            print_error("No response to PASS command");
            return 0;
        }
    }

    const char *type_cmd = "TYPE I\r\n";
    send(control_sock, type_cmd, strlen(type_cmd), 0);
    bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        DEBUG_PRINT("TYPE response: %s", buffer);
        if (strncmp(buffer, "200", 3) != 0) {
            print_error("Failed to set binary mode");
            return 0;
        }
    } else {
        print_error("No response to TYPE command");
        return 0;
    }

    return 1;
}

void interact_with_ftp(const char *ip, int port, FileList *file_list) {
    int control_sock;
    struct sockaddr_in server_addr;
    char buffer[MAX_BUFFER];
    int bytes;

    control_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (control_sock < 0) {
        perror("control socket");
        return;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server_addr.sin_addr);

    if (connect(control_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("control connect");
        close(control_sock);
        return;
    }

    bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf(COLOR_BOLD COLOR_GREEN "\n[FTP Banner from %s:%d]\n" COLOR_RESET "%s", ip, port, buffer);
        DEBUG_PRINT("Banner: %s", buffer);
    } else {
        print_error("Failed to receive FTP banner");
        close(control_sock);
        return;
    }

    if (!login_ftp(control_sock)) {
        close(control_sock);
        return;
    }

    char listing_buffer[MAX_LISTING_BUFFER] = {0};
    if (list_directory(control_sock, listing_buffer, MAX_LISTING_BUFFER)) {
        DEBUG_PRINT("Raw listing buffer:\n%s", listing_buffer);
        parse_directory_listing(listing_buffer, file_list);
    }

    const char *cmds[] = {"SYST\r\n", "FEAT\r\n", "PWD\r\n", "STAT\r\n"};
    for (int i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
        send(control_sock, cmds[i], strlen(cmds[i]), 0);
        bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            printf(COLOR_CYAN "[Response to '%s']\n%s" COLOR_RESET, cmds[i], buffer);
        }
    }

    send(control_sock, "QUIT\r\n", 6, 0);
    bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        DEBUG_PRINT("QUIT response: %s", buffer);
    }

    close(control_sock);
}

int main(int argc, char *argv[]) {
    print_banner();

    int ports[] = {2221, 21, 2121};
    int num_ports = sizeof(ports) / sizeof(ports[0]);

    char *local_ip = get_ip_from_interface();
    if (!local_ip) {
        print_error("No network interface with 192.168.x.x address found");
        print_info("Run 'ifconfig' or 'ip addr' to check available interfaces");
        return 1;
    }

    char ip_prefix[INET_ADDRSTRLEN];
    char *last_dot = strrchr(local_ip, '.');
    if (!last_dot) {
        print_error("Invalid IP format");
        return 1;
    }

    strncpy(ip_prefix, local_ip, last_dot - local_ip);
    ip_prefix[last_dot - local_ip] = '\0';

    char target_ip[INET_ADDRSTRLEN];
    printf(COLOR_BOLD COLOR_YELLOW "\n[*] Scanning subnet: %s.1 - %s.254 for ports: " COLOR_RESET, ip_prefix, ip_prefix);
    for (int p = 0; p < num_ports; p++) {
        printf("%d ", ports[p]);
    }
    printf("\n");

    FileList file_list = {NULL, 0, NULL, 0};
    int ftp_found = 0;
    char found_ip[INET_ADDRSTRLEN] = {0};
    int found_port = 0;

    for (int i = 1; i <= 254; i++) {
        snprintf(target_ip, sizeof(target_ip), "%s.%d", ip_prefix, i);

        if (strcmp(target_ip, local_ip) == 0)
            continue;

        for (int p = 0; p < num_ports; p++) {
            printf("\rScanning %s:%d...", target_ip, ports[p]);
            fflush(stdout);
            
            if (scan_host(target_ip, ports[p])) {
                printf("\n");
                print_success("FTP service found");
                interact_with_ftp(target_ip, ports[p], &file_list);
                ftp_found = 1;
                strncpy(found_ip, target_ip, INET_ADDRSTRLEN);
                found_port = ports[p];
                break;
            }
        }
        if (ftp_found)
            break;
    }

    if (ftp_found) {
        printf(COLOR_BOLD COLOR_CYAN "\n[Scan Results]\n" COLOR_RESET);
        printf("Files found: %d\nDirectories found: %d\n", file_list.file_count, file_list.dir_count);
        
        if (file_list.file_count > 0 || file_list.dir_count > 0) {
            char choice[10];
            printf(COLOR_BOLD COLOR_YELLOW "\nDo you want to download all data? (y/n): " COLOR_RESET);
            if (fgets(choice, sizeof(choice), stdin) != NULL) {
                choice[strcspn(choice, "\n")] = '\0';
                if (strcmp(choice, "y") == 0 || strcmp(choice, "Y") == 0) {
                    char dest_path[256];
                    printf(COLOR_YELLOW "Enter destination folder path: " COLOR_RESET);
                    if (fgets(dest_path, sizeof(dest_path), stdin) != NULL) {
                        dest_path[strcspn(dest_path, "\n")] = '\0';

                        struct stat st;
                        if (stat(dest_path, &st) != 0) {
                            if (mkdir_recursive(dest_path, 0755) != 0) {
                                perror("mkdir_recursive");
                                free_file_list(&file_list);
                                return 1;
                            }
                            print_info("Created destination folder");
                        } else if (!S_ISDIR(st.st_mode)) {
                            print_error("Path is not a directory");
                            free_file_list(&file_list);
                            return 1;
                        }

                        int control_sock = socket(AF_INET, SOCK_STREAM, 0);
                        if (control_sock < 0) {
                            perror("control socket");
                            free_file_list(&file_list);
                            return 1;
                        }

                        struct sockaddr_in server_addr;
                        server_addr.sin_family = AF_INET;
                        server_addr.sin_port = htons(found_port);
                        inet_pton(AF_INET, found_ip, &server_addr.sin_addr);

                        if (connect(control_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                            perror("control connect");
                            close(control_sock);
                            free_file_list(&file_list);
                            return 1;
                        }

                        char buffer[MAX_BUFFER];
                        int bytes = recv(control_sock, buffer, sizeof(buffer) - 1, 0);
                        if (bytes <= 0) {
                            print_error("Failed to receive FTP banner");
                            close(control_sock);
                            free_file_list(&file_list);
                            return 1;
                        }

                        if (!login_ftp(control_sock)) {
                            close(control_sock);
                            free_file_list(&file_list);
                            return 1;
                        }

                        print_info("Starting recursive download");
                        download_directory(control_sock, "/", dest_path, "");

                        send(control_sock, "QUIT\r\n", 6, 0);
                        close(control_sock);
                    }
                }
            }
        } else {
            print_info("No files or directories found to download");
        }
    } else {
        print_info("No FTP servers found");
    }

    free_file_list(&file_list);
    print_success("Scan complete");
    return 0;
}