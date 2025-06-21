#include <stdio.h>      // For standard I/O (printf, fopen, fclose, etc.)
#include <stdlib.h>     // For standard library functions (malloc, free, exit)
#include <string.h>     // For string manipulation (strlen, strcpy, strncmp, etc.)
#include <winsock2.h>   // For Windows Sockets API (socket, bind, listen, accept, send, recv, closesocket)
#include <ws2tcpip.h>   // For InetNtopA, INET_ADDRSTRLEN
#include <windows.h>    // For Windows API functions (CreateDirectory, security, etc.)
#include <direct.h>     // For _mkdir, if needed (CreateDirectory is preferred)
#include <io.h>         // For _access
#include <sys/stat.h>   // For _stat struct and function
#include <time.h>       // For time functions (used in file modification time)
#include <lmcons.h>     // For UNLEN (max username length)
#include <aclapi.h>     // For access control functions (if needed, but simpler security checks used)
#include <sddl.h>       // For ConvertSidToStringSid
#include <errno.h>      // For strerror(errno)

// Link with Ws2_32.lib implicitly through pragma comment
#pragma comment(lib, "Ws2_32.lib")

// Define constants for the server
#define PORT 8080       // Changed default port to 8080
#define BUFFER_SIZE 8192 // Buffer size for network operations
#define MAX_PATH_LEN 260 // Max path length on Windows

// Define the content directory and icon directory names relative to the executable
#define CONTENT_DIR_NAME "files"
#define ICONS_DIR_NAME "icons"

// Function prototypes
const char *get_mime_type(const char *file_ext);
void send_response(SOCKET client_sock, const char *status, const char *content_type, const char *body, long content_length);
// Added force_download parameter to send_file
void send_file(SOCKET client_sock, const char *filepath, const char *content_type, int force_download);
void generate_listing(SOCKET client_sock, const char *dirpath);
void handle_client(SOCKET client_sock); // No base_dir needed here anymore, it's handled internally

// NEW: Helper function to get the appropriate icon filename based on extension
const char *get_icon_filename_for_extension(const char *file_ext) {
    if (file_ext == NULL) return "file.ico"; // Default for no extension

    // Use _stricmp for case-insensitive comparison
    if (_stricmp(file_ext, "txt") == 0) return "txt.ico";
    if (_stricmp(file_ext, "html") == 0 || _stricmp(file_ext, "htm") == 0) return "page.ico";
    if (_stricmp(file_ext, "css") == 0) return "css.ico";
    if (_stricmp(file_ext, "js") == 0) return "js.ico";
    if (_stricmp(file_ext, "json") == 0) return "json.ico";
    if (_stricmp(file_ext, "jpg") == 0 || _stricmp(file_ext, "jpeg") == 0 || _stricmp(file_ext, "png") == 0 || _stricmp(file_ext, "gif") == 0) return "image.ico";
    if (_stricmp(file_ext, "pdf") == 0) return "pdf.ico";
    if (_stricmp(file_ext, "zip") == 0 || _stricmp(file_ext, "rar") == 0 || _stricmp(file_ext, "7z") == 0) return "zip.ico";
    if (_stricmp(file_ext, "mp3") == 0 || _stricmp(file_ext, "wav") == 0 || _stricmp(file_ext, "flac") == 0) return "audio.ico";
    if (_stricmp(file_ext, "mp4") == 0 || _stricmp(file_ext, "avi") == 0 || _stricmp(file_ext, "mkv") == 0) return "video.ico";
    if (_stricmp(file_ext, "exe") == 0 || _stricmp(file_ext, "msi") == 0) return "exe.ico";
    if (_stricmp(file_ext, "doc") == 0 || _stricmp(file_ext, "docx") == 0) return "doc.ico";
    if (_stricmp(file_ext, "xml") == 0) return "xml.ico";

    return "file.ico"; // Default icon for unrecognized file types
}

// Helper function to get MIME type based on file extension
const char *get_mime_type(const char *file_ext) {
    // Use _stricmp for case-insensitive comparison (Windows-specific)
    if (_stricmp(file_ext, "html") == 0 || _stricmp(file_ext, "htm") == 0) return "text/html";
    if (_stricmp(file_ext, "txt") == 0) return "text/plain";
    if (_stricmp(file_ext, "css") == 0) return "text/css";
    if (_stricmp(file_ext, "js") == 0) return "application/javascript";
    if (_stricmp(file_ext, "json") == 0) return "application/json";
    if (_stricmp(file_ext, "jpg") == 0 || _stricmp(file_ext, "jpeg") == 0) return "image/jpeg";
    if (_stricmp(file_ext, "png") == 0) return "image/png";
    if (_stricmp(file_ext, "gif") == 0) return "image/gif";
    if (_stricmp(file_ext, "ico") == 0) return "image/x-icon";
    if (_stricmp(file_ext, "pdf") == 0) return "application/pdf";
    if (_stricmp(file_ext, "zip") == 0) return "application/zip";
    if (_stricmp(file_ext, "mp3") == 0) return "audio/mpeg";
    if (_stricmp(file_ext, "mp4") == 0) return "video/mp4";
    return "application/octet-stream"; // Default type for unknown files
}

// Function to send an HTTP response
void send_response(SOCKET client_sock, const char *status, const char *content_type, const char *body, long content_length) {
    char header[BUFFER_SIZE];
    // Use snprintf to prevent buffer overflows
    int header_len = snprintf(header, BUFFER_SIZE,
             "HTTP/1.1 %s\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %ld\r\n"
             "Connection: close\r\n"
             "\r\n",
             status, content_type, content_length);

    if (header_len < 0 || header_len >= BUFFER_SIZE) {
        fprintf(stderr, "Error creating HTTP header or buffer too small.\n");
        return;
    }

    send(client_sock, header, header_len, 0);
    if (body != NULL && content_length > 0) {
        send(client_sock, body, content_length, 0);
    }
}

// Function to send a file as an HTTP response
// Added 'force_download' parameter
void send_file(SOCKET client_sock, const char *filepath, const char *content_type, int force_download) {
    FILE *file = fopen(filepath, "rb");
    if (file == NULL) {
        perror("Error opening file");
        send_response(client_sock, "404 Not Found", "text/plain", "404 Not Found", strlen("404 Not Found"));
        return;
    }

    // Get file size (using fseek/ftell for portable size detection)
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char header[BUFFER_SIZE];
    int header_len;

    if (force_download) {
        // Extract filename from filepath for Content-Disposition
        const char *filename_start = strrchr(filepath, '\\');
        if (filename_start == NULL) {
            filename_start = filepath; // No backslash, so filepath is the filename
        } else {
            filename_start++; // Move past the backslash
        }

        header_len = snprintf(header, BUFFER_SIZE,
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: %s\r\n"
                 "Content-Disposition: attachment; filename=\"%s\"\r\n" // Force download
                 "Content-Length: %ld\r\n"
                 "Connection: close\r\n"
                 "\r\n",
                 content_type, filename_start, file_size);
    } else {
        header_len = snprintf(header, BUFFER_SIZE,
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: %s\r\n"
                 "Content-Length: %ld\r\n"
                 "Connection: close\r\n"
                 "\r\n",
                 content_type, file_size);
    }


    if (header_len < 0 || header_len >= BUFFER_SIZE) {
        fprintf(stderr, "Error creating HTTP header or buffer too small.\n");
        fclose(file);
        return;
    }

    send(client_sock, header, header_len, 0);

    char buffer[BUFFER_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        send(client_sock, buffer, bytes_read, 0);
    }

    fclose(file);
}

// Function to generate a directory listing as HTML
void generate_listing(SOCKET client_sock, const char *dirpath) {
    WIN32_FIND_DATAA findFileData; // Use WIN32_FIND_DATAA for ANSI strings
    HANDLE hFind;
    char searchPath[MAX_PATH_LEN];
    char fullpath[MAX_PATH_LEN];
    char listing_buffer[BUFFER_SIZE * 4]; // Larger buffer for HTML listing
    int offset = 0;

    // Append "\*" to the directory path to search all files/directories
    snprintf(searchPath, MAX_PATH_LEN, "%s\\*", dirpath);

    offset += snprintf(listing_buffer + offset, sizeof(listing_buffer) - offset,
                       "<!DOCTYPE html>\n"
                       "<html><head><title>Directory Listing for %s</title>"
                       "<style>"
                       "body { font-family: sans-serif; background-color: #f4f4f4; color: #333; margin: 20px; }"
                       "h1 { color: #0056b3; }"
                       "table { width: 90%%; border-collapse: collapse; margin-top: 20px; background-color: #fff; box-shadow: 0 0 10px rgba(0,0,0,0.1); }"
                       "th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }"
                       "th { background-color: #e2e2e2; }"
                       "tr:nth-child(even) { background-color: #f9f9f9; }"
                       "a { text-decoration: none; color: #007bff; }"
                       "a:hover { text-decoration: underline; }"
                       ".icon { vertical-align: middle; margin-right: 5px; width: 16px; height: 16px; }"
                       ".dir { color: #b30000; font-weight: bold; }" // Style for directories
                       ".file { color: #0056b3; }" // Style for files
                       ".action-links a { margin-right: 10px; font-size: 0.9em; }" // Style for view/download links
                       "</style>"
                       "</head><body><h1>Directory Listing for %s</h1><table>"
                       "<thead><tr><th>Icon</th><th>Name</th><th>Size</th><th>Last Modified</th><th>Actions</th></tr></thead></thead><tbody>",
                       dirpath, dirpath); // Added 'Actions' column

    // Add ".." (parent directory) link
    offset += snprintf(listing_buffer + offset, sizeof(listing_buffer) - offset,
                       "<tr><td><img src=\"/%s/up.ico\" class=\"icon\" alt=\"Parent Directory Icon\" width=\"16\" height=\"16\"></td>" // Used up.ico
                       "<td><a href=\"../\" class=\"dir\">..</a></td><td></td><td></td><td></td></tr>", // Added empty cell for Actions
                       ICONS_DIR_NAME); //

    hFind = FindFirstFileA(searchPath, &findFileData); // Use FindFirstFileA for ANSI
    if (hFind == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error opening directory for listing (FindFirstFile): %lu\n", GetLastError());
        send_response(client_sock, "500 Internal Server Error", "text/plain", "500 Internal Server Error", strlen("500 Internal Server Error"));
        return;
    }

    do {
        // Skip current and parent directory entries as they are handled explicitly or not needed here
        if (strcmp(findFileData.cFileName, ".") == 0 || strcmp(findFileData.cFileName, "..") == 0) {
            continue;
        }

        // Construct full path for _stat
        snprintf(fullpath, MAX_PATH_LEN, "%s\\%s", dirpath, findFileData.cFileName);

        char size_str[32];
        char last_mod_str[64];
        SYSTEMTIME stUTC, stLocal;
        FILETIME ftLastWriteTime;

        // Get last modified time
        ftLastWriteTime = findFileData.ftLastWriteTime;
        FileTimeToSystemTime(&ftLastWriteTime, &stUTC);
        SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal); // Convert to local time zone

        snprintf(last_mod_str, sizeof(last_mod_str), "%04d-%02d-%02d %02d:%02d:%02d",
                 stLocal.wYear, stLocal.wMonth, stLocal.wDay,
                 stLocal.wHour, stLocal.wMinute, stLocal.wSecond);


        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { // Check if it's a directory
            strcpy(size_str, "-");
            offset += snprintf(listing_buffer + offset, sizeof(listing_buffer) - offset,
                               "<tr><td><img src=\"/%s/dir.ico\" class=\"icon\" alt=\"Directory Icon\" width=\"16\" height=\"16\"></td>" // Used dir.ico for folders
                               "<td><a href=\"%s/\" class=\"dir\">%s/</a></td><td>%s</td><td>%s</td><td></td></tr>", // Added empty cell for Actions
                               ICONS_DIR_NAME, findFileData.cFileName, findFileData.cFileName, size_str, last_mod_str);
        } else { // It's a regular file
            // Note: nFileSizeHigh and nFileSizeLow form a 64-bit size
            long long file_size = ((long long)findFileData.nFileSizeHigh << 32) | findFileData.nFileSizeLow;
            snprintf(size_str, sizeof(size_str), "%lld bytes", file_size);

            // Extract file extension for icon
            const char *ext = strrchr(findFileData.cFileName, '.');
            const char *icon_to_use = get_icon_filename_for_extension(ext ? (ext + 1) : NULL); // Pass extension (or NULL if no extension)
            
            char icon_path_html[MAX_PATH_LEN]; // Path for HTML img src
            snprintf(icon_path_html, MAX_PATH_LEN, "/%s/%s", ICONS_DIR_NAME, icon_to_use); // Construct full path to icon

            // Determine if it's a text file to offer view/download options
            int is_text_file = (ext != NULL && _stricmp(ext + 1, "txt") == 0);

            offset += snprintf(listing_buffer + offset, sizeof(listing_buffer) - offset,
                               "<tr><td><img src=\"%s\" class=\"icon\" alt=\"File Icon\" width=\"16\" height=\"16\"></td>" // Use determined icon
                               "<td><a href=\"%s\" class=\"file\">%s</a></td><td>%s</td><td>%s</td><td class=\"action-links\">",
                               icon_path_html, findFileData.cFileName, findFileData.cFileName, size_str, last_mod_str);

            if (is_text_file) {
                // Offer both view and download for text files
                offset += snprintf(listing_buffer + offset, sizeof(listing_buffer) - offset,
                                   "<a href=\"%s\">View</a> | <a href=\"%s?download=1\">Download</a>",
                                   findFileData.cFileName, findFileData.cFileName);
            } else {
                // For other file types, the default click behavior (view/open) is usually sufficient,
                // and download can be done via browser's right-click save-as.
                offset += snprintf(listing_buffer + offset, sizeof(listing_buffer) - offset,
                                   "<a href=\"%s\">Open</a>", findFileData.cFileName);
            }

            offset += snprintf(listing_buffer + offset, sizeof(listing_buffer) - offset,
                               "</td></tr>"); // Close action-links cell and row
        }

        // Basic check to prevent buffer overflow (might need more robust handling for very large directories)
        if (offset >= sizeof(listing_buffer) - 500) { // Keep some space for closing tags
            fprintf(stderr, "Warning: Directory listing buffer nearing capacity. Some entries might be truncated.\n");
            break;
        }
    } while (FindNextFileA(hFind, &findFileData) != 0); // Use FindNextFileA

    FindClose(hFind);

    offset += snprintf(listing_buffer + offset, sizeof(listing_buffer) - offset,
                       "</tbody></table></body></html>");

    send_response(client_sock, "200 OK", "text/html", listing_buffer, strlen(listing_buffer));
}


// Function to handle a single client request
void handle_client(SOCKET client_sock) { // Removed base_dir parameter
    char request[BUFFER_SIZE];
    // Use recv (Winsock)
    int bytes_received = recv(client_sock, request, BUFFER_SIZE - 1, 0);
    if (bytes_received <= 0) {
        if (bytes_received == 0) {
            fprintf(stderr, "Client disconnected.\n");
        } else {
            fprintf(stderr, "Failed to receive data: %d\n", WSAGetLastError());
        }
        closesocket(client_sock); // Use closesocket() for Winsock
        return;
    }
    request[bytes_received] = '\0'; // Null-terminate the received data

    printf("Received request:\n%s\n", request);

    // Parse the request line (e.g., "GET /index.html HTTP/1.1")
    char *method = strtok(request, " ");
    char *path_with_query = strtok(NULL, " "); // Path might contain query string
    char *http_version = strtok(NULL, "\r\n");

    if (!method || !path_with_query || !http_version) {
        send_response(client_sock, "400 Bad Request", "text/plain", "Bad Request", strlen("Bad Request"));
        closesocket(client_sock);
        return;
    }

    if (_stricmp(method, "GET") != 0) { // Case-insensitive comparison for method
        send_response(client_sock, "501 Not Implemented", "text/plain", "Not Implemented", strlen("Not Implemented"));
        closesocket(client_sock);
        return;
    }

    // Determine if download is requested and extract clean path
    int force_download = 0;
    char *query_start = strchr(path_with_query, '?');
    char clean_path[MAX_PATH_LEN];
    if (query_start != NULL) {
        strncpy(clean_path, path_with_query, query_start - path_with_query);
        clean_path[query_start - path_with_query] = '\0'; // Null-terminate
        // Check for ?download=1
        if (strstr(query_start, "download=1") != NULL) {
            force_download = 1;
        }
    } else {
        strncpy(clean_path, path_with_query, MAX_PATH_LEN - 1);
        clean_path[MAX_PATH_LEN - 1] = '\0';
    }


    // Determine the absolute base path for content and icons
    char server_executable_path[MAX_PATH_LEN];
    GetModuleFileNameA(NULL, server_executable_path, MAX_PATH_LEN);
    char drive[_MAX_DRIVE];
char dir[_MAX_DIR];
    char fname[_MAX_FNAME]; // Add these variables
    char ext[_MAX_EXT];     // Add these variables

    _splitpath(server_executable_path, drive, dir, fname, ext); // Now split the full path

    char base_dir_for_content[MAX_PATH_LEN];
    snprintf(base_dir_for_content, MAX_PATH_LEN, "%s%s%s\\", drive, dir, CONTENT_DIR_NAME);

    char base_dir_for_icons[MAX_PATH_LEN];
    snprintf(base_dir_for_icons, MAX_PATH_LEN, "%s%s%s\\", drive, dir, ICONS_DIR_NAME);


    // Convert forward slashes in URL path to backslashes for Windows file paths
    char windows_path[MAX_PATH_LEN];
    strncpy(windows_path, clean_path, MAX_PATH_LEN - 1);
    windows_path[MAX_PATH_LEN - 1] = '\0'; // Ensure null-termination
    for (int i = 0; windows_path[i] != '\0'; i++) {
        if (windows_path[i] == '/') {
            windows_path[i] = '\\';
        }
    }

    char target_file_path[MAX_PATH_LEN]; // The actual path on the file system to serve

    // --- Path Mapping Logic ---
    // Handle special cases first: root and icon requests
    if (strcmp(windows_path, "\\") == 0) {
        // Request for http://127.0.0.1:8080/ -> serve the root of the content directory
        snprintf(target_file_path, MAX_PATH_LEN, "%s", base_dir_for_content);
    } else if (_strnicmp(windows_path, "\\", 1) == 0 && _strnicmp(windows_path + 1, ICONS_DIR_NAME, strlen(ICONS_DIR_NAME)) == 0) {
        // Request for http://127.0.0.1:8080/icons/...
        // Construct path relative to the icons directory. Use path+1 to skip leading '/' from URL.
        snprintf(target_file_path, MAX_PATH_LEN, "%s%s", base_dir_for_icons, windows_path + 1 + strlen(ICONS_DIR_NAME));
    } else if (_strnicmp(windows_path, "\\", 1) == 0 && _strnicmp(windows_path + 1, CONTENT_DIR_NAME, strlen(CONTENT_DIR_NAME)) == 0) {
        // Request for http://127.0.0.1:8080/files/...
        // Strip the "/files" part from the URL path.
        snprintf(target_file_path, MAX_PATH_LEN, "%s%s", base_dir_for_content, windows_path + 1 + strlen(CONTENT_DIR_NAME));
    }
    else {
        // All other requests are relative to the content directory.
        // Construct path from the content base and the requested path.
        snprintf(target_file_path, MAX_PATH_LEN, "%s%s", base_dir_for_content, windows_path + 1); // +1 to skip leading '\'
    }

    // Canonicalize path to prevent directory traversal attacks
    char safe_path[MAX_PATH_LEN];
    if (_fullpath(safe_path, target_file_path, MAX_PATH_LEN) == NULL) {
        fprintf(stderr, "Error resolving full path for %s: %s (might not exist or invalid)\n", target_file_path, strerror(errno));
        send_response(client_sock, "404 Not Found", "text/plain", "404 Not Found", strlen("404 Not Found"));
        closesocket(client_sock);
        return;
    }

    // --- SECURITY CHECK: Ensure the resolved path is within EITHER content_dir OR icons_dir ---
    char full_content_base_dir_resolved[MAX_PATH_LEN];
    char full_icons_base_dir_resolved[MAX_PATH_LEN];

    if (_fullpath(full_content_base_dir_resolved, base_dir_for_content, MAX_PATH_LEN) == NULL ||
        _fullpath(full_icons_base_dir_resolved, base_dir_for_icons, MAX_PATH_LEN) == NULL) {
        fprintf(stderr, "Error resolving base content/icons directory paths for security check.\n");
        send_response(client_sock, "500 Internal Server Error", "text/plain", "500 Internal Server Error", strlen("500 Internal Server Error"));
        closesocket(client_sock);
        return;
    }

    // Add trailing backslash for robust prefix comparison if not present
    size_t len_content = strlen(full_content_base_dir_resolved);
    if (len_content > 0 && full_content_base_dir_resolved[len_content - 1] != '\\') {
        strncat(full_content_base_dir_resolved, "\\", MAX_PATH_LEN - len_content - 1);
    }
    size_t len_icons = strlen(full_icons_base_dir_resolved);
    if (len_icons > 0 && full_icons_base_dir_resolved[len_icons - 1] != '\\') {
        strncat(full_icons_base_dir_resolved, "\\", MAX_PATH_LEN - len_icons - 1);
    }

    // Check if safe_path is within content_dir OR icons_dir
    if (!(_strnicmp(safe_path, full_content_base_dir_resolved, strlen(full_content_base_dir_resolved)) == 0 ||
          _strnicmp(safe_path, full_icons_base_dir_resolved, strlen(full_icons_base_dir_resolved)) == 0)) {
        printf("Attempted directory traversal: %s (Content base: %s, Icons base: %s)\n", safe_path, full_content_base_dir_resolved, full_icons_base_dir_resolved);
        send_response(client_sock, "403 Forbidden", "text/plain", "Forbidden", strlen("Forbidden"));
        closesocket(client_sock);
        return;
    }
    // --- END SECURITY CHECK ---

    struct _stat path_stat; // Use _stat for Windows
    if (_stat(safe_path, &path_stat) == -1) { // Check if path exists
        fprintf(stderr, "_stat error for path %s: %d\n", safe_path, GetLastError());
        send_response(client_sock, "404 Not Found", "text/plain", "404 Not Found", strlen("404 Not Found"));
        closesocket(client_sock);
        return;
    }

    // Check if it's a directory or a regular file
    if ((path_stat.st_mode & _S_IFDIR)) { // Check if it's a directory (_S_IFDIR from sys/stat.h)
        char index_html_path[MAX_PATH_LEN];
        snprintf(index_html_path, MAX_PATH_LEN, "%s\\index.html", safe_path);
        struct _stat index_stat;
        if (_stat(index_html_path, &index_stat) == 0 && (index_stat.st_mode & _S_IFREG)) {
            // Serve index.html if it exists in the directory
            send_file(client_sock, index_html_path, "text/html", 0); // No force download for index.html
        } else {
            // Otherwise, generate and serve a directory listing
            generate_listing(client_sock, safe_path);
        }
    } else if ((path_stat.st_mode & _S_IFREG)) { // If it's a regular file
        const char *file_ext = strrchr(clean_path, '.'); // Use clean_path for extension logic
        const char *content_type = "application/octet-stream"; // Default

        if (file_ext) {
            content_type = get_mime_type(file_ext + 1);
        }
        // Pass the force_download flag to send_file
        send_file(client_sock, safe_path, content_type, force_download);
    } else {
        // Not a regular file or directory (e.g., device, pipe)
        send_response(client_sock, "403 Forbidden", "text/plain", "Forbidden", strlen("Forbidden"));
    }

    closesocket(client_sock); // Use closesocket()
}


// Main function for the server
int main() {
    WSADATA wsaData; // Structure for Winsock initialization
    SOCKET server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    int client_len = sizeof(client_addr);

    // Initialize Winsock (REQUIRED on Windows)
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }

    // Create socket (AF_INET for IPv4, SOCK_STREAM for TCP)
    server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // Use IPPROTO_TCP
    if (server_sock == INVALID_SOCKET) { // Use INVALID_SOCKET for error check
        fprintf(stderr, "Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // Set up server address structure
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all available interfaces
    server_addr.sin_port = htons(PORT); // Convert port to network byte order

    // Bind socket to the specified IP and port
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "Socket binding failed: %d\n", WSAGetLastError());
        closesocket(server_sock);
        WSACleanup();
        return 1;
    }

    // Start listening for incoming connections
    if (listen(server_sock, SOMAXCONN) == SOCKET_ERROR) { // SOMAXCONN is fine here
        fprintf(stderr, "Listen failed: %d\n", WSAGetLastError());
        closesocket(server_sock);
        WSACleanup();
        return 1;
    }

    printf("File server running on http://localhost:%d\n", PORT);
    printf("Serving content from: .\\%s\\\n", CONTENT_DIR_NAME);
    printf("Serving icons from: .\\%s\\\n", ICONS_DIR_NAME);

    // Get the executable's directory to create subdirectories reliably
    char server_executable_path[MAX_PATH_LEN];
    GetModuleFileNameA(NULL, server_executable_path, MAX_PATH_LEN);
    char drive[_MAX_DRIVE];
    char dir[_MAX_DIR];
    _splitpath(server_executable_path, drive, dir, NULL, NULL);

    char content_full_path[MAX_PATH_LEN];
    char icons_full_path[MAX_PATH_LEN];
    snprintf(content_full_path, MAX_PATH_LEN, "%s%s%s", drive, dir, CONTENT_DIR_NAME);
    snprintf(icons_full_path, MAX_PATH_LEN, "%s%s%s", drive, dir, ICONS_DIR_NAME);


    // Check and create content and icon directories if they don't exist
    if (CreateDirectoryA(content_full_path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
        // Directory created or already exists
        printf("Content directory exists or created: %s\n", content_full_path);
    } else {
        fprintf(stderr, "Failed to create content directory %s: %lu\n", content_full_path, GetLastError());
    }
    if (CreateDirectoryA(icons_full_path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
        // Directory created or already exists
        printf("Icons directory exists or created: %s\n", icons_full_path);
    } else {
        fprintf(stderr, "Failed to create icons directory %s: %lu\n", icons_full_path, GetLastError());
    }

    // --- Windows Admin Check (Original logic, simplified) ---
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                 &AdministratorsGroup)) {
        if (!CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin)) {
            isAdmin = FALSE; // Error checking membership
        }
        FreeSid(AdministratorsGroup);
    }
    if (!isAdmin) {
        printf("WARNING: Server is not running with administrative privileges. Directory creation or binding to privileged ports (like 80) might fail.\n");
    }
    // --- End Windows Admin Check ---

    // Main loop to accept and handle client connections
    while (1) {
        printf("Waiting for connections...\n");
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock == INVALID_SOCKET) {
            fprintf(stderr, "Accept failed: %d\n", WSAGetLastError());
            continue; // Continue to next iteration if accept fails
        }

        char client_ip[INET_ADDRSTRLEN];
        // Use inet_ntop for IPv4 address to string conversion
        if (InetNtopA(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN) == NULL) {
            strcpy(client_ip, "Unknown");
        }
        printf("Accepted connection from %s:%d\n", client_ip, ntohs(client_addr.sin_port));

        handle_client(client_sock); // Call handle_client without base_dir
    }

    // Close the server socket (unreachable in this infinite loop, but good practice)
    closesocket(server_sock);
    WSACleanup(); // Clean up Winsock (REQUIRED on Windows)
    return 0;
}