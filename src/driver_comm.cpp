#include "sentinel/driver/comm.h"
#include "sentinel/core/error.h"
#include "sentinel/utils/logger.h"
#include <cstring>

#define SENTINEL_COMM_MAGIC 0x534E544C /* SNTL */

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

int sentinel_comm_open(sentinel_comm_channel_t* channel, const char* device_name) {
    if (!channel || !device_name) return SENTINEL_ERROR_INVALID_PARAMETER;
    memset(channel, 0, sizeof(*channel));

    char path[SENTINEL_MAX_PATH];
    snprintf(path, sizeof(path), "\\.\%s", device_name);

    HANDLE dev = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                             0, nullptr, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
    if (dev == INVALID_HANDLE_VALUE) {
        SLOG_ERROR("Failed to open device: %s (error %lu)", path, GetLastError());
        return SENTINEL_ERROR_DRIVER_COMM_FAILED;
    }

    channel->device_handle = dev;
    strncpy(channel->device_path, path, SENTINEL_MAX_PATH - 1);
    channel->is_connected = true;
    channel->protocol_version = 1;
    SLOG_INFO("Connected to driver device: %s", path);
    return SENTINEL_OK;
}

void sentinel_comm_close(sentinel_comm_channel_t* channel) {
    if (channel && channel->is_connected) {
        CloseHandle((HANDLE)channel->device_handle);
        channel->is_connected = false;
        channel->device_handle = SENTINEL_INVALID_HANDLE;
    }
}

int sentinel_comm_send(sentinel_comm_channel_t* channel, u32 ioctl,
                       const void* in_buf, usize in_size,
                       void* out_buf, usize out_size, usize* bytes_returned) {
    if (!channel || !channel->is_connected)
        return SENTINEL_ERROR_NOT_INITIALIZED;

    DWORD returned = 0;
    DWORD ioctl_code = CTL_CODE(FILE_DEVICE_UNKNOWN, ioctl, METHOD_BUFFERED, FILE_ANY_ACCESS);

    if (!DeviceIoControl((HANDLE)channel->device_handle, ioctl_code,
                         (LPVOID)in_buf, (DWORD)in_size,
                         out_buf, (DWORD)out_size, &returned, nullptr)) {
        return SENTINEL_ERROR_DRIVER_COMM_FAILED;
    }

    if (bytes_returned) *bytes_returned = (usize)returned;
    return SENTINEL_OK;
}

int sentinel_comm_read_kernel_memory(sentinel_comm_channel_t* channel,
                                      sentinel_pid_t pid, sentinel_addr_t addr,
                                      void* buf, usize size) {
    sentinel_comm_read_req_t req = {};
    req.header.magic = SENTINEL_COMM_MAGIC;
    req.header.ioctl_code = SENTINEL_IOCTL_READ_MEMORY;
    req.header.data_size = (u32)size;
    req.pid = pid;
    req.address = addr;
    req.size = size;

    usize returned = 0;
    return sentinel_comm_send(channel, SENTINEL_IOCTL_READ_MEMORY,
                              &req, sizeof(req), buf, size, &returned);
}

int sentinel_comm_write_kernel_memory(sentinel_comm_channel_t* channel,
                                       sentinel_pid_t pid, sentinel_addr_t addr,
                                       const void* buf, usize size) {
    usize req_size = sizeof(sentinel_comm_write_req_t) + size;
    sentinel_comm_write_req_t* req = (sentinel_comm_write_req_t*)malloc(req_size);
    if (!req) return SENTINEL_ERROR_OUT_OF_MEMORY;

    req->header.magic = SENTINEL_COMM_MAGIC;
    req->header.ioctl_code = SENTINEL_IOCTL_WRITE_MEMORY;
    req->header.data_size = (u32)size;
    req->pid = pid;
    req->address = addr;
    req->size = size;
    memcpy(req->data, buf, size);

    usize returned = 0;
    int rc = sentinel_comm_send(channel, SENTINEL_IOCTL_WRITE_MEMORY,
                                req, req_size, nullptr, 0, &returned);
    free(req);
    return rc;
}

#else
int sentinel_comm_open(sentinel_comm_channel_t* c, const char* d) { (void)c;(void)d; return SENTINEL_ERROR_UNSUPPORTED; }
void sentinel_comm_close(sentinel_comm_channel_t* c) { (void)c; }
int sentinel_comm_send(sentinel_comm_channel_t* c, u32 i, const void* a, usize b, void* d, usize e, usize* f) { (void)c;(void)i;(void)a;(void)b;(void)d;(void)e;(void)f; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_comm_read_kernel_memory(sentinel_comm_channel_t* c, sentinel_pid_t p, sentinel_addr_t a, void* b, usize s) { (void)c;(void)p;(void)a;(void)b;(void)s; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_comm_write_kernel_memory(sentinel_comm_channel_t* c, sentinel_pid_t p, sentinel_addr_t a, const void* b, usize s) { (void)c;(void)p;(void)a;(void)b;(void)s; return SENTINEL_ERROR_UNSUPPORTED; }
#endif
