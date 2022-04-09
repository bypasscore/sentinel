#ifndef SENTINEL_DRIVER_COMM_H
#define SENTINEL_DRIVER_COMM_H
#include "sentinel/core/types.h"
#ifdef __cplusplus
extern "C" {
#endif
#define SENTINEL_IOCTL_BASE 0x800
#define SENTINEL_IOCTL_READ_MEMORY   (SENTINEL_IOCTL_BASE + 1)
#define SENTINEL_IOCTL_WRITE_MEMORY  (SENTINEL_IOCTL_BASE + 2)
#define SENTINEL_IOCTL_GET_MODULE    (SENTINEL_IOCTL_BASE + 3)
#define SENTINEL_IOCTL_PROTECT_MEMORY (SENTINEL_IOCTL_BASE + 4)
#define SENTINEL_IOCTL_HIDE_PROCESS  (SENTINEL_IOCTL_BASE + 5)

typedef struct sentinel_comm_header {
    u32 magic;
    u32 ioctl_code;
    u32 data_size;
    i32 status;
} sentinel_comm_header_t;

typedef struct sentinel_comm_read_req {
    sentinel_comm_header_t header;
    sentinel_pid_t pid;
    sentinel_addr_t address;
    usize size;
} sentinel_comm_read_req_t;

typedef struct sentinel_comm_write_req {
    sentinel_comm_header_t header;
    sentinel_pid_t pid;
    sentinel_addr_t address;
    usize size;
    u8 data[1];
} sentinel_comm_write_req_t;

typedef struct sentinel_comm_channel {
    sentinel_handle_t device_handle;
    char device_path[SENTINEL_MAX_PATH];
    bool is_connected;
    u32 protocol_version;
} sentinel_comm_channel_t;

int sentinel_comm_open(sentinel_comm_channel_t* channel, const char* device_name);
void sentinel_comm_close(sentinel_comm_channel_t* channel);
int sentinel_comm_send(sentinel_comm_channel_t* channel, u32 ioctl,
                       const void* in_buf, usize in_size,
                       void* out_buf, usize out_size, usize* bytes_returned);
int sentinel_comm_read_kernel_memory(sentinel_comm_channel_t* channel,
                                      sentinel_pid_t pid, sentinel_addr_t addr,
                                      void* buf, usize size);
int sentinel_comm_write_kernel_memory(sentinel_comm_channel_t* channel,
                                       sentinel_pid_t pid, sentinel_addr_t addr,
                                       const void* buf, usize size);
#ifdef __cplusplus
}
#endif
#endif
