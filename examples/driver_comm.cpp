/*
 * driver_comm.cpp -- Driver communication example
 *
 * Shows how to open a communication channel with a kernel driver
 * and perform basic read/write operations.
 */

#include "sentinel/sentinel.h"
#include "sentinel/driver/comm.h"
#include "sentinel/driver/loader.h"
#include "sentinel/core/platform.h"
#include "sentinel/utils/logger.h"
#include <cstdio>

int main(int argc, char* argv[]) {
    sentinel_init();
    sentinel_log_init(SENTINEL_LOG_DEBUG);

    printf("Sentinel Driver Communication Example\n");
    printf("======================================\n\n");

    /* Check if running elevated */
    if (!sentinel_is_elevated()) {
        printf("[!] WARNING: Not running as administrator.\n");
        printf("    Driver operations require elevated privileges.\n\n");
    }

    /* Check for VBS - it affects driver loading */
    if (sentinel_is_vbs_enabled()) {
        printf("[!] VBS/HVCI is enabled. Unsigned drivers cannot be loaded.\n\n");
    }

    /* Example: Open communication channel */
    const char* device_name = argc > 1 ? argv[1] : "SentinelDrv";
    printf("[*] Attempting to connect to driver: %s\n", device_name);

    sentinel_comm_channel_t channel = {};
    int rc = sentinel_comm_open(&channel, device_name);

    if (rc == SENTINEL_OK) {
        printf("[+] Connected to driver successfully!\n");
        printf("    Protocol version: %u\n\n", channel.protocol_version);

        /* Example: Read some kernel memory */
        printf("[*] Example: Reading kernel memory...\n");
        u8 buffer[256] = {};
        rc = sentinel_comm_read_kernel_memory(&channel, 0, 0xFFFFF78000000000ULL,
                                               buffer, sizeof(buffer));
        if (rc == SENTINEL_OK) {
            printf("    Read %zu bytes from KUSER_SHARED_DATA\n", sizeof(buffer));
            printf("    First 16 bytes: ");
            for (int i = 0; i < 16; i++) printf("%02X ", buffer[i]);
            printf("\n");
        } else {
            printf("    Read failed: %s\n", sentinel_error_string(rc));
        }

        sentinel_comm_close(&channel);
        printf("\n[*] Channel closed.\n");
    } else {
        printf("[-] Failed to connect: %s\n", sentinel_error_string(rc));
        printf("    Make sure the driver is loaded first.\n");
    }

    printf("\nDone.\n");
    sentinel_shutdown();
    return 0;
}
