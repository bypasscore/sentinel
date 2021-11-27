#include "sentinel/driver/loader.h"
#include "sentinel/core/error.h"
#include "sentinel/utils/logger.h"
#include <cstring>
#include <cstdio>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

int sentinel_driver_register_service(const char* driver_path, const char* service_name) {
    if (!driver_path || !service_name) return SENTINEL_ERROR_INVALID_PARAMETER;

    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return SENTINEL_ERROR_ACCESS_DENIED;

    char full_path[SENTINEL_MAX_PATH];
    GetFullPathNameA(driver_path, SENTINEL_MAX_PATH, full_path, nullptr);

    SC_HANDLE svc = CreateServiceA(scm, service_name, service_name,
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE, full_path, nullptr, nullptr, nullptr, nullptr, nullptr);

    if (!svc) {
        DWORD err = GetLastError();
        CloseServiceHandle(scm);
        if (err == ERROR_SERVICE_EXISTS) return SENTINEL_OK;
        return SENTINEL_ERROR_DRIVER_LOAD_FAILED;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return SENTINEL_OK;
}

int sentinel_driver_load(const char* driver_path, const char* service_name) {
    if (!driver_path || !service_name) return SENTINEL_ERROR_INVALID_PARAMETER;

    int rc = sentinel_driver_register_service(driver_path, service_name);
    if (rc != SENTINEL_OK) return rc;

    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return SENTINEL_ERROR_ACCESS_DENIED;

    SC_HANDLE svc = OpenServiceA(scm, service_name, SERVICE_START);
    if (!svc) { CloseServiceHandle(scm); return SENTINEL_ERROR_NOT_FOUND; }

    if (!StartServiceA(svc, 0, nullptr)) {
        DWORD err = GetLastError();
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        if (err == ERROR_SERVICE_ALREADY_RUNNING) return SENTINEL_OK;
        SLOG_ERROR("Failed to start driver service: %lu", err);
        return SENTINEL_ERROR_DRIVER_LOAD_FAILED;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    SLOG_INFO("Driver loaded: %s (%s)", service_name, driver_path);
    return SENTINEL_OK;
}

int sentinel_driver_unload(const char* service_name) {
    if (!service_name) return SENTINEL_ERROR_INVALID_PARAMETER;

    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return SENTINEL_ERROR_ACCESS_DENIED;

    SC_HANDLE svc = OpenServiceA(scm, service_name, SERVICE_STOP | DELETE);
    if (!svc) { CloseServiceHandle(scm); return SENTINEL_ERROR_NOT_FOUND; }

    SERVICE_STATUS status;
    ControlService(svc, SERVICE_CONTROL_STOP, &status);
    DeleteService(svc);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return SENTINEL_OK;
}

int sentinel_driver_delete_service(const char* service_name) {
    return sentinel_driver_unload(service_name);
}

bool sentinel_driver_is_loaded(const char* service_name) {
    if (!service_name) return false;
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceA(scm, service_name, SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); return false; }
    SERVICE_STATUS status;
    QueryServiceStatus(svc, &status);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return (status.dwCurrentState == SERVICE_RUNNING);
}

#else
int sentinel_driver_load(const char* p, const char* s) { (void)p;(void)s; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_driver_unload(const char* s) { (void)s; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_driver_register_service(const char* p, const char* s) { (void)p;(void)s; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_driver_delete_service(const char* s) { (void)s; return SENTINEL_ERROR_UNSUPPORTED; }
bool sentinel_driver_is_loaded(const char* s) { (void)s; return false; }
#endif
