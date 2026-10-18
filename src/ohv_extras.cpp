// ohv_extras.cpp - extended-API helpers with no Apple counterpart.
#include <string>
#include <cstring>
#include "openhyp/openhyp.hpp"
#include "openhyp/ohv_vmm.h"

extern "C" const char *ohv_error_string(hv_return_t r) {
    switch (r) {
        case HV_SUCCESS: return "success";
        case HV_ERROR: return "error";
        case HV_BUSY: return "busy";
        case HV_BAD_ARGUMENT: return "bad argument";
        case HV_ILLEGAL_GUEST_STATE: return "illegal guest state";
        case HV_NO_RESOURCES: return "no resources";
        case HV_NO_DEVICE: return "no device (create a VM first)";
        case HV_DENIED: return "denied by kernel policy";
        case HV_FAULT: return "fault";
        case HV_UNSUPPORTED: return "unsupported";
        default: return "unknown error";
    }
}

// Library build/protocol identity, queryable at runtime; see ohv_vmm.h for
// what each version adds.
extern "C" uint32_t ohv_api_version(void) { return OHV_API_VERSION; }

// The row hv_vcpu_create() chose for this kernel (ohv_vcpu.cpp); see ohv_vmm.h.
extern const ohv_hv_layout_t *ohv_layout __attribute__((visibility("hidden")));
extern "C" const ohv_hv_layout_t *ohv_hv_layout(void) { return ohv_layout; }
