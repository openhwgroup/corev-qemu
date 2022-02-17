
#include "qemu/osdep.h"
#include "cpu.h"
#include "qemu/log.h"
#include "exec/exec-all.h"
#include "exec/helper-proto.h"

void HELPER(check_hwlp_body)(CPURISCVState *env, target_ulong pc,
                             target_ulong type)
{
    if (((pc >= env->hwlp[0].lpstart) &&
         (pc < env->hwlp[0].lpend) && (env->hwlp[0].lpcount > 1)) ||
        ((pc >= env->hwlp[1].lpstart) &&
         (pc < env->hwlp[1].lpend) && (env->hwlp[1].lpcount > 1))) {
        switch (type) {
        case HWLP_TYPE_RVC:
            qemu_log_mask(LOG_GUEST_ERROR,
                          "HWLoop: No Compressed instructions (RVC) allowed "
                          "in the HWLoop body.");
            break;
        case HWLP_TYPE_JUMP_BR:
            qemu_log_mask(LOG_GUEST_ERROR,
                          "HWLoop: No jump or branch instructions allowed in "
                          "the HWLoop body.");
            break;
        case HWLP_TYPE_MEMORY_ORDER:
            qemu_log_mask(LOG_GUEST_ERROR,
                          "HWLoop: No memory ordering instructions (fence, "
                          "fence.i) allowed in the HWLoop body.");
            break;
        case HWLP_TYPE_PRIV:
            qemu_log_mask(LOG_GUEST_ERROR,
                          "No privileged instructions (mret, dret, ecall, wfi "
                          ") allowed in the HWLoop body.");
            break;
        case HWLP_TYPE_TARGET_PC:
            qemu_log_mask(LOG_GUEST_ERROR,
                          "HWLoop must always be entered from its start "
                          "location (no branch/jump to a location inside a "
                          "HWLoop body).");
            break;
        }
    }
}
