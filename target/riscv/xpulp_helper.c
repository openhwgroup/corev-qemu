
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

typedef void SIMDArith(void *, void *, void *, uint8_t);

static inline target_ulong xpulp_simd(target_ulong a, target_ulong b,
                                      uint8_t size, SIMDArith *fn)
{
    int i, passes = sizeof(target_ulong) / size;
    target_ulong result = 0;

    for (i = 0; i < passes; i++) {
        fn(&result, &a, &b, i);
    }
    return result;
}

#define XPULP_SIMD(NAME, OPSIZE)                             \
target_ulong HELPER(NAME)(target_ulong a, target_ulong b)    \
{                                                            \
    return xpulp_simd(a, b, OPSIZE, (SIMDArith *)do_##NAME); \
}

static inline void do_min_h(void *vd, void *va, void *vb, uint8_t i)
{
    int16_t *d = vd, *a = va, *b = vb;

    d[i] = a[i] > b[i] ? b[i] : a[i];
}
XPULP_SIMD(min_h, 2);

static inline void do_min_b(void *vd, void *va,
                             void *vb, uint8_t i)
{
    int8_t *d = vd, *a = va, *b = vb;

    d[i] = a[i] > b[i] ? b[i] : a[i];
}
XPULP_SIMD(min_b, 1);

static inline void do_max_h(void *vd, void *va, void *vb, uint8_t i)
{
    int16_t *d = vd, *a = va, *b = vb;

    d[i] = a[i] > b[i] ? a[i] : b[i];
}
XPULP_SIMD(max_h, 2);

static inline void do_max_b(void *vd, void *va, void *vb, uint8_t i)
{
    int8_t *d = vd, *a = va, *b = vb;

    d[i] = a[i] > b[i] ? a[i] : b[i];
}
XPULP_SIMD(max_b, 1);

static inline void do_minu_h(void *vd, void *va, void *vb, uint8_t i)
{
    uint16_t *d = vd, *a = va, *b = vb;

    d[i] = a[i] > b[i] ? b[i] : a[i];
}
XPULP_SIMD(minu_h, 2);

static inline void do_minu_b(void *vd, void *va, void *vb, uint8_t i)
{
    uint8_t *d = vd, *a = va, *b = vb;

    d[i] = a[i] > b[i] ? b[i] : a[i];
}
XPULP_SIMD(minu_b, 1);

static inline void do_maxu_h(void *vd, void *va, void *vb, uint8_t i)
{
    uint16_t *d = vd, *a = va, *b = vb;

    d[i] = a[i] > b[i] ? a[i] : b[i];
}
XPULP_SIMD(maxu_h, 2);

static inline void do_maxu_b(void *vd, void *va, void *vb, uint8_t i)
{
    uint8_t *d = vd, *a = va, *b = vb;

    d[i] = a[i] > b[i] ? a[i] : b[i];
}
XPULP_SIMD(maxu_b, 1);

static inline void do_shr_h(void *vd, void *va, void *vb, uint8_t i)
{
    uint16_t *d = vd, *a = va, *b = vb;

    d[i] = a[i] >> b[i];
}
XPULP_SIMD(shr_h, 2);

static inline void do_shr_b(void *vd, void *va, void *vb, uint8_t i)
{
    uint8_t *d = vd, *a = va, *b = vb;

    d[i] = a[i] >> b[i];
}
XPULP_SIMD(shr_b, 1);

static inline void do_sra_h(void *vd, void *va, void *vb, uint8_t i)
{
    int16_t *d = vd, *a = va, *b = vb;

    d[i] = a[i] >> b[i];
}
XPULP_SIMD(sra_h, 2);

static inline void do_sra_b(void *vd, void *va, void *vb, uint8_t i)
{
    int8_t *d = vd, *a = va, *b = vb;

    d[i] = a[i] >> b[i];
}
XPULP_SIMD(sra_b, 1);

static inline void do_shl_h(void *vd, void *va, void *vb, uint8_t i)
{
    uint16_t *d = vd, *a = va, *b = vb;

    d[i] = a[i] << b[i];
}
XPULP_SIMD(shl_h, 2);

static inline void do_shl_b(void *vd, void *va, void *vb, uint8_t i)
{
    uint8_t *d = vd, *a = va, *b = vb;

    d[i] = a[i] << b[i];
}
XPULP_SIMD(shl_b, 1);

static inline void do_dotup_h(void *vd, void *va, void *vb, uint8_t i)
{
    uint16_t *a = va, *b = vb;
    target_ulong *d = vd;

    *d += (target_ulong)a[i] * b[i];
}
XPULP_SIMD(dotup_h, 2);

static inline void do_dotup_b(void *vd, void *va, void *vb, uint8_t i)
{
    uint8_t *a = va, *b = vb;
    target_ulong *d = vd;

    *d += (target_ulong)a[i] * b[i];
}
XPULP_SIMD(dotup_b, 1);

static inline void do_dotusp_h(void *vd, void *va, void *vb, uint8_t i)
{
    uint16_t *a = va;
    int16_t *b = vb;
    target_ulong *d = vd;

    *d += (target_ulong)a[i] * b[i];
}
XPULP_SIMD(dotusp_h, 2);

static inline void do_dotusp_b(void *vd, void *va, void *vb, uint8_t i)
{
    uint8_t *a = va;
    int8_t *b = vb;
    target_ulong *d = vd;

    *d += (target_ulong)a[i] * b[i];
}
XPULP_SIMD(dotusp_b, 1);

static inline void do_dotsp_h(void *vd, void *va, void *vb, uint8_t i)
{
    int16_t *a = va, *b = vb;
    target_ulong *d = vd;

    *d += (target_ulong)a[i] * b[i];
}
XPULP_SIMD(dotsp_h, 2);

static inline void do_dotsp_b(void *vd, void *va, void *vb, uint8_t i)
{
    int8_t *a = va, *b = vb;
    target_ulong *d = vd;

    *d += (target_ulong)a[i] * b[i];
}
XPULP_SIMD(dotsp_b, 1);
