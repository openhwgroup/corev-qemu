
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

static inline void do_shuffle_h(void *vd, void *va, void *vb, uint8_t i)
{
    int16_t *d = vd, *a = va, *b = vb;

    d[i] = a[b[i] & 0x1];
}
XPULP_SIMD(shuffle_h, 2);

static inline void do_shuffle_sc_h(void *vd, void *va, void *vb, uint8_t i)
{
    int16_t *d = vd, *a = va, *b = vb;

    d[i] = a[(b[0] >> i) & 0x1];
}
XPULP_SIMD(shuffle_sc_h, 2);

static inline void do_shuffle_b(void *vd, void *va, void *vb, uint8_t i)
{
    int8_t *d = vd, *a = va, *b = vb;

    d[i] = a[b[i] & 0x3];
}
XPULP_SIMD(shuffle_b, 1);

typedef void SIMDArith3(void *, void *, void *, void *, uint8_t);
static inline target_ulong xpulp_simd3(target_ulong a, target_ulong b,
                                       target_ulong c, uint8_t size,
                                       SIMDArith3 *fn)
{
    int i, passes = sizeof(target_ulong) / size;
    target_ulong result = 0;

    for (i = 0; i < passes; i++) {
        fn(&result, &a, &b, &c, i);
    }
    return result;
}

#define XPULP_SIMD3(NAME, OPSIZE)                                          \
target_ulong HELPER(NAME)(target_ulong a, target_ulong b, target_ulong c)  \
{                                                                          \
    return xpulp_simd3(a, b, c, OPSIZE, (SIMDArith3 *)do_##NAME);          \
}

static inline void do_shuffle_sc_b(void *vd, void *va, void *vb, void *vc,
                                   uint8_t i)
{
    int8_t *d = vd, *a = va, *b = vb, *c = vc;

    if (i == 3) {
        d[i] = a[c[0]];
    } else {
        d[i] = a[(b[0] >> (2 * i)) & 0x3];
    }
}
XPULP_SIMD3(shuffle_sc_b, 1);

static inline void do_shuffle2_h(void *vd, void *va, void *vb, void *vc,
                                 uint8_t i)
{
    int16_t *d = vd, *a = va, *b = vb, *c = vc;

    if (b[i] & 0x2) {
        d[i] = a[b[i] & 0x1];
    } else {
        d[i] = c[b[i] & 0x1];
    }
}
XPULP_SIMD3(shuffle2_h, 2);

static inline void do_shuffle2_b(void *vd, void *va, void *vb, void *vc,
                                 uint8_t i)
{
    int8_t *d = vd, *a = va, *b = vb, *c = vc;

    if (b[i] & 0x4) {
        d[i] = a[b[i] & 0x3];
    } else {
        d[i] = c[b[i] & 0x3];
    }
}
XPULP_SIMD3(shuffle2_b, 1);

#define HELPER_CMP(NAME, OP, TYPE, LEN)                                \
static inline void do_##NAME(void *vd, void *va, void *vb, uint8_t i)  \
{                                                                      \
    TYPE *d = vd, *a = va, *b = vb;                                    \
                                                                       \
    d[i] = a[i] OP b[i] ? ~0 : 0;                                      \
}                                                                      \
XPULP_SIMD(NAME, LEN)

HELPER_CMP(cmpeq_h, ==, int16_t, 2);
HELPER_CMP(cmpeq_b, ==, int8_t, 1);
HELPER_CMP(cmpne_h, !=, int16_t, 2);
HELPER_CMP(cmpne_b, !=, int8_t, 1);
HELPER_CMP(cmpgt_h, >, int16_t, 2);
HELPER_CMP(cmpgt_b, >, int8_t, 1);
HELPER_CMP(cmpge_h, >=, int16_t, 2);
HELPER_CMP(cmpge_b, >=, int8_t, 1);
HELPER_CMP(cmplt_h, <, int16_t, 2);
HELPER_CMP(cmplt_b, <, int8_t, 1);
HELPER_CMP(cmple_h, <=, int16_t, 2);
HELPER_CMP(cmple_b, <=, int8_t, 1);
HELPER_CMP(cmpgtu_h, >, uint16_t, 2);
HELPER_CMP(cmpgtu_b, >, uint8_t, 1);
HELPER_CMP(cmpgeu_h, >=, uint16_t, 2);
HELPER_CMP(cmpgeu_b, >=, uint8_t, 1);
HELPER_CMP(cmpltu_h, <, uint16_t, 2);
HELPER_CMP(cmpltu_b, <, uint8_t, 1);
HELPER_CMP(cmpleu_h, <=, uint16_t, 2);
HELPER_CMP(cmpleu_b, <=, uint8_t, 1);

target_ulong HELPER(subrotmj)(target_ulong a, target_ulong b,
                              target_ulong div)
{
    target_ulong result = 0;
    int16_t *d = (int16_t *)&result;
    int16_t *s1 = (int16_t *)&a, *s2 = (int16_t *)&b;

    d[0] = (int16_t)(s1[1] - s2[1]) >> div;
    d[1] = (int16_t)(s2[0] - s1[0]) >> div;
    return result;
}

target_ulong HELPER(cplxmul_r)(target_ulong a, target_ulong b,
                               target_ulong c, target_ulong div)
{
    target_ulong result = 0;
    int16_t *d = (int16_t *)&result;
    int16_t *s1 = (int16_t *)&a, *s2 = (int16_t *)&b, *s3 = (int16_t *)&c;

    d[0] = (s1[0] * s2[0] - s1[1] * s2[1]) >> (div + 15);
    d[1] = s3[1];
    return result;
}

target_ulong HELPER(cplxmul_i)(target_ulong a, target_ulong b,
                               target_ulong c, target_ulong div)
{
    target_ulong result = 0;
    int16_t *d = (int16_t *)&result;
    int16_t *s1 = (int16_t *)&a, *s2 = (int16_t *)&b, *s3 = (int16_t *)&c;

    d[1] = (s1[0] * s2[1] + s1[1] * s2[0]) >> (div + 15);
    d[0] = s3[0];
    return result;
}
