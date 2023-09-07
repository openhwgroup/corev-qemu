
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

target_ulong HELPER(muluN)(target_ulong a, target_ulong b, target_ulong c,
                           target_ulong i)
{
    target_ulong result = 0;
    uint16_t *s1 = (uint16_t *)&a, *s2 = (uint16_t *)&b;

    result = (target_ulong)(s1[i] * s2[i]) >> c;
    return result;
}

target_ulong HELPER(mulsN)(target_ulong a, target_ulong b, target_ulong c,
                           target_ulong i)
{
    target_ulong result = 0;
    int16_t *s1 = (int16_t *)&a, *s2 = (int16_t *)&b;

    result = (target_long)(s1[i] * s2[i]) >> c;
    return result;
}

target_ulong HELPER(muluRN)(target_ulong a, target_ulong b, target_ulong c,
                            target_ulong i)
{
    target_ulong result = 0;
    uint16_t *s1 = (uint16_t *)&a, *s2 = (uint16_t *)&b;

    result = (target_ulong)(s1[i] * s2[i] + (1 << (c - 1))) >> c;
    return result;
}

target_ulong HELPER(mulsRN)(target_ulong a, target_ulong b, target_ulong c,
                            target_ulong i)
{
    target_ulong result = 0;
    int16_t *s1 = (int16_t *)&a, *s2 = (int16_t *)&b;

    result = (target_long)(s1[i] * s2[i] + (1 << (c - 1))) >> c;
    return result;
}

target_ulong HELPER(macuN)(target_ulong a, target_ulong b, target_ulong c,
                           target_ulong d, target_ulong i)
{
    target_ulong result = 0;
    uint16_t *s1 = (uint16_t *)&a, *s2 = (uint16_t *)&b;

    result = (target_ulong)(s1[i] * s2[i] + c) >> d;
    return result;
}

target_ulong HELPER(macsN)(target_ulong a, target_ulong b, target_ulong c,
                           target_ulong d, target_ulong i)
{
    target_long result = 0;
    int16_t *s1 = (int16_t *)&a, *s2 = (int16_t *)&b;

    result = (target_long)(s1[i] * s2[i] + c) >> d;
    return result;
}

target_ulong HELPER(macuRN)(target_ulong a, target_ulong b, target_ulong c,
                            target_ulong d, target_ulong i)
{
    target_ulong result = 0;
    uint16_t *s1 = (uint16_t *)&a, *s2 = (uint16_t *)&b;

    result = (target_ulong)(s1[i] * s2[i] + c + (1 << (d - 1))) >> d;
    return result;
}

target_ulong HELPER(macsRN)(target_ulong a, target_ulong b, target_ulong c,
                            target_ulong d, target_ulong i)
{
    target_ulong result = 0;
    int16_t *s1 = (int16_t *)&a, *s2 = (int16_t *)&b;

    result = (target_long)(s1[i] * s2[i] + c + (1 << (d - 1))) >> d;
    return result;
}

target_ulong HELPER(extract)(target_ulong a, target_ulong b)
{
    uint32_t is2 = b & 0x1F;
    uint32_t is3 = (b >> 5) & 0x1F;
    uint32_t msb = is2 + is3;
    int32_t ret;

    msb = msb > 31 ? 31 : msb;
    ret = ((int32_t)a << (31 - msb)) >> (31 + is2 - msb);
    return  ret;
}

target_ulong HELPER(extractu)(target_ulong a, target_ulong b)
{
    uint32_t is2 = b & 0x1F;
    uint32_t is3 = (b >> 5) & 0x1F;
    uint32_t msb = is2 + is3;
    uint32_t ret;

    msb = msb > 31 ? 31 : msb;
    ret = ((uint32_t)a << (31 - msb)) >> (31 + is2 - msb);
    return  ret;
}

target_ulong HELPER(insert)(target_ulong a, target_ulong b, target_ulong c)
{
    uint32_t is2 = b & 0x1F;
    uint32_t is3 = (b >> 5) & 0x1F;
    uint32_t lsb = is2 + is3 > 31 ? is2 + is3 - 32 : 0;
    uint32_t mask = (~(0xfffffffe << is3)) << is2;
    uint32_t field = a << (is2 - lsb);

    return (c & ~mask) | (field & mask);
}

target_ulong HELPER(bclr)(target_ulong a, target_ulong b)
{
    uint32_t is2 = b & 0x1F;
    uint32_t is3 = (b >> 5) & 0x1F;
    uint32_t mask = (~(0xfffffffe << is3)) << is2;

    return a & ~mask;
}

target_ulong HELPER(bset)(target_ulong a, target_ulong b)
{
    uint32_t is2 = b & 0x1F;
    uint32_t is3 = (b >> 5) & 0x1F;
    uint32_t mask = (~(0xfffffffe << is3)) << is2;

    return a | mask;
}

static uint32_t revpowerbits(uint32_t x, uint32_t shamt)
{
    if (shamt &  1) {
        x = ((x & 0x55555555) <<  1) | ((x & 0xAAAAAAAA) >>  1);
    }

    if (shamt &  2) {
        x = ((x & 0x33333333) <<  2) | ((x & 0xCCCCCCCC) >>  2);
    }

    if (shamt &  4) {
        x = ((x & 0x0F0F0F0F) <<  4) | ((x & 0xF0F0F0F0) >>  4);
    }

    if (shamt &  8) {
        x = ((x & 0x00FF00FF) <<  8) | ((x & 0xFF00FF00) >>  8);
    }

    if (shamt & 16) {
        x = ((x & 0x0000FFFF) << 16) | ((x & 0xFFFF0000) >> 16);
    }
    return x;
}

static uint32_t rev3bits(uint32_t rs1)
{
    uint32_t x = rs1 >> 5;

    x = ((x & 0b111000000111000000111000000LL) >> 6) |
        ((x & 0b000111000000111000000111000LL)) |
        ((x & 0b000000111000000111000000111LL) << 6);
    x = ((x & 0b111111111000000000000000000LL) >> 18) |
        ((x & 0b000000000111111111000000000LL)) |
        ((x & 0b000000000000000000111111111LL) << 18);
    x |= (rs1 & 0x3) << 30;
    x |= (rs1 & 0x1C) << 25;
    return x;
}

target_ulong HELPER(bitrev)(target_ulong a, target_ulong b)
{
    uint32_t is2 = b & 0x1F;
    uint32_t is3 = (b >> 5) & 0x3;
    uint32_t res = a << is2;

    switch (is3) {
    case 0:
        res = revpowerbits(res, 0b11111);
        break;
    case 1:
        res = revpowerbits(res, 0b11110);
        break;
    default:
        res = rev3bits(res);
        break;
    }
    return res;
}

static target_ulong do_clz(target_ulong a)
{
    int i;

    for (i = 0; i < 32; i++) {
        if (a & (1 << (31 - i))) {
            break;
        }
    }
    return i;
}

target_ulong HELPER(fl1)(target_ulong a)
{
    target_ulong t = do_clz(a);

    return t == 32 ? 32 : 31 - t;
}

target_ulong HELPER(clb)(target_ulong a)
{
    target_ulong  t = a & (1 << 31) ? ~a : a;

    return a == 0 ? 0 : do_clz(t) - 1;
}

target_ulong HELPER(clip)(target_ulong a, target_ulong b)
{
    target_long min = b == 0 ? -1 : -(1 << (b - 1));
    target_long max = b == 0 ? 0 : (1 << (b - 1)) - 1;
    target_long c = *(target_long *)&a;

    if (c <= min) {
        return min;
    } else if (c >= max) {
        return max;
    } else {
        return a;
    }
}

target_ulong HELPER(clipr)(target_ulong a, target_ulong b)
{
    target_long min = -(b + 1);
    target_long max = b;
    target_long c = *(target_long *)&a;

    if (c <= min) {
        return min;
    } else if (c >= max) {
        return max;
    } else {
        return a;
    }
}

target_ulong HELPER(clipu)(target_ulong a, target_ulong b)
{
    target_long min = 0;
    target_long max = b == 0 ? 0 : (1 << (b - 1)) - 1;
    target_long c = *(target_long *)&a;

    if (c <= min) {
        return min;
    } else if (c >= max) {
        return max;
    } else {
        return a;
    }
}

target_ulong HELPER(clipur)(target_ulong a, target_ulong b)
{
    target_long min = 0;
    target_long max = b;
    target_long c = *(target_long *)&a;

    if (c <= min) {
        return min;
    } else if (c >= max) {
        return max;
    } else {
        return a;
    }
}
