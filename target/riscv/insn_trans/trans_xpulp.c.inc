/*
 * RISC-V translation routines for the XPulp extension.
 *
 * Copyright (c) 2021-2022 PLCT Lab.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "tcg/tcg-op-gvec.h"
#include "tcg/tcg-gvec-desc.h"

#define REQUIRE_XCVMEM(ctx) do {          \
    if (!ctx->cfg_ptr->ext_xcvmem) {      \
        return false;                     \
    }                                     \
} while (0)

#define REQUIRE_XCVHWLP(ctx) do {         \
    if (!ctx->cfg_ptr->ext_xcvhwlp) {     \
        return false;                     \
    }                                     \
} while (0)

#define REQUIRE_XCVSIMD(ctx) do {         \
    if (!ctx->cfg_ptr->ext_xcvsimd) {     \
        return false;                     \
    }                                     \
} while (0)

#define REQUIRE_XCVMAC(ctx) do {          \
    if (!ctx->cfg_ptr->ext_xcvmac) {      \
        return false;                     \
    }                                     \
} while (0)

#define REQUIRE_XCVBITMANIP(ctx) do {     \
    if (!ctx->cfg_ptr->ext_xcvbitmanip) { \
        return false;                     \
    }                                     \
} while (0)

#define REQUIRE_XCVALU(ctx) do {          \
    if (!ctx->cfg_ptr->ext_xcvalu) {      \
        return false;                     \
    }                                     \
} while (0)

#define REQUIRE_XCVBI(ctx) do {           \
    if (!ctx->cfg_ptr->ext_xcvbi) {       \
        return false;                     \
    }                                     \
} while (0)

static bool gen_load_rr_tl(DisasContext *ctx, arg_r *a, MemOp memop,
                           bool postInc)
{
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv addr;

    if (postInc) {
        addr = get_address(ctx, a->rs1, 0);
    } else {
        addr = get_address_rr(ctx, a->rs1, a->rs2);
    }

    tcg_gen_qemu_ld_tl(dest, addr, ctx->mem_idx, memop);

    gen_set_gpr(ctx, a->rd, dest);
    if (postInc) {
        TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
        TCGv src2 = get_gpr(ctx, a->rs2, EXT_NONE);
        tcg_gen_add_tl(src1, src1, src2);
        gen_set_gpr(ctx, a->rs1, src1);
    }
    return true;
}

static bool trans_cv_lb_ripi(DisasContext *ctx, arg_cv_lb_ripi *a)
{
    REQUIRE_XCVMEM(ctx);
    return gen_load_tl(ctx, a, MO_SB, true);
}

static bool trans_cv_lbu_ripi(DisasContext *ctx, arg_cv_lbu_ripi *a)
{
    REQUIRE_XCVMEM(ctx);
    return gen_load_tl(ctx, a, MO_UB, true);
}

static bool trans_cv_lh_ripi(DisasContext *ctx, arg_cv_lh_ripi *a)
{
    REQUIRE_XCVMEM(ctx);
    return gen_load_tl(ctx, a, MO_TESW, true);
}

static bool trans_cv_lhu_ripi(DisasContext *ctx, arg_cv_lhu_ripi *a)
{
    REQUIRE_XCVMEM(ctx);
    return gen_load_tl(ctx, a, MO_TEUW, true);
}

static bool trans_cv_lw_ripi(DisasContext *ctx, arg_cv_lw_ripi *a)
{
    REQUIRE_XCVMEM(ctx);
    return gen_load_tl(ctx, a, MO_TESL, true);
}

static bool trans_cv_lb_rrpi(DisasContext *ctx, arg_cv_lb_rrpi *a)
{
    REQUIRE_XCVMEM(ctx);
    return gen_load_rr_tl(ctx, a, MO_SB, true);
}

static bool trans_cv_lbu_rrpi(DisasContext *ctx, arg_cv_lbu_rrpi *a)
{
    REQUIRE_XCVMEM(ctx);
    return gen_load_rr_tl(ctx, a, MO_UB, true);
}

static bool trans_cv_lh_rrpi(DisasContext *ctx, arg_cv_lh_rrpi *a)
{
    REQUIRE_XCVMEM(ctx);
    return gen_load_rr_tl(ctx, a, MO_TESW, true);
}

static bool trans_cv_lhu_rrpi(DisasContext *ctx, arg_cv_lhu_rrpi *a)
{
    REQUIRE_XCVMEM(ctx);
    return gen_load_rr_tl(ctx, a, MO_TEUW, true);
}

static bool trans_cv_lw_rrpi(DisasContext *ctx, arg_cv_lw_rrpi *a)
{
    REQUIRE_XCVMEM(ctx);
    return gen_load_rr_tl(ctx, a, MO_TESL, true);
}

static bool trans_cv_lb_rr(DisasContext *ctx, arg_cv_lb_rr *a)
{
    REQUIRE_XCVMEM(ctx);
    return gen_load_rr_tl(ctx, a, MO_SB, false);
}

static bool trans_cv_lbu_rr(DisasContext *ctx, arg_cv_lbu_rr *a)
{
    REQUIRE_XCVMEM(ctx);
    return gen_load_rr_tl(ctx, a, MO_UB, false);
}

static bool trans_cv_lh_rr(DisasContext *ctx, arg_cv_lh_rr *a)
{
    REQUIRE_XCVMEM(ctx);
    return gen_load_rr_tl(ctx, a, MO_TESW, false);
}

static bool trans_cv_lhu_rr(DisasContext *ctx, arg_cv_lhu_rr *a)
{
    REQUIRE_XCVMEM(ctx);
    return gen_load_rr_tl(ctx, a, MO_TEUW, false);
}

static bool trans_cv_lw_rr(DisasContext *ctx, arg_cv_lw_rr *a)
{
    REQUIRE_XCVMEM(ctx);
    return gen_load_rr_tl(ctx, a, MO_TESL, false);
}

static bool gen_store_rr_tl(DisasContext *ctx, arg_r *a, MemOp memop,
                            bool postInc)
{
    TCGv data = get_gpr(ctx, a->rs2, EXT_NONE);
    TCGv addr;

    if (postInc) {
        addr = get_address(ctx, a->rs1, 0);
    } else {
        addr = get_address_rr(ctx, a->rs1, a->rd);
    }

    tcg_gen_qemu_st_tl(data, addr, ctx->mem_idx, memop);

    if (postInc) {
        TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
        TCGv src3 = get_gpr(ctx, a->rd, EXT_NONE);
        tcg_gen_add_tl(src1, src1, src3);
        gen_set_gpr(ctx, a->rs1, src1);
    }
    return true;
}

static bool trans_cv_sb_ripi(DisasContext *ctx, arg_cv_sb_ripi *a)
{
    REQUIRE_XCVMEM(ctx);
    return gen_store_tl(ctx, a, MO_SB, true);
}

static bool trans_cv_sh_ripi(DisasContext *ctx, arg_cv_sh_ripi *a)
{
    REQUIRE_XCVMEM(ctx);
    return gen_store_tl(ctx, a, MO_TESW, true);
}

static bool trans_cv_sw_ripi(DisasContext *ctx, arg_cv_sw_ripi *a)
{
    REQUIRE_XCVMEM(ctx);
    return gen_store_tl(ctx, a, MO_TESL, true);
}

static bool trans_cv_sb_rrpi(DisasContext *ctx, arg_cv_sb_rrpi *a)
{
    REQUIRE_XCVMEM(ctx);
    return gen_store_rr_tl(ctx, a, MO_SB, true);
}

static bool trans_cv_sh_rrpi(DisasContext *ctx, arg_cv_sh_rrpi *a)
{
    REQUIRE_XCVMEM(ctx);
    return gen_store_rr_tl(ctx, a, MO_TESW, true);
}

static bool trans_cv_sw_rrpi(DisasContext *ctx, arg_cv_sw_rrpi *a)
{
    REQUIRE_XCVMEM(ctx);
    return gen_store_rr_tl(ctx, a, MO_TESL, true);
}

static bool trans_cv_sb_rr(DisasContext *ctx, arg_cv_sb_rr *a)
{
    REQUIRE_XCVMEM(ctx);
    return gen_store_rr_tl(ctx, a, MO_SB, false);
}

static bool trans_cv_sh_rr(DisasContext *ctx, arg_cv_sh_rr *a)
{
    REQUIRE_XCVMEM(ctx);
    return gen_store_rr_tl(ctx, a, MO_TESW, false);
}

static bool trans_cv_sw_rr(DisasContext *ctx, arg_cv_sw_rr *a)
{
    REQUIRE_XCVMEM(ctx);
    return gen_store_rr_tl(ctx, a, MO_TESL, false);
}

static bool trans_cv_starti(DisasContext *ctx, arg_cv_starti *a)
{
    REQUIRE_XCVHWLP(ctx);
    target_ulong lpstart = ctx->base.pc_next + (a->imm << 2);
    TCGv src = tcg_constant_tl(lpstart);

    return do_csrw(ctx, a->l == 0 ? CSR_LPSTART0 : CSR_LPSTART1, src);
}

static bool trans_cv_start(DisasContext *ctx, arg_cv_start *a)
{
    REQUIRE_XCVHWLP(ctx);
    TCGv src = get_gpr(ctx, a->rs1, EXT_NONE);

    return do_csrw(ctx, a->l == 0 ? CSR_LPSTART0 : CSR_LPSTART1, src);
}

static bool trans_cv_endi(DisasContext *ctx, arg_cv_endi *a)
{
    REQUIRE_XCVHWLP(ctx);
    target_ulong lpend = ctx->base.pc_next + (a->imm << 2);
    TCGv src = tcg_constant_tl(lpend);

    return do_csrw(ctx, a->l == 0 ? CSR_LPEND0 : CSR_LPEND1, src);
}

static bool trans_cv_end(DisasContext *ctx, arg_cv_end *a)
{
    REQUIRE_XCVHWLP(ctx);
    TCGv src = get_gpr(ctx, a->rs1, EXT_NONE);

    return do_csrw(ctx, a->l == 0 ? CSR_LPEND0 : CSR_LPEND1, src);
}

static bool trans_cv_counti(DisasContext *ctx, arg_cv_counti *a)
{
    REQUIRE_XCVHWLP(ctx);
    TCGv src = tcg_constant_tl(a->imm);

    return do_csrw(ctx, a->l == 0 ? CSR_LPCOUNT0 : CSR_LPCOUNT1, src);
}

static bool trans_cv_count(DisasContext *ctx, arg_cv_count *a)
{
    REQUIRE_XCVHWLP(ctx);
    TCGv src = get_gpr(ctx, a->rs1, EXT_NONE);

    return do_csrw(ctx, a->l == 0 ? CSR_LPCOUNT0 : CSR_LPCOUNT1, src);
}

static bool trans_cv_setup(DisasContext *ctx, arg_cv_setup *a)
{
    REQUIRE_XCVHWLP(ctx);
    TCGv start = tcg_constant_tl(ctx->pc_succ_insn);
    TCGv end = tcg_constant_tl(ctx->base.pc_next + (a->imm << 2));
    TCGv count = get_gpr(ctx, a->rs1, EXT_NONE);
    int start_csr = a->l == 0 ? CSR_LPSTART0 : CSR_LPSTART1;
    int end_csr = a->l == 0 ? CSR_LPEND0 : CSR_LPEND1;
    int count_csr = a->l == 0 ? CSR_LPCOUNT0 : CSR_LPCOUNT1;

    if (tb_cflags(ctx->base.tb) & CF_USE_ICOUNT) {
        gen_io_start();
    }

    gen_helper_csrw(cpu_env, tcg_constant_i32(count_csr), count);
    gen_helper_csrw(cpu_env, tcg_constant_i32(end_csr), end);
    gen_helper_csrw(cpu_env, tcg_constant_i32(start_csr), start);

    return do_csr_post(ctx);
}

static bool trans_cv_setupi(DisasContext *ctx, arg_cv_setupi *a)
{
    REQUIRE_XCVHWLP(ctx);
    TCGv start = tcg_constant_tl(ctx->pc_succ_insn);
    TCGv end = tcg_constant_tl(ctx->base.pc_next + (a->imms << 2));
    TCGv count = tcg_constant_tl(a->imm);
    int start_csr = a->l == 0 ? CSR_LPSTART0 : CSR_LPSTART1;
    int end_csr = a->l == 0 ? CSR_LPEND0 : CSR_LPEND1;
    int count_csr = a->l == 0 ? CSR_LPCOUNT0 : CSR_LPCOUNT1;

    if (tb_cflags(ctx->base.tb) & CF_USE_ICOUNT) {
        gen_io_start();
    }

    gen_helper_csrw(cpu_env, tcg_constant_i32(count_csr), count);
    gen_helper_csrw(cpu_env, tcg_constant_i32(end_csr), end);
    gen_helper_csrw(cpu_env, tcg_constant_i32(start_csr), start);

    return do_csr_post(ctx);
}

static bool trans_cv_add_h(DisasContext *ctx, arg_cv_add_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, tcg_gen_vec_add16_tl, NULL);
}

static bool gen_simd_scalar(DisasContext *ctx, arg_r *a, DisasExtend ext,
                            unsigned vece, void (*func)(TCGv, TCGv, TCGv))
{
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, ext);
    TCGv src2 = get_gpr(ctx, a->rs2, ext);
    TCGv t0 = tcg_temp_new();

    tcg_gen_dup_tl(vece, t0, src2);
    func(dest, src1, t0);
    gen_set_gpr(ctx, a->rd, dest);

    tcg_temp_free(t0);
    return true;
}

static bool trans_cv_add_sc_h(DisasContext *ctx, arg_cv_add_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_16, tcg_gen_vec_add16_tl);
}

static bool gen_simd_scalar_imm(DisasContext *ctx, arg_i *a, DisasExtend ext,
                                unsigned vece, void (*func)(TCGv, TCGv, TCGv))
{
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, ext);
    TCGv src2 = tcg_constant_tl(a->imm);
    TCGv t0 = tcg_temp_new();

    tcg_gen_dup_tl(vece, t0, src2);
    func(dest, src1, t0);
    gen_set_gpr(ctx, a->rd, dest);

    tcg_temp_free(t0);
    return true;
}

static bool trans_cv_add_sci_h(DisasContext *ctx, arg_cv_add_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_16, tcg_gen_vec_add16_tl);
}

static bool trans_cv_add_b(DisasContext *ctx, arg_cv_add_b *a)
{
    return gen_arith(ctx, a, EXT_NONE, tcg_gen_vec_add8_tl, NULL);
}

static bool trans_cv_add_sc_b(DisasContext *ctx, arg_cv_add_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_8, tcg_gen_vec_add8_tl);
}

static bool trans_cv_add_sci_b(DisasContext *ctx, arg_cv_add_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_8, tcg_gen_vec_add8_tl);
}

static bool gen_simd_div(DisasContext *ctx, arg_r *a, DisasExtend ext,
                         int32_t shift, void (*func)(TCGv, TCGv, TCGv),
                         void (*shift_func)(TCGv, TCGv, target_long))
{
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, ext);
    TCGv src2 = get_gpr(ctx, a->rs2, ext);

    func(dest, src1, src2);
    shift_func(dest, dest, shift);

    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_sub_h(DisasContext *ctx, arg_cv_sub_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, tcg_gen_vec_sub16_tl, NULL);
}

static bool trans_cv_sub_sc_h(DisasContext *ctx, arg_cv_sub_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_16, tcg_gen_vec_sub16_tl);
}

static bool trans_cv_sub_sci_h(DisasContext *ctx, arg_cv_sub_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_16, tcg_gen_vec_sub16_tl);
}

static bool trans_cv_sub_b(DisasContext *ctx, arg_cv_sub_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, tcg_gen_vec_sub8_tl, NULL);
}

static bool trans_cv_sub_sc_b(DisasContext *ctx, arg_cv_sub_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_8, tcg_gen_vec_sub8_tl);
}

static bool trans_cv_sub_sci_b(DisasContext *ctx, arg_cv_sub_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_8, tcg_gen_vec_sub8_tl);
}

static bool trans_cv_avg_h(DisasContext *ctx, arg_cv_avg_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_div(ctx, a, EXT_NONE, 1, tcg_gen_vec_add16_tl,
                        tcg_gen_vec_sar16i_tl);
}

static bool gen_simd_div_scalar(DisasContext *ctx, arg_r *a, DisasExtend ext,
                                int32_t shift, unsigned vece,
                                void (*func)(TCGv, TCGv, TCGv),
                                void (*shift_func)(TCGv, TCGv, target_long))
{
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, ext);
    TCGv src2 = get_gpr(ctx, a->rs2, ext);
    TCGv t0 = tcg_temp_new();

    tcg_gen_dup_tl(vece, t0, src2);
    func(dest, src1, t0);
    shift_func(dest, dest, shift);

    gen_set_gpr(ctx, a->rd, dest);
    tcg_temp_free(t0);
    return true;
}

static bool trans_cv_avg_sc_h(DisasContext *ctx, arg_cv_avg_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_div_scalar(ctx, a, EXT_NONE, 1, MO_16,
                               tcg_gen_vec_add16_tl, tcg_gen_vec_sar16i_tl);
}

static bool gen_simd_div_scalar_imm(DisasContext *ctx, arg_i *a,
                                    DisasExtend ext, int32_t shift,
                                    unsigned vece,
                                    void (*func)(TCGv, TCGv, TCGv),
                                    void (*shift_func)(TCGv, TCGv,
                                                       target_long))
{
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, ext);
    TCGv src2 = tcg_constant_tl(a->imm);
    TCGv t0 = tcg_temp_new();

    tcg_gen_dup_tl(vece, t0, src2);
    func(dest, src1, t0);
    shift_func(dest, dest, shift);

    gen_set_gpr(ctx, a->rd, dest);
    tcg_temp_free(t0);
    return true;
}

static bool trans_cv_avg_sci_h(DisasContext *ctx, arg_cv_avg_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_div_scalar_imm(ctx, a, EXT_NONE, 1, MO_16,
                                   tcg_gen_vec_add16_tl,
                                   tcg_gen_vec_sar16i_tl);
}

static bool trans_cv_avg_b(DisasContext *ctx, arg_cv_avg_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_div(ctx, a, EXT_NONE, 1, tcg_gen_vec_add8_tl,
                        tcg_gen_vec_sar8i_tl);
}

static bool trans_cv_avg_sc_b(DisasContext *ctx, arg_cv_avg_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_div_scalar(ctx, a, EXT_NONE, 1, MO_8,
                               tcg_gen_vec_add8_tl, tcg_gen_vec_sar8i_tl);
}

static bool trans_cv_avg_sci_b(DisasContext *ctx, arg_cv_avg_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_div_scalar_imm(ctx, a, EXT_NONE, 1, MO_8,
                                   tcg_gen_vec_add8_tl, tcg_gen_vec_sar8i_tl);
}

static bool trans_cv_avgu_h(DisasContext *ctx, arg_cv_avgu_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_div(ctx, a, EXT_NONE, 1, tcg_gen_vec_add16_tl,
                        tcg_gen_vec_shr16i_tl);
}

static bool trans_cv_avgu_sc_h(DisasContext *ctx, arg_cv_avgu_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_div_scalar(ctx, a, EXT_NONE, 1, MO_16,
                               tcg_gen_vec_add16_tl, tcg_gen_vec_shr16i_tl);
}

static bool trans_cv_avgu_sci_h(DisasContext *ctx, arg_cv_avgu_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_div_scalar_imm(ctx, a, EXT_NONE, 1, MO_16,
                                   tcg_gen_vec_add16_tl,
                                   tcg_gen_vec_shr16i_tl);
}

static bool trans_cv_avgu_b(DisasContext *ctx, arg_cv_avgu_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_div(ctx, a, EXT_NONE, 1, tcg_gen_vec_add8_tl,
                        tcg_gen_vec_shr8i_tl);
}

static bool trans_cv_avgu_sc_b(DisasContext *ctx, arg_cv_avgu_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_div_scalar(ctx, a, EXT_NONE, 1, MO_8,
                               tcg_gen_vec_add8_tl, tcg_gen_vec_shr8i_tl);
}

static bool trans_cv_avgu_sci_b(DisasContext *ctx, arg_cv_avgu_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_div_scalar_imm(ctx, a, EXT_NONE, 1, MO_8,
                                   tcg_gen_vec_add8_tl, tcg_gen_vec_shr8i_tl);
}

static bool trans_cv_min_h(DisasContext *ctx, arg_cv_min_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_min_h, NULL);
}

static bool trans_cv_min_sc_h(DisasContext *ctx, arg_cv_min_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_16, gen_helper_min_h);
}

static bool trans_cv_min_sci_h(DisasContext *ctx, arg_cv_min_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_16, gen_helper_min_h);
}

static bool trans_cv_min_b(DisasContext *ctx, arg_cv_min_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_min_b, NULL);
}

static bool trans_cv_min_sc_b(DisasContext *ctx, arg_cv_min_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_8, gen_helper_min_b);
}

static bool trans_cv_min_sci_b(DisasContext *ctx, arg_cv_min_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_8, gen_helper_min_b);
}

static bool trans_cv_minu_h(DisasContext *ctx, arg_cv_minu_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_minu_h, NULL);
}

static bool trans_cv_minu_sc_h(DisasContext *ctx, arg_cv_minu_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_16, gen_helper_minu_h);
}

static bool trans_cv_minu_sci_h(DisasContext *ctx, arg_cv_minu_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_16, gen_helper_minu_h);
}

static bool trans_cv_minu_b(DisasContext *ctx, arg_cv_minu_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_minu_b, NULL);
}

static bool trans_cv_minu_sc_b(DisasContext *ctx, arg_cv_minu_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_8, gen_helper_minu_b);
}

static bool trans_cv_minu_sci_b(DisasContext *ctx, arg_cv_minu_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_8, gen_helper_minu_b);
}

static bool trans_cv_max_h(DisasContext *ctx, arg_cv_max_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_max_h, NULL);
}

static bool trans_cv_max_sc_h(DisasContext *ctx, arg_cv_max_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_16, gen_helper_max_h);
}

static bool trans_cv_max_sci_h(DisasContext *ctx, arg_cv_max_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_16, gen_helper_max_h);
}

static bool trans_cv_max_b(DisasContext *ctx, arg_cv_max_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_max_b, NULL);
}

static bool trans_cv_max_sc_b(DisasContext *ctx, arg_cv_max_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_8, gen_helper_max_b);
}

static bool trans_cv_max_sci_b(DisasContext *ctx, arg_cv_max_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_8, gen_helper_max_b);
}

static bool trans_cv_maxu_h(DisasContext *ctx, arg_cv_maxu_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_maxu_h, NULL);
}

static bool trans_cv_maxu_sc_h(DisasContext *ctx, arg_cv_maxu_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_16, gen_helper_maxu_h);
}

static bool trans_cv_maxu_sci_h(DisasContext *ctx, arg_cv_maxu_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_16, gen_helper_maxu_h);
}

static bool trans_cv_maxu_b(DisasContext *ctx, arg_cv_maxu_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_maxu_b, NULL);
}

static bool trans_cv_maxu_sc_b(DisasContext *ctx, arg_cv_maxu_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_8, gen_helper_maxu_b);
}

static bool trans_cv_maxu_sci_b(DisasContext *ctx, arg_cv_maxu_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_8, gen_helper_maxu_b);
}

static bool trans_cv_srl_h(DisasContext *ctx, arg_cv_srl_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_shr_h, NULL);
}

static void gen_vec_shr16(TCGv d, TCGv a, TCGv c)
{
    TCGv mask = tcg_temp_new();

    tcg_gen_shr_tl(mask, tcg_constant_tl(0xffff), c);
    tcg_gen_dup_tl(MO_16, mask, mask);
    tcg_gen_shr_tl(d, a, c);
    tcg_gen_and_tl(d, d, mask);

    tcg_temp_free(mask);
}

static bool trans_cv_srl_sc_h(DisasContext *ctx, arg_cv_srl_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_vec_shr16, NULL);
}

static bool trans_cv_srl_sci_h(DisasContext *ctx, arg_cv_srl_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith_imm_fn(ctx, a, EXT_NONE, tcg_gen_vec_shr16i_tl, NULL);
}

static bool trans_cv_srl_b(DisasContext *ctx, arg_cv_srl_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_shr_b, NULL);
}

static void gen_vec_shr8(TCGv d, TCGv a, TCGv c)
{
    TCGv mask = tcg_temp_new();

    tcg_gen_shr_tl(mask, tcg_constant_tl(0xff), c);
    tcg_gen_dup_tl(MO_8, mask, mask);
    tcg_gen_shr_tl(d, a, c);
    tcg_gen_and_tl(d, d, mask);

    tcg_temp_free(mask);
}

static bool trans_cv_srl_sc_b(DisasContext *ctx, arg_cv_srl_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_vec_shr8, NULL);
}

static bool trans_cv_srl_sci_b(DisasContext *ctx, arg_cv_srl_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith_imm_fn(ctx, a, EXT_NONE, tcg_gen_vec_shr8i_tl, NULL);
}

static bool trans_cv_sra_h(DisasContext *ctx, arg_cv_sra_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_sra_h, NULL);
}

static bool trans_cv_sra_sc_h(DisasContext *ctx, arg_cv_sra_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_16, gen_helper_sra_h);
}

static bool trans_cv_sra_sci_h(DisasContext *ctx, arg_cv_sra_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith_imm_fn(ctx, a, EXT_NONE, tcg_gen_vec_sar16i_tl, NULL);
}

static bool trans_cv_sra_b(DisasContext *ctx, arg_cv_sra_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_sra_b, NULL);
}

static bool trans_cv_sra_sc_b(DisasContext *ctx, arg_cv_sra_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_8, gen_helper_sra_b);
}

static bool trans_cv_sra_sci_b(DisasContext *ctx, arg_cv_sra_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith_imm_fn(ctx, a, EXT_NONE, tcg_gen_vec_sar8i_tl, NULL);
}

static bool trans_cv_sll_h(DisasContext *ctx, arg_cv_sll_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_shl_h, NULL);
}

static void gen_vec_shl16(TCGv d, TCGv a, TCGv c)
{
    TCGv mask = tcg_temp_new();

    tcg_gen_shl_tl(mask, tcg_constant_tl(0xffff), c);
    tcg_gen_dup_tl(MO_16, mask, mask);
    tcg_gen_shl_tl(d, a, c);
    tcg_gen_and_tl(d, d, mask);

    tcg_temp_free(mask);
}

static bool trans_cv_sll_sc_h(DisasContext *ctx, arg_cv_sll_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_vec_shl16, NULL);
}

static bool trans_cv_sll_sci_h(DisasContext *ctx, arg_cv_sll_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith_imm_fn(ctx, a, EXT_NONE, tcg_gen_vec_shl16i_tl, NULL);
}

static bool trans_cv_sll_b(DisasContext *ctx, arg_cv_sll_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_shl_b, NULL);
}

static void gen_vec_shl8(TCGv d, TCGv a, TCGv c)
{
    TCGv mask = tcg_temp_new();

    tcg_gen_shl_tl(mask, tcg_constant_tl(0xff), c);
    tcg_gen_dup_tl(MO_8, mask, mask);
    tcg_gen_shl_tl(d, a, c);
    tcg_gen_and_tl(d, d, mask);

    tcg_temp_free(mask);
}

static bool trans_cv_sll_sc_b(DisasContext *ctx, arg_cv_sll_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_vec_shl8, NULL);
}

static bool trans_cv_sll_sci_b(DisasContext *ctx, arg_cv_sll_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith_imm_fn(ctx, a, EXT_NONE, tcg_gen_vec_shl8i_tl, NULL);
}

static bool trans_cv_or_h(DisasContext *ctx, arg_cv_or_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_logic(ctx, a, tcg_gen_or_tl);
}

static bool trans_cv_or_sc_h(DisasContext *ctx, arg_cv_or_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_16, tcg_gen_or_tl);
}

static bool trans_cv_or_sci_h(DisasContext *ctx, arg_cv_or_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_16, tcg_gen_or_tl);
}

static bool trans_cv_or_b(DisasContext *ctx, arg_cv_or_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_logic(ctx, a, tcg_gen_or_tl);
}

static bool trans_cv_or_sc_b(DisasContext *ctx, arg_cv_or_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_8, tcg_gen_or_tl);
}

static bool trans_cv_or_sci_b(DisasContext *ctx, arg_cv_or_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_8, tcg_gen_or_tl);
}

static bool trans_cv_xor_h(DisasContext *ctx, arg_cv_xor_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_logic(ctx, a, tcg_gen_xor_tl);
}

static bool trans_cv_xor_sc_h(DisasContext *ctx, arg_cv_xor_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_16, tcg_gen_xor_tl);
}

static bool trans_cv_xor_sci_h(DisasContext *ctx, arg_cv_xor_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_16, tcg_gen_xor_tl);
}

static bool trans_cv_xor_b(DisasContext *ctx, arg_cv_xor_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_logic(ctx, a, tcg_gen_xor_tl);
}

static bool trans_cv_xor_sc_b(DisasContext *ctx, arg_cv_xor_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_8, tcg_gen_xor_tl);
}

static bool trans_cv_xor_sci_b(DisasContext *ctx, arg_cv_xor_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_8, tcg_gen_xor_tl);
}

static bool trans_cv_and_h(DisasContext *ctx, arg_cv_and_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_logic(ctx, a, tcg_gen_and_tl);
}

static bool trans_cv_and_sc_h(DisasContext *ctx, arg_cv_and_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_16, tcg_gen_and_tl);
}

static bool trans_cv_and_sci_h(DisasContext *ctx, arg_cv_and_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_16, tcg_gen_and_tl);
}

static bool trans_cv_and_b(DisasContext *ctx, arg_cv_and_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_logic(ctx, a, tcg_gen_and_tl);
}

static bool trans_cv_and_sc_b(DisasContext *ctx, arg_cv_and_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_8, tcg_gen_and_tl);
}

static bool trans_cv_and_sci_b(DisasContext *ctx, arg_cv_and_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_8, tcg_gen_and_tl);
}

static void gen_abs(TCGv d, TCGv b, unsigned vece)
{
    TCGv t = tcg_temp_new();
    int nbit = 8 << vece;
    target_ulong mask = dup_const_tl(vece, 1);

    /* Create -1 for each negative element.  */
    tcg_gen_shri_tl(t, b, nbit - 1);
    tcg_gen_andi_tl(t, t, mask);
    tcg_gen_muli_tl(t, t, (1 << nbit) - 1);

    /*
     * Invert (via xor -1) and add one.
     * Because of the ordering the msb is cleared,
     * so we never have carry into the next element.
     */
    tcg_gen_xor_tl(d, b, t);
    tcg_gen_andi_tl(t, t, mask);
    tcg_gen_add_tl(d, d, t);

    tcg_temp_free(t);
}

static void gen_abs8(TCGv dest, TCGv src)
{
    gen_abs(dest, src, MO_8);
}

static void gen_abs16(TCGv dest, TCGv src)
{
    gen_abs(dest, src, MO_16);
}

static bool trans_cv_abs_h(DisasContext *ctx, arg_cv_abs_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_unary(ctx, a, EXT_NONE, gen_abs16);
}

static bool trans_cv_abs_b(DisasContext *ctx, arg_cv_abs_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_unary(ctx, a, EXT_NONE, gen_abs8);
}

static bool trans_cv_extract_h(DisasContext *ctx, arg_cv_extract_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);

    tcg_gen_sextract_tl(dest, src1, (a->imm & 0x1) * 16, 16);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_extract_b(DisasContext *ctx, arg_cv_extract_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);

    tcg_gen_sextract_tl(dest, src1, (a->imm & 0x3) * 8, 8);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_extractu_h(DisasContext *ctx, arg_cv_extractu_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);

    tcg_gen_extract_tl(dest, src1, (a->imm & 0x1) * 16, 16);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_extractu_b(DisasContext *ctx, arg_cv_extractu_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);

    tcg_gen_extract_tl(dest, src1, (a->imm & 0x3) * 8, 8);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_insert_h(DisasContext *ctx, arg_cv_insert_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src = get_gpr(ctx, a->rd, EXT_NONE);
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);

    tcg_gen_deposit_tl(dest, src, src1, (a->imm & 0x1) * 16, 16);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_insert_b(DisasContext *ctx, arg_cv_extract_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src = get_gpr(ctx, a->rd, EXT_NONE);
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);

    tcg_gen_deposit_tl(dest, src, src1, (a->imm & 0x3) * 8, 8);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_dotup_h(DisasContext *ctx, arg_cv_dotup_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_dotup_h, NULL);
}

static bool trans_cv_dotup_sc_h(DisasContext *ctx, arg_cv_dotup_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_16, gen_helper_dotup_h);
}

static bool trans_cv_dotup_sci_h(DisasContext *ctx, arg_cv_dotup_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_16, gen_helper_dotup_h);
}

static bool trans_cv_dotup_b(DisasContext *ctx, arg_cv_dotup_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_dotup_b, NULL);
}

static bool trans_cv_dotup_sc_b(DisasContext *ctx, arg_cv_dotup_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_8, gen_helper_dotup_b);
}

static bool trans_cv_dotup_sci_b(DisasContext *ctx, arg_cv_dotup_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_8, gen_helper_dotup_b);
}

static bool trans_cv_dotusp_h(DisasContext *ctx, arg_cv_dotusp_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_dotusp_h, NULL);
}

static bool trans_cv_dotusp_sc_h(DisasContext *ctx, arg_cv_dotusp_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_16, gen_helper_dotusp_h);
}

static bool trans_cv_dotusp_sci_h(DisasContext *ctx, arg_cv_dotusp_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_16, gen_helper_dotusp_h);
}

static bool trans_cv_dotusp_b(DisasContext *ctx, arg_cv_dotusp_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_dotusp_b, NULL);
}

static bool trans_cv_dotusp_sc_b(DisasContext *ctx, arg_cv_dotusp_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_8, gen_helper_dotusp_b);
}

static bool trans_cv_dotusp_sci_b(DisasContext *ctx, arg_cv_dotusp_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_8, gen_helper_dotusp_b);
}

static bool trans_cv_dotsp_h(DisasContext *ctx, arg_cv_dotsp_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_dotsp_h, NULL);
}

static bool trans_cv_dotsp_sc_h(DisasContext *ctx, arg_cv_dotsp_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_16, gen_helper_dotsp_h);
}

static bool trans_cv_dotsp_sci_h(DisasContext *ctx, arg_cv_dotsp_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_16, gen_helper_dotsp_h);
}

static bool trans_cv_dotsp_b(DisasContext *ctx, arg_cv_dotsp_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_dotsp_b, NULL);
}

static bool trans_cv_dotsp_sc_b(DisasContext *ctx, arg_cv_dotsp_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_8, gen_helper_dotsp_b);
}

static bool trans_cv_dotsp_sci_b(DisasContext *ctx, arg_cv_dotsp_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_8, gen_helper_dotsp_b);
}

static inline bool gen_simd_sdot(DisasContext *ctx, arg_r *a, DisasExtend ext,
                                 void (*fn)(TCGv, TCGv, TCGv))
{
    TCGv tmp = tcg_temp_new();
    TCGv dest = get_gpr(ctx, a->rd, ext);
    TCGv src1 = get_gpr(ctx, a->rs1, ext);
    TCGv src2 = get_gpr(ctx, a->rs2, ext);

    fn(tmp, src1, src2);
    tcg_gen_add_tl(tmp, dest, tmp);
    gen_set_gpr(ctx, a->rd, tmp);

    tcg_temp_free(tmp);
    return true;
}

static inline bool gen_simd_sdot_sc(DisasContext *ctx, arg_r *a,
                                    DisasExtend ext, unsigned vece,
                                    void (*fn)(TCGv, TCGv, TCGv))
{
    TCGv tmp = tcg_temp_new();
    TCGv dest = get_gpr(ctx, a->rd, ext);
    TCGv src1 = get_gpr(ctx, a->rs1, ext);
    TCGv src2 = get_gpr(ctx, a->rs2, ext);

    tcg_gen_dup_tl(vece, tmp, src2);
    fn(tmp, src1, tmp);
    tcg_gen_add_tl(tmp, dest, tmp);
    gen_set_gpr(ctx, a->rd, tmp);
    tcg_temp_free(tmp);

    return true;
}

static inline bool gen_simd_sdot_sci(DisasContext *ctx, arg_i *a,
                                     DisasExtend ext, unsigned vece,
                                     void (*fn)(TCGv, TCGv, TCGv))
{
    TCGv tmp = tcg_temp_new();
    TCGv dest = get_gpr(ctx, a->rd, ext);
    TCGv src1 = get_gpr(ctx, a->rs1, ext);
    TCGv src2 = tcg_constant_tl(dup_const_tl(vece, a->imm));

    fn(tmp, src1, src2);
    tcg_gen_add_tl(tmp, dest, tmp);
    gen_set_gpr(ctx, a->rd, tmp);

    tcg_temp_free(tmp);
    return true;
}

#define GEN_SDOT_TRANS(NAME, FUNC, EXT)                         \
static bool trans_##NAME(DisasContext *s, arg_r *a)             \
{                                                               \
    REQUIRE_XCVSIMD(s);                                         \
    return gen_simd_sdot(s, a, EXT, gen_helper_##FUNC);         \
}

#define GEN_SDOT_SC_TRANS(NAME, FUNC, EXT, M)                   \
static bool trans_##NAME(DisasContext *s, arg_r *a)             \
{                                                               \
    REQUIRE_XCVSIMD(s);                                         \
    return gen_simd_sdot_sc(s, a, EXT, M, gen_helper_##FUNC);   \
}

#define GEN_SDOT_SCI_TRANS(NAME, FUNC, EXT, M)                  \
static bool trans_##NAME(DisasContext *s, arg_i *a)             \
{                                                               \
    REQUIRE_XCVSIMD(s);                                         \
    return gen_simd_sdot_sci(s, a, EXT, M, gen_helper_##FUNC);  \
}

GEN_SDOT_TRANS(cv_sdotup_h, dotup_h, EXT_NONE)
GEN_SDOT_SC_TRANS(cv_sdotup_sc_h, dotup_h, EXT_NONE, MO_16)
GEN_SDOT_SCI_TRANS(cv_sdotup_sci_h, dotup_h, EXT_NONE, MO_16)
GEN_SDOT_TRANS(cv_sdotup_b, dotup_b, EXT_NONE)
GEN_SDOT_SC_TRANS(cv_sdotup_sc_b, dotup_b, EXT_NONE, MO_8)
GEN_SDOT_SCI_TRANS(cv_sdotup_sci_b, dotup_b, EXT_NONE, MO_8)

GEN_SDOT_TRANS(cv_sdotusp_h, dotusp_h, EXT_NONE)
GEN_SDOT_SC_TRANS(cv_sdotusp_sc_h, dotusp_h, EXT_NONE, MO_16)
GEN_SDOT_SCI_TRANS(cv_sdotusp_sci_h, dotusp_h, EXT_NONE, MO_16)
GEN_SDOT_TRANS(cv_sdotusp_b, dotusp_b, EXT_NONE)
GEN_SDOT_SC_TRANS(cv_sdotusp_sc_b, dotusp_b, EXT_NONE, MO_8)
GEN_SDOT_SCI_TRANS(cv_sdotusp_sci_b, dotusp_b, EXT_NONE, MO_8)

GEN_SDOT_TRANS(cv_sdotsp_h, dotsp_h, EXT_NONE)
GEN_SDOT_SC_TRANS(cv_sdotsp_sc_h, dotsp_h, EXT_NONE, MO_16)
GEN_SDOT_SCI_TRANS(cv_sdotsp_sci_h, dotsp_h, EXT_NONE, MO_16)
GEN_SDOT_TRANS(cv_sdotsp_b, dotsp_b, EXT_NONE)
GEN_SDOT_SC_TRANS(cv_sdotsp_sc_b, dotsp_b, EXT_NONE, MO_8)
GEN_SDOT_SCI_TRANS(cv_sdotsp_sci_b, dotsp_b, EXT_NONE, MO_8)

static bool trans_cv_shuffle_h(DisasContext *ctx, arg_cv_shuffle_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_shuffle_h, NULL);
}

static bool trans_cv_shuffle_sci_h(DisasContext *ctx, arg_cv_shuffle_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith_imm_tl(ctx, a, EXT_NONE, gen_helper_shuffle_sc_h, NULL);
}

static bool trans_cv_shuffle_b(DisasContext *ctx, arg_cv_shuffle_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_shuffle_b, NULL);
}

static inline bool gen_simd_shuf_sci(DisasContext *ctx, arg_i *a,
                                     target_ulong i, DisasExtend ext,
                                     void (*fn)(TCGv, TCGv, TCGv, TCGv))
{
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, ext);
    TCGv src2 = tcg_constant_tl(a->imm);

    fn(dest, src1, src2, tcg_constant_tl(i));
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

#define GEN_SHUF_SCI_TRANS(NAME, FUNC, NUM, EXT)                  \
static bool trans_##NAME(DisasContext *s, arg_i *a)               \
{                                                                 \
    REQUIRE_XCVSIMD(s);                                           \
    return gen_simd_shuf_sci(s, a, NUM, EXT, gen_helper_##FUNC);  \
}

GEN_SHUF_SCI_TRANS(cv_shuffleI0_sci_b, shuffle_sc_b, 0, EXT_NONE)
GEN_SHUF_SCI_TRANS(cv_shuffleI1_sci_b, shuffle_sc_b, 1, EXT_NONE)
GEN_SHUF_SCI_TRANS(cv_shuffleI2_sci_b, shuffle_sc_b, 2, EXT_NONE)
GEN_SHUF_SCI_TRANS(cv_shuffleI3_sci_b, shuffle_sc_b, 3, EXT_NONE)

static inline bool gen_simd_shuf2(DisasContext *ctx, arg_r *a,
                                  DisasExtend ext,
                                  void (*fn)(TCGv, TCGv, TCGv, TCGv))
{
    TCGv tmp = tcg_temp_new();
    TCGv dest = get_gpr(ctx, a->rd, ext);
    TCGv src1 = get_gpr(ctx, a->rs1, ext);
    TCGv src2 = get_gpr(ctx, a->rs2, ext);

    fn(tmp, src1, src2, dest);
    gen_set_gpr(ctx, a->rd, tmp);
    tcg_temp_free(tmp);
    return true;
}

#define GEN_SHUF2_TRANS(NAME, FUNC, EXT)                          \
static bool trans_##NAME(DisasContext *s, arg_r *a)               \
{                                                                 \
    REQUIRE_XCVSIMD(s);                                           \
    return gen_simd_shuf2(s, a, EXT, gen_helper_##FUNC);          \
}

GEN_SHUF2_TRANS(cv_shuffle2_h, shuffle2_h, EXT_NONE)
GEN_SHUF2_TRANS(cv_shuffle2_b, shuffle2_b, EXT_NONE)

static bool trans_cv_pack(DisasContext *ctx, arg_cv_pack *a)
{
    REQUIRE_XCVSIMD(ctx);
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv src2 = get_gpr(ctx, a->rs2, EXT_NONE);
    TCGv tmp = tcg_temp_new();

    tcg_gen_ext16u_tl(tmp, src2);
    tcg_gen_shli_tl(dest, src1, 16);
    tcg_gen_or_tl(dest, dest, tmp);
    gen_set_gpr(ctx, a->rd, dest);
    tcg_temp_free(tmp);
    return true;
}

static bool trans_cv_pack_h(DisasContext *ctx, arg_cv_pack_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv src2 = get_gpr(ctx, a->rs2, EXT_NONE);
    TCGv tmp = tcg_temp_new();

    tcg_gen_andi_tl(tmp, src1, 0xffff0000);
    tcg_gen_shri_tl(dest, src2, 16);
    tcg_gen_or_tl(dest, dest, tmp);
    gen_set_gpr(ctx, a->rd, dest);
    tcg_temp_free(tmp);
    return true;
}

static bool trans_cv_packhi_b(DisasContext *ctx, arg_cv_packhi_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    TCGv dest = get_gpr(ctx, a->rd, EXT_NONE);
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv src2 = get_gpr(ctx, a->rs2, EXT_NONE);

    tcg_gen_deposit_tl(dest, dest, src1, 24, 8);
    tcg_gen_deposit_tl(dest, dest, src2, 16, 8);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_packlo_b(DisasContext *ctx, arg_cv_packlo_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    TCGv dest = get_gpr(ctx, a->rd, EXT_NONE);
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv src2 = get_gpr(ctx, a->rs2, EXT_NONE);

    tcg_gen_deposit_tl(dest, dest, src1, 8, 8);
    tcg_gen_deposit_tl(dest, dest, src2, 0, 8);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_cmpeq_h(DisasContext *ctx, arg_cv_cmpeq_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_cmpeq_h, NULL);
}

static bool trans_cv_cmpeq_sc_h(DisasContext *ctx, arg_cv_cmpeq_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_16, gen_helper_cmpeq_h);
}

static bool trans_cv_cmpeq_sci_h(DisasContext *ctx, arg_cv_cmpeq_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_16, gen_helper_cmpeq_h);
}

static bool trans_cv_cmpeq_b(DisasContext *ctx, arg_cv_cmpeq_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_cmpeq_b, NULL);
}

static bool trans_cv_cmpeq_sc_b(DisasContext *ctx, arg_cv_cmpeq_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_8, gen_helper_cmpeq_b);
}

static bool trans_cv_cmpeq_sci_b(DisasContext *ctx, arg_cv_cmpeq_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_8, gen_helper_cmpeq_b);
}

static bool trans_cv_cmpne_h(DisasContext *ctx, arg_cv_cmpne_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_cmpne_h, NULL);
}

static bool trans_cv_cmpne_sc_h(DisasContext *ctx, arg_cv_cmpne_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_16, gen_helper_cmpne_h);
}

static bool trans_cv_cmpne_sci_h(DisasContext *ctx, arg_cv_cmpne_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_16, gen_helper_cmpne_h);
}

static bool trans_cv_cmpne_b(DisasContext *ctx, arg_cv_cmpne_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_cmpne_b, NULL);
}

static bool trans_cv_cmpne_sc_b(DisasContext *ctx, arg_cv_cmpne_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_8, gen_helper_cmpne_b);
}

static bool trans_cv_cmpne_sci_b(DisasContext *ctx, arg_cv_cmpne_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_8, gen_helper_cmpne_b);
}

static bool trans_cv_cmpgt_h(DisasContext *ctx, arg_cv_cmpgt_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_cmpgt_h, NULL);
}

static bool trans_cv_cmpgt_sc_h(DisasContext *ctx, arg_cv_cmpgt_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_16, gen_helper_cmpgt_h);
}

static bool trans_cv_cmpgt_sci_h(DisasContext *ctx, arg_cv_cmpgt_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_16, gen_helper_cmpgt_h);
}

static bool trans_cv_cmpgt_b(DisasContext *ctx, arg_cv_cmpgt_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_cmpgt_b, NULL);
}

static bool trans_cv_cmpgt_sc_b(DisasContext *ctx, arg_cv_cmpgt_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_8, gen_helper_cmpgt_b);
}

static bool trans_cv_cmpgt_sci_b(DisasContext *ctx, arg_cv_cmpgt_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_8, gen_helper_cmpgt_b);
}

static bool trans_cv_cmpge_h(DisasContext *ctx, arg_cv_cmpge_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_cmpge_h, NULL);
}

static bool trans_cv_cmpge_sc_h(DisasContext *ctx, arg_cv_cmpge_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_16, gen_helper_cmpge_h);
}

static bool trans_cv_cmpge_sci_h(DisasContext *ctx, arg_cv_cmpge_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_16, gen_helper_cmpge_h);
}

static bool trans_cv_cmpge_b(DisasContext *ctx, arg_cv_cmpge_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_cmpge_b, NULL);
}

static bool trans_cv_cmpge_sc_b(DisasContext *ctx, arg_cv_cmpge_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_8, gen_helper_cmpge_b);
}

static bool trans_cv_cmpge_sci_b(DisasContext *ctx, arg_cv_cmpge_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_8, gen_helper_cmpge_b);
}

static bool trans_cv_cmplt_h(DisasContext *ctx, arg_cv_cmplt_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_cmplt_h, NULL);
}

static bool trans_cv_cmplt_sc_h(DisasContext *ctx, arg_cv_cmplt_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_16, gen_helper_cmplt_h);
}

static bool trans_cv_cmplt_sci_h(DisasContext *ctx, arg_cv_cmplt_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_16, gen_helper_cmplt_h);
}

static bool trans_cv_cmplt_b(DisasContext *ctx, arg_cv_cmplt_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_cmplt_b, NULL);
}

static bool trans_cv_cmplt_sc_b(DisasContext *ctx, arg_cv_cmplt_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_8, gen_helper_cmplt_b);
}

static bool trans_cv_cmplt_sci_b(DisasContext *ctx, arg_cv_cmplt_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_8, gen_helper_cmplt_b);
}

static bool trans_cv_cmple_h(DisasContext *ctx, arg_cv_cmple_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_cmple_h, NULL);
}

static bool trans_cv_cmple_sc_h(DisasContext *ctx, arg_cv_cmple_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_16, gen_helper_cmple_h);
}

static bool trans_cv_cmple_sci_h(DisasContext *ctx, arg_cv_cmple_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_16, gen_helper_cmple_h);
}

static bool trans_cv_cmple_b(DisasContext *ctx, arg_cv_cmple_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_cmple_b, NULL);
}

static bool trans_cv_cmple_sc_b(DisasContext *ctx, arg_cv_cmple_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_8, gen_helper_cmple_b);
}

static bool trans_cv_cmple_sci_b(DisasContext *ctx, arg_cv_cmple_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_8, gen_helper_cmple_b);
}

static bool trans_cv_cmpgtu_h(DisasContext *ctx, arg_cv_cmpgtu_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_cmpgtu_h, NULL);
}

static bool trans_cv_cmpgtu_sc_h(DisasContext *ctx, arg_cv_cmpgtu_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_16, gen_helper_cmpgtu_h);
}

static bool trans_cv_cmpgtu_sci_h(DisasContext *ctx, arg_cv_cmpgtu_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_16, gen_helper_cmpgtu_h);
}

static bool trans_cv_cmpgtu_b(DisasContext *ctx, arg_cv_cmpgtu_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_cmpgtu_b, NULL);
}

static bool trans_cv_cmpgtu_sc_b(DisasContext *ctx, arg_cv_cmpgtu_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_8, gen_helper_cmpgtu_b);
}

static bool trans_cv_cmpgtu_sci_b(DisasContext *ctx, arg_cv_cmpgtu_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_8, gen_helper_cmpgtu_b);
}

static bool trans_cv_cmpgeu_h(DisasContext *ctx, arg_cv_cmpgeu_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_cmpgeu_h, NULL);
}

static bool trans_cv_cmpgeu_sc_h(DisasContext *ctx, arg_cv_cmpgeu_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_16, gen_helper_cmpgeu_h);
}

static bool trans_cv_cmpgeu_sci_h(DisasContext *ctx, arg_cv_cmpgeu_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_16, gen_helper_cmpgeu_h);
}

static bool trans_cv_cmpgeu_b(DisasContext *ctx, arg_cv_cmpgeu_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_cmpgeu_b, NULL);
}

static bool trans_cv_cmpgeu_sc_b(DisasContext *ctx, arg_cv_cmpgeu_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_8, gen_helper_cmpgeu_b);
}

static bool trans_cv_cmpgeu_sci_b(DisasContext *ctx, arg_cv_cmpgeu_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_8, gen_helper_cmpgeu_b);
}

static bool trans_cv_cmpltu_h(DisasContext *ctx, arg_cv_cmpltu_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_cmpltu_h, NULL);
}

static bool trans_cv_cmpltu_sc_h(DisasContext *ctx, arg_cv_cmpltu_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_16, gen_helper_cmpltu_h);
}

static bool trans_cv_cmpltu_sci_h(DisasContext *ctx, arg_cv_cmpltu_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_16, gen_helper_cmpltu_h);
}

static bool trans_cv_cmpltu_b(DisasContext *ctx, arg_cv_cmpltu_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_cmpltu_b, NULL);
}

static bool trans_cv_cmpltu_sc_b(DisasContext *ctx, arg_cv_cmpltu_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_8, gen_helper_cmpltu_b);
}

static bool trans_cv_cmpltu_sci_b(DisasContext *ctx, arg_cv_cmpltu_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_8, gen_helper_cmpltu_b);
}

static bool trans_cv_cmpleu_h(DisasContext *ctx, arg_cv_cmpleu_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_cmpleu_h, NULL);
}

static bool trans_cv_cmpleu_sc_h(DisasContext *ctx, arg_cv_cmpleu_sc_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_16, gen_helper_cmpleu_h);
}

static bool trans_cv_cmpleu_sci_h(DisasContext *ctx, arg_cv_cmpleu_sci_h *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_16, gen_helper_cmpleu_h);
}

static bool trans_cv_cmpleu_b(DisasContext *ctx, arg_cv_cmpleu_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_cmpleu_b, NULL);
}

static bool trans_cv_cmpleu_sc_b(DisasContext *ctx, arg_cv_cmpleu_sc_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar(ctx, a, EXT_NONE, MO_8, gen_helper_cmpleu_b);
}

static bool trans_cv_cmpleu_sci_b(DisasContext *ctx, arg_cv_cmpleu_sci_b *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_scalar_imm(ctx, a, EXT_NONE, MO_8, gen_helper_cmpleu_b);
}

static inline bool gen_subrotmj(DisasContext *ctx, arg_r *a,
                                DisasExtend ext, int div,
                                void (*fn)(TCGv, TCGv, TCGv, TCGv))
{
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, ext);
    TCGv src2 = get_gpr(ctx, a->rs2, ext);

    fn(dest, src1, src2, tcg_constant_tl(div));
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

#define GEN_SUBROTMJ_TRANS(NAME, FUNC, EXT, DIV)             \
static bool trans_##NAME(DisasContext *s, arg_r *a)          \
{                                                            \
    REQUIRE_XCVSIMD(s);                                      \
    return gen_subrotmj(s, a, EXT, DIV, gen_helper_##FUNC);  \
}

GEN_SUBROTMJ_TRANS(cv_subrotmj, subrotmj, EXT_NONE, 0)
GEN_SUBROTMJ_TRANS(cv_subrotmj_div2, subrotmj, EXT_NONE, 1)
GEN_SUBROTMJ_TRANS(cv_subrotmj_div4, subrotmj, EXT_NONE, 2)
GEN_SUBROTMJ_TRANS(cv_subrotmj_div8, subrotmj, EXT_NONE, 3)

static bool trans_cv_cplxconj(DisasContext *ctx, arg_cv_cplxconj *a)
{
    REQUIRE_XCVSIMD(ctx);
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);

    tcg_gen_sari_tl(dest, src1, 16);
    tcg_gen_neg_tl(dest, dest);
    tcg_gen_shli_tl(dest, dest, 16);
    tcg_gen_deposit_tl(dest, dest, src1, 0, 16);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static inline bool gen_cplxmul(DisasContext *ctx, arg_r *a,
                                DisasExtend ext, int div,
                                void (*fn)(TCGv, TCGv, TCGv, TCGv, TCGv))
{
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, ext);
    TCGv src2 = get_gpr(ctx, a->rs2, ext);
    TCGv src3 = get_gpr(ctx, a->rd, ext);

    fn(dest, src1, src2, src3, tcg_constant_tl(div));
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

#define GEN_CPLXMUL_TRANS(NAME, FUNC, EXT, DIV)               \
static bool trans_##NAME(DisasContext *s, arg_r *a)           \
{                                                             \
    REQUIRE_XCVSIMD(s);                                       \
    return gen_cplxmul(s, a, EXT, DIV, gen_helper_##FUNC);    \
}

GEN_CPLXMUL_TRANS(cv_cplxmul_r, cplxmul_r, EXT_NONE, 0)
GEN_CPLXMUL_TRANS(cv_cplxmul_r_div2, cplxmul_r, EXT_NONE, 1)
GEN_CPLXMUL_TRANS(cv_cplxmul_r_div4, cplxmul_r, EXT_NONE, 2)
GEN_CPLXMUL_TRANS(cv_cplxmul_r_div8, cplxmul_r, EXT_NONE, 3)
GEN_CPLXMUL_TRANS(cv_cplxmul_i, cplxmul_i, EXT_NONE, 0)
GEN_CPLXMUL_TRANS(cv_cplxmul_i_div2, cplxmul_i, EXT_NONE, 1)
GEN_CPLXMUL_TRANS(cv_cplxmul_i_div4, cplxmul_i, EXT_NONE, 2)
GEN_CPLXMUL_TRANS(cv_cplxmul_i_div8, cplxmul_i, EXT_NONE, 3)

static bool trans_cv_add_div2(DisasContext *ctx, arg_cv_add_div2 *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_div(ctx, a, EXT_NONE, 1, tcg_gen_vec_add16_tl,
                        tcg_gen_vec_shr16i_tl);
}

static bool trans_cv_add_div4(DisasContext *ctx, arg_cv_add_div4 *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_div(ctx, a, EXT_NONE, 2, tcg_gen_vec_add16_tl,
                        tcg_gen_vec_shr16i_tl);
}

static bool trans_cv_add_div8(DisasContext *ctx, arg_cv_add_div8 *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_div(ctx, a, EXT_NONE, 3, tcg_gen_vec_add16_tl,
                        tcg_gen_vec_shr16i_tl);
}

static bool trans_cv_sub_div2(DisasContext *ctx, arg_cv_sub_div2 *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_div(ctx, a, EXT_NONE, 1, tcg_gen_vec_sub16_tl,
                        tcg_gen_vec_shr16i_tl);
}

static bool trans_cv_sub_div4(DisasContext *ctx, arg_cv_sub_div4 *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_div(ctx, a, EXT_NONE, 2, tcg_gen_vec_sub16_tl,
                        tcg_gen_vec_shr16i_tl);
}

static bool trans_cv_sub_div8(DisasContext *ctx, arg_cv_sub_div8 *a)
{
    REQUIRE_XCVSIMD(ctx);
    return gen_simd_div(ctx, a, EXT_NONE, 3, tcg_gen_vec_sub16_tl,
                        tcg_gen_vec_shr16i_tl);
}

static bool trans_cv_mac(DisasContext *ctx, arg_cv_mac *a)
{
    REQUIRE_XCVMAC(ctx);
    TCGv dest = tcg_temp_new();
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv src2 = get_gpr(ctx, a->rs2, EXT_NONE);
    TCGv src3 = get_gpr(ctx, a->rd, EXT_NONE);

    tcg_gen_mul_tl(dest, src1, src2);
    tcg_gen_add_tl(dest, dest, src3);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_msu(DisasContext *ctx, arg_cv_msu *a)
{
    REQUIRE_XCVMAC(ctx);
    TCGv dest = tcg_temp_new();
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv src2 = get_gpr(ctx, a->rs2, EXT_NONE);
    TCGv src3 = get_gpr(ctx, a->rd, EXT_NONE);

    tcg_gen_mul_tl(dest, src1, src2);
    tcg_gen_sub_tl(dest, src3, dest);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static inline bool gen_mul(DisasContext *ctx, arg_mac *a,
                           DisasExtend ext, int extra,
                           void (*fn)(TCGv, TCGv, TCGv,
                                      TCGv, TCGv))
{
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, ext);
    TCGv src2 = get_gpr(ctx, a->rs2, ext);
    TCGv src3 = tcg_constant_tl(a->imm);

    fn(dest, src1, src2, src3, tcg_constant_tl(extra));
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

#define GEN_MUL16X16_TRANS(NAME, FUNC, EXT, HIGH)        \
static bool trans_##NAME(DisasContext *s, arg_mac *a)    \
{                                                        \
    REQUIRE_XCVMAC(s);                                   \
    return gen_mul(s, a, EXT, HIGH, gen_helper_##FUNC);  \
}

GEN_MUL16X16_TRANS(cv_muluN, muluN, EXT_NONE, 0)
GEN_MUL16X16_TRANS(cv_mulhhuN, muluN, EXT_NONE, 1)
GEN_MUL16X16_TRANS(cv_mulsN, mulsN, EXT_NONE, 0)
GEN_MUL16X16_TRANS(cv_mulhhsN, mulsN, EXT_NONE, 1)
GEN_MUL16X16_TRANS(cv_muluRN, muluRN, EXT_NONE, 0)
GEN_MUL16X16_TRANS(cv_mulhhuRN, muluRN, EXT_NONE, 1)
GEN_MUL16X16_TRANS(cv_mulsRN, mulsRN, EXT_NONE, 0)
GEN_MUL16X16_TRANS(cv_mulhhsRN, mulsRN, EXT_NONE, 1)

static inline bool gen_mac(DisasContext *ctx, arg_mac *a,
                           DisasExtend ext, int extra,
                           void (*fn)(TCGv, TCGv, TCGv,
                                       TCGv, TCGv, TCGv))
{
    TCGv dest = tcg_temp_new();
    TCGv src1 = get_gpr(ctx, a->rs1, ext);
    TCGv src2 = get_gpr(ctx, a->rs2, ext);
    TCGv src3 = get_gpr(ctx, a->rd, ext);
    TCGv src4 = tcg_constant_tl(a->imm);

    fn(dest, src1, src2, src3, src4, tcg_constant_tl(extra));
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

#define GEN_MAC16X16_TRANS(NAME, FUNC, EXT, HIGH)        \
static bool trans_##NAME(DisasContext *s, arg_mac *a)    \
{                                                        \
    REQUIRE_XCVMAC(s);                                   \
    return gen_mac(s, a, EXT, HIGH, gen_helper_##FUNC);  \
}

GEN_MAC16X16_TRANS(cv_macuN, macuN, EXT_NONE, 0)
GEN_MAC16X16_TRANS(cv_machhuN, macuN, EXT_NONE, 1)
GEN_MAC16X16_TRANS(cv_macsN, macsN, EXT_NONE, 0)
GEN_MAC16X16_TRANS(cv_machhsN, macsN, EXT_NONE, 1)
GEN_MAC16X16_TRANS(cv_macuRN, macuRN, EXT_NONE, 0)
GEN_MAC16X16_TRANS(cv_machhuRN, macuRN, EXT_NONE, 1)
GEN_MAC16X16_TRANS(cv_macsRN, macsRN, EXT_NONE, 0)
GEN_MAC16X16_TRANS(cv_machhsRN, macsRN, EXT_NONE, 1)

static bool trans_cv_extract(DisasContext *ctx, arg_cv_extract *a)
{
    REQUIRE_XCVBITMANIP(ctx);
    return gen_arith_imm_tl(ctx, a, EXT_NONE, gen_helper_extract, NULL);
}

static bool trans_cv_extractu(DisasContext *ctx, arg_cv_extractu *a)
{
    REQUIRE_XCVBITMANIP(ctx);
    return gen_arith_imm_tl(ctx, a, EXT_NONE, gen_helper_extractu, NULL);
}

static bool trans_cv_insert(DisasContext *ctx, arg_cv_insert *a)
{
    REQUIRE_XCVBITMANIP(ctx);
    TCGv result = tcg_temp_new();
    TCGv dest = get_gpr(ctx, a->rd, EXT_NONE);
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);

    gen_helper_insert(result, src1, tcg_constant_tl(a->imm), dest);
    gen_set_gpr(ctx, a->rd, result);
    return true;
}

static bool trans_cv_bclr(DisasContext *ctx, arg_cv_bclr *a)
{
    REQUIRE_XCVBITMANIP(ctx);
    return gen_arith_imm_tl(ctx, a, EXT_NONE, gen_helper_bclr, NULL);
}

static bool trans_cv_bset(DisasContext *ctx, arg_cv_bset *a)
{
    REQUIRE_XCVBITMANIP(ctx);
    return gen_arith_imm_tl(ctx, a, EXT_NONE, gen_helper_bset, NULL);
}

static bool trans_cv_extractr(DisasContext *ctx, arg_cv_extractr *a)
{
    REQUIRE_XCVBITMANIP(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_extract, NULL);
}

static bool trans_cv_extractur(DisasContext *ctx, arg_cv_extractur *a)
{
    REQUIRE_XCVBITMANIP(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_extractu, NULL);
}

static bool trans_cv_insertr(DisasContext *ctx, arg_cv_insertr *a)
{
    REQUIRE_XCVBITMANIP(ctx);
    TCGv result = tcg_temp_new();
    TCGv dest = get_gpr(ctx, a->rd, EXT_NONE);
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv src2 = get_gpr(ctx, a->rs2, EXT_NONE);

    gen_helper_insert(result, src1, src2, dest);
    gen_set_gpr(ctx, a->rd, result);
    return true;
}

static bool trans_cv_bclrr(DisasContext *ctx, arg_cv_bclrr *a)
{
    REQUIRE_XCVBITMANIP(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_bclr, NULL);
}

static bool trans_cv_bsetr(DisasContext *ctx, arg_cv_bsetr *a)
{
    REQUIRE_XCVBITMANIP(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_bset, NULL);
}

static bool trans_cv_bitrev(DisasContext *ctx, arg_cv_bitrev *a)
{
    REQUIRE_XCVBITMANIP(ctx);
    /* Is3 can be either 0 (radix-2), 1 (radix-4) or 2 (radix-8) */
    target_ulong is3 = (a->imm >> 5) & 0x3;

    if (is3 == 3) {
        return false;
    }
    return gen_arith_imm_tl(ctx, a, EXT_NONE, gen_helper_bitrev, NULL);
}

static bool trans_cv_ff1(DisasContext *ctx, arg_cv_ff1 *a)
{
    REQUIRE_XCVBITMANIP(ctx);
    return gen_unary(ctx, a, EXT_NONE, gen_ctz);
}

static bool trans_cv_fl1(DisasContext *ctx, arg_cv_fl1 *a)
{
    REQUIRE_XCVBITMANIP(ctx);
    return gen_unary(ctx, a, EXT_NONE, gen_helper_fl1);
}

static bool trans_cv_clb(DisasContext *ctx, arg_cv_clb *a)
{
    REQUIRE_XCVBITMANIP(ctx);
    return gen_unary(ctx, a, EXT_ZERO, gen_helper_clb);
}

static bool trans_cv_cnt(DisasContext *ctx, arg_cv_cnt *a)
{
    REQUIRE_XCVBITMANIP(ctx);
    return gen_unary(ctx, a, EXT_ZERO, tcg_gen_ctpop_tl);
}

static bool trans_cv_ror(DisasContext *ctx, arg_cv_ror *a)
{
    REQUIRE_XCVBITMANIP(ctx);
    return gen_arith(ctx, a, EXT_ZERO, tcg_gen_rotr_tl, NULL);
}

static bool trans_cv_abs(DisasContext *ctx, arg_cv_abs *a)
{
    REQUIRE_XCVALU(ctx);
    return gen_unary(ctx, a, EXT_NONE, tcg_gen_abs_tl);
}

static bool trans_cv_slet(DisasContext *ctx, arg_cv_slet *a)
{
    REQUIRE_XCVALU(ctx);
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv src2 = get_gpr(ctx, a->rs2, EXT_NONE);

    tcg_gen_setcond_tl(TCG_COND_LE, dest, src1, src2);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_sletu(DisasContext *ctx, arg_cv_slet *a)
{
    REQUIRE_XCVALU(ctx);
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv src2 = get_gpr(ctx, a->rs2, EXT_NONE);

    tcg_gen_setcond_tl(TCG_COND_LEU, dest, src1, src2);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_min(DisasContext *ctx, arg_cv_min *a)
{
    REQUIRE_XCVALU(ctx);
    return gen_arith(ctx, a, EXT_NONE, tcg_gen_smin_tl, NULL);
}

static bool trans_cv_minu(DisasContext *ctx, arg_cv_minu *a)
{
    REQUIRE_XCVALU(ctx);
    return gen_arith(ctx, a, EXT_NONE, tcg_gen_umin_tl, NULL);
}

static bool trans_cv_max(DisasContext *ctx, arg_cv_max *a)
{
    REQUIRE_XCVALU(ctx);
    return gen_arith(ctx, a, EXT_NONE, tcg_gen_smax_tl, NULL);
}

static bool trans_cv_maxu(DisasContext *ctx, arg_cv_maxu *a)
{
    REQUIRE_XCVALU(ctx);
    return gen_arith(ctx, a, EXT_NONE, tcg_gen_umax_tl, NULL);
}

static bool trans_cv_exths(DisasContext *ctx, arg_cv_exths *a)
{
    REQUIRE_XCVALU(ctx);
    return gen_unary(ctx, a, EXT_NONE, tcg_gen_ext16s_tl);
}

static bool trans_cv_exthz(DisasContext *ctx, arg_cv_exthz *a)
{
    REQUIRE_XCVALU(ctx);
    return gen_unary(ctx, a, EXT_NONE, tcg_gen_ext16u_tl);
}

static bool trans_cv_extbs(DisasContext *ctx, arg_cv_extbs *a)
{
    REQUIRE_XCVALU(ctx);
    return gen_unary(ctx, a, EXT_NONE, tcg_gen_ext8s_tl);
}

static bool trans_cv_extbz(DisasContext *ctx, arg_cv_extbz *a)
{
    REQUIRE_XCVALU(ctx);
    return gen_unary(ctx, a, EXT_NONE, tcg_gen_ext8u_tl);
}

static bool trans_cv_clip(DisasContext *ctx, arg_cv_clip *a)
{
    REQUIRE_XCVALU(ctx);
    return gen_arith_imm_tl(ctx, a, EXT_NONE, gen_helper_clip, NULL);
}

static bool trans_cv_clipr(DisasContext *ctx, arg_cv_clipr *a)
{
    REQUIRE_XCVALU(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_clipr, NULL);
}

static bool trans_cv_clipu(DisasContext *ctx, arg_cv_clipu *a)
{
    REQUIRE_XCVALU(ctx);
    return gen_arith_imm_tl(ctx, a, EXT_NONE, gen_helper_clipu, NULL);
}

static bool trans_cv_clipur(DisasContext *ctx, arg_cv_clipur *a)
{
    REQUIRE_XCVALU(ctx);
    return gen_arith(ctx, a, EXT_NONE, gen_helper_clipur, NULL);
}

#define GEN_ARITH_SHIFT_IMM(NAME, OP, SHIFT, EXT)           \
static bool trans_##NAME(DisasContext *ctx, arg_##NAME *a)  \
{                                                           \
    REQUIRE_XCVALU(ctx);                                    \
    TCGv dest = dest_gpr(ctx, a->rd);                       \
    TCGv src1 = get_gpr(ctx, a->rs1, EXT);                  \
    TCGv src2 = get_gpr(ctx, a->rs2, EXT);                  \
                                                            \
    tcg_gen_##OP##_tl(dest, src1, src2);                    \
    tcg_gen_##SHIFT##_tl(dest, dest, a->imm);               \
    gen_set_gpr(ctx, a->rd, dest);                          \
    return true;                                            \
}

GEN_ARITH_SHIFT_IMM(cv_addN, add, sari, EXT_NONE)
GEN_ARITH_SHIFT_IMM(cv_adduN, add, shri, EXT_NONE)
GEN_ARITH_SHIFT_IMM(cv_subN, sub, sari, EXT_NONE)
GEN_ARITH_SHIFT_IMM(cv_subuN, sub, shri, EXT_NONE)

#define GEN_ARITH_R_SHIFT_IMM(NAME, OP, SHIFT, EXT)         \
static bool trans_##NAME(DisasContext *ctx, arg_##NAME *a)  \
{                                                           \
    REQUIRE_XCVALU(ctx);                                    \
    TCGv dest = dest_gpr(ctx, a->rd);                       \
    TCGv src1 = get_gpr(ctx, a->rs1, EXT);                  \
    TCGv src2 = get_gpr(ctx, a->rs2, EXT);                  \
    TCGv src3 = tcg_constant_tl(1 << (a->imm - 1));         \
                                                            \
    tcg_gen_##OP##_tl(dest, src1, src2);                    \
    tcg_gen_add_tl(dest, dest, src3);                       \
    tcg_gen_##SHIFT##_tl(dest, dest, a->imm);               \
    gen_set_gpr(ctx, a->rd, dest);                          \
    return true;                                            \
}

GEN_ARITH_R_SHIFT_IMM(cv_addRN, add, sari, EXT_NONE)
GEN_ARITH_R_SHIFT_IMM(cv_adduRN, add, shri, EXT_NONE)
GEN_ARITH_R_SHIFT_IMM(cv_subRN, sub, sari, EXT_NONE)
GEN_ARITH_R_SHIFT_IMM(cv_subuRN, sub, shri, EXT_NONE)

#define GEN_ARITH_SHIFT_REG(NAME, OP, SHIFT, EXT)           \
static bool trans_##NAME(DisasContext *ctx, arg_##NAME *a)  \
{                                                           \
    REQUIRE_XCVALU(ctx);                                    \
    TCGv t0 = tcg_temp_new();                               \
    TCGv t1 = tcg_temp_new();                               \
    TCGv dest = get_gpr(ctx, a->rd, EXT);                   \
    TCGv src1 = get_gpr(ctx, a->rs1, EXT);                  \
    TCGv src2 = get_gpr(ctx, a->rs2, EXT);                  \
                                                            \
    tcg_gen_##OP##_tl(t0, dest, src1);                      \
    tcg_gen_andi_tl(t1, src2, 0x1F);                        \
    tcg_gen_##SHIFT##_tl(t0, t0, t1);                       \
    gen_set_gpr(ctx, a->rd, t0);                            \
    tcg_temp_free(t0);                                      \
    tcg_temp_free(t1);                                      \
    return true;                                            \
}

GEN_ARITH_SHIFT_REG(cv_addNr, add, sar, EXT_NONE)
GEN_ARITH_SHIFT_REG(cv_adduNr, add, shr, EXT_NONE)
GEN_ARITH_SHIFT_REG(cv_subNr, sub, sar, EXT_NONE)
GEN_ARITH_SHIFT_REG(cv_subuNr, sub, shr, EXT_NONE)

#define GEN_ARITH_R_SHIFT_REG(NAME, OP, SHIFT, EXT)         \
static bool trans_##NAME(DisasContext *ctx, arg_##NAME *a)  \
{                                                           \
    REQUIRE_XCVALU(ctx);                                    \
    TCGv t0 = tcg_temp_new();                               \
    TCGv t1 = tcg_temp_new();                               \
    TCGv t2 = tcg_temp_new();                               \
    TCGv dest = get_gpr(ctx, a->rd, EXT);                   \
    TCGv src1 = get_gpr(ctx, a->rs1, EXT);                  \
    TCGv src2 = get_gpr(ctx, a->rs2, EXT);                  \
                                                            \
    tcg_gen_##OP##_tl(t0, dest, src1);                      \
    tcg_gen_andi_tl(t1, src2, 0x1F);                        \
    tcg_gen_subi_tl(t2, t1, 1);                             \
    tcg_gen_shl_tl(t2, tcg_constant_tl(1), t2);             \
    tcg_gen_add_tl(t0, t0, t2);                             \
    tcg_gen_##SHIFT##_tl(t0, t0, t1);                       \
    gen_set_gpr(ctx, a->rd, t0);                            \
    tcg_temp_free(t0);                                      \
    tcg_temp_free(t1);                                      \
    tcg_temp_free(t2);                                      \
    return true;                                            \
}

GEN_ARITH_R_SHIFT_REG(cv_addRNr, add, sar, EXT_NONE)
GEN_ARITH_R_SHIFT_REG(cv_adduRNr, add, shr, EXT_NONE)
GEN_ARITH_R_SHIFT_REG(cv_subRNr, sub, sar, EXT_NONE)
GEN_ARITH_R_SHIFT_REG(cv_subuRNr, sub, shr, EXT_NONE)

static bool gen_bimm(DisasContext *ctx, arg_bimm *a, TCGCond cond)
{
    check_hwlp_body(ctx, HWLP_TYPE_JUMP_BR);
    TCGLabel *l = gen_new_label();
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv src2 = tcg_constant_tl(a->imm);

    tcg_gen_brcond_tl(cond, src1, src2, l);
    gen_goto_tb(ctx, 1, ctx->pc_succ_insn);

    gen_set_label(l); /* branch taken */

    if (!has_ext(ctx, RVC) && ((ctx->base.pc_next + a->offset) & 0x3)) {
        /* misaligned */
        gen_exception_inst_addr_mis(ctx);
    } else {
        gen_goto_tb(ctx, 0, ctx->base.pc_next + a->offset);
    }
    ctx->base.is_jmp = DISAS_NORETURN;

    return true;
}

static bool trans_cv_beqimm(DisasContext *ctx, arg_cv_beqimm *a)
{
    REQUIRE_XCVBI(ctx);
    return gen_bimm(ctx, a, TCG_COND_EQ);
}

static bool trans_cv_bneimm(DisasContext *ctx, arg_cv_bneimm *a)
{
    REQUIRE_XCVBI(ctx);
    return gen_bimm(ctx, a, TCG_COND_NE);
}
