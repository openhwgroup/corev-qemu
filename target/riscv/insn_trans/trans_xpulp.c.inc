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
