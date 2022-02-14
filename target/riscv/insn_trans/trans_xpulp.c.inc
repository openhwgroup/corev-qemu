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

#define REQUIRE_XCVMEM(ctx) do {          \
    if (!ctx->cfg_ptr->ext_xcvmem) {      \
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
