/*
 * RISC-V translation routines for the XCVbitmanip Vendor Extension.
 *
 * Copyright (c) 2024 OPENHW group with PLCT lab
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

#define REQUIRE_XCVBITMANIP(ctx) do {            \
    if (!ctx->cfg_ptr->ext_xcvbitmanip) {        \
        return false;                      \
    }                                      \
} while (0)

static bool gen_cv_bitrev(DisasContext *ctx, arg_cv_bitrev *a,
                          void (*func)(TCGv, TCGv, TCGv, TCGv))
{
    TCGv limm2 = tcg_constant_tl(a->limm2);
    TCGv limm5 = tcg_constant_tl(a->limm5);
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    
    func(dest, src1, limm5, limm2);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_bitrev(DisasContext *ctx, arg_cv_bitrev *a)
{
    REQUIRE_32BIT(ctx);
    REQUIRE_XCVBITMANIP(ctx);
    return gen_cv_bitrev(ctx, a, gen_helper_cv_bitrev);
}

static bool gen_cv_extract(DisasContext *ctx, arg_cv_extract *a,
                           void (*func)(TCGv, TCGv, TCGv, TCGv))
{
    TCGv rimm5 = tcg_constant_tl(a->rimm5);
    TCGv limm5 = tcg_constant_tl(a->limm5);
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    
    func(dest, src1, limm5, rimm5);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_extract(DisasContext *ctx, arg_cv_extract *a)
{
    REQUIRE_32BIT(ctx);
    REQUIRE_XCVBITMANIP(ctx);
    return gen_cv_extract(ctx, a, gen_helper_cv_extract);
}

static bool gen_cv_extractu(DisasContext *ctx, arg_cv_extractu *a,
                            void (*func)(TCGv, TCGv, TCGv, TCGv))
{
    TCGv rimm5 = tcg_constant_tl(a->rimm5);
    TCGv limm5 = tcg_constant_tl(a->limm5);
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    
    func(dest, src1, limm5, rimm5);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_extractu(DisasContext *ctx, arg_cv_extractu *a)
{
    REQUIRE_32BIT(ctx);
    REQUIRE_XCVBITMANIP(ctx);
    return gen_cv_extractu(ctx, a, gen_helper_cv_extractu);
}

static bool gen_cv_extractr(DisasContext *ctx, arg_cv_extractr *a,
                            void (*func)(TCGv, TCGv, TCGv))
{
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv src2 = get_gpr(ctx, a->rs2, EXT_NONE);
    TCGv dest = dest_gpr(ctx, a->rd);
    
    func(dest, src1, src2);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_extractr(DisasContext *ctx, arg_cv_extractr *a)
{
    REQUIRE_32BIT(ctx);
    REQUIRE_XCVBITMANIP(ctx);
    return gen_cv_extractr(ctx, a, gen_helper_cv_extractr);
}

static bool gen_cv_extractur(DisasContext *ctx, arg_cv_extractur *a,
                             void (*func)(TCGv, TCGv, TCGv))
{
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv src2 = get_gpr(ctx, a->rs2, EXT_NONE);
    TCGv dest = dest_gpr(ctx, a->rd);
    
    func(dest, src1, src2);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_extractur(DisasContext *ctx, arg_cv_extractur *a)
{
    REQUIRE_32BIT(ctx);
    REQUIRE_XCVBITMANIP(ctx);
    return gen_cv_extractur(ctx, a, gen_helper_cv_extractur);
}

static bool gen_cv_insert(DisasContext *ctx, arg_cv_insert *a,
                            void (*func)(TCGv, TCGv, TCGv, TCGv))
{
    TCGv rimm5 = tcg_constant_tl(a->rimm5);
    TCGv limm5 = tcg_constant_tl(a->limm5);
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    
    func(dest, src1, limm5, rimm5);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_insert(DisasContext *ctx, arg_cv_insert *a)
{
    REQUIRE_32BIT(ctx);
    REQUIRE_XCVBITMANIP(ctx);
    return gen_cv_insert(ctx, a, gen_helper_cv_insert);
}

static bool gen_cv_insertr(DisasContext *ctx, arg_cv_insertr *a,
                            void (*func)(TCGv, TCGv, TCGv))
{
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv src2 = get_gpr(ctx, a->rs2, EXT_NONE);
    TCGv dest = dest_gpr(ctx, a->rd);
    
    func(dest, src1, src2);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_insertr(DisasContext *ctx, arg_cv_insertr *a)
{
    REQUIRE_32BIT(ctx);
    REQUIRE_XCVBITMANIP(ctx);
    return gen_cv_insertr(ctx, a, gen_helper_cv_insertr);
}

static bool gen_cv_bclr(DisasContext *ctx, arg_cv_bclr *a,
                        void (*func)(TCGv, TCGv, TCGv, TCGv))
{
    TCGv rimm5 = tcg_constant_tl(a->rimm5);
    TCGv limm5 = tcg_constant_tl(a->limm5);
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    
    func(dest, src1, limm5, rimm5);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_bclr(DisasContext *ctx, arg_cv_bclr *a)
{
    REQUIRE_32BIT(ctx);
    REQUIRE_XCVBITMANIP(ctx);
    return gen_cv_bclr(ctx, a, gen_helper_cv_bclr);
}

static bool gen_cv_bclrr(DisasContext *ctx, arg_cv_bclrr *a,
                         void (*func)(TCGv, TCGv, TCGv))
{
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv src2 = get_gpr(ctx, a->rs2, EXT_NONE);
    TCGv dest = dest_gpr(ctx, a->rd);
    
    func(dest, src1, src2);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_bclrr(DisasContext *ctx, arg_cv_bclrr *a)
{
    REQUIRE_32BIT(ctx);
    REQUIRE_XCVBITMANIP(ctx);
    return gen_cv_bclrr(ctx, a, gen_helper_cv_bclrr);
}

static bool gen_cv_bset(DisasContext *ctx, arg_cv_bset *a,
                        void (*func)(TCGv, TCGv, TCGv, TCGv))
{
    TCGv rimm5 = tcg_constant_tl(a->rimm5);
    TCGv limm5 = tcg_constant_tl(a->limm5);
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    
    func(dest, src1, limm5, rimm5);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_bset(DisasContext *ctx, arg_cv_bset *a)
{
    REQUIRE_32BIT(ctx);
    REQUIRE_XCVBITMANIP(ctx);
    return gen_cv_bset(ctx, a, gen_helper_cv_bset);
}

static bool gen_cv_bsetr(DisasContext *ctx, arg_cv_bsetr *a,
                         void (*func)(TCGv, TCGv, TCGv))
{
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv src2 = get_gpr(ctx, a->rs2, EXT_NONE);
    TCGv dest = dest_gpr(ctx, a->rd);
    
    func(dest, src1, src2);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_bsetr(DisasContext *ctx, arg_cv_bsetr *a)
{
    REQUIRE_32BIT(ctx);
    REQUIRE_XCVBITMANIP(ctx);
    return gen_cv_bsetr(ctx, a, gen_helper_cv_bsetr);
}

static bool gen_cv_ff1(DisasContext *ctx, arg_cv_ff1 *a,
                       void (*func)(TCGv, TCGv))
{
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv dest = dest_gpr(ctx, a->rd);
    
    func(dest, src1);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_ff1(DisasContext *ctx, arg_cv_ff1 *a)
{
    REQUIRE_32BIT(ctx);
    REQUIRE_XCVBITMANIP(ctx);
    return gen_cv_ff1(ctx, a, gen_helper_cv_ff1);
}

static bool gen_cv_fl1(DisasContext *ctx, arg_cv_fl1 *a,
                       void (*func)(TCGv, TCGv))
{
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv dest = dest_gpr(ctx, a->rd);
    
    func(dest, src1);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_fl1(DisasContext *ctx, arg_cv_fl1 *a)
{
    REQUIRE_32BIT(ctx);
    REQUIRE_XCVBITMANIP(ctx);
    return gen_cv_fl1(ctx, a, gen_helper_cv_fl1);
}

static bool gen_cv_clb(DisasContext *ctx, arg_cv_clb *a,
                       void (*func)(TCGv, TCGv))
{
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv dest = dest_gpr(ctx, a->rd);
    
    func(dest, src1);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_clb(DisasContext *ctx, arg_cv_clb *a)
{
    REQUIRE_32BIT(ctx);
    REQUIRE_XCVBITMANIP(ctx);
    return gen_cv_clb(ctx, a, gen_helper_cv_clb);
}

static bool gen_cv_cnt(DisasContext *ctx, arg_cv_cnt *a,
                       void (*func)(TCGv, TCGv))
{
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv dest = dest_gpr(ctx, a->rd);
    
    func(dest, src1);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_cnt(DisasContext *ctx, arg_cv_cnt *a)
{
    REQUIRE_32BIT(ctx);
    REQUIRE_XCVBITMANIP(ctx);
    return gen_cv_cnt(ctx, a, gen_helper_cv_cnt);
}

static bool gen_cv_ror(DisasContext *ctx, arg_cv_ror *a,
                       void (*func)(TCGv, TCGv, TCGv))
{
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv src2 = get_gpr(ctx, a->rs2, EXT_NONE);
    TCGv dest = dest_gpr(ctx, a->rd);
    
    func(dest, src1, src2);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_cv_ror(DisasContext *ctx, arg_cv_ror *a)
{
    REQUIRE_32BIT(ctx);
    REQUIRE_XCVBITMANIP(ctx);
    return gen_cv_ror(ctx, a, gen_helper_cv_ror);
}
