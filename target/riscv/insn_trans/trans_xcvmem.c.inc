/*
 * CORE-V Instruction Set Custom XCVMEM Extensions.
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

#define REQUIRE_XCVMEM(ctx) do {            \
    if (!ctx->cfg_ptr->ext_xcvmem) {         \
        return false;                      \
    }                                      \
} while (0)

static bool gen_cv_load_tl(DisasContext *ctx, arg_lb *a, MemOp memop)
{
    TCGv dest = dest_gpr(ctx, a->rd);            // Destination register
    TCGv addr = get_address(ctx, a->rs1, a->imm); // Calculate address with immediate

    // Load from memory
    tcg_gen_qemu_ld_tl(dest, addr, ctx->mem_idx, memop);
    gen_set_gpr(ctx, a->rd, dest);

    // Update the value of rs1 with the immediate value
    TCGv rs1 = get_gpr(ctx, a->rs1, EXT_NONE);

    // Extract immediate value directly as an integer
    int32_t imm = a->imm; 
    tcg_gen_addi_tl(rs1, rs1, imm);
    gen_set_gpr(ctx, a->rs1, rs1);

    return true;
}

static bool gen_cv_load(DisasContext *ctx, arg_lb *a, MemOp memop)
{
    bool out;

    decode_save_opc(ctx);

    // Use the cv_load translation function if the extension is enabled
    out = gen_cv_load_tl(ctx, a, memop);

    if (ctx->ztso) {
        tcg_gen_mb(TCG_MO_ALL | TCG_BAR_LDAQ);
    }

    return out;
}

static bool trans_cv_lb(DisasContext *ctx, arg_cv_lb *a)
{
    REQUIRE_XCVMEM(ctx);

    // Use the gen_cv_load function with bytes.
    return gen_cv_load(ctx, a, MO_SB);
}

static bool trans_cv_lbu(DisasContext *ctx, arg_cv_lbu *a)
{
    REQUIRE_XCVMEM(ctx);

    // Use the gen_cv_load function with unsigned byte.
    return gen_cv_load(ctx, a, MO_UB);
}

static bool trans_cv_lh(DisasContext *ctx, arg_cv_lh *a)
{
    REQUIRE_XCVMEM(ctx);

    // Use the gen_cv_load function with halfword.
    return gen_cv_load(ctx, a, MO_TESW);
}

static bool trans_cv_lhu(DisasContext *ctx, arg_cv_lhu *a)
{
    REQUIRE_XCVMEM(ctx);

    // Use the gen_cv_load function with unsigned halfword.
    return gen_cv_load(ctx, a, MO_TEUW);
}

static bool trans_cv_lw(DisasContext *ctx, arg_cv_lw *a)
{
    REQUIRE_XCVMEM(ctx);

    // Use the gen_cv_load function with word.
    return gen_cv_load(ctx, a, MO_TESL);
}

static bool gen_cv_store_tl(DisasContext *ctx, arg_cv_sb *a, MemOp memop)
{
    // Retrieve the address and data
    TCGv addr = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv data = get_gpr(ctx, a->rs2, EXT_NONE);

    if (ctx->ztso) {
        tcg_gen_mb(TCG_MO_ALL | TCG_BAR_STRL);
    }

    // Perform the store operation
    tcg_gen_qemu_st_tl(data, addr, ctx->mem_idx, memop);

    // Update the value of rs1 with the sign-extended immediate value (post-increment)
    int32_t imm = a->imm;
    tcg_gen_addi_tl(addr, addr, imm);
    gen_set_gpr(ctx, a->rs1, addr);

    return true;
}

static bool gen_cv_store(DisasContext *ctx, arg_cv_sb *a, MemOp memop)
{
    decode_save_opc(ctx);

    return gen_cv_store_tl(ctx, a, memop);
}

static bool trans_cv_sb(DisasContext *ctx, arg_cv_sb *a)
{
    REQUIRE_XCVMEM(ctx);

    // Use the generic cv_store function for storing a signed byte with post-increment
    return gen_cv_store(ctx, a, MO_SB);
}

static bool trans_cv_sh(DisasContext *ctx, arg_cv_sh *a)
{
    REQUIRE_XCVMEM(ctx);

    // Use the generic cv_store function for storing a signed half-word with post-increment
    return gen_cv_store(ctx, a, MO_TESW);
}

static bool trans_cv_sw(DisasContext *ctx, arg_cv_sw *a)
{
    REQUIRE_XCVMEM(ctx);

    // Use the generic cv_store function for storing a signed word with post-increment
    return gen_cv_store(ctx, a, MO_TESL);
}

static bool trans_cv_elw(DisasContext *ctx, arg_cv_elw *a)
{
    // Check if the PULP Cluster extension is enabled
    if (!ctx->cfg_ptr->corev_cluster) {
        return false; // PULP Cluster extension not enabled
    }

    // Load immediate value into TCG variable
    TCGv rs1 = get_gpr(ctx, a->rs1, EXT_NONE); // Source register (base address)

    // Calculate the memory address by adding the sign-extended immediate value to rs1
    TCGv mem_addr = rs1; // Use rs1 directly for address calculation
    tcg_gen_addi_tl(mem_addr, rs1, a->imm); // mem_addr = rs1 + imm

    // Perform the load operation from memory
    gen_cv_load(ctx, a, MO_TESL); // Load the word from the calculated address into rd

    // Conditions for core sleep state
    // Note: This is a placeholder for actual hardware integration
    bool debug_req_pending = false; // Determine based on actual debug request status
    bool in_debug_mode = false; // Determine based on actual debug mode status
    bool single_stepping = false; // Determine based on actual single-stepping status
    bool trigger_match = false; // Determine based on actual trigger match status

    // Simulate core sleep state handling
    if (debug_req_pending || in_debug_mode || single_stepping || trigger_match) {
        // Core cannot go to sleep if any of these conditions are true
        // Set core_sleep_o to 0 (not going to sleep)
        // Integration with actual hardware signal mechanism is required here
    } else {
        // Core can go to sleep, set core_sleep_o to 1
        // Integration with actual hardware signal mechanism is required here
    }

    return true; // Indicate that the translation was successful
}
