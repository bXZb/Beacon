#pragma once
/* Pass-1 stub: keep bw_layout_reg_n and the live table the same shape as a
 * typical 6-region image so gargle codegen size matches pass-2. */
#define BW_LAYOUT_SOI        0x400000ULL
#define BW_LAYOUT_REG_MAX    16
static const unsigned long long bw_layout_reg[BW_LAYOUT_REG_MAX][2] = {
    {0x0ULL, 0x1000ULL},
    {0x1000ULL, 0x20000ULL},
    {0x20000ULL, 0x30000ULL},
    {0x30000ULL, 0x40000ULL},
    {0x40000ULL, 0x50000ULL},
    {0x50000ULL, 0x60000ULL},
    {0ULL, 0ULL},{0ULL, 0ULL},{0ULL, 0ULL},{0ULL, 0ULL},
    {0ULL, 0ULL},{0ULL, 0ULL},{0ULL, 0ULL},{0ULL, 0ULL},
    {0ULL, 0ULL},{0ULL, 0ULL},
};
static const unsigned long long bw_layout_reg_n = 6ULL;
