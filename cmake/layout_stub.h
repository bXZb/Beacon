#pragma once
#define BW_LAYOUT_SOI        0x400000ULL
#define BW_LAYOUT_REG_MAX    16
#pragma section(".bwlay", read)
__declspec(allocate(".bwlay"))
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
__declspec(allocate(".bwlay"))
static const unsigned long long bw_layout_reg_n = 6ULL;
