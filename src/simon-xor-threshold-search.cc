/*
 *    Copyright (c) 2012-2013 Luxembourg University,
 *    Laboratory of Algorithmics, Cryptology and Security (LACS).
 *
 *    This file is part of the YAARX toolkit. YAARX stands for
 *    Yet Another ARX toolkit for analysis of ARX cryptographic algorithms.
 *
 *    YAARX is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    YAARX is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with YAARX.  If not, see <http://www.gnu.org/licenses/>.
 */
/**
 * \file  simon-xor-threshold-search.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Automatic search for XOR differentials in block cipher Simon.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_AND_H
#include "xdp-and.hh"
#endif
#ifndef XDP_ROT_AND_H
#include "xdp-rot-and.hh"
#endif
#ifndef SIMON_H
#include "simon.hh"
#endif
#ifndef SIMON_XOR_THRESHOLD_SEARCH_H
#include "simon-xor-threshold-search.hh"
#endif


// Best found bounds and trails for Simon32
#if(WORD_SIZE == 16)

#if 0									  // trail 1, 13R, 2^-36
/*
Found with parameters:

[./src/simon-xor-threshold-search.cc:2042] WORD_SIZE 16 NROUNDS 13 XDP_ROT_AND_P_THRES 0.060000 2^-4.058894 XDP_ROT_AND_MAX_DIFF_CNT 128 2^7.00 SIMON_EPS 0.000031 2^-15.000000 XDP_ROT_AND_MAX_HW 32 TRAIL_MAX_HW 32 SIMON_BACK_TO_HWAY 1

*/
double g_B[SIMON_TRAIL_LEN] = {
  (1.0 / (double)(1ULL <<  0)),
  (1.0 / (double)(1ULL <<  4)),
  (1.0 / (double)(1ULL <<  4)),
  (1.0 / (double)(1ULL <<  6)),
  (1.0 / (double)(1ULL <<  8)),
  (1.0 / (double)(1ULL << 12)),
  (1.0 / (double)(1ULL << 14)),
  (1.0 / (double)(1ULL << 18)),
  (1.0 / (double)(1ULL << 20)),
  (1.0 / (double)(1ULL << 26)),
  (1.0 / (double)(1ULL << 30)),
  (1.0 / (double)(1ULL << 34)), // 12
  (1.0 / (double)(1ULL << 36)), // 13
  0.0,
  0.0,
};
differential_t g_trail[SIMON_TRAIL_LEN] = {
  {   0x0,    0x0, 0,  1.000000}, //(2^0.000000)
  {0x8000,    0x2, 0, 0.250000}, //(2^-2.000000)
  {   0x2, 0x8008, 0, 0.250000}, //(2^-2.000000)
  {0x8008,   0x20, 0, 0.062500}, //(2^-4.000000)
  {  0x20, 0x8088, 0, 0.250000}, //(2^-2.000000)
  {0x8088,  0x202, 0, 0.015625}, //(2^-6.000000)
  { 0x202, 0x8880, 0, 0.062500}, //(2^-4.000000)
  {0x8880, 0x2000, 0, 0.015625}, //(2^-6.000000)
  {0x2000,  0x880, 0, 0.250000}, //(2^-2.000000)
  { 0x880,  0x200, 0, 0.062500}, //(2^-4.000000)
  { 0x200,   0x80, 0, 0.250000}, //(2^-2.000000)
  {  0x80,    0x0, 0, 0.250000}, //(2^-2.000000)
  {   0x0,   0x80, 0, 1.000000}, //(2^0.000000)
  {0, 0, 0, 0.0},
  {0, 0, 0, 0.0}
};
#endif
#if 0									  // trail 2, 13R, 2^-36
double g_B[SIMON_TRAIL_LEN] = {
  (1.0 / (double)(1ULL <<  0)),
  (1.0 / (double)(1ULL <<  4)),
  (1.0 / (double)(1ULL <<  4)),
  (1.0 / (double)(1ULL <<  6)),
  (1.0 / (double)(1ULL <<  8)),
  (1.0 / (double)(1ULL << 12)),
  (1.0 / (double)(1ULL << 14)),
  (1.0 / (double)(1ULL << 18)),
  (1.0 / (double)(1ULL << 20)),
  (1.0 / (double)(1ULL << 25)),
  (1.0 / (double)(1ULL << 30)),
  (1.0 / (double)(1ULL << 34)), // 12
  (1.0 / (double)(1ULL << 36)), // 13
  (1.0 / (double)(1ULL << 38)),
  (1.0 / (double)(1ULL << 40))
};
differential_t g_trail[SIMON_TRAIL_LEN] = {
  {   0x0,    0x0, 0, 1.000000}, //(2^-0.000000)
  {  0x40,  0x100, 0, 0.250000}, //(2^-2.000000)
  { 0x100,  0x440, 0, 0.250000}, //(2^-2.000000)
  { 0x440, 0x1000, 0, 0.062500}, //(2^-4.000000)
  {0x1000, 0x4440, 0, 0.250000}, //(2^-2.000000)
  {0x4440,  0x101, 0, 0.015625}, //(2^-6.000000)
  { 0x101, 0x4044, 0, 0.062500}, //(2^-4.000000)
  {0x4044,   0x10, 0, 0.015625}, //(2^-6.000000)
  {  0x10, 0x4004, 0, 0.250000}, //(2^-2.000000)
  {0x4004,    0x1, 0, 0.062500}, //(2^-4.000000)
  {   0x1, 0x4000, 0, 0.250000}, //(2^-2.000000)
  {0x4000,    0x0, 0, 0.250000}, //(2^-2.000000)
  {   0x0, 0x4000, 0, 1.000000}, //(2^-0.000000)
  {0x4000,    0x1, 0, 0.250000}, //(2^-2.000000)
  {   0x1, 0x4004, 0, 0.250000} //(2^-2.000000)
};
#endif  // #if 0
#if 1									  // trail 3, 12R, 2^-34
double g_B[SIMON_TRAIL_LEN] = {
  (1.0 / (double)(1ULL <<  0)),
  (1.0 / (double)(1ULL <<  4)),
  (1.0 / (double)(1ULL <<  4)),
  (1.0 / (double)(1ULL <<  6)),
  (1.0 / (double)(1ULL <<  8)),
  (1.0 / (double)(1ULL << 12)),
  (1.0 / (double)(1ULL << 14)),
  (1.0 / (double)(1ULL << 18)),
  (1.0 / (double)(1ULL << 20)),
  (1.0 / (double)(1ULL << 25)),
  (1.0 / (double)(1ULL << 30)),
  (1.0 / (double)(1ULL << 34)), // 12
  0.0,
  0.0,
  0.0
};
differential_t g_trail[SIMON_TRAIL_LEN] = {
{ 0x400, 0x1800, 0, 0.250000}, //(2^-2.000000)
{ 0x100,    0x0, 0, 0.250000}, //(2^-2.000000)
{   0x0,  0x100, 0, 1.000000}, //(2^0.000000)
{ 0x100,  0x400, 0, 0.250000}, //(2^-2.000000)
{ 0x400, 0x1100, 0, 0.250000}, //(2^-2.000000)
{0x1100, 0x4200, 0, 0.062500}, //(2^-4.000000)
{0x4200, 0x1D01, 0, 0.062500}, //(2^-4.000000)
{0x1D01,  0x500, 0, 0.003906}, //(2^-8.000000)
{ 0x500,  0x100, 0, 0.125000}, //(2^-3.000000)
{ 0x100,  0x100, 0, 0.250000}, //(2^-2.000000)
{ 0x100,  0x500, 0, 0.250000}, //(2^-2.000000)
{ 0x500, 0x1500, 0, 0.125000}, //(2^-3.000000)
{0, 0, 0, 0.0},
{0, 0, 0, 0.0},
{0, 0, 0, 0.0}
};
#endif  // #if 0

#elif(WORD_SIZE == 24)
// Best found bounds and trails for Simon48
/*
Found with parameters:
Time: Tue Oct 29 11:59:36 2013
[./tests/simon-xor-threshold-search-tests.cc:2205] 
 WORD_SIZE 24
 NROUNDS 15
 XDP_ROT_AND_P_THRES 0.05
 XDP_ROT_AND_MAX_DIFF_CNT 32 2^5.00
 SIMON_EPS 0.000031 2^-15.000000
*/

#if 1
double g_B[SIMON_TRAIL_LEN] = {
  (1.0 / (double)(1ULL <<  0)),
  (1.0 / (double)(1ULL <<  4)),
  (1.0 / (double)(1ULL <<  4)),
  (1.0 / (double)(1ULL <<  6)),
  (1.0 / (double)(1ULL <<  8)),
  (1.0 / (double)(1ULL << 12)),
  (1.0 / (double)(1ULL << 14)),
  (1.0 / (double)(1ULL << 18)),
  (1.0 / (double)(1ULL << 24)),
  (1.0 / (double)(1ULL << 28)),
  (1.0 / (double)(1ULL << 30)),
  (1.0 / (double)(1ULL << 36)),
  (1.0 / (double)(1ULL << 38)),
  (1.0 / (double)(1ULL << 44)),
  (1.0 / (double)(1ULL << 48))
};

differential_t g_trail[SIMON_TRAIL_LEN] = {
  {0x200020, 0x800080, 0, 0.062500}, //(2^-4.000000)
  {0x880008,      0x2, 0, 0.015625}, //(2^-6.000000)
  {     0x2, 0x880000, 0, 0.250000}, //(2^-2.000000)
  {0x880000, 0x200000, 0, 0.062500}, //(2^-4.000000)
  {0x200000,  0x80000, 0, 0.250000}, //(2^-2.000000)
  { 0x80000,      0x0, 0, 0.250000}, //(2^-2.000000)
  {     0x0,  0x80000, 0, 1.000000}, //(2^0.000000)
  { 0x80000, 0x200000, 0, 0.250000}, //(2^-2.000000)
  {0x200000, 0x880000, 0, 0.250000}, //(2^-2.000000)
  {0x880000,      0x2, 0, 0.062500}, //(2^-4.000000)
  {     0x2, 0x880008, 0, 0.250000}, //(2^-2.000000)
  {0x880008, 0x200020, 0, 0.015625}, //(2^-6.000000)
  {0x200020,  0x80088, 0, 0.062500}, //(2^-4.000000)
  { 0x80088,    0x200, 0, 0.015625}, //(2^-6.000000)
  {   0x200,  0x80888, 0, 0.250000} //(2^-2.000000)
};
#endif
#if 0
double g_B[SIMON_TRAIL_LEN] = {
  (1.0 / (double)(1ULL <<  0)),
  (1.0 / (double)(1ULL <<  4)),
  (1.0 / (double)(1ULL <<  4)),
  (1.0 / (double)(1ULL <<  6)),
  (1.0 / (double)(1ULL <<  8)),
  (1.0 / (double)(1ULL << 12)),
  (1.0 / (double)(1ULL << 14)),
  (1.0 / (double)(1ULL << 18)),
  (1.0 / (double)(1ULL << 20)),
  (1.0 / (double)(1ULL << 26)),
  (1.0 / (double)(1ULL << 30)),
  (1.0 / (double)(1ULL << 36)), // 12
  (1.0 / (double)(1ULL << 38)), // 13
  (1.0 / (double)(1ULL << 44)),
  (1.0 / (double)(1ULL << 48))
};
differential_t g_trail[SIMON_TRAIL_LEN] = {
  {0x200000, 0x800000, 0, 0.250000}, //(2^-2.000000)
  { 0x88080,  0x20200, 0, 0.015625}, //(2^-6.000000)
  { 0x20200,   0x8880, 0, 0.062500}, //(2^-4.000000)
  {  0x8880,   0x2000, 0, 0.015625}, //(2^-6.000000)
  {  0x2000,    0x880, 0, 0.250000}, //(2^-2.000000)
  {   0x880,    0x200, 0, 0.062500}, //(2^-4.000000)
  {   0x200,     0x80, 0, 0.250000}, //(2^-2.000000)
  {    0x80,      0x0, 0, 0.250000}, //(2^-2.000000)
  {     0x0,     0x80, 0, 1.000000}, //(2^0.000000)
  {    0x80,    0x200, 0, 0.250000}, //(2^-2.000000)
  {   0x200,    0x880, 0, 0.250000}, //(2^-2.000000)
  {   0x880,   0x2000, 0, 0.062500}, //(2^-4.000000)
  {  0x2000,   0x8880, 0, 0.250000}, //(2^-2.000000)
  {  0x8880,  0x20200, 0, 0.015625}, //(2^-6.000000)
  { 0x20200,  0x88080, 0, 0.062500} //(2^-4.000000)
};
#endif  // #if 0
#elif(WORD_SIZE == 32)
// Best found bounds and trails for Simon64
double g_B[SIMON_TRAIL_LEN] = {
  (1.0 / (double)(1ULL <<  0)),
  (1.0 / (double)(1ULL <<  4)),
  (1.0 / (double)(1ULL <<  4)),
  (1.0 / (double)(1ULL <<  6)),
  (1.0 / (double)(1ULL <<  8)),
  (1.0 / (double)(1ULL << 12)),
  (1.0 / (double)(1ULL << 14)),
  (1.0 / (double)(1ULL << 18)),
  (1.0 / (double)(1ULL << 20)),
  (1.0 / (double)(1ULL << 26)),
  (1.0 / (double)(1ULL << 30)),
  (1.0 / (double)(1ULL << 36)),
  (1.0 / (double)(1ULL << 38)),
  (1.0 / (double)(1ULL << 44)),
  (1.0 / (double)(1ULL << 48)),
  (1.0 / (double)(1ULL << 54)),
  (1.0 / (double)(1ULL << 56)),
  ((1.0 / (double)(1ULL << 60)) * (1.0 / (double)(1ULL << 4))), // 2^-64
  ((1.0 / (double)(1ULL << 60)) * (1.0 / (double)(1ULL << 8))), // 2^-68
  ((1.0 / (double)(1ULL << 60)) * (1.0 / (double)(1ULL << 10))), // 2^-70
  ((1.0 / (double)(1ULL << 60)) * (1.0 / (double)(1ULL << 12))) // 2^-72  <--- !! artificially added
};
differential_t g_trail[SIMON_TRAIL_LEN] = {
  { 0x4000000, 0x10000000, 0, 0.250000}, //(2^-2.000000)
  { 0x1000000,        0x0, 0, 0.250000}, //(2^-2.000000)
  {       0x0,  0x1000000, 0, 1.000000}, //(2^0.000000)
  { 0x1000000,  0x4000000, 0, 0.250000}, //(2^-2.000000)
  { 0x4000000, 0x11000000, 0, 0.250000}, //(2^-2.000000)
  {0x11000000, 0x60000000, 0, 0.062500}, //(2^-4.000000)
  {0x60000000, 0x51000001, 0, 0.062500}, //(2^-4.000000)
  {0x51000001,  0x4000004, 0, 0.003906}, //(2^-8.000000)
  { 0x4000004, 0x41000011, 0, 0.062500}, //(2^-4.000000)
  {0x41000011,        0x0, 0, 0.003906}, //(2^-8.000000)
  {       0x0, 0x41000011, 0, 1.000000}, //(2^0.000000)
  {0x41000011,  0x4000004, 0, 0.003906}, //(2^-8.000000)
  { 0x4000004, 0x51000001, 0, 0.062500}, //(2^-4.000000)
  {0x51000001, 0x60000000, 0, 0.003906}, //(2^-8.000000)
  {0x60000000, 0x11000000, 0, 0.062500}, //(2^-4.000000)
  {0x11000000,  0x4000000, 0, 0.062500}, //(2^-4.000000)
  { 0x4000000,  0x1000000, 0, 0.250000}, //(2^-2.000000)
  { 0x1000000,        0x0, 0, 0.250000}, //(2^-2.000000)
  {       0x0,  0x1000000, 0, 1.000000}, //(2^0.000000)
  { 0x1000000,  0x4000000, 0, 0.250000},  //(2^-2.000000)
  { 0x4000000, 0x11000000, 0, 0.250000}  //(2^-2.000000) <--- ! artificially added
};
#endif  // #if(WORD_SIZE == 16)

// store the full trail
std::string trail_to_string(differential_t* trail, uint32_t trail_len) 
{
  std::stringstream oss("");
  for(uint32_t i = 0; i < trail_len; i++) {
	 oss << std::hex << std::setfill('0') << std::setw(WORD_SIZE / 4) << trail[i].dx;
	 oss << std::hex << std::setfill('0') << std::setw(WORD_SIZE / 4) << trail[i].dy;
  }
#if 1									  // TEST
  // xxx: 20131018
#endif
  return oss.str();
}

// store only the input and output difference (i.e. the differential)
std::string diff_to_string(differential_t* trail, uint32_t trail_len) 
{
  std::stringstream oss("");
  oss << std::hex << std::setfill('0') << std::setw(WORD_SIZE / 4) << trail[0].dx;
  oss << std::hex << std::setfill('0') << std::setw(WORD_SIZE / 4) << (trail[0].dy ^ trail[1].dx); // !!
  oss << std::hex << std::setfill('0') << std::setw(WORD_SIZE / 4) << trail[trail_len - 1].dx;
  oss << std::hex << std::setfill('0') << std::setw(WORD_SIZE / 4) << trail[trail_len - 1].dy;
  return oss.str();
}

std::string differential_to_string(const differential_t diff) 
{
#if 1
  std::stringstream oss("");
  oss << std::hex << std::setfill('0') << std::setw(WORD_SIZE / 4) << diff.dx;
  oss << std::hex << std::setfill('0') << std::setw(WORD_SIZE / 4) << diff.dy;
  return oss.str();
#else
  uint32_t n = ((diff.dx << WORD_SIZE) | diff.dy);
  //  itoa (i,buffer,16);
  std::string s { std::to_string(n) };
  return s;
#endif
}

uint32_t differential_to_num(const differential_t diff) 
{
  assert(WORD_SIZE <= 16);
  uint32_t n = 0;
#if(WORD_SIZE <= 16)
  n = ((diff.dx << WORD_SIZE) | diff.dy);
#endif  // #if(WORD_SIZE <= 16)
  return n;
}

void simon_print_diff_array(std::array<differential_t, SIMON_NDIFFS> diff_array)
{
  for(uint32_t i = 0; i < SIMON_NDIFFS; i++) {
	 printf("%4X %4X ", diff_array[i].dx, diff_array[i].dy);
  }
  printf("\n");
}

void simon_print_diff_hash_map(boost::unordered_map<std::array<differential_t, SIMON_NDIFFS>, uint32_t, simon_diff_hash, simon_diff_equal_to> diffs_hash_map)
{
  boost::unordered_map<std::array<differential_t, SIMON_NDIFFS>, uint32_t, simon_diff_hash, simon_diff_equal_to>::const_iterator map_iter 
	 = diffs_hash_map.begin();
  uint32_t diff_cnt = 0; 
  while(map_iter != diffs_hash_map.end()) {
	 diff_cnt++;
	 printf(" %5d: H[%X] | ", diff_cnt, map_iter->second);
	 simon_print_diff_array(map_iter->first);
	 map_iter++;
  }
}

void simon_print_trail_array(std::array<differential_t, NROUNDS> trail_array)
{
  for(uint32_t i = 0; i < NROUNDS; i++) {
	 printf("%4X %4X ", trail_array[i].dx, trail_array[i].dy);
  }
  printf("\n");
}

void simon_print_trail_hash_map(boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, simon_trail_hash, simon_trail_equal_to> trails_hash_map)
{
  boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, simon_trail_hash, simon_trail_equal_to>::const_iterator map_iter 
	 = trails_hash_map.begin();
  uint32_t trail_cnt = 0; 
  while(map_iter != trails_hash_map.end()) {
	 trail_cnt++;
	 printf(" %5d: H[%X] | ", trail_cnt, map_iter->second);
	 simon_print_trail_array(map_iter->first);
	 map_iter++;
  }
}

void simon_print_round_diffs_latex(FILE* fp, uint32_t nrounds, uint32_t keys[4], differential_t trail[NROUNDS + 1])
{
  //  assert(NKEYS == 1);
  double p_tot = 1.0;
  fprintf(fp, "\n%%------------------------\n");
  //  fprintf(fp, "\\texttt{key} & \\texttt{%8X} & & \\texttt{%8X} & \\texttt{%8X} & \\texttt{%8X} \\\\\n", keys[0], keys[1], keys[2], keys[3]);
  fprintf(fp, "\\toprule\n");
  fprintf(fp, "$r$ & $\\Delta X_{\\mathrm{L}}$ & $\\Delta X_{\\mathrm{R}}$ & $\\mathrm{log}_2 p$\\\\\n");
  fprintf(fp, "\\midrule\n");
  for(uint32_t i = 0; i < nrounds; i++) {
	 if(trail[i].p != 1.0) {
		fprintf(fp, "$%2d$ & \\texttt{%8X} & \\texttt{%8X} & $%3.2f$ \\\\\n", i, trail[i].dx, trail[i].dy, log2(trail[i].p));
	 } else {
		fprintf(fp, "$%2d$ & \\texttt{%8X} & \\texttt{%8X} & $-%3.2f$ \\\\\n", i, trail[i].dx, trail[i].dy, log2(trail[i].p));
	 }
	 p_tot *= trail[i].p;
  }
  fprintf(fp, "\\midrule\n");
  fprintf(fp, " $\\sum_{r}\\mathrm{log}_2 p_r$ & & & $%3.2f$ \\\\\n", log2(p_tot));
  fprintf(fp, "\\midrule\n");
  fprintf(fp, " $\\mathrm{log}_2 (p_{\\mathrm{thres}})$ & & & $%3.2f$ \\\\\n", log2(XDP_ROT_AND_P_THRES));
  fprintf(fp, " $\\#{\\mathrm{hways}}$ & & & $%lld$ \\\\\n", XDP_ROT_AND_MAX_DIFF_CNT);
  fprintf(fp, " Time: & & & $0.0$ min.\\\\\n");
  fprintf(fp, "\\bottomrule\n");
  fprintf(fp, "%% WORD_SIZE = %d, XDP_ROT_AND_P_THRES = %f, XDP_ROT_AND_MAX_DIFF_CNT = 2^%f, SIMON_LROT_CONST_S = %d, SIMON_LROT_CONST_T = %d, SIMON_LROT_CONST_U = %d, NROUNDS = %d\n", WORD_SIZE, XDP_ROT_AND_P_THRES, log2(XDP_ROT_AND_MAX_DIFF_CNT), SIMON_LROT_CONST_S, SIMON_LROT_CONST_T, SIMON_LROT_CONST_U, NROUNDS);
}

/**
 * Count the number of differentials in a \p trail that have
 * probabilities below a given threshold.
 *
 * \param trail a differential trail for \p trail_len rounds.
 * \param trail_len length of the differential trail.
 * \param p_thres probability threshold.
 *
 * \see tea_add_threshold_count_lp
 */
uint32_t simon_xor_threshold_count_lp(differential_t trail[NROUNDS], uint32_t trail_len, double p_thres)
{
  assert(trail_len < NROUNDS);
  uint32_t cnt = 0;

  for(uint32_t i = 0; i < trail_len; i++) {
	 if(trail[i].p < p_thres) {
		cnt++;
	 }
  }

  return cnt;
}



/**
 * Experimentally verify the probability of all 1-round differentials
 * from which an N round trail for Simon is composed.
 */
uint32_t simon_verify_xor_trail(uint32_t nrounds, uint32_t npairs, 
										  uint32_t key_in[SIMON_MAX_NROUNDS],
										  differential_t trail[NROUNDS], uint32_t dy_init,
										  uint32_t lrot_const_s, uint32_t lrot_const_t, uint32_t lrot_const_u)
{
  printf("[%s:%s():%d] dy_init %8X\n", __FILE__, __FUNCTION__, __LINE__, dy_init);
  // assert(nrounds == 1);
  assert(lrot_const_s == SIMON_LROT_CONST_S); 
  assert(lrot_const_t == SIMON_LROT_CONST_T);
  assert(lrot_const_u == SIMON_LROT_CONST_U);

  uint32_t key[SIMON_MAX_NROUNDS] = {0};
  for(uint32_t i = 0; i < SIMON_MAX_NROUNDS; i++) {
	 key[i] = key_in[i];
  }

  uint32_t word_size = WORD_SIZE;
  uint32_t key_size = simon_get_keysize(word_size);
  uint32_t nkey_words = simon_compute_nkeywords(word_size, key_size);
  uint32_t zseq_j = 0;
  uint32_t nrounds_tot = simon_compute_nrounds(word_size, nkey_words, &zseq_j);
  simon_key_expansion(key, g_simon_zseq, zseq_j, nrounds_tot, nkey_words);

  uint32_t one_round = 1;
  uint32_t warn_cnt = 0;
  printf("[%s:%d] Verify P for one round (2^%f CPs)...\n", __FILE__, __LINE__, log2(npairs));
  for(uint32_t i = 0; i < nrounds; i++) {

	 uint32_t cnt = 0;

	 uint32_t dx_in = trail[i].dx;
	 uint32_t dy_in = 0;
	 if(i == 0) {
		dy_in = dy_init;
	 } else {
		dy_in = trail[i-1].dx;
	 }
	 uint32_t dx_out = trail[i].dy;
	 uint32_t dy_out = trail[i].dx;

	 for(uint64_t j = 0; j < npairs; j++) {
		uint32_t x1 = random32() & MASK;
		uint32_t x2 = XOR(x1, dx_in);

		uint32_t y1 = random32() & MASK;
		uint32_t y2 = XOR(y1, dy_in);

		simon_encrypt(key, one_round, &x1, &y1);
		simon_encrypt(key, one_round, &x2, &y2);

		uint32_t dx_ctext = XOR(x1, x2);
		uint32_t dy_ctext = XOR(y1, y2);

		if((dx_ctext == dx_out) && (dy_ctext == dy_out)) {
		  cnt++;
		}

	 }
	 double p_exp = (double)cnt / (double)npairs;

#if 1									  // DEBUG
	 printf("THE %2d: %f (2^%f) %8X -> %8X\n", i, trail[i].p, log2(trail[i].p), trail[i].dx, trail[i].dy);
	 printf("EXP %2d: %f (2^%f) %8X -> %8X\n\n", i, p_exp, log2(p_exp), trail[i].dx, trail[i].dy);
	 //	 assert(((p_exp != 0.0) && (trail[i].p != 0.0)));
#endif

	 if((p_exp == 0.0) && (trail[i].p != 0.0)) {
		warn_cnt++;
	 }
  }
  printf("OK\n");
  return warn_cnt;
}

/**
 * Transforms a trail obtained using threshold search 
 * into a sequence of input/output differences to each round
 * suitable for verifying the trail.
 */
void simon_trail_to_round_diffs(differential_t trail_in[NROUNDS], differential_t round_diffs[NROUNDS + 1],
										  uint32_t nrounds, uint32_t lrot_const_s, uint32_t lrot_const_t, uint32_t lrot_const_u)
{
  assert(NROUNDS <= SIMON_TRAIL_LEN_MAX);
  assert(lrot_const_s == SIMON_LROT_CONST_S); 
  assert(lrot_const_t == SIMON_LROT_CONST_T);
  assert(lrot_const_u == SIMON_LROT_CONST_U);

  differential_t trail[NROUNDS] = {{0, 0, 0, 0.0}}; 
  //  for(uint32_t i = 0; i < NROUNDS; i++) {
  for(uint32_t i = 0; i < nrounds; i++) {
	 trail[i] = {trail_in[i].dx, trail_in[i].dy, trail_in[i].npairs, trail_in[i].p};
  }

  uint32_t dx_in = trail[0].dx;
  uint32_t dy_in = trail[1].dx ^ trail[0].dy;
  trail[0].dy = trail[1].dx;

  double p_in = 1.0;
  round_diffs[0] = {dx_in, dy_in, 0, p_in};
#if 0									  // DEBUG
  printf("Input differences: %8X %8X\n", dx_in, dy_in);
#endif
  for(uint32_t i = 0; i < nrounds; i++) {
	 uint32_t dx_out = trail[i].dy;
	 uint32_t dy_out = trail[i].dx;
	 double p = trail[i].p;
	 round_diffs[i+1] = {dx_out, dy_out, 0, p};
#if 0									  // DEBUG
	 printf("R#%2d Output differences: %8X %8X\n", i, dx_out, dy_out);
#endif
  }

}

/** 
 * Given an XOR trail for \f$N\f$ rounds, experimentally verify
 * the probabilities of the corresponding \f$N\f$ differentials:
 *
 *       - Differential for 1 round: round 0. 
 *       - Differential for 2 rounds: rounds \f$0,1\f$. 
 *       - Differential for 3 rounds: rounds \f$0,1,2\f$. 
 *       - \f$\ldots\f$
 *       - Differential for \f$N\f$ rounds: rounds \f$0,1,2,\ldots,(N-1)\f$. 
 */
uint32_t simon_verify_xor_differential(uint32_t nrounds, uint32_t npairs, 
													uint32_t key_in[SIMON_MAX_NROUNDS],
													differential_t trail_in[NROUNDS], uint32_t dy_init,
													uint32_t lrot_const_s, uint32_t lrot_const_t, uint32_t lrot_const_u)
{
  //  if(nrounds > 10) {
  //	 npairs =( 1ULL << 27);
  //  }

  assert(dy_init == 0);
  assert(lrot_const_s == SIMON_LROT_CONST_S); 
  assert(lrot_const_t == SIMON_LROT_CONST_T);
  assert(lrot_const_u == SIMON_LROT_CONST_U);

  differential_t trail[NROUNDS] = {{0, 0, 0, 0.0}}; 
  for(uint32_t i = 0; i < NROUNDS; i++) {
	 trail[i] = {trail_in[i].dx, trail_in[i].dy, trail_in[i].npairs, trail_in[i].p};
  }

  uint32_t key[SIMON_MAX_NROUNDS] = {0};
  for(uint32_t i = 0; i < SIMON_MAX_NROUNDS; i++) {
	 key[i] = key_in[i];
  }

  uint32_t word_size = WORD_SIZE;
  uint32_t key_size = simon_get_keysize(word_size);
  uint32_t nkey_words = simon_compute_nkeywords(word_size, key_size);
  uint32_t zseq_j = 0;
  uint32_t nrounds_tot = simon_compute_nrounds(word_size, nkey_words, &zseq_j);
  simon_key_expansion(key, g_simon_zseq, zseq_j, nrounds_tot, nkey_words);

  uint32_t warn_cnt = 0;
  printf("[%s:%d] Verify P of differentials (2^%f CPs)...\n", __FILE__, __LINE__, log2(npairs));

  // First two Fesitel rounds are freely chosen, so add correction at dy[0]
  uint32_t dx_in = trail[0].dx;
  uint32_t dy_in = trail[1].dx ^ trail[0].dy ^ dy_init;
  trail[0].dy = trail[1].dx;

  printf("Input differences: %8X %8X\n\n", dx_in, dy_in);

  double p_the = 1.0;
  for(uint32_t i = 0; i < nrounds; i++) {

	 uint32_t enc_nrounds = i+1;

	 uint32_t cnt = 0;

	 uint32_t dx_out = trail[i].dy;
	 uint32_t dy_out = trail[i].dx;
	 p_the *= trail[i].p;

	 for(uint64_t j = 0; j < npairs; j++) {
		uint32_t x1 = random32() & MASK;
		uint32_t x2 = XOR(x1, dx_in);

		uint32_t y1 = random32() & MASK;
		uint32_t y2 = XOR(y1, dy_in);

		simon_encrypt(key, enc_nrounds, &x1, &y1);
		simon_encrypt(key, enc_nrounds, &x2, &y2);

		uint32_t dx_ctext = XOR(x1, x2);
		uint32_t dy_ctext = XOR(y1, y2);

		if((dx_ctext == dx_out) && (dy_ctext == dy_out)) {
		  cnt++;
		}
	 }
	 double p_exp = (double)cnt / (double)npairs;;

	 printf("R#%2d Output differences: %8X %8X\n", i, dx_out, dy_out);
#if 1									  // DEBUG
	 printf("THE %2d: %f (2^%f) %8X -> %8X\n", i+1,   p_the, log2(p_the), trail[i].dx, trail[i].dy);
	 printf("EXP %2d: %f (2^%f) %8X -> %8X\n\n", i+1, p_exp, log2(p_exp), trail[i].dx, trail[i].dy);
#endif

	 if((p_exp == 0.0) && (trail[i].p != 0.0)) {
		warn_cnt++;
	 }
  }
  printf("OK\n");
  return warn_cnt;
}

void simon_diff_graph_print_nodes(std::map<simon_diff_graph_node_t, simon_diff_graph_node_t, simon_diff_graph_node_comp> V)
{
  std::map<simon_diff_graph_node_t, simon_diff_graph_node_t, simon_diff_graph_node_comp>::iterator node_iter;
  uint32_t node_cnt = 0;
  for(node_iter = V.begin(); node_iter != V.end(); node_iter++) {
	 node_cnt++;
	 simon_diff_graph_node_t node = node_iter->second;
#if 1									  // DEBUG
	 printf("[%s:%d] node #%5d: %2d (%8X, %8X) | %d %d %f %4.2f\n", __FILE__, __LINE__, 
			  node_cnt, node.level, node.node[0], node.node[1], node.deg_in, node.deg_out, node.p_sum, log2(node.p_sum));
#endif  // #if 1									  // DEBUG
  }
#if 1									  // DEBUG
  printf("[%s:%d] V.size %d\n", __FILE__, __LINE__, V.size());
#endif  // #if 1									  // DEBUG
}

bool simon_diff_vec_comp(std::pair<simon_diff_graph_node_t, simon_diff_graph_node_t> a, 
								 std::pair<simon_diff_graph_node_t, simon_diff_graph_node_t> b)
{
  bool b_less = false;
  if(a.second.level != b.second.level) {
	 b_less = (a.second.level < b.second.level);
  } else {
	 if(a.second.p_sum >= b.second.p_sum) {
		b_less = true;
	 } 
  }
  return b_less;
}


/*
 * Compute the in- and out-degree of the nodes of 
 * a differential trail graph for Simon (using \p simon_diff_graph_edge_t)
 */

void simon_diff_graph_extract_nodes(std::vector<simon_diff_graph_edge_t> E,
												std::map<simon_diff_graph_node_t, // key
															simon_diff_graph_node_t, // value
															simon_diff_graph_node_comp>* V) // comparison function
{
  for(uint32_t d = 0; d < 2; d++) { // d = 0: deg_in; d = 1: deg_out;
	 bool b_deg_in = (d == 0);
	 bool b_deg_out = (d == 1);

	 assert(b_deg_out == !b_deg_in);

	 for(uint32_t i = 0; i < E.size(); i++) {

		simon_diff_graph_node_t new_node;
		if(b_deg_out) {
		  new_node.level = E.at(i).level;
		  new_node.node[0] = E.at(i).node_from[0];
		  new_node.node[1] = E.at(i).node_from[1];
		  new_node.p_sum = 1.0;
		  new_node.deg_in = 0;
		  new_node.deg_out = 1;
		} else { //		if(b_deg_in) {
		  new_node.level = E.at(i).level + 1;
		  new_node.node[0] = E.at(i).node_to[0];
		  new_node.node[1] = E.at(i).node_to[1];
		  new_node.p_sum = E.at(i).p * E.at(i).cnt; // !!!
		  new_node.deg_in = 1;
		  new_node.deg_out = 0;
		}

		std::map<simon_diff_graph_node_t, simon_diff_graph_node_t, simon_diff_graph_node_comp>::iterator node_iter = V->find(new_node);
		if(node_iter == V->end()) {
		  simon_diff_graph_node_t new_key = new_node; // the hashtable key is the first three fields of the node (level, dx, dy)
		  new_key.p_sum = 0.0;		  // not used
		  new_key.deg_in = 0;
		  new_key.deg_out = 0;
		  std::pair<simon_diff_graph_node_t, simon_diff_graph_node_t> new_pair (new_key, new_node);
		  V->insert(new_pair);
#if 0									  // DEBUG
		  printf("[%s:%d] Add new node: %2d(%8X, %8X)\n", __FILE__, __LINE__, new_node.level, new_node.node[0], new_node.node[1]);
#endif  // #if 1									  // DEBUG
		} else {
#if 0									  // DEBUG
		  printf("[%s:%d] Update node: %2d(%8X, %8X)\n", __FILE__, __LINE__, node_iter->second.level, node_iter->second.node[0], node_iter->second.node[1]);
#endif  // #if 1									  // DEBUG
		  assert(node_iter->second.node[0] == new_node.node[0]);
		  assert(node_iter->second.node[1] == new_node.node[1]);
		  if(b_deg_out) {
			 node_iter->second.deg_out++;
		  }
		  if(b_deg_in) {
			 node_iter->second.deg_in++;
			 node_iter->second.p_sum += new_node.p_sum;
			 //			 assert(node_iter->second.p_sum <= 1.0);
		  }
		}
	 }
  }

  // convert to vector of values sorted by probability
  std::vector<std::pair<simon_diff_graph_node_t, simon_diff_graph_node_t> > diff_vec(V->begin(), V->end());
  std::sort(diff_vec.begin(), diff_vec.end(), &simon_diff_vec_comp);

  // compute average degree
#if 0									  // DEBUG
#define COMPUTE_AVERAGE_NODE_DEGS 0
#if COMPUTE_AVERAGE_NODE_DEGS
  uint32_t i_level = 0;
  uint32_t sum_in = 0;
  uint32_t sum_out = 0;
  uint32_t node_cnt = 0;
#endif  // #if COMPUTE_AVERAGE_NODE_DEGS
  for(uint32_t i = 0; i < diff_vec.size(); i++) {
	 simon_diff_graph_node_t node = diff_vec[i].second;
#if COMPUTE_AVERAGE_NODE_DEGS
	 if(i_level == node.level) {
		sum_in += node.deg_in;
		sum_out += node.deg_out;
		node_cnt++;
	 } else { 	  // new level
		double av_in = (double)((double)sum_in / (double)node_cnt); 
		double av_out = (double)((double)sum_out / (double)node_cnt); 
		printf("Averge degs level %2d (%5d nodes)   | %4.2f %4.2f\n", i_level, node_cnt, av_in, av_out);
		i_level = node.level;
		sum_in = node.deg_in;
		sum_out = node.deg_out;
		node_cnt = 1;
	 }
#endif  // #if COMPUTE_AVERAGE_NODE_DEGS
#if 0									  // DEBUG
	 printf("node #%5d: %2d (%8X, %8X) | %2d %2d\n", 
			  i, node.level, node.node[0], node.node[1], node.deg_in, node.deg_out);
	 //	 printf("node #%5d: %2d (%8X, %8X) | %2d %2d %6.5f\n", 
	 //			  i, node.level, node.node[0], node.node[1], node.deg_in, node.deg_out, node.p_sum);
#endif  // #if 1									  // DEBUG
  }
#endif  // #if 0									  // DEBUG
}

void simon_cluster_trails_datfile_read(std::vector<simon_diff_graph_edge_t>* E)
{
  FILE* fp = fopen(SIMON_CLUSTER_TRAILS_DATFILE, "r");

  if(!fp) {
	 printf("[%s:%d] File %s does not exist. Exiting...\n", __FILE__, __LINE__, SIMON_CLUSTER_TRAILS_DATFILE);
	 return;
  }

  //  const differential_t diff_input = {0, 0, 0, 0.0};

  uint32_t dx = 0;
  uint32_t dy = 0;
  double p = 0.0;

  char* line = NULL;
  size_t len = 0;
  ssize_t read;
  uint32_t nline = 0;

  double p_diff = 0.0;			  // total prob. of differential
  while((read = getline(&line, &len, fp)) != -1) {
	 nline++;
#if 1									  // DEBUG
	 //	 printf("line #%5d: length %zu :%s\n", nline, read, line);
	 printf("\rline %d", nline);
	 fflush(stdout);
#endif  // #if 1									  // DEBUG
	 int n = 0;
	 uint32_t level = 0;
	 differential_t diff_prev = {0, 0, 0, 0.0};

#if 0									  // DEBUG
	 printf("[%2d] diff_input: %8X %8X %f\n", level, diff_prev.dx, diff_prev.dy, diff_prev.p);
#endif  // #if 1									  // DEBUG

    double p_trail = 1.0;			  // prb. of a single trail
	 while(sscanf(line, "%X %X %lf %n", &dx, &dy, &p, &n) == 3) {
		differential_t diff = {dx, dy, 0, p};

		p_trail *= diff.p;

#if 0									  // DEBUG
		printf("[%2d] %8X %8X %f\n", level, dx, dy, p);
#endif  // #if 1									  // DEBUG

		if(level > 0) {

		  simon_diff_graph_edge_t new_edge;
		  new_edge.level = level - 1;

		  new_edge.node_from[0] = diff_prev.dx;
		  new_edge.node_from[1] = diff_prev.dy;
		  new_edge.node_to[0] = diff.dx;
		  new_edge.node_to[1] = diff.dy;
		  new_edge.p = diff.p;
		  new_edge.cnt = 1;

		  simon_diff_graph_check_edge(E, new_edge);
#if 0									  // DEBUG
		  printf("[%s:%d] Add new edge: %d(%8X %8X) -> %d(%8X %8X) %f\n", __FILE__, __LINE__, 
					level - 1, new_edge.node_from[0], new_edge.node_from[1],
					level, new_edge.node_to[0], new_edge.node_to[1],
					new_edge.p);
#endif  // #if 1									  // DEBUG

		}
		diff_prev = diff;

		line += n;
		level++;

	 }
	 //	 printf("\n ------------------------- \n");
	 line = NULL;
	 p_diff += p_trail;
  }
#if 1									  // DEBUG
  printf("[%s:%d] %d trail | P_DIFF %f 2^%f\n", __FILE__, __LINE__, nline, p_diff, log2(p_diff));
#endif
  if (line != NULL) {
	 free(line);
  }

  fclose(fp);
}

void simon_graphviz_write_file(char* datfile, // GraphViz data file for full graph
										 char* datfile_con, // GraphViz data file for fconcentrated graph
										 std::vector<simon_diff_graph_edge_t> E)
{
  std::map<simon_diff_graph_node_t, simon_diff_graph_node_t, simon_diff_graph_node_comp> V;
  simon_diff_graph_extract_nodes(E, &V);

#define PRINT_NODE_INFO 0
#if PRINT_NODE_INFO									  // compute node degree-IN, degree-OUT, \sum prob.
  simon_diff_graph_print_nodes(V);
#endif  // #if PRINT_NODE_INFO

  // full graph
  FILE* fp = fopen(datfile, "w");
  fprintf(fp, "digraph G {\n");
  fprintf(fp, "ranksep = \"1.1 equally\"\n");
  fprintf(fp, "node [shape=point]\n");
  //  fprintf(fp, "node [shape=plaintext, fontsize=7]\n");

  // concentrated graph (replace equivalent edges by single edge)
  FILE* fp_con = fopen(datfile_con, "w");
  fprintf(fp_con, "digraph G {\n");
  fprintf(fp_con, "ranksep = \"1.1 equally\"\n");
  fprintf(fp_con, "node [shape=point]\n");
  //  fprintf(fp, "node [shape=plaintext, fontsize=7]\n");
  //  fprintf(fp, "node [shape=plaintext]\n");

  for(uint32_t i = 0; i < E.size(); i++) {
	 uint32_t level = E.at(i).level;
	 uint32_t dx_from = E.at(i).node_from[0];
	 uint32_t dy_from = E.at(i).node_from[1];
	 uint32_t dx_to = E.at(i).node_to[0];
	 uint32_t dy_to = E.at(i).node_to[1];
	 uint32_t cnt = E.at(i).cnt;

#if PRINT_NODE_INFO
	 simon_diff_graph_node_t node_from = {0, {0, 0}, 0, 0, 0.0};
	 node_from.level = level;
	 node_from.node[0] = dx_from;
	 node_from.node[1] = dy_from;

	 simon_diff_graph_node_t node_to = {0, {0, 0}, 0, 0, 0.0};
	 node_to.level = level + 1;
	 node_to.node[0] = dx_to;
	 node_to.node[1] = dy_to;

	 std::map<simon_diff_graph_node_t, simon_diff_graph_node_t, simon_diff_graph_node_comp>::iterator node_from_iter = V.find(node_from);
	 assert(node_from_iter != V.end());
	 double p_sum_from = node_from_iter->second.p_sum;
	 uint32_t deg_in_from = node_from_iter->second.deg_in;
	 uint32_t deg_out_from = node_from_iter->second.deg_out;

	 std::map<simon_diff_graph_node_t, simon_diff_graph_node_t, simon_diff_graph_node_comp>::iterator node_to_iter = V.find(node_to);
	 assert(node_to_iter != V.end());
	 double p_sum_to = node_to_iter->second.p_sum;
	 uint32_t deg_in_to = node_to_iter->second.deg_in;
	 uint32_t deg_out_to = node_to_iter->second.deg_out;
#endif  // #if PRINT_NODE_INFO

	 // write concentrated graph
	 double scale_fact = 0.25;//1.0;
	 double pwidth = (1.0 + (scale_fact * log2(cnt)));

#if PRINT_NODE_INFO
	 fprintf(fp_con, "    \"%2d(%X,%X,%d,%d,%4.2f)\" -> \"%2d(%X,%X,%d,%d,%4.2f)\" [penwidth = %f]\n",
				(level+0), dx_from, dy_from, deg_in_from, deg_out_from, log2(p_sum_from),
				(level+1), dx_to, dy_to, deg_in_to, deg_out_to, log2(p_sum_to),
				pwidth);
	 //	 fprintf(fp_con, "    \"%2d(%X,%X,%d,%d,%4.2f)\" -> \"%2d(%X,%X,%d,%d,%4.2f)\" [penwidth = %f]\n",
	 //				(level+0), dx_from, dy_from, deg_in_from, deg_out_from, (p_sum_from),
	 //				(level+1), dx_to, dy_to, deg_in_to, deg_out_to, (p_sum_to),
	 //				pwidth);
#else
	 fprintf(fp_con, "    \"%2d(%X,%X)\" -> \"%2d(%X,%X)\" [penwidth = %f]\n",level, dx_from, dy_from, (level+1), dx_to, dy_to, pwidth);
#endif

	 // write full graph
	 for(uint32_t j = 0; j < cnt; j++) {
		fprintf(fp, "    \"%2d(%X,%X)\" -> \"%2d(%X,%X)\"\n",level, dx_from, dy_from, (level+1), dx_to, dy_to);
	 }
  }

  // close con graph
  fprintf(fp_con, "}\n");
  fclose(fp_con);

  // close full graph
  fprintf(fp, "}\n");
  fclose(fp);
}

// verify a single differential for nrounds over a random set of inputs
double simon_verify_differential_approx(const uint32_t key_in[SIMON_MAX_NROUNDS],
													 const differential_t input_diff, 
													 const differential_t output_diff, 
													 const uint32_t nrounds,
													 const uint64_t npairs,
													 std::vector<simon_diff_graph_edge_t>* E)
{
  assert(1 == SIMON_LROT_CONST_S); 
  assert(8 == SIMON_LROT_CONST_T);
  assert(2 == SIMON_LROT_CONST_U);

  //  std::vector<simon_diff_graph_edge_t> E;

  uint32_t key[SIMON_MAX_NROUNDS] = {0};
  for(uint32_t i = 0; i < SIMON_MAX_NROUNDS; i++) {
	 key[i] = key_in[i];
  }
#if 1									  // key schedule
  uint32_t word_size = WORD_SIZE;
  uint32_t key_size = simon_get_keysize(word_size);
  uint32_t nkey_words = simon_compute_nkeywords(word_size, key_size);
  uint32_t zseq_j = 0;
  uint32_t nrounds_tot = simon_compute_nrounds(word_size, nkey_words, &zseq_j);
  simon_key_expansion(key, g_simon_zseq, zseq_j, nrounds_tot, nkey_words);
  printf("[%s:%d] Round keys from key schedule, %d R:\n", __FILE__, __LINE__, nrounds);
  for(uint32_t i = 0; i < nrounds; i++) {
	 printf("[%2d]%8X ", i, key[i]);
  }
  printf("\n");
#else	 // random keys
  for(uint32_t i = 0; i < SIMON_MAX_NROUNDS; i++) {
	 key[i] = random32() & MASK;
  }
  printf("[%s:%d] Random round keys, %d R:\n", __FILE__, __LINE__, nrounds);
  for(uint32_t i = 0; i < nrounds; i++) {
	 printf("[%2d]%8X ", i, key[i]);
  }
  printf("\n");
#endif

  uint32_t dx_in = input_diff.dx;
  uint32_t dy_in = input_diff.dy;

  uint32_t dx_out = output_diff.dx;
  uint32_t dy_out = output_diff.dy;

  uint32_t enc_nrounds = nrounds;

  uint64_t cnt = 0;				  // (dx,dy)

  for(uint32_t i = 0; i < npairs; i++) {
	 uint32_t x1 = random32() & MASK;
	 uint32_t x2 = XOR(x1, dx_in);
#if SIMON_DRAW_GRAPH
	 uint32_t x1_ptext = x1;
	 uint32_t x2_ptext = x2;
#endif

	 uint32_t y1 = random32() & MASK;
	 uint32_t y2 = XOR(y1, dy_in);
#if SIMON_DRAW_GRAPH
	 uint32_t y1_ptext = y1;
	 uint32_t y2_ptext = y2;
#endif

	 simon_encrypt(key, enc_nrounds, &x1, &y1);
	 simon_encrypt(key, enc_nrounds, &x2, &y2);

	 uint32_t dx_ctext = XOR(x1, x2);
	 uint32_t dy_ctext = XOR(y1, y2);

	 //	 if((dx_ctext == dx_out) && (hw32(dy_ctext & MASK) <= 5)) {
	 //		printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, dx_ctext, dy_ctext);
	 //	 }
	 if((dx_ctext == dx_out) && (dy_ctext == dy_out)) {
		cnt++;
#if SIMON_DRAW_GRAPH
		double p_temp = (double)cnt / (double)(npairs);
		printf("Found %lld right pairs (2^%f) | %8X %8X | 1:(%8X %8X) 2:(%8X %8X)\n", cnt, log2(p_temp), dx_ctext, dy_ctext, x1_ptext, y1_ptext, x2_ptext, y2_ptext);
		simon_encrypt_pairs(key, enc_nrounds, &x1_ptext, &y1_ptext, &x2_ptext, &y2_ptext, E);
#endif  // #if SIMON_DRAW_GRAPH
	 }
  }
  double p_exp = (double)cnt / (double)(npairs);

  printf("[%s:%d] p = 2^%f\n", __FILE__, __LINE__, log2(p_exp));

  //#if SIMON_DRAW_GRAPH
  //  char datfile[0xFFFF] = {0};// = SIMON_LOG_FILE_NAME;
  //  sprintf(datfile, SIMON_GVIZ_CONCENTRATE_DATFILE);
  //  bool b_concentrate = true;
  //  simon_graphviz_write_file(datfile, *E, b_concentrate);
  //#endif

  return p_exp;
}


// verify a single differential for nrounds over all 2^32 inputs
double simon_verify_differential(const uint32_t key_in[SIMON_MAX_NROUNDS],
											const differential_t input_diff, 
											const differential_t output_diff, 
											const uint32_t nrounds,
											const uint64_t npairs,
											std::vector<simon_diff_graph_edge_t>* E)
{
  assert(1 == SIMON_LROT_CONST_S); 
  assert(8 == SIMON_LROT_CONST_T);
  assert(2 == SIMON_LROT_CONST_U);
  assert(npairs == (1ULL << 32));

  //std::vector<simon_diff_graph_edge_t> E; // for graphviz

  uint32_t key[SIMON_MAX_NROUNDS] = {0};
  for(uint32_t i = 0; i < SIMON_MAX_NROUNDS; i++) {
	 key[i] = key_in[i];
  }
#if 1									  // key schedule
  uint32_t word_size = WORD_SIZE;
  uint32_t key_size = simon_get_keysize(word_size);
  uint32_t nkey_words = simon_compute_nkeywords(word_size, key_size);
  uint32_t zseq_j = 0;
  uint32_t nrounds_tot = simon_compute_nrounds(word_size, nkey_words, &zseq_j);
  simon_key_expansion(key, g_simon_zseq, zseq_j, nrounds_tot, nkey_words);
  printf("[%s:%d] Round keys from key schedule, %d R:\n", __FILE__, __LINE__, nrounds);
  for(uint32_t i = 0; i < nrounds; i++) {
#if 0									  // WARNINIG: DEBUG! remove in production!
	 uint32_t s = 0;//6;//5;//1;
	 key[i] = LROT(key[i], s);
#endif
	 printf("[%2d]%8X ", i, key[i]);
  }
  printf("\n");
#else	 // random keys
  for(uint32_t i = 0; i < SIMON_MAX_NROUNDS; i++) {
	 key[i] = random32() & MASK;
  }
  printf("[%s:%d] Random round keys, %d R:\n", __FILE__, __LINE__, nrounds);
  for(uint32_t i = 0; i < nrounds; i++) {
	 printf("[%2d]%8X ", i, key[i]);
  }
  printf("\n");
#endif

  uint32_t dx_in = input_diff.dx;
  uint32_t dy_in = input_diff.dy;

  uint32_t dx_out = output_diff.dx;
  uint32_t dy_out = output_diff.dy;

  uint32_t enc_nrounds = nrounds;

  uint64_t cnt = 0;				  // (dx,dy)

#define VERBOSE 1

  uint64_t N = (1ULL << 16);
  //  uint32_t N = npairs;
  for(uint32_t i = 0; i < N; i++) {
	 for(uint32_t j = 0; j < N; j++) {
		uint32_t x1 = i;//random32() & MASK;
		uint32_t x2 = XOR(x1, dx_in);
#if VERBOSE
		uint32_t x1_ptext = x1;
		uint32_t x2_ptext = x2;
#endif

		uint32_t y1 = j;//random32() & MASK;
		uint32_t y2 = XOR(y1, dy_in);
#if VERBOSE
		uint32_t y1_ptext = y1;
		uint32_t y2_ptext = y2;
#endif

		simon_encrypt(key, enc_nrounds, &x1, &y1);
		simon_encrypt(key, enc_nrounds, &x2, &y2);

		uint32_t dx_ctext = XOR(x1, x2);
		uint32_t dy_ctext = XOR(y1, y2);

		if((dx_ctext == dx_out) && (dy_ctext == dy_out)) {
		  cnt++;
#if VERBOSE
		  double p_temp = (double)cnt / (double)(N * N);
		  printf("Found %lld right pairs (2^%f) | %8X %8X | 1:(%8X %8X) 2:(%8X %8X)\n", cnt, log2(p_temp), dx_ctext, dy_ctext, x1_ptext, y1_ptext, x2_ptext, y2_ptext);
		  simon_encrypt_pairs(key, enc_nrounds, &x1_ptext, &y1_ptext, &x2_ptext, &y2_ptext, E);
#endif
		}
	 }
  }
  double p_exp = (double)cnt / (double)(N * N);

  printf("[%s:%d] p = 2^%f\n", __FILE__, __LINE__, log2(p_exp));
  return p_exp;
}

void simon_print_hash_table(std::unordered_map<std::string, differential_t**> trails_hash_map, uint32_t trail_len) 
{
  uint32_t key[SIMON_MAX_NROUNDS] = {0};
  key[0] = random32() & MASK;
  key[1] = random32() & MASK;
  key[2] = random32() & MASK;
  key[3] = random32() & MASK;
  std::unordered_map<std::string, differential_t**>::const_iterator hash_map_iter = trails_hash_map.begin();
  printf("[%s:%d] Found %d trails:\n", __FILE__, __LINE__, (uint32_t)trails_hash_map.size());
  uint32_t trail_cnt = 0;
  double p_tot = 0.0;
  while(hash_map_iter != trails_hash_map.end()) {
	 trail_cnt++;
	 printf("[%5d] ", trail_cnt);
	 double p = 1.0;
	 for(uint32_t i = 0; i < trail_len; i++) {
		printf("%4X %4X ", (*(hash_map_iter->second))[i].dx, (*(hash_map_iter->second))[i].dy);
		p *= (*(hash_map_iter->second))[i].p;
	 }
	 p_tot += p;
	 printf(" | 2^%f ", log2(p));
#if 1								  // Verify probability of differential
	 uint32_t dx_in = (*(hash_map_iter->second))[0].dx;
	 uint32_t dy_in = (*(hash_map_iter->second))[0].dy ^ (*(hash_map_iter->second))[1].dx;;;
	 uint32_t dx_out = (*(hash_map_iter->second))[trail_len - 1].dy;
	 uint32_t dy_out = (*(hash_map_iter->second))[trail_len - 1].dx;
	 differential_t input_diff = {dx_in, dy_in, 0, 0.0};
	 differential_t output_diff = {dx_out, dy_out, 0, 0.0};
	 uint32_t npairs = 1U << 22;
	 uint32_t nrounds = trail_len;
	 std::vector<simon_diff_graph_edge_t> E;
	 double p_exp = simon_verify_differential_approx(key, input_diff, output_diff, nrounds, npairs, &E);
	 //	 double p_exp = simon_verify_differential(key, input_diff, output_diff, nrounds, npairs, &E);
	 //	 printf("[%s:%s():%d]:\n Verified %d R differential (%8X %8X) -> (%8X %8X) | 2^%4.2f CP pairs\n Final probability p = 2^%f\n", __FILE__, __FUNCTION__, __LINE__, nrounds, dx_in, dy_in, dx_out, dy_out, log2(npairs*npairs), log2(p_exp));
	 printf(" | 2^%f\n", log2(p_exp));
#endif
	 hash_map_iter++;
  }
  //  printf("[%s:%d] 2^%f CP\n",  __FILE__, __LINE__, log2(npairs * npairs));
  printf("Probability of differential: 2^%f\n", log2(p_tot));
}

// Simon: store trails in file (optimized)
void simon_boost_new_trail_store_to_file(uint32_t dx_in, uint32_t dy_in, differential_t trail[NROUNDS], uint32_t trail_len)
{
  differential_t round_diffs[SIMON_TRAIL_LEN_MAX + 1] = {{0, 0, 0, 0.0}};
  simon_trail_to_round_diffs(trail, round_diffs, trail_len, SIMON_LROT_CONST_S, SIMON_LROT_CONST_T, SIMON_LROT_CONST_U);
  round_diffs[0] = {dx_in, dy_in, 0, 1.0}; // !!!

  FILE* fp = fopen(SIMON_CLUSTER_TRAILS_DATFILE, "a");
#if 0									  // DEBUG
  printf("\n");
#endif
  for(uint32_t i = 0; i < trail_len + 1; i++) {
	 fprintf(fp, "%8X %8X %10.9f ", round_diffs[i].dx, round_diffs[i].dy, round_diffs[i].p);
#if 0									  // DEBUG
	 printf("%8X %8X %10.9f ", round_diffs[i].dx, round_diffs[i].dy, round_diffs[i].p);
#endif
  }
  fprintf(fp, "\n");
#if 0									  // DEBUG
  printf("\n");
#endif
  fclose(fp);
}


void simon_boost_print_hash_table(boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, simon_trail_hash, simon_trail_equal_to> trails_hash_map, uint32_t trail_len)
{

  //  printf("[%s:%d] CHECKPOINT! Enter %s() trail_len %d hmap_size %d\n", __FILE__, __LINE__, __FUNCTION__, trail_len, (uint32_t)trails_hash_map.size());
#if 0//(WORD_SIZE <= 16)
  uint32_t key[SIMON_MAX_NROUNDS] = {0};
  key[0] = random32() & MASK;
  key[1] = random32() & MASK;
  key[2] = random32() & MASK;
  key[3] = random32() & MASK;
#endif
  boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, simon_trail_hash, simon_trail_equal_to>::iterator hash_map_iter 
	 = trails_hash_map.begin();
  uint32_t dx_in = hash_map_iter->first[0].dx;
#if 0
  uint32_t dy_in = hash_map_iter->first[0].dy ^ hash_map_iter->first[1].dx;
#else
  uint32_t dy_in = g_trail[0].dy ^ g_trail[1].dx;
#endif
  //  printf("\n%8X %8X %8X\n", g_trail[0].dy, g_trail[1].dx, dy_in);
  //  printf("%8X %8X %8X\n", hash_map_iter->first[0].dy, hash_map_iter->first[1].dx, hash_map_iter->first[0].dy ^ hash_map_iter->first[1].dx);
  //  sleep(5);
#if 0
  uint32_t dx_out = hash_map_iter->first[trail_len - 1].dy;
  uint32_t dy_out = hash_map_iter->first[trail_len - 1].dx;
#else
  uint32_t dx_out = hash_map_iter->first[trail_len - 1].dx;
  uint32_t dy_out = hash_map_iter->first[trail_len - 1].dy;
#endif
  uint32_t trail_cnt = 0;
  double p_tot = 0.0;
#if 0
  printf("[%s:%d] Found %d trails:\n", __FILE__, __LINE__, (uint32_t)trails_hash_map.size());
#endif

#define PRINT_TRAIL_FILE 1
#if PRINT_TRAIL_FILE									  // print trail to file
  FILE* fp = fopen(SIMON_CLUSTER_TRAILS_DATFILE, "w"); // truncate file;
  fclose(fp);
#endif
  while(hash_map_iter != trails_hash_map.end()) {
	 trail_cnt++;
	 double p = 1.0;

#if PRINT_TRAIL_FILE									  // print trail
	 differential_t trail[SIMON_TRAIL_LEN_MAX] = {{0, 0, 0, 0.0}};
#endif

#define PRINT_TRAIL 0
#if PRINT_TRAIL									  // print trail
	 printf("[%5d] ", trail_cnt);
#endif
	 for(uint32_t i = 0; i < trail_len; i++) {
#if PRINT_TRAIL									  // print trail
		printf("%X %X ", hash_map_iter->first[i].dx, hash_map_iter->first[i].dy);
#endif
		trail[i] = {hash_map_iter->first[i].dx, hash_map_iter->first[i].dy, 0, hash_map_iter->first[i].p};
		p *= hash_map_iter->first[i].p;
	 }

#if PRINT_TRAIL_FILE									  // print differentials to file : SIMON_CLUSTER_TRAILS_DATFILE
	 differential_t round_diffs[SIMON_TRAIL_LEN_MAX + 1] = {{0, 0, 0, 0.0}};
	 simon_trail_to_round_diffs(trail, round_diffs, trail_len, SIMON_LROT_CONST_S, SIMON_LROT_CONST_T, SIMON_LROT_CONST_U);
	 round_diffs[0] = {dx_in, dy_in, 0, 1.0};

	 fp = fopen(SIMON_CLUSTER_TRAILS_DATFILE, "a");
	 //	 printf("\ndifferential: \n");
	 for(uint32_t i = 0; i < trail_len + 1; i++) {
		fprintf(fp, "%8X %8X %10.9f ", round_diffs[i].dx, round_diffs[i].dy, round_diffs[i].p);
		//		printf("%8X %8X ", round_diffs[i].dx, round_diffs[i].dy);
	 }
	 fprintf(fp, "\n");
	 //	 printf("\n");
	 fclose(fp);
#endif

	 p_tot += p;
#if PRINT_TRAIL									  // print trail
	 printf(" | 2^%f ", log2(p));
	 //	 fp = fopen(SIMON_CLUSTER_TRAILS_DATFILE, "a");
	 //	 fprintf(fp, "\n");
	 //	 fclose(fp);
#endif
	 //	 printf("[%s:%d] %f 2^%f\n", __FILE__, __LINE__, p_tot, log2(p_tot));
#if 0//(WORD_SIZE <= 16)								  // Verify probability of differential
	 differential_t input_diff = {dx_in, dy_in, 0, 0.0};
	 differential_t output_diff = {dx_out, dy_out, 0, 0.0};
	 uint32_t npairs = 1U << 22;
	 uint32_t nrounds = trail_len;
	 std::vector<simon_diff_graph_edge_t> E;
	 double p_exp = simon_verify_differential_approx(key, input_diff, output_diff, nrounds, npairs, &E);
	 printf(" | 2^%f ", log2(p_exp));
#endif
#if PRINT_TRAIL									  // print trail
	 printf("\n");
#endif
	 hash_map_iter++;
  }
#if PRINT_TRAIL
  printf("Probability of differential: 2^%f\n", log2(p_tot));
  printf("[%s:%d] %2d R (%8X %8X) -> (%8X %8X) : [%10d trails]  2^%f\n", __FILE__, __LINE__, trail_len, dx_in, dy_in, dx_out, dy_out, (uint32_t)trails_hash_map.size(), log2(p_tot));
#else
  printf("\r[%s:%d] %2d R (%8X %8X) -> (%8X %8X) : [%10d trails]  2^%f", __FILE__, __LINE__, trail_len, dx_in, dy_in, dx_out, dy_out, (uint32_t)trails_hash_map.size(), log2(p_tot));
  fflush(stdout);
#endif
#if 0
  printf("[%s:%d] WORD_SIZE %d NROUNDS %d XDP_ROT_AND_P_THRES %f 2^%f XDP_ROT_AND_MAX_DIFF_CNT %lld 2^%4.2f SIMON_EPS %f 2^%f XDP_ROT_AND_MAX_HW %d TRAIL_MAX_HW %d SIMON_BACK_TO_HWAY %d\n", 
			 __FILE__, __LINE__, WORD_SIZE, NROUNDS, XDP_ROT_AND_P_THRES, log2(XDP_ROT_AND_P_THRES), XDP_ROT_AND_MAX_DIFF_CNT, log2(XDP_ROT_AND_MAX_DIFF_CNT), SIMON_EPS, log2(SIMON_EPS), XDP_ROT_AND_MAX_HW, TRAIL_MAX_HW, SIMON_BACK_TO_HWAY);
#endif
  //  printf("[%s:%d] CHECKPOINT! Exit %s()\n", __FILE__, __LINE__, __FUNCTION__);
}

void simon_print_diff_hash_table(std::unordered_map<std::string, differential_t**> diffs_hash_map, uint32_t nrounds) 
{
  uint32_t key[SIMON_MAX_NROUNDS] = {0};
  key[0] = random32() & MASK;
  key[1] = random32() & MASK;
  key[2] = random32() & MASK;
  key[3] = random32() & MASK;
  std::unordered_map<std::string, differential_t**>::const_iterator hash_map_iter = diffs_hash_map.begin();
  printf("[%s:%d] Found %d differentials:\n", __FILE__, __LINE__, (uint32_t)diffs_hash_map.size());
  uint32_t trail_cnt = 0;
  while(hash_map_iter != diffs_hash_map.end()) {
	 trail_cnt++;
	 printf("[%5d] ", trail_cnt);
	 printf("%4X %4X -> ", (*(hash_map_iter->second))[0].dx, (*(hash_map_iter->second))[0].dy);
	 printf("%4X %4X ", (*(hash_map_iter->second))[1].dx, (*(hash_map_iter->second))[1].dy);
	 double p = (*(hash_map_iter->second))[1].p;
	 printf(" | 2^%f", log2(p));
#if 1								  // Verify probability of differential
	 uint32_t dx_in = (*(hash_map_iter->second))[0].dx;
	 uint32_t dy_in = (*(hash_map_iter->second))[0].dy;
	 uint32_t dx_out = (*(hash_map_iter->second))[1].dy;
	 uint32_t dy_out = (*(hash_map_iter->second))[1].dx;
	 differential_t input_diff = {dx_in, dy_in, 0, 0.0};
	 differential_t output_diff = {dx_out, dy_out, 0, 0.0};
	 uint32_t npairs = 1U << 10;
	 std::vector<simon_diff_graph_edge_t> E;
	 // generate random key
	 double p_exp = simon_verify_differential(key, input_diff, output_diff, nrounds, npairs, &E);
	 //	 printf("[%s:%s():%d]:\n Verified %d R differential (%8X %8X) -> (%8X %8X) | 2^%4.2f CP pairs\n Final probability p = 2^%f\n", __FILE__, __FUNCTION__, __LINE__, nrounds, dx_in, dy_in, dx_out, dy_out, log2(npairs*npairs), log2(p_exp));
	 printf(" | 2^%f\n", log2(p_exp));
#endif
	 hash_map_iter++;
  }
}

void simon_boost_print_diff_hash_table(boost::unordered_map<std::array<differential_t, SIMON_NDIFFS>, uint32_t, simon_diff_hash, simon_diff_equal_to> diffs_hash_map)
{
#define SIMON_PRINT_DIFFS_TO_FILE 1 // store data in file

#if SIMON_PRINT_DIFFS_TO_FILE
  time_t rawtime;
  time(&rawtime);
  char logfile[0xFFFF] = {0};
  //  sprintf(logfile, "simon%d-diffs-%lld.log", (2*WORD_SIZE), XDP_ROT_AND_MAX_DIFF_CNT);
  sprintf(logfile, "simon%d-diffs.log", (2*WORD_SIZE));
  FILE* fp = fopen(logfile, "w");
  fprintf(fp, "\nLast Update: %s", ctime (&rawtime));
  fprintf(fp, "[%s:%d] Parameters:\n WORD_SIZE %d\n NROUNDS %d\n XDP_ROT_AND_P_THRES %f 2^%f\n XDP_ROT_AND_MAX_DIFF_CNT %lld 2^%4.2f\n SIMON_EPS %f 2^%f\n XDP_ROT_AND_MAX_HW %d\n TRAIL_MAX_HW %d\n SIMON_BACK_TO_HWAY %d\n XDP_ROT_PDDT_GEN_RANDOM %d\n XDP_ROT_AND_P_LOW_THRES %f\n", 
			 __FILE__, __LINE__, WORD_SIZE, NROUNDS, XDP_ROT_AND_P_THRES, log2(XDP_ROT_AND_P_THRES), XDP_ROT_AND_MAX_DIFF_CNT, log2(XDP_ROT_AND_MAX_DIFF_CNT), SIMON_EPS, log2(SIMON_EPS), XDP_ROT_AND_MAX_HW, TRAIL_MAX_HW, SIMON_BACK_TO_HWAY, XDP_ROT_PDDT_GEN_RANDOM, XDP_ROT_AND_P_LOW_THRES);
#endif  // #if SIMON_PRINT_DIFFS_TO_FILE

  //  simon_diff_hash diff_hash;  // differential hash function
  boost::unordered_map<std::array<differential_t, SIMON_NDIFFS>, uint32_t, simon_diff_hash, simon_diff_equal_to>::iterator hash_map_iter 
	 = diffs_hash_map.begin();
  uint32_t diff_cnt = 0;
#if SIMON_PRINT_DIFFS_TO_FILE
  fprintf(fp, "[%s:%d] Found %d differentials:\n", __FILE__, __LINE__, (uint32_t)diffs_hash_map.size());
#else
  printf("[%s:%d] Found %d differentials:\n", __FILE__, __LINE__, (uint32_t)diffs_hash_map.size());
#endif  // #if SIMON_PRINT_DIFFS_TO_FILE

  differential_t diff_max[2] = {{0, 0, 0, 0.0}, {0, 0, 0, 0.0}};
  double p_max = 0;

  while(hash_map_iter != diffs_hash_map.end()) {
	 diff_cnt++;
#if SIMON_PRINT_DIFFS_TO_FILE
	 fprintf(fp, "[%5d] H[%8X] %2dR : (%8X %8X) -> (%8X %8X) 2^%f\n", 
				diff_cnt, hash_map_iter->second, NROUNDS,
				hash_map_iter->first[0].dx, hash_map_iter->first[0].dy, 
				hash_map_iter->first[1].dx, hash_map_iter->first[1].dy, 
				log2(hash_map_iter->first[1].p));
#else
	 printf("[%5d] H[%8X] %2dR : (%8X %8X) -> (%8X %8X) 2^%f\n", 
			  diff_cnt, hash_map_iter->second, NROUNDS, 
			  hash_map_iter->first[0].dx, hash_map_iter->first[0].dy, 
			  hash_map_iter->first[1].dx, hash_map_iter->first[1].dy, 
			  log2(hash_map_iter->first[1].p));
#endif  // #if SIMON_PRINT_DIFFS_TO_FILE
	 double p = hash_map_iter->first[1].p;
	 if(p > p_max) {
		p_max = p;
		diff_max[0].dx = hash_map_iter->first[0].dx;
		diff_max[0].dy = hash_map_iter->first[0].dy;
		diff_max[0].p = hash_map_iter->first[0].p;
		diff_max[1].dx = hash_map_iter->first[1].dx;
		diff_max[1].dy = hash_map_iter->first[1].dy;
		diff_max[1].p = hash_map_iter->first[1].p;
	 }

	 hash_map_iter++;
  }
#if SIMON_PRINT_DIFFS_TO_FILE	  // store data in file
  fprintf(fp, "MAX %2dR : (%8X %8X) -> (%8X %8X) 2^%f\n", NROUNDS, 
			diff_max[0].dx, diff_max[0].dy, diff_max[1].dx, diff_max[1].dy, log2(diff_max[1].p));
  assert(p_max == diff_max[1].p);
  fclose(fp);
#else
  printf("\nMAX %2dR : (%8X %8X) -> (%8X %8X) 2^%f\n", NROUNDS, 
			diff_max[0].dx, diff_max[0].dy, diff_max[1].dx, diff_max[1].dy, log2(diff_max[1].p));
#endif
  assert(p_max == diff_max[1].p);
}

/**
 * Add new trail in the hash table.
 */
void simon_trails_hash_map_add_new(differential_t diff[NROUNDS], 
											  const uint32_t trail_len,
											  std::unordered_map<std::string, differential_t**>* trails_hash_map)
{
  std::string s_trail = trail_to_string(diff, trail_len);
  differential_t** new_trail;
  new_trail = (differential_t** )calloc(1, sizeof(differential_t*));
  *new_trail = (differential_t*)calloc(trail_len, sizeof(differential_t));
  for(uint32_t i = 0; i < trail_len; i++) {
	 (*new_trail)[i].dx = diff[i].dx;
	 (*new_trail)[i].dy = diff[i].dy;
	 (*new_trail)[i].p = diff[i].p;
  }
  std::pair<std::string, differential_t**> new_pair (s_trail, new_trail);
  trails_hash_map->insert(new_pair);
}

/**
 * Add new differential in the hash table.
 */
void simon_diffs_hash_map_add_new(differential_t diff[NROUNDS], 
											const uint32_t trail_len,
											std::unordered_map<std::string, differential_t**>* diffs_hash_map)
{
  std::string s_diff = diff_to_string(diff, trail_len);

  double p = 1.0;
  for(uint32_t i = 0; i < trail_len; i++) {
	 p *= diff[i].p;
  }

  differential_t** new_diff;
  new_diff = (differential_t** )calloc(1, sizeof(differential_t*));
  *new_diff = (differential_t*)calloc(2, sizeof(differential_t));
  (*new_diff)[0].dx = diff[0].dx;
  (*new_diff)[0].dy = diff[0].dy ^ diff[1].dx; // !!
  (*new_diff)[0].p = 1.0;
  (*new_diff)[1].dx = diff[trail_len - 1].dx;
  (*new_diff)[1].dy = diff[trail_len - 1].dy;
  (*new_diff)[1].p = p;

  std::pair<std::string, differential_t**> new_pair (s_diff,new_diff);
  diffs_hash_map->insert(new_pair);
}

/**
 * Check if a trail and its corresponding diferential are already in the hash maps 
 * and if not -- add them. Also update the probability of the maximum differential 
 * if necessary.
 *	
 */
void simon_hash_map_update(differential_t diff[NROUNDS], 
									const uint32_t trail_len,
									std::unordered_map<std::string, differential_t**>* diffs_hash_map,
									std::unordered_map<std::string, differential_t**>* trails_hash_map,
									differential_t** diff_max)
{
  //  const int nrounds = (int32_t)trail_len;
  const uint32_t nrounds = trail_len;
  double p = 1.0;
  for(uint32_t i = 0; i < trail_len; i++) {
	 p *= diff[i].p;
  }

  std::string s_trail = trail_to_string(diff, trail_len);
  std::unordered_map<std::string, differential_t**>::const_iterator hash_map_iter = 
	 trails_hash_map->find(s_trail);

  if(hash_map_iter == trails_hash_map->end()) { // trail is not in the trail table
#if 0															// DEBUG
	 printf("\r[%s:%d] Add new trail: 2^%f | %d", __FILE__, __LINE__, log2(p), (uint32_t)trails_hash_map->size());
	 fflush(stdout);
#endif
    // Add new trail
	 simon_trails_hash_map_add_new(diff, trail_len, trails_hash_map);

	 const double p_max = (*diff_max)[1].p;
	 std::string s_diff = diff_to_string(diff, trail_len);
	 std::unordered_map<std::string, differential_t**>::const_iterator diff_hash_map_iter = 
		diffs_hash_map->find(s_diff);

	 if(diff_hash_map_iter == diffs_hash_map->end()) { // differential is not in the diff table

		printf("\r[%s:%d] Add new differential: %4X %4X -> %4X %4X 2^%f | #trails %d", __FILE__, __LINE__, diff[0].dx, diff[0].dy ^ diff[1].dx, diff[trail_len - 1].dx, diff[trail_len -1].dy, log2(p), (uint32_t)trails_hash_map->size());
		fflush(stdout);

		// Add differential
		simon_diffs_hash_map_add_new(diff, trail_len, diffs_hash_map);

		if(p > p_max) {
		  (*diff_max)[0].p = 1.0;
		  (*diff_max)[0].dx = diff[0].dx;
		  (*diff_max)[0].dy = diff[0].dy ^ diff[1].dx; // !!
		  (*diff_max)[1].p = p;
		  (*diff_max)[1].dx = diff[trail_len - 1].dx;
		  (*diff_max)[1].dy = diff[trail_len - 1].dy;
		  printf("\n[%s:%d] Update max for %d R: (%4X %4X) -> (%4X %4X) 2^%f\n", __FILE__, __LINE__,  nrounds, (*diff_max)[0].dx, (*diff_max)[0].dy, (*diff_max)[1].dx, (*diff_max)[1].dy, log2((*diff_max)[1].p));
		}
	 } else {						  // differential is already stored
		//		double old_p = (*(diff_hash_map_iter->second))[1].p;
		(*(diff_hash_map_iter->second))[1].p += p;
		double new_p = (*(diff_hash_map_iter->second))[1].p;
#if 0									  // DEBUG
		printf("\r[%s:%d] Improve differential prob:  %4X %4X -> %4X %4X 2^%f -> 2^%f | #trails %d", __FILE__, __LINE__, (*(diff_hash_map_iter->second))[0].dx, (*(diff_hash_map_iter->second))[0].dy, (*(diff_hash_map_iter->second))[1].dx, (*(diff_hash_map_iter->second))[1].dy, log2(old_p), log2(new_p), (uint32_t)trails_hash_map->size());
		fflush(stdout);
#endif
#if 1									  // DEBUG
		assert((*(diff_hash_map_iter->second))[0].dx == diff[0].dx);
		assert((*(diff_hash_map_iter->second))[0].dy == (diff[0].dy ^ diff[1].dx));
		assert((*(diff_hash_map_iter->second))[1].dx == diff[trail_len - 1].dx);
		assert((*(diff_hash_map_iter->second))[1].dy == diff[trail_len - 1].dy);
#endif
		if(new_p > p_max) {
		  (*diff_max)[0].p = 1.0;
		  (*diff_max)[0].dx = (*(diff_hash_map_iter->second))[0].dx;
		  (*diff_max)[0].dy = (*(diff_hash_map_iter->second))[0].dy;
		  (*diff_max)[1].p = new_p;
		  (*diff_max)[1].dx = (*(diff_hash_map_iter->second))[1].dx;
		  (*diff_max)[1].dy = (*(diff_hash_map_iter->second))[1].dy;
		  printf("\n[%s:%d] Update max for %d R: (%4X %4X) -> (%4X %4X) 2^%f\n", __FILE__, __LINE__,  nrounds, (*diff_max)[0].dx, (*diff_max)[0].dy, (*diff_max)[1].dx, (*diff_max)[1].dy, log2((*diff_max)[1].p));
		}
	 }

	 if((*diff_max)[1].p > p_max) {
		//			 printf("\n[%s:%d] Update max for %d R: (%4X %4X) -> (%4X %4X) 2^%f\n", __FILE__, __LINE__,  nrounds, (*diff_max)[0].dx, (*diff_max)[0].dy, (*diff_max)[1].dx, (*diff_max)[1].dy, log2((*diff_max)[1].p));
#if 1
		// Print all trails
		uint32_t dx_in = ((*diff_max))[0].dx;
		uint32_t dy_in = ((*diff_max))[0].dy;
		uint32_t dx_out = ((*diff_max))[1].dx;
		uint32_t dy_out = ((*diff_max))[1].dy;
		std::unordered_map<std::string, differential_t**>::const_iterator hash_map_iter = trails_hash_map->begin();
		double p_tot = 0.0;
		while(hash_map_iter != trails_hash_map->end()) {
		  uint32_t dx_trail_in = (*(hash_map_iter->second))[0].dx;
		  uint32_t dy_trail_in = (*(hash_map_iter->second))[0].dy ^ (*(hash_map_iter->second))[1].dx;
		  uint32_t dx_trail_out = (*(hash_map_iter->second))[trail_len - 1].dx;
		  uint32_t dy_trail_out = (*(hash_map_iter->second))[trail_len - 1].dy;
		  //				printf("[%s:%d] (%4X %4X %4X %4X) (%4X %4X %4X %4X)\n", __FILE__, __LINE__, dx_in, dy_in, dx_out, dy_out, dx_trail_in, dy_trail_in, dx_trail_out, dy_trail_out);
		  if((dx_in == dx_trail_in) && (dy_in == dy_trail_in) && (dx_out == dx_trail_out) && (dy_out == dy_trail_out)) {
			 double p = 1.0;
			 for(uint32_t i = 0; i < trail_len; i++) {
				printf("%4X %4X ", (*(hash_map_iter->second))[i].dx, (*(hash_map_iter->second))[i].dy);
				p *= (*(hash_map_iter->second))[i].p;
			 }
			 printf(" | 2^%f\n", log2(p));
			 p_tot += p;
		  }
		  hash_map_iter++;
		}
		printf("[%s:%d] Sum 2^%f\n", __FILE__, __LINE__, log2(p_tot));
#endif
	 }
  } else { 							  // trail already added
#if 1									  // DEBUG
	 std::string s_diff = diff_to_string(diff, trail_len);
	 std::unordered_map<std::string, differential_t**>::const_iterator diff_hash_map_iter = 
		diffs_hash_map->find(s_diff);
	 assert(diff_hash_map_iter != diffs_hash_map->end());
	 assert((*diff_max)[1].p >= p);
#endif
  }
}

void simon_boost_hash_map_update(differential_t diff[NROUNDS], 
											const uint32_t trail_len,
											boost::unordered_map<std::array<differential_t, SIMON_NDIFFS>, uint32_t, simon_diff_hash, simon_diff_equal_to>* diffs_hash_map,
											boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, simon_trail_hash, simon_trail_equal_to>* trails_hash_map,
											differential_t** diff_max)
{
  //  printf("\n[%s:%d] ------- diff %4X %4X | #h %d ------\n", __FILE__, __LINE__, diff[0].dy, diff[1].dx, trails_hash_map->size());
  const uint32_t nrounds = trail_len;
#if 0									  // DEBUG
  //  printf("[%s:%s():%d] Incoming trail:\n", __FILE__, __FUNCTION__, __LINE__);
  for(uint32_t i = 0; i < trail_len; i++) {
	 printf("%4X %4X ", diff[i].dx, diff[i].dy);
  }
  printf("\n");
#endif
  assert(trail_len == NROUNDS);
  double p = 1.0;
  for(uint32_t i = 0; i < trail_len; i++) {
	 p *= diff[i].p;
  }
  std::array<differential_t, NROUNDS> trail_array;
  for(uint32_t i = 0; i < NROUNDS; i++) {
	 trail_array[i].dx = diff[i].dx;
	 trail_array[i].dy = diff[i].dy;
	 trail_array[i].npairs = diff[i].npairs;
	 trail_array[i].p = diff[i].p;
  }

#if 0									  // DEBUG
  printf("[%s:%d] CHECKPOINT! Current trails table\n", __FILE__, __LINE__);
  simon_boost_print_hash_table(*trails_hash_map, trail_len);
  printf("\n");
#endif
#if 0									  // print diff table
  printf("[%s:%d] CHECKPOINT! Current diff table\n", __FILE__, __LINE__);
  simon_boost_print_diff_hash_table(*diffs_hash_map);
  printf("[%s:%d] Total #trails: %5d\n", __FILE__, __LINE__, (uint32_t)trails_hash_map->size());
  printf("\n");
#endif

  simon_diff_hash diff_hash;  // differential hash function
  simon_trail_hash trail_hash;  // trails hash function

  boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, simon_trail_hash, simon_trail_equal_to>::iterator trail_iter 
	 = trails_hash_map->find(trail_array);

  if(trail_iter == trails_hash_map->end()) { // trail is not in the trail table
	 //	 printf("\r[%s:%d] Add new trail: 2^%f | %d", __FILE__, __LINE__, log2(p), (uint32_t)trails_hash_map->size());
	 //	 fflush(stdout);
	 //	 printf("\n[%s:%d] --- [#ntrails %5d] Add new trail: 2^%f --- \n", __FILE__, __LINE__, (uint32_t)trails_hash_map->size(), log2(p));
#if 0
	 printf("\r[%s:%d] (#ntrails %5d) Add new trail: 2^%f", __FILE__, __LINE__, (uint32_t)trails_hash_map->size(), log2(p));
	 fflush(stdout);
#endif
#if 0									  // print trail
	 double p_tmp = 1.0;
	 for(uint32_t i = 0; i < trail_len; i++) {
		printf("%2d(%X %X) ", i, trail_array[i].dx, trail_array[i].dy);
		p_tmp *= trail_array[i].p;
	 }
	 printf(" | 2^%f\n", log2(p_tmp));
#endif
	 uint32_t trail_hash_val = trail_hash(trail_array);
	 std::pair<std::array<differential_t, NROUNDS>, uint32_t> new_pair (trail_array, trail_hash_val);
	 trails_hash_map->insert(new_pair);

	 std::array<differential_t, SIMON_NDIFFS> diff_array;

	 diff_array[0].p = 1.0;
	 diff_array[0].dx = diff[0].dx;
	 diff_array[0].dy = diff[0].dy ^ diff[1].dx; // !!
	 diff_array[1].p = p;
	 diff_array[1].dx = diff[trail_len - 1].dx;
	 diff_array[1].dy = diff[trail_len - 1].dy;

	 boost::unordered_map<std::array<differential_t, SIMON_NDIFFS>, uint32_t, simon_diff_hash, simon_diff_equal_to>::iterator diff_iter 
		= diffs_hash_map->find(diff_array);

	 const double p_max = (*diff_max)[1].p;

	 if(diff_iter == diffs_hash_map->end()) { // differential is not in the diff table

		printf("[%s:%d] [%5d] Add new differential: (%8X %8X) -> (%8X %8X) 2^%f \n", __FILE__, __LINE__, 
				 (uint32_t)trails_hash_map->size(), diff_array[0].dx, diff_array[0].dy, diff_array[1].dx, diff_array[1].dy, log2(diff_array[1].p));

		uint32_t diff_hash_val = diff_hash(diff_array);
		std::pair<std::array<differential_t, SIMON_NDIFFS>, uint32_t> new_pair (diff_array, diff_hash_val);
		diffs_hash_map->insert(new_pair);
#if 1									  // print diff table
		simon_boost_print_diff_hash_table(*diffs_hash_map);
#endif
		if(p > p_max) {
		  (*diff_max)[0].p = 1.0;
		  (*diff_max)[0].dx = diff[0].dx;
		  (*diff_max)[0].dy = diff[0].dy ^ diff[1].dx; // !!
		  (*diff_max)[1].p = p;
		  (*diff_max)[1].dx = diff[trail_len - 1].dx;
		  (*diff_max)[1].dy = diff[trail_len - 1].dy;
		  printf("\n [%s:%d] BINGO! Update max for %d R: (%4X %4X) -> (%4X %4X) 2^%f\n", __FILE__, __LINE__,  nrounds, (*diff_max)[0].dx, (*diff_max)[0].dy, (*diff_max)[1].dx, (*diff_max)[1].dy, log2((*diff_max)[1].p));
		  //		  fflush(stdout);
		}

	 } else {						  // differential is already in the diff table
#if 1									  // DEBUG
		double old_p = diff_iter->first[1].p;
		double new_p = diff_iter->first[1].p + p;
#endif
		std::array<differential_t, SIMON_NDIFFS> new_diff_array = diff_iter->first;
		new_diff_array[1].p += p; // update probability
#if 1									  // DEBUG
		assert(new_diff_array[1].p == new_p);
#endif
		// remove old differential
		diffs_hash_map->erase(diff_iter);

		// add new differential
		uint32_t new_diff_hash_val = diff_hash(new_diff_array);
		std::pair<std::array<differential_t, SIMON_NDIFFS>, uint32_t> new_pair (new_diff_array, new_diff_hash_val);
		diffs_hash_map->insert(new_pair);
#if 1									  // DEBUG
		diff_iter = diffs_hash_map->find(new_diff_array);
		assert(diff_iter != diffs_hash_map->end());
		//		printf("\r[%s:%d] Improve prob of diff:  (%8X %8X) -> (%8X %8X) 2^%f -> 2^%f | #trails %d", __FILE__, __LINE__, diff_iter->first[0].dx, diff_iter->first[0].dy, diff_iter->first[1].dx, diff_iter->first[1].dy, log2(old_p), log2(new_p), (uint32_t)trails_hash_map->size());
		printf("\r[%s:%d] Improve prob of diff:  %2dR (%8X %8X) -> (%8X %8X) 2^%f -> 2^%f", __FILE__, __LINE__, nrounds, diff_iter->first[0].dx, diff_iter->first[0].dy, diff_iter->first[1].dx, diff_iter->first[1].dy, log2(old_p), log2(new_p));
		fflush(stdout);
#endif
#if 1									  // print diff table
		simon_boost_print_diff_hash_table(*diffs_hash_map);
#endif
#if 1									  // DEBUG
		assert(diff_iter->first[0].dx == diff[0].dx);
		assert(diff_iter->first[0].dy == (diff[0].dy ^ diff[1].dx));
		assert(diff_iter->first[1].dx == diff[trail_len - 1].dx);
		assert(diff_iter->first[1].dy == diff[trail_len - 1].dy);
#endif
		if(new_p > p_max) {		  // update maximum
		  (*diff_max)[0].p = 1.0;
		  (*diff_max)[0].dx = diff_iter->first[0].dx;
		  (*diff_max)[0].dy = diff_iter->first[0].dy;
		  (*diff_max)[1].p = new_p;
		  (*diff_max)[1].dx = diff_iter->first[1].dx;
		  (*diff_max)[1].dy = diff_iter->first[1].dy;
		  printf("\n[%s:%d] BONGO! Update max for %2dR: (%8X %8X) -> (%8X %8X) 2^%f\n", __FILE__, __LINE__,  nrounds, (*diff_max)[0].dx, (*diff_max)[0].dy, (*diff_max)[1].dx, (*diff_max)[1].dy, log2((*diff_max)[1].p));
		}

	 }

	 if((*diff_max)[1].p > p_max) {
		//			 printf("\n[%s:%d] Update max for %d R: (%4X %4X) -> (%4X %4X) 2^%f\n", __FILE__, __LINE__,  nrounds, (*diff_max)[0].dx, (*diff_max)[0].dy, (*diff_max)[1].dx, (*diff_max)[1].dy, log2((*diff_max)[1].p));
#if 1
		// Print all trails
		uint32_t dx_in = ((*diff_max))[0].dx;
		uint32_t dy_in = ((*diff_max))[0].dy;
		uint32_t dx_out = ((*diff_max))[1].dx;
		uint32_t dy_out = ((*diff_max))[1].dy;
		boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, simon_trail_hash, simon_trail_equal_to>::iterator hash_map_iter
		  = trails_hash_map->begin();
		double p_tot = 0.0;
		while(hash_map_iter != trails_hash_map->end()) {
		  uint32_t dx_trail_in = hash_map_iter->first[0].dx;
		  uint32_t dy_trail_in = hash_map_iter->first[0].dy ^ hash_map_iter->first[1].dx;
		  uint32_t dx_trail_out = hash_map_iter->first[trail_len - 1].dx;
		  uint32_t dy_trail_out = hash_map_iter->first[trail_len - 1].dy;
		  //				printf("[%s:%d] (%4X %4X %4X %4X) (%4X %4X %4X %4X)\n", __FILE__, __LINE__, dx_in, dy_in, dx_out, dy_out, dx_trail_in, dy_trail_in, dx_trail_out, dy_trail_out);
		  if((dx_in == dx_trail_in) && (dy_in == dy_trail_in) && (dx_out == dx_trail_out) && (dy_out == dy_trail_out)) {
			 double p = 1.0;
			 for(uint32_t i = 0; i < trail_len; i++) {
				printf("%4X %4X ", hash_map_iter->first[i].dx, hash_map_iter->first[i].dy);
				p *= hash_map_iter->first[i].p;
			 }
			 printf(" | 2^%f\n", log2(p));
			 p_tot += p;
		  }
		  hash_map_iter++;
		}
		printf("[%s:%d] Sum 2^%f\n", __FILE__, __LINE__, log2(p_tot));
#endif
	 }
  } else { // trail already added
#if 0		  // DEBUG
	 printf("[%s:%d] CHECKPOINT! Trail already in hash table\n", __FILE__, __LINE__);
#endif
#if 1									  // DEBUG
	 std::array<differential_t, SIMON_NDIFFS> diff_array;
	 diff_array[0].p = 1.0;
	 diff_array[0].dx = diff[0].dx;
	 diff_array[0].dy = diff[0].dy ^ diff[1].dx; // !!
	 diff_array[1].p = p;
	 diff_array[1].dx = diff[trail_len - 1].dx;
	 diff_array[1].dy = diff[trail_len - 1].dy;
	 boost::unordered_map<std::array<differential_t, SIMON_NDIFFS>, uint32_t, simon_diff_hash, simon_diff_equal_to>::iterator diff_iter 
		= diffs_hash_map->find(diff_array);
	 assert(diff_iter != diffs_hash_map->end());
	 assert((*diff_max)[1].p >= p);
#endif
  }

}

uint32_t simon_diffsets_remove_rot_equivalent(std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p, // highways 
															 std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy)
{
  assert(diff_set_dx_dy->size() != 0);
  std::set<differential_t, struct_comp_diff_dx_dy>::iterator set_iter = diff_set_dx_dy->begin();
  uint32_t old_set_size = diff_set_dx_dy->size();
  diff_mset_p->clear();
  while(set_iter != diff_set_dx_dy->end()) {
	 uint32_t dx = set_iter->dx;
	 uint32_t dy = set_iter->dy;
	 uint32_t npairs = set_iter->npairs;
	 double p = set_iter->p;
	 differential_t diff = {dx, dy, npairs, p};
	 diff_mset_p->insert(diff);
	 for(uint32_t i = 1; i < WORD_SIZE; i++) {
		uint32_t dx_rot = LROT(dx, i);
		uint32_t dy_rot = LROT(dy, i);
		differential_t diff_rot = {dx_rot, dy_rot, 0, 0.0};
		//		uint32_t nerased = 0;
		if(!((dx_rot == dx) && (dy_rot == dy))) {
		  diff_set_dx_dy->erase(diff_rot);
#if 0									  // DEBUG
		  printf("[%s:%d] Erased equiv (%8X %8X) = (%8X %8X)\n", __FILE__, __LINE__, dx_rot, dy_rot, dx, dy);
#endif
		}
	 }
	 set_iter++;
  }
  uint32_t new_set_size = diff_set_dx_dy->size();
  uint32_t nremoved = (old_set_size - new_set_size);
#if 1									  // DEBUG
  printf("\r[%s:%d] HW erased %d entries. New size %d 2^%4.2f", __FILE__, __LINE__, nremoved, new_set_size, log2(new_set_size));
  fflush(stdout);
#endif
  assert(diff_set_dx_dy->size() != 0);
  assert(diff_set_dx_dy->size() == diff_mset_p->size());
  return nremoved;
}

uint32_t simon_diffsets_remove_rot_equivalent_diff(differential_t diff,
																	std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p)
{
  uint32_t old_set_size = diff_mset_p->size();
  uint32_t dx = diff.dx;
  uint32_t dy = diff.dy;
  for(uint32_t i = 1; i < WORD_SIZE; i++) {
	 uint32_t dx_rot = LROT(dx, i);
	 uint32_t dy_rot = LROT(dy, i);
	 differential_t diff_rot = {dx_rot, dy_rot, 0, 0.0};
	 if(!((dx_rot == dx) && (dy_rot == dy))) {
		diff_mset_p->erase(diff_rot);
#if 1									  // DEBUG
		printf("\r[%s:%d] Erased equiv (%8X %8X) = (%8X %8X)", __FILE__, __LINE__, dx_rot, dy_rot, dx, dy);
		fflush(stdout);
#endif
	 }
  }
  uint32_t new_set_size = diff_mset_p->size();
  uint32_t nremoved = (old_set_size - new_set_size);
#if 1									  // DEBUG
  printf("\r[%s:%d] HW erased %d entries. New size %d 2^%4.2f", __FILE__, __LINE__, nremoved, new_set_size, log2(new_set_size));
  fflush(stdout);
#endif
  return nremoved;
}

/**
 * The pDDT contains entries of the form (dx, dy, p) where dx and dy are resp. the
 * input and output differences of the ROT-AND component f of Simon: y = f(x) = (x <<< s) & (x <<< t)
 * 
 * If b_hash_map is \p TRUE, then the algorithm searches for differentials and stores them in \p diffs_hash_map
 *
 * \param dyy_init initial right input difference to Simon
 */
void simon_xor_threshold_search(const int n, const int nrounds, 
										  double B[NROUNDS], double* Bn,
										  const differential_t diff_in[NROUNDS], differential_t trail[NROUNDS], 
										  const uint32_t dyy_init,
										  uint32_t lrot_const_s, uint32_t lrot_const_t, uint32_t lrot_const_u,
										  std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p, // initial highways
										  std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy,
										  std::multiset<differential_t, struct_comp_diff_p>* hways_diff_mset_p, // all highways
										  std::set<differential_t, struct_comp_diff_dx_dy>* hways_diff_set_dx_dy,
										  std::multiset<differential_t, struct_comp_diff_p>* croads_diff_mset_p, // country roads
										  std::set<differential_t, struct_comp_diff_dx_dy>* croads_diff_set_dx_dy,
										  boost::unordered_map<std::array<differential_t, SIMON_NDIFFS>, uint32_t, simon_diff_hash, simon_diff_equal_to>* diffs_hash_map,
										  boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, simon_trail_hash, simon_trail_equal_to>* trails_hash_map,
										  differential_t** diff_max,
										  bool b_hash_map,
										  double p_eps,
										  double p_thres)
{
  assert(dyy_init == 0);

  //  uint32_t max_hw = 4;//XDP_ROT_AND_MAX_HW;
  double pn = 0.0;

  // make a local copy of the input diff trail
  differential_t diff[NROUNDS] = {{0, 0, 0, 0.0}};
  for(int i = 0; i < n; i++) {
	 diff[i].dx = diff_in[i].dx;
	 diff[i].dy = diff_in[i].dy;
	 diff[i].p = diff_in[i].p;
  }

  if((n == 0) && (nrounds == 1)) {						  // Only one round

	 bool b_end = false;
	 std::multiset<differential_t, struct_comp_diff_p>::iterator mset_iter = diff_mset_p->begin();
	 uint32_t cnt = 0;
	 while((mset_iter != diff_mset_p->end()) && (!b_end)) {
		uint32_t dx = mset_iter->dx; // alpha
		uint32_t dy = mset_iter->dy; // gamma
		pn = mset_iter->p;
		uint32_t dxx = dy ^ dyy_init ^ LROT(dx, lrot_const_u); // gamma ^ dy_i ^ (alpha <<< 2)
#if 1									  // DEBUG
		printf("\r[%s:%d] %2d: [%2d / %2d] %8X -> %8X, 2^%f, 2^%f", __FILE__, __LINE__, n, cnt, diff_mset_p->size(), dx, dy, log2(pn), log2(*Bn));
		fflush(stdout);
#endif
		//		bool b_low_hw = true;
		bool b_low_hw = ((hw32(dx) <= TRAIL_MAX_HW) && (hw32(dxx) <= TRAIL_MAX_HW));
		if(!b_hash_map)
		  b_low_hw = true;
		if(b_low_hw) {
		  if((pn >= *Bn) && (pn != 0.0)) {
			 trail[n].dx = dx;		  // dx_{i}
			 trail[n].dy = dxx;		  // dx_{i+1} 
			 trail[n].p = pn;
			 if(!b_hash_map) {
				*Bn = pn;
				B[n] = pn;
			 }
		  } else {
			 b_end = true;
		  }
		}
		mset_iter++;
		cnt++;
	 }	// while()
  }

  if((n == 0) && (nrounds > 1)) {						  // Round-0 and not last round
	 bool b_end = false;
	 std::multiset<differential_t, struct_comp_diff_p>::iterator mset_iter = diff_mset_p->begin();
	 uint32_t cnt = 0;
	 while((mset_iter != diff_mset_p->end()) && (!b_end)) {
		uint32_t dx = mset_iter->dx; // alpha
		uint32_t dy = mset_iter->dy; // gamma
		pn = mset_iter->p;
		uint32_t dxx = dy ^ dyy_init ^ LROT(dx, lrot_const_u); // dx_{i+1} = gamma ^ dy_i ^ (alpha <<< 2)
		double p = pn * B[nrounds - 1 - (n + 1)];
		assert(B[nrounds - 1 - (n + 1)] != 0.0);
#if 0									  // DEBUG
		printf("\r[%s:%d] %2d: [%2d / %2d] %8X -> %8X, 2^%f, 2^%f", __FILE__, __LINE__, n, cnt, diff_mset_p->size(), dx, dy, log2(pn), log2(*Bn));
		fflush(stdout);
		printf("[%s:%d] %2d: [%2d / %2d] %8X -> %8X, 2^%f, 2^%f\n", __FILE__, __LINE__, n, cnt, diff_mset_p->size(), dx, dy, log2(pn), log2(*Bn));
#endif
#if 0								  // DEBUG
		if(b_hash_map) {
		  printf("[%s:%d] n %2d: p 2^%4.2f Bn 2^%4.2f\n", __FILE__, __LINE__, n, log2(p), log2(*Bn));
		}
#endif
		std::multiset<differential_t, struct_comp_diff_p>::iterator begin_iter = diff_mset_p->begin();
		bool b_low_hw = ((hw32(dx) <= TRAIL_MAX_HW) && (hw32(dxx) <= TRAIL_MAX_HW));
		if(!b_hash_map)
		  b_low_hw = true;
		if(b_low_hw) {
		  if((p >= *Bn) && (p != 0.0)) {
			 diff[n].dx = dx;		  // dx_{i}
			 diff[n].dy = dxx;		  // dx_{i+1}
			 diff[n].p = pn;

			 simon_xor_threshold_search(n+1, nrounds, B, Bn, diff, trail, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u, diff_mset_p, diff_set_dx_dy, hways_diff_mset_p, hways_diff_set_dx_dy, croads_diff_mset_p, croads_diff_set_dx_dy, diffs_hash_map, trails_hash_map, diff_max, b_hash_map, p_eps, p_thres);
		  } else {
			 b_end = true;
		  }
		}

		if(begin_iter != diff_mset_p->begin()) { // if the root was updated, start from beginning
		  mset_iter = diff_mset_p->begin();
		  b_end = false;
		  cnt = 0;
		  printf("[%s:%d] Return to beginning\n", __FILE__, __LINE__);
		  assert(0 == 1);
		} else {
		  mset_iter++;
		  cnt++;
		}
	 }
  }

  if((n == 1) && (n != (nrounds - 1))) {						  // Round-1 and not last round
	 bool b_end = false;
	 uint32_t cnt = 0;
	 std::multiset<differential_t, struct_comp_diff_p>::iterator mset_iter = diff_mset_p->begin();
	 while((mset_iter != diff_mset_p->end()) && (!b_end)) {
		uint32_t dx = mset_iter->dx; // alpha = dx_{i}
		uint32_t dy = mset_iter->dy; // gamma
		pn = mset_iter->p;
		uint32_t dyy = diff[n-1].dx; // dy_{i} = dx_{i-1}
		uint32_t dxx = dy ^ dyy ^ LROT(dx, lrot_const_u); // dx_{i+1} = gamma ^ dx_{i-1} ^ (alpha <<< 2)
		double p = diff[0].p * pn * B[nrounds - 1 - (n + 1)];
#if 1									  // DEBUG
		printf("\r[%s:%d] %2d: [%2d / %2d] %8X -> %8X, 2^%f, 2^%f hw %5d %5d", __FILE__, __LINE__, n, cnt, diff_mset_p->size(), dx, dy, log2(pn), log2(*Bn), hw32(dx), hw32(dy));
		fflush(stdout);
		//		printf("\n[%s:%d] %2d: [%2d / %2d] %8X -> %8X, 2^%f, 2^%f hw %5d %5d\n", __FILE__, __LINE__, n, cnt, diff_mset_p->size(), dx, dy, log2(pn), log2(*Bn), hw32(dx), hw32(dy));
#endif
#if 0								  // DEBUG
		if(b_hash_map) {
		  printf("\n[%s:%d] n %2d: p 2^%4.2f Bn 2^%4.2f\n", __FILE__, __LINE__, n, log2(p), log2(*Bn));
		}
#endif
		std::multiset<differential_t, struct_comp_diff_p>::iterator begin_iter = diff_mset_p->begin();
		bool b_low_hw = ((hw32(dx) <= TRAIL_MAX_HW) && (hw32(dxx) <= TRAIL_MAX_HW));
		if(!b_hash_map)
		  b_low_hw = true;
		if(b_low_hw) {
		  if((p >= *Bn) && (p != 0.0)) {
			 diff[n].dx = dx;		  // dx_{i}
			 diff[n].dy = dxx;		  // dx_{i+1}
			 diff[n].p = pn;

			 simon_xor_threshold_search(n+1, nrounds, B, Bn, diff, trail, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u, diff_mset_p, diff_set_dx_dy, hways_diff_mset_p, hways_diff_set_dx_dy, croads_diff_mset_p, croads_diff_set_dx_dy, diffs_hash_map, trails_hash_map, diff_max, b_hash_map, p_eps, p_thres);
		  } else {
			 b_end = true;
		  } 
		}

		if(begin_iter != diff_mset_p->begin()) { // if the root was updated, start from beginning
		  mset_iter = diff_mset_p->begin();
		  b_end = false;
		  cnt = 0;
		  printf("[%s:%d] Return to beginning\n", __FILE__, __LINE__);
		  assert(0 == 1);
		} else {
		  mset_iter++;
		  cnt++;
		}
	 }	// while()
  }

  if((n >= 2) && (n != (nrounds - 1))) { // Round-i and not last round
	 uint32_t dx = diff[n - 1].dy; // dx_{i} = dy_{i - 1}
	 uint32_t dy = 0;					 // gamma

	 differential_t diff_dy;
	 diff_dy.dx = dx;  			  // alpha
	 diff_dy.dy = 0;
	 diff_dy.p = 0.0;

	 //	 std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy;
	 std::multiset<differential_t, struct_comp_diff_p> found_mset_p;

	 // p_i >= p_min = Bn / p1 * p2 ... * p{i-1} * B{n-i} 
	 double p_min = 0.0;
	 p_min = 1.0;
	 for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
		p_min *= diff[i].p;
	 }
	 p_min = p_min * 1.0 * B[nrounds - 1 - (n + 1)]; 
	 p_min = *Bn / p_min;
#if 1								  // DEBUG
	 if(!(p_min <= 1.001)) {
		printf("[%s:%d] n %2d: %41.40f p_min 2^%4.2f Bn 2^%4.2f B[%d] 2^%4.2f\n", __FILE__, __LINE__, n, p_min, log2(p_min), log2(*Bn), nrounds - 1 - (n + 1), log2(B[nrounds - 1 - (n + 1)]));
	 }
#endif
	 assert(p_min <= 1.0);
#if 0								  // DEBUG
	 if(b_hash_map) {
		printf("[%s:%d] n %2d: p_min 2^%4.2f Bn 2^%4.2f\n", __FILE__, __LINE__, n, log2(p_min), log2(*Bn));
	 }
#endif

	 // check if the differential is not already in the set
	 std::set<differential_t, struct_comp_diff_dx_dy>::iterator hway_iter = diff_set_dx_dy->lower_bound(diff_dy);
 	 bool b_found_in_hways = (hway_iter != diff_set_dx_dy->end()) && (hway_iter->dx == dx);
	 bool b_found_in_croads = false;

	 if(b_found_in_hways) {
		while(hway_iter->dx == dx) {
		  found_mset_p.insert(*hway_iter);
		  hway_iter++;
		}
	 } else {
		double p_max = max_xdp_rot_and(dx, &dy, lrot_const_s, lrot_const_t);

		differential_t diff_max = {dx, dy, 0, p_max};
		found_mset_p.insert(diff_max);
		bool b_low_hw = (hw32(dx) <= XDP_ROT_AND_MAX_HW);
		if(!b_hash_map)
		  b_low_hw = true;

		if((p_max > XDP_ROT_AND_P_THRES) && (b_low_hw)) { // is the max a Hway?
		  uint32_t old_size = hways_diff_set_dx_dy->size();
		  hways_diff_set_dx_dy->insert(diff_max);
		  uint32_t new_size = hways_diff_set_dx_dy->size();
		  if(old_size != new_size) {
			 hways_diff_mset_p->insert(diff_max);
		  }
		  //		  diff_set_dx_dy->insert(diff_max);
		  //		  diff_mset_p->insert(diff_max);
		  //		  printf("[%s:%d] CHECKPOINT! n %d Add highway\n", __FILE__, __LINE__, n);
		} 
	 } 

#define CLEAR_CROADS 1
#if CLEAR_CROADS
	 croads_diff_set_dx_dy->clear();
	 croads_diff_mset_p->clear();
#endif

	 std::set<differential_t, struct_comp_diff_dx_dy>::iterator croad_iter = croads_diff_set_dx_dy->lower_bound(diff_dy);
	 b_found_in_croads = (croad_iter != croads_diff_set_dx_dy->end()) && (croad_iter->dx == dx);

	 uint32_t dx_prev = diff[n - 1].dx; // dy_{i} = dx_{i - 1}
	 assert(diff_set_dx_dy->size() != 0);
	 uint64_t max_cnt = (1ULL << WORD_SIZE);//(1ULL << WORD_SIZE);//(1ULL << WORD_SIZE);//unlimited //XDP_ROT_AND_MAX_DIFF_CNT;
	 bool b_backto_hway = SIMON_BACK_TO_HWAY;
	 if(b_hash_map == true) {
		//		max_cnt = (1ULL << 3);
		//		b_backto_hway = false;	
	 }
	 //	 if((b_hash_map == true) && ((n == (nrounds - 2)))) { // hash map and next round is last
	 //		b_backto_hway = true;	
	 //	 }

	 uint32_t cnt_new = xdp_rot_and_dx_pddt(diff_dy.dx, dx_prev, diff_set_dx_dy, diff_mset_p, hways_diff_set_dx_dy, hways_diff_mset_p, croads_diff_set_dx_dy, croads_diff_mset_p, lrot_const_s, lrot_const_t, lrot_const_u, max_cnt, p_min, b_backto_hway);
	 if(cnt_new != 0) {

#if 0									  // DEBUG
		printf("\r[%s:%d] [%2d / %2d] New sizes CR: Dxy %10d, Dp %10d, HW: %10d, Dp %10d", __FILE__, __LINE__, n, NROUNDS, croads_diff_set_dx_dy->size(), croads_diff_mset_p->size(), diff_set_dx_dy->size(), diff_mset_p->size());
		fflush(stdout);
#endif
		croad_iter = croads_diff_set_dx_dy->lower_bound(diff_dy);
		b_found_in_croads = (croad_iter != croads_diff_set_dx_dy->end()) && (croad_iter->dx == dx);

	 }
	 //	 b_found_in_croads = false;  // !!!

	 if(b_found_in_croads) {
		while((croad_iter->dx == dx) && (croad_iter->p >= p_min)) {
#if 0 // DEBUG
		  uint32_t dx = croad_iter->dx;
		  uint32_t dy = croad_iter->dy;
		  uint32_t dx_prev = diff[n - 1].dx;
		  bool b_is_hway = xdp_rot_and_is_dx_in_set_dx_dy(dy, dx, dx_prev, lrot_const_u, *diff_set_dx_dy);
		  assert(b_is_hway == true);
#endif
		  found_mset_p.insert(*croad_iter);
		  croad_iter++;
		}
	 }

	 std::multiset<differential_t, struct_comp_diff_p>::iterator find_iter = found_mset_p.begin();

#if 0									  // DEBUG
	 printf("\r[%s:%d] %2d: Temp set size %d ", __FILE__, __LINE__, n, found_mset_p.size());
	 fflush(stdout);
#endif

	 if(find_iter->dx == dx) {
		while((find_iter->dx == dx) && (find_iter != found_mset_p.end())) {
		  assert((find_iter->dx == dx));
		  diff_dy = *find_iter;

		  dx = diff_dy.dx;
		  dy = diff_dy.dy;
		  pn = diff_dy.p;

		  double p = 1.0;
		  for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
			 p *= diff[i].p;
		  }
		  p = p * pn * B[nrounds - 1 - (n + 1)]; 

		  uint32_t dyy = diff[n-1].dx; // dy_{i} = dx_{i-1}
		  uint32_t dxx = dy ^ dyy ^ LROT(dx, lrot_const_u); // dx_{i+1} = gamma ^ dx_{i-1} ^ (alpha <<< 2)

		  // store the beginnig
		  bool b_low_hw = ((hw32(dx) <= TRAIL_MAX_HW) && (hw32(dxx) <= TRAIL_MAX_HW));
		  if(!b_hash_map)
			 b_low_hw = true;
		  if(b_low_hw) {
			 if((p >= *Bn) && (p != 0.0)) {
				diff[n].dx = dx;		  // dx_{i}
				diff[n].dy = dxx;	  // dx_{i+1}
				diff[n].p = pn;
				simon_xor_threshold_search(n+1, nrounds, B, Bn, diff, trail, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u, diff_mset_p, diff_set_dx_dy, hways_diff_mset_p, hways_diff_set_dx_dy, croads_diff_mset_p, croads_diff_set_dx_dy, diffs_hash_map, trails_hash_map, diff_max, b_hash_map, p_eps, p_thres);
			 }
		  }
		  find_iter++;
		}	// while
	 }		// if
  }

  if((n == (nrounds - 1)) && (nrounds > 1)) {		  // Last round

	 uint32_t dx = diff[n - 1].dy; // dx_{i} = dy_{i - 1}
	 uint32_t dy = 0;					 // gamma

	 pn = max_xdp_rot_and(dx, &dy, lrot_const_s, lrot_const_t);
#if 0									  // DEBUG
	 double p_tmp = xdp_rot_and(dx, dy, lrot_const_s, lrot_const_t);
	 assert(pn == p_tmp);
#endif

	 uint32_t dyy = diff[n-1].dx; // dy_{i} = dx_{i-1}
	 uint32_t dxx = dy ^ dyy ^ LROT(dx, lrot_const_u); // dx_{i+1} = gamma ^ dx_{i-1} ^ (alpha <<< 2)

	 double p = 1.0;
	 for(int i = 0; i < n; i++) {
		p *= diff[i].p;
	 }
	 p *= pn;
	 diff[n].dx = dx;
	 diff[n].dy = dxx;
	 diff[n].p = pn;

	 bool b_low_hw = ((hw32(dx) <= TRAIL_MAX_HW) && (hw32(dxx) <= TRAIL_MAX_HW));
	 //	 bool b_low_hw = ((hw32(dx) + hw32(dxx)) <= 5); // !!!
	 if(!b_hash_map)
		b_low_hw = true;
	 if(b_low_hw) {

		if((!b_hash_map) && (p >= *Bn) && (p != 1.0) && (p != 0.0)) { // skip the 0-diff trail (p = 1.0)
#if 1									  // DEBUG
		  if (p > *Bn) {
			 printf("\n[%s:%d] %d | Update best found Bn: 2^%f -> 2^%f\n", __FILE__, __LINE__, n, log2(*Bn), log2(p));
		  }
#endif
		  *Bn = p;
		  B[n] = p;
		  for(int i = 0; i < nrounds; i++) {
			 trail[i].dx = diff[i].dx;
			 trail[i].dy = diff[i].dy;
			 trail[i].p = diff[i].p;
		  }
		  //		  simon_diffsets_remove_rot_equivalent_diff(diff[0], diff_mset_p);
		} 

	 }

	 // store trail in hash table
    //	 if((b_hash_map) && (p != 1.0) && (p != 0.0) && (n == (NROUNDS - 1)) && (b_low_hw)) {
	 if((b_hash_map) && (p >= *Bn) && (p != 1.0) && (p != 0.0) && (n == (NROUNDS - 1)) && (b_low_hw)) { // skip the 0-diff trail (p = 1.0)
#if 0
		if(*Bn != B[n]) {
		  printf("[%s:%d] 2^%f 2^%f\n", __FILE__, __LINE__, log2(*Bn), log2(B[n]));
		}
		assert(*Bn == B[n]);
#endif
		uint32_t trail_len = n + 1;
		assert(trail_len == (uint32_t)nrounds);
#if 0									  // DEBUG
		//		std::cout << std::string(50, '\n'); // clear screen
		double p_tmp = 1.0;
		printf("\n\n[%s:%d] Incoming trail\n", __FILE__, __LINE__);
		for(int i = 0; i <= n; i++) {
		  //		  p_tmp *= trail[i].p;
		  //		  printf("%2d(%X %X) ", i, trail[i].dx, trail[i].dy);
		  //		  printf("%X %X ", trail[i].dx, trail[i].dy);
		  p_tmp *= diff[i].p;
		  printf("%X %X ", diff[i].dx, diff[i].dy);
		}
		printf(" | 2^%f\n", log2(p_tmp));
		//		printf("[%s:%d] Trails:\n", __FILE__, __LINE__);
		//		simon_boost_print_hash_table(*trails_hash_map, trail_len);
#endif
		//		simon_boost_hash_map_update(trail, trail_len, diffs_hash_map, trails_hash_map, diff_max);
		simon_boost_hash_map_update(diff, trail_len, diffs_hash_map, trails_hash_map, diff_max);
		//		sleep(5);
	 }

  }
}

void simon_diff_mset_p_to_mset_hw(std::multiset<differential_t, struct_comp_diff_p> diff_mset_p, std::multiset<differential_t, struct_comp_diff_hw>* diff_mset_hw) {
  std::multiset<differential_t, struct_comp_diff_p>::iterator iter = diff_mset_p.begin();
  while(iter != diff_mset_p.end()) {
	 diff_mset_hw->insert(*iter);
	 iter++;
  }
}

/**
 * \param best_trail best found trail with prob. below exhaustive search
 * \param lowp_trail best found trail with prob. above exhaustive search (best low prob. trail)
 */
uint32_t simon_xor_trail_search(uint32_t key[SIMON_MAX_NROUNDS], double B[NROUNDS], 
										  differential_t best_trail[NROUNDS], uint32_t* best_trail_len)
{
  boost::unordered_map<std::array<differential_t, SIMON_NDIFFS>, uint32_t, simon_diff_hash, simon_diff_equal_to> diffs_hash_map;
  boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, simon_trail_hash, simon_trail_equal_to> trails_hash_map;

  uint32_t lrot_const_s = SIMON_LROT_CONST_S; 
  uint32_t lrot_const_t = SIMON_LROT_CONST_T;
  uint32_t lrot_const_u = SIMON_LROT_CONST_U;
  double p_thres = XDP_ROT_AND_P_THRES;
  uint32_t npairs = SIMON_NPAIRS;

  differential_t diff[NROUNDS];	  // arrey of differences
  differential_t trail[NROUNDS] = {{0, 0, 0, 0.0}};

  // init bounds
  for(int i = 0; i < NROUNDS; i++) {
	 B[i] = 0.0;
  }

  std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy; // Dxy
  std::multiset<differential_t, struct_comp_diff_p> diff_mset_p;	 // Dp

  std::multiset<differential_t, struct_comp_diff_p> hways_diff_mset_p; // all highways
  std::set<differential_t, struct_comp_diff_dx_dy> hways_diff_set_dx_dy;

  std::set<differential_t, struct_comp_diff_dx_dy> croads_diff_set_dx_dy; // Dxy
  std::multiset<differential_t, struct_comp_diff_p> croads_diff_mset_p;	 // Dp

#if 1									  // recursive pDDT
  printf("[%s:%d] Initialize hways:\n", __FILE__, __LINE__);
  uint64_t max_cnt = XDP_ROT_AND_MAX_DIFF_CNT;
  xdp_rot_and_pddt(&diff_set_dx_dy, &diff_mset_p, lrot_const_s, lrot_const_t, max_cnt, p_thres);

  hways_diff_mset_p = diff_mset_p;
  hways_diff_set_dx_dy = diff_set_dx_dy;

  //  xdp_rot_and_print_set_dx_dy(diff_set_dx_dy);

#else	 // full DDT
  xdp_rot_and_ddt(&diff_set_dx_dy, &diff_mset_p, lrot_const_s, lrot_const_t, p_thres);
#endif

  //#if !CLEAR_CROADS								  // !!!
  //  croads_diff_set_dx_dy = diff_set_dx_dy;
  //  croads_diff_mset_p = diff_mset_p;
  //#endif
#if 0//(WORD_SIZE < 12)									  // DEBUG
  std::set<differential_t, struct_comp_diff_dx_dy> full_diff_set_dx_dy; // Dxy
  std::multiset<differential_t, struct_comp_diff_p> full_diff_mset_p;	 // Dp
  xdp_rot_and_ddt(&full_diff_set_dx_dy, &full_diff_mset_p, lrot_const_s, lrot_const_t, p_thres);

  uint32_t len_pddt_dx_dy = diff_set_dx_dy.size();
  uint32_t len_pddt_p = diff_mset_p.size();
  uint32_t len_ddt_dx_dy = full_diff_set_dx_dy.size();
  uint32_t len_ddt_p = full_diff_mset_p.size();
  printf("[%s:%d] %d %d | %d %d\n", __FILE__, __LINE__, len_pddt_dx_dy, len_pddt_p, len_ddt_dx_dy, len_ddt_p);
  assert(len_pddt_dx_dy == len_ddt_dx_dy);
  assert(len_pddt_p == len_ddt_p);
  assert(len_pddt_dx_dy == len_pddt_p);
  assert(len_ddt_dx_dy == len_ddt_p);
#endif

  printf("Initial set sizes: Dp %d, Dxy %d\n", (uint32_t)diff_mset_p.size(), (uint32_t)diff_set_dx_dy.size());
  assert(diff_set_dx_dy.size() == diff_mset_p.size());

  differential_t** diff_max;//[2] = {{0,0,0,0.0}};
  diff_max = (differential_t** )calloc(1, sizeof(differential_t*));
  *diff_max = (differential_t*)calloc(2, sizeof(differential_t));
  (*diff_max)[0] = {0, 0, 0, 0.0};
  (*diff_max)[1] = {0, 0, 0, 0.0};

  double Bn_init = 0.0;
  uint32_t dyy_init = 0;

  uint32_t nrounds = 0;

#define USE_PRECOMPUTED_BOUNDS 0

// use bounds computed from previous run
#if USE_PRECOMPUTED_BOUNDS	
  assert(NROUNDS <= 20);
#if(WORD_SIZE == 32)
  uint32_t N = 20;
  for(uint32_t i = 0; i < N; i++) {
	 B[i] = g_B32[i];
	 trail[i] = g_trail32[i];
	 diff[i] = g_trail32[i];
  }
#endif  // #if(WORD_SIZE == 32)
//  nrounds = 17; // start the search from a round other than the first 
  Bn_init = B[nrounds];
#endif  // #if USE_PRECOMPUTED_BOUNDS	


  do {

	 //		printf("--- [%s:%d] hways_diff_set_dx_dy ---\n", __FILE__, __LINE__);
	 //		xdp_rot_and_print_set_dx_dy(diff_set_dx_dy);

	 nrounds++;
	 printf("[%s:%d] nrounds = %d, Bn_init = 2^%f : key %8X %8X %8X %8X\n", __FILE__, __LINE__, nrounds, log2(Bn_init), key[0], key[1], key[2], key[3]);
	 double Bn = Bn_init;
	 B[nrounds - 1] = Bn_init;
	 int r = 0;						  // initial round
//	 int r = 15;//nrounds - 1;						  // initial round

	 // init diffs
	 for(int i = r; i < NROUNDS; i++) { // !!! i = r
		diff[i].dx = 0;
		diff[i].dy = 0;
		diff[i].p = 0.0;
	 }

	 assert(dyy_init == 0);
	 bool b_hash_map = false;
	 double p_eps = 1.0;
	 trails_hash_map.clear();
	 diffs_hash_map.clear();

	 //	 uint32_t hways_size_before = hways_diff_mset_p.size();
	 simon_xor_threshold_search(r, nrounds, B, &Bn, diff, trail, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u, &diff_mset_p, &diff_set_dx_dy, &hways_diff_mset_p, &hways_diff_set_dx_dy, &croads_diff_mset_p, &croads_diff_set_dx_dy, &diffs_hash_map, &trails_hash_map, diff_max, b_hash_map, p_eps, p_thres);
	 assert(B[nrounds - 1] == Bn);

#if 1									  // DEBUG
	 printf("\n");
	 for(uint32_t i = 0; i < nrounds; i++) {
		printf("B[%2d] = 2^%f", i, log2(B[i]));
		if(i > 0) {
		  if(B[i-1] < B[i]) {
			 printf(" <-");
		  }
		}
		printf("\n");
	 }
#endif

#if 0
	 if(diff_mset_p.size() != diff_set_dx_dy.size()) {
		printf("--- [%s:%d] hways_diff_set_dx_dy ---\n", __FILE__, __LINE__);
		xdp_rot_and_print_set_dx_dy(diff_set_dx_dy);

		printf("\n---[%s:%d] hways_diff_mset_p --- \n", __FILE__, __LINE__);
		xdp_rot_and_print_mset_p(diff_mset_p);
	 }
#endif

	 printf("pDDT sizes: HW Dp %d, Dxy %d, CR Dp %d, Dxy %d, p_thres %f 2^%f\n", diff_mset_p.size(), diff_set_dx_dy.size(), croads_diff_mset_p.size(), croads_diff_set_dx_dy.size(), p_thres, log2(p_thres));

	 //	 assert(diff_mset_p.size() == diff_set_dx_dy.size());

#if 1									  // DEBUG
	 double p_tot = 1.0;
	 for(uint32_t i = 0; i < nrounds; i++) {
		printf("%2d: %8X -> %8X %f (2^%f)\n", i, trail[i].dx, trail[i].dy, trail[i].p, log2(trail[i].p));
		p_tot *= trail[i].p;
	 }
	 printf("p_tot = %16.15f = 2^%f, Bn = %f = 2^%f\n", p_tot, log2(p_tot), Bn, log2(Bn));
#endif  // #if 0									  // DEBUG
#if 1	  // VERIFY
	 if(nrounds >=3) {
		for(uint32_t i = (nrounds - 1); i >= 2; i--) {
		  assert(trail[i].dx == trail[i-1].dy);
		  //		  assert(trail[i].dy == trail[i-1].dx);
		}
	 }
#endif  // #if 1	  // VERIFY

	 // Compute an initial bound for the next round
	 uint32_t next_round = nrounds;

#if !USE_PRECOMPUTED_BOUNDS	
	 if((next_round >= 2) && (next_round < NROUNDS)) {
		//		uint32_t dx = diff[next_round - 1].dy; // dx_{i} = dy_{i - 1}
		uint32_t dx = trail[next_round - 1].dy; // dx_{i} = dy_{i - 1}
		uint32_t dy = 0;
		double p = 0.0;

		p = max_xdp_rot_and(dx, &dy, lrot_const_s, lrot_const_t);
		assert(p != 0.0);
#if 1									  // DEBUG
		double p_tmp = xdp_rot_and(dx, dy, lrot_const_s, lrot_const_t);
		if(p != p_tmp) {
		  printf("[%s:%d] ERROR %X -> %X = %f != %f\n", 
					__FILE__, __LINE__, dx, dy, p, p_tmp);
		} else {
		  printf("[%s:%d] Init bound: %X -> %X = %f 2^%f\n", 
					__FILE__, __LINE__, dx, dy, p, log2(p));
		}
		assert(p == p_tmp);
#endif
		uint32_t dyy = trail[next_round - 1].dx; // dy_{i} = dx_{i-1}
		uint32_t dxx = dy ^ dyy ^ LROT(dx, lrot_const_u); // dx_{i+1} = gamma ^ dx_{i-1} ^ (alpha <<< 2)

		//		printf("[%s:%d] Set B[%d] = 2^%f\n", __FILE__, __LINE__, next_round, log2(Bn_init));
		Bn_init = B[next_round - 1] * p;
		B[next_round] = Bn_init;
		trail[next_round].dx = dx;
		trail[next_round].dy = dxx;
		trail[next_round].p = p;

		assert(trail[next_round].dx == trail[next_round-1].dy);

	 } else {
		Bn_init = 0.0;
	 }
#else	 // USE_PRECOMPUTED_BOUNDS	
	 Bn_init = g_B32[next_round];
	 trail[next_round].dx = g_trail32[next_round].dx;
	 trail[next_round].dy = g_trail32[next_round].dy;
	 trail[next_round].p = g_trail32[next_round].p;
#endif  // #if !USE_PRECOMPUTED_BOUNDS	

#if 0
	 uint32_t hways_size_after = hways_diff_mset_p.size();
	 if(hways_size_before != hways_size_after) {
		diff_set_dx_dy.clear();
		diff_mset_p.clear();

		diff_set_dx_dy = hways_diff_set_dx_dy;
		diff_mset_p = hways_diff_mset_p;

		//		simon_diff_mset_p_to_mset_hw(diff_mset_p, &diff_mset_hw);
#if 0									  // DEBUG
 		xdp_rot_and_print_set_dx_dy(diff_set_dx_dy);
		xdp_rot_and_print_mset_p(diff_mset_p);
#endif

		Bn_init = Bn;
		uint32_t next_round = nrounds;
		B[next_round] = 0;
		trail[next_round].dx = 0;
		trail[next_round].dy = 0;
		trail[next_round].p = 0.0;

		nrounds -= 1;

		printf("\n\n --- [%s:%d] Hway table update Dp %d Dxy %d: start again from round %d ---\n\n", __FILE__, __LINE__, diff_mset_p.size(), diff_set_dx_dy.size(), nrounds);
	 } 
#endif

	 // If the bound for i rounds is better than the bound for (i - 1) rounds -- start the search again from round 1
	 uint32_t i = nrounds - 1;
	 if(i > 0) {
		if(B[i-1] < B[i]) {
		  nrounds = 0;
		  Bn_init = 0.0;
		  for(int j = 0; j < NROUNDS; j++) {
			 B[j] = 0.0;
		  }
		  printf("[%s:%d] Start again from round 1\n", __FILE__, __LINE__);
		}
		assert(B[i-1] >= B[i]);
	 }

#if 0
	 if(B[nrounds - 1] > p_rand) {
		for(uint32_t i = 0; i < nrounds; i++) {
		  best_trail[i].dx = trail[i].dx;
		  best_trail[i].dy = trail[i].dy;
		  best_trail[i].p = trail[i].p;
		}
		*best_trail_len = nrounds;
	 }
#endif

#if 0									  // DEBUG
	 simon_verify_xor_trail(nrounds + 1, npairs, key, trail, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u);
#endif
	 printf("[%s:%d] WORD_SIZE %d NROUNDS %d XDP_ROT_AND_P_THRES %f 2^%f XDP_ROT_AND_MAX_DIFF_CNT %lld 2^%4.2f SIMON_EPS %f 2^%f XDP_ROT_AND_MAX_HW %d TRAIL_MAX_HW %d SIMON_BACK_TO_HWAY %d\n", 
			  __FILE__, __LINE__, WORD_SIZE, NROUNDS, XDP_ROT_AND_P_THRES, log2(XDP_ROT_AND_P_THRES), XDP_ROT_AND_MAX_DIFF_CNT, log2(XDP_ROT_AND_MAX_DIFF_CNT), SIMON_EPS, log2(SIMON_EPS), XDP_ROT_AND_MAX_HW, TRAIL_MAX_HW, SIMON_BACK_TO_HWAY);

  } while(nrounds < NROUNDS);

  printf("[%s:%d] nrounds = %d\n", __FILE__, __LINE__, nrounds);
  assert(nrounds == NROUNDS);

  assert(dyy_init == 0);
  simon_verify_xor_trail(NROUNDS, npairs, key, trail, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u);
  simon_verify_xor_differential(NROUNDS, npairs, key, trail, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u);

  // Store best found trail
  for(int i = 0; i < NROUNDS; i++) {
	 best_trail[i].dx = trail[i].dx;
	 best_trail[i].dy = trail[i].dy;
	 best_trail[i].p = trail[i].p;
  }
  *best_trail_len = NROUNDS;

  // Reset diff
  for(int i = 0; i < NROUNDS; i++) {
	 diff[i].dx = 0;
	 diff[i].dy = 0;
	 diff[i].p = 0.0;
  }

  // Add initial trail
  double p = 1.0;
  for(uint32_t i = 0; i < NROUNDS; i++) {
	 p *= trail[i].p;
  }

  // Init diff
  for(int i = 0; i < NROUNDS; i++) {
	 diff[i].dx = trail[i].dx;
	 diff[i].dy = trail[i].dy;
	 diff[i].p = trail[i].p;
  }

#if 0
  std::array<differential_t, NROUNDS> trail_array;
  for(uint32_t i = 0; i < NROUNDS; i++) {
	 trail_array[i].dx = trail[i].dx;
	 trail_array[i].dy = trail[i].dy;
	 trail_array[i].npairs = trail[i].npairs;
	 trail_array[i].p = trail[i].p;
  }

  simon_trail_hash trail_hash;  // trails hash function
  uint32_t trail_hash_val = trail_hash(trail_array);
  std::pair<std::array<differential_t, NROUNDS>, uint32_t> new_pair (trail_array, trail_hash_val);
  trails_hash_map.insert(new_pair);

  printf("[%s:%d] Initial trail\n", __FILE__, __LINE__);
  simon_print_trail_hash_map(trails_hash_map);

  // Add initial differential
  std::array<differential_t, SIMON_NDIFFS> diff_array;
  diff_array[0].p = 1.0;
  diff_array[0].dx = diff[0].dx;
  diff_array[0].dy = diff[0].dy ^ diff[1].dx; // !!
  diff_array[1].p = p;
  diff_array[1].dx = diff[nrounds - 1].dx;
  diff_array[1].dy = diff[nrounds - 1].dy;

  simon_diff_hash diff_hash;  // differential hash function
  boost::unordered_map<std::array<differential_t, SIMON_NDIFFS>, uint32_t, simon_diff_hash, simon_diff_equal_to>::iterator diff_iter 
	 = diffs_hash_map.find(diff_array);

  double p_max = (*diff_max)[1].p;

  assert((*diff_max)[1].p == 0.0);
  assert(diff_iter == diffs_hash_map.end());
  if(diff_iter == diffs_hash_map.end()) {
	 uint32_t diff_hash_val = diff_hash(diff_array);
	 std::pair<std::array<differential_t, SIMON_NDIFFS>, uint32_t> new_pair (diff_array, diff_hash_val);
	 diffs_hash_map.insert(new_pair);

	 //	 printf("[%s:%d] CHECKPOINT!\n", __FILE__, __LINE__);
	 if(p > p_max) {
		(*diff_max)[0].p = (*diff_max)[1].p = p;
		(*diff_max)[0].dx = trail[0].dx;
		(*diff_max)[0].dy = trail[0].dy ^ trail[1].dx; // !!
		(*diff_max)[1].dx = trail[NROUNDS - 1].dx;
		(*diff_max)[1].dy = trail[NROUNDS - 1].dy;
		printf("[%s:%d] Update MAX differential: %4X %4X -> %4X %4X 2^%f | #trails %d\n", __FILE__, __LINE__, (*diff_max)[0].dx, (*diff_max)[0].dy, (*diff_max)[1].dx, (*diff_max)[1].dy, log2((*diff_max)[1].p), trails_hash_map.size());
	 }
  }
  printf("[%s:%d] Initial MAX differential: %4X %4X -> %4X %4X 2^%f | #trails %d\n", __FILE__, __LINE__, (*diff_max)[0].dx, (*diff_max)[0].dy, (*diff_max)[1].dx, (*diff_max)[1].dy, log2((*diff_max)[1].p), trails_hash_map.size());
#endif

  // Search for differentials (store multiple trails for last round)
#if 0
  double Bn = B[nrounds - 1] * SIMON_EPS;
  //  double Bn = B[*lowp_trail_len - 1] * SIMON_EPS;
  int r = 0;						  // initial round
  bool b_hash_map = true;
  double p_eps = 1.0;
  simon_xor_threshold_search(r, nrounds, B, &Bn, diff, trail, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u, &diff_mset_p, &diff_set_dx_dy, &hways_diff_mset_p, &hways_diff_set_dx_dy, &croads_diff_mset_p, &croads_diff_set_dx_dy, &diffs_hash_map, &trails_hash_map, diff_max, b_hash_map, p_eps, p_thres);
#endif
  //  uint32_t trail_len = nrounds;

  //  printf("[%s:%d] Trails:\n", __FILE__, __LINE__);
  //  simon_print_hash_table(trails_hash_map, trail_len);
  //  printf("\n[%s:%d] Differentials:\n", __FILE__, __LINE__);
  //  simon_print_diff_hash_table(diffs_hash_map, trail_len);

  printf("\n[%s:%d] Best differential for %d R: (%4X %4X) -> (%4X %4X) 2^%f\n", __FILE__, __LINE__,  nrounds, (*diff_max)[0].dx, (*diff_max)[0].dy, (*diff_max)[1].dx, (*diff_max)[1].dy, log2((*diff_max)[1].p));

#if 0								  // Verify probability of differential
  //  uint32_t key[SIMON_MAX_NROUNDS] = {0};
  key[0] = random32() & MASK;
  key[1] = random32() & MASK;
  key[2] = random32() & MASK;
  key[3] = random32() & MASK;
  uint32_t dx_in = ((*diff_max))[0].dx;
  uint32_t dy_in = ((*diff_max))[0].dy;
  uint32_t dx_out = ((*diff_max))[1].dy;
  uint32_t dy_out = ((*diff_max))[1].dx;
  differential_t input_diff = {dx_in, dy_in, 0, 0.0};
  differential_t output_diff = {dx_out, dy_out, 0, 0.0};
  uint32_t temp_npairs = 1U << 27;
  std::vector<simon_diff_graph_edge_t> E;
  // generate random key
  double p_exp = simon_verify_differential_approx(key, input_diff, output_diff, nrounds, temp_npairs, &E);
  printf("\n[%s:%s():%d]:\n Verified %d R differential (%8X %8X) -> (%8X %8X) | 2^%4.2f CP pairs\n Final probability p = 2^%f\n", __FILE__, __FUNCTION__, __LINE__, nrounds, dx_in, dy_in, dx_out, dy_out, log2(temp_npairs * temp_npairs), log2(p_exp));
  //  printf(" | 2^%f\n", log2(p_exp));
#endif

  //  diff_max = (differential_t** )calloc(1, sizeof(differential_t*));
  //  *diff_max = (differential_t*)calloc(2, sizeof(differential_t));
  free(*diff_max);
  free(diff_max);

  //  simon_trail_cluster_search(trails_hash_map, B, trail, num_rounds);
  printf("[%s:%d] nrounds %d\n", __FILE__, __LINE__, nrounds);
  assert(nrounds == NROUNDS);
  return NROUNDS;
}


// {--- Simon cluster trails ---

/**
 * Compute (an approximation of) the probability of a differential
 * corresponding to the best trail found by \ref
 * simon_xor_threshold_search . The algorithm grows a cluster of
 * differential trails, each of which connects the input and outout
 * differences corresponding to the best found trail. The sum of their
 * probabilities is an approximation of the prob. of the differential.
 *
 * \param B array of the probabilities of the best found trails for up
 *        to \ref simon_xor_threshold_search nrounds . Computed by
 * \param trail best trail found by \ref simon_xor_threshold_search .
 * \param input_diff input difference of the differential.
 * \param output_diff output difference of the differential.
 * \param eps times away from the optimal (e.g. eps = 2, 3, 2^{10}, ...).
 *
 */
void simon_xor_cluster_trails(const int n, const int nrounds, 
										const double B[NROUNDS], 
										const differential_t diff_in[NROUNDS], const differential_t best_trail[NROUNDS], 
										std::unordered_map<std::string, differential_t**>* trails_hash_map,
										const differential_t input_diff, const differential_t output_diff, 
										uint32_t lrot_const_s, uint32_t lrot_const_t, uint32_t lrot_const_u,
										std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p, // highways
										std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy,
										std::multiset<differential_t, struct_comp_diff_p>* croads_diff_mset_p, // country roads
										std::set<differential_t, struct_comp_diff_dx_dy>* croads_diff_set_dx_dy,
										double eps)
{
#if 1
  double pn = 0.0;

  assert(nrounds > 1);

  // make a local copy of the input diff trail
  differential_t diff[NROUNDS] = {{0, 0, 0, 0.0}};
  for(int i = 0; i < n; i++) {
	 diff[i].dx = diff_in[i].dx;
	 diff[i].dy = diff_in[i].dy;
	 diff[i].p = diff_in[i].p;
  }

  if((n >= 0) && (n != (nrounds - 1))) { // Round-i and not last round
	 uint32_t dx = input_diff.dx;
	 if(n > 0) {
		dx = diff[n - 1].dy; // dx_{i} = dy_{i - 1}
	 }
	 uint32_t dy = 0;					 // gamma

	 differential_t diff_dy;
	 diff_dy.dx = dx;  			  // alpha
	 diff_dy.dy = 0;
	 diff_dy.p = 0.0;

	 std::multiset<differential_t, struct_comp_diff_p> found_mset_p;

	 // p_i >= p_min = Bn / p1 * p2 ... * p{i-1} * B{n-i} 
	 double p_min = 1.0;
	 for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
		p_min *= diff[i].p;
	 }
	 p_min = p_min * 1.0 * B[nrounds - 1 - (n + 1)]; 
	 p_min = (B[nrounds - 1] * eps) / p_min;
	 assert(p_min <= 1.0);

	 // check if the differential is not already in the set
	 std::set<differential_t, struct_comp_diff_dx_dy>::iterator hway_iter = diff_set_dx_dy->lower_bound(diff_dy);
	 bool b_found_in_hways = (hway_iter != diff_set_dx_dy->end()) && (hway_iter->dx == dx);
	 bool b_found_in_croads = false;
	 if((b_found_in_hways) && (hway_iter->p >= p_min)) { // !!
		while(hway_iter->dx == dx) {
		  found_mset_p.insert(*hway_iter);
		  hway_iter++;
		}
	 }

	 croads_diff_set_dx_dy->clear();
	 croads_diff_mset_p->clear();
	 b_found_in_croads = false;
	 std::set<differential_t, struct_comp_diff_dx_dy>::iterator croad_iter;

	 uint32_t dx_prev = input_diff.dx;
	 if(n > 0) {
		dx_prev = diff[n - 1].dx;
	 }
	 assert(diff_set_dx_dy->size() != 0);
	 const uint64_t max_cnt = (1ULL << 5);//(1ULL << WORD_SIZE);//(1ULL << 5);//XDP_ROT_AND_MAX_DIFF_CNT;  // !!!
	 bool b_backto_hway = false;
#if 1
	 std::set<differential_t, struct_comp_diff_dx_dy> dummy_hways_diff_set_dx_dy = *diff_set_dx_dy;
	 std::multiset<differential_t, struct_comp_diff_p> dummy_hways_diff_mset_p = *diff_mset_p; 
#endif
	 uint32_t cnt_new = xdp_rot_and_dx_pddt(diff_dy.dx, dx_prev, diff_set_dx_dy, diff_mset_p, &dummy_hways_diff_set_dx_dy, &dummy_hways_diff_mset_p, croads_diff_set_dx_dy, croads_diff_mset_p, lrot_const_s, lrot_const_t, lrot_const_u, max_cnt, p_min, b_backto_hway);

	 if(cnt_new != 0) {
#if 1									  // DEBUG
		printf("\r[%s:%d] [%2d / %2d]: Added %d new country roads: p_min = %f (2^%f). New sizes: Dxy %d, Dp %d.", __FILE__, __LINE__, n, NROUNDS, cnt_new, p_min, log2(p_min), (uint32_t)croads_diff_set_dx_dy->size(), (uint32_t)croads_diff_mset_p->size());
		fflush(stdout);
#endif
		croad_iter = croads_diff_set_dx_dy->lower_bound(diff_dy);
		b_found_in_croads = (croad_iter != croads_diff_set_dx_dy->end()) && (croad_iter->dx == dx);
	 } 

	 if(b_found_in_croads) {
		assert(croad_iter->p >= p_min);
		//		while(croad_iter->dx == dx) {
		while((croad_iter->dx == dx) && (croad_iter->p >= p_min)) {
		  found_mset_p.insert(*croad_iter);
		  croad_iter++;
		}
	 }

	 std::multiset<differential_t, struct_comp_diff_p>::iterator find_iter = found_mset_p.begin();

	 if(find_iter->dx == dx) {
		while((find_iter->dx == dx) && (find_iter != found_mset_p.end())) {
		  assert((find_iter->dx == dx));
		  diff_dy = *find_iter;

		  dx = diff_dy.dx;
		  dy = diff_dy.dy;
		  pn = diff_dy.p;

		  double p = 1.0;
		  for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
			 p *= diff[i].p;
		  }
		  //		  p = p * pn * B[nrounds - 1 - (n + 1)]; 
		  p = p * pn;				  // p[0] * p[1] * p[n-1] * p[n]

		  // !!
		  //			 uint32_t dyy = input_diff.dy;
		  uint32_t dyy = input_diff.dy;
		  if(n > 0) {
			 dyy = diff[n-1].dx; // dy_{i} = dx_{i-1}
		  }
		  uint32_t dxx = dy ^ dyy ^ LROT(dx, lrot_const_u); // dx_{i+1} = gamma ^ dx_{i-1} ^ (alpha <<< 2)

		  diff[n].dx = dx;		  // dx_{i}
		  diff[n].dy = dxx;	  // dx_{i+1}
		  diff[n].p = pn;

		  bool b_penultimate = true;
		  if(n == (nrounds - 2)) {
			 b_penultimate = (diff[n].dy == output_diff.dx);
		  }
		bool b_low_hw = ((hw32(dx) <= TRAIL_MAX_HW) && (hw32(dxx) <= TRAIL_MAX_HW)); // !!!
		//		  if(b_penultimate) {
		if((b_penultimate) && (b_low_hw)) {
			 //			 simon_xor_cluster_trails(n+1, nrounds, B, diff, best_trail, trails_hash_map, dyy_init, input_diff, output_diff, lrot_const_s, lrot_const_t, lrot_const_u, diff_mset_p, diff_set_dx_dy, croads_diff_mset_p, croads_diff_set_dx_dy, eps);
			 simon_xor_cluster_trails(n+1, nrounds, B, diff, best_trail, trails_hash_map, input_diff, output_diff, lrot_const_s, lrot_const_t, lrot_const_u, diff_mset_p, diff_set_dx_dy, croads_diff_mset_p, croads_diff_set_dx_dy, eps);
		  } else {
			 printf("\r[%s:%d] Penultimate round does not match output diff: %8X vs. %8X", __FILE__, __LINE__, diff[n].dy, output_diff.dx);
			 fflush(stdout);
		  }
		  find_iter++;
		}	// while
	 }		// if
  }

  if((n == (nrounds - 1)) && (nrounds > 1)) {		  // Last round

	 uint32_t dx = diff[n - 1].dy; // dx_{i} = dy_{i - 1}
	 uint32_t dy = 0;					 // gamma

	 pn = max_xdp_rot_and(dx, &dy, lrot_const_s, lrot_const_t);

	 uint32_t dyy = diff[n-1].dx; // dy_{i} = dx_{i-1}
	 uint32_t dxx = dy ^ dyy ^ LROT(dx, lrot_const_u); // dx_{i+1} = gamma ^ dx_{i-1} ^ (alpha <<< 2)

	 double p = 1.0;
	 for(int i = 0; i < n; i++) {
		p *= diff[i].p;
	 }
	 p *= pn;

	 //	 double p_min = B[n] * eps;
	 //	 if((p >= p_min) && (p != 1.0) && (p != 0.0)) { // skip the 0-diff trail (p = 1.0)
	 if((p != 1.0) && (p != 0.0)) { // skip the 0-diff trail (p = 1.0)

		diff[n].dx = dx;
		diff[n].dy = dxx;
		diff[n].p = pn;

		if((diff[n].dx == output_diff.dx) && (diff[n].dy == output_diff.dy)) {

		  uint32_t trail_len = nrounds;
		  differential_t trail[NROUNDS] = {{0,0,0,0.0}};

		  for(int i = 0; i < nrounds; i++) {
			 trail[i].dx = diff[i].dx;
			 trail[i].dy = diff[i].dy;
			 trail[i].p = diff[i].p;
		  }
		
		  std::string s_trail = trail_to_string(trail, trail_len);

		  std::unordered_map<std::string, differential_t**>::const_iterator hash_map_iter = 
			 trails_hash_map->find(s_trail);

		  if(hash_map_iter == trails_hash_map->end()) {
			 printf("[%s:%d] Add new trail: 2^%f\n", __FILE__, __LINE__, log2(p));

			 differential_t** new_trail;
			 new_trail = (differential_t** )calloc(1, sizeof(differential_t*));
			 *new_trail = (differential_t*)calloc(trail_len, sizeof(differential_t));
			 for(uint32_t i = 0; i < trail_len; i++) {
				(*new_trail)[i].dx = trail[i].dx;
				(*new_trail)[i].dy = trail[i].dy;
				(*new_trail)[i].p = trail[i].p;
			 }

			 std::pair<std::string, differential_t**> new_pair (s_trail,new_trail);
			 trails_hash_map->insert(new_pair);

			 for(int i = 0; i < nrounds; i++) {
				printf("[%s:%d] %8X %8X 2^%f\n", __FILE__, __LINE__, trail[i].dx, trail[i].dy, log2(trail[i].p));
			 }
			 printf("\n");

			 simon_print_hash_table(*trails_hash_map, trail_len);

		  } else {
			 //			 printf("[%s:%d] Trail already stored.\n", __FILE__, __LINE__);
		  }
		} else {
		  printf("\r[%s:%d] Does not match output diffs: (%8X,%8X) vs. (%8X,%8X)", __FILE__, __LINE__, 
					diff[n].dx, diff[n].dy, output_diff.dx, output_diff.dy);
		  fflush(stdout);
		}
	 }
  }
#endif
}


/**
 * Search for differentials in Simon: a wrapper for \ref simon_xor_cluster_trails
 *
 * \param trails_hash_map hash table for storing the trails
 * \param B array of best diff. prob. for \p N rounds computed with \ref simon_xor_threshold_search
 * \param trail Best found trail with \ref simon_xor_threshold_search
 * \param taril_len length of \p trail
 * 
 */
void simon_trail_cluster_search(std::unordered_map<std::string, differential_t**>* trails_hash_map,
										  double B[NROUNDS], const differential_t trail_in[NROUNDS], uint32_t trail_len, uint32_t* dyy_init)
{
  printf("[%s:%d] trail_len %d\n", __FILE__, __LINE__, trail_len);

  //	 uint32_t dyy_init = 0;
  differential_t diff[NROUNDS] = {{0,0,0,0.0}};
  differential_t trail[NROUNDS] = {{0, 0, 0, 0.0}}; 
  for(uint32_t i = 0; i < NROUNDS; i++) {
	 trail[i] = {trail_in[i].dx, trail_in[i].dy, trail_in[i].npairs, trail_in[i].p};
  }

  uint32_t lrot_const_s = SIMON_LROT_CONST_S; 
  uint32_t lrot_const_t = SIMON_LROT_CONST_T;
  uint32_t lrot_const_u = SIMON_LROT_CONST_U;
  std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy; // Dxy
  std::multiset<differential_t, struct_comp_diff_p> diff_mset_p;	 // Dp
  std::set<differential_t, struct_comp_diff_dx_dy> croads_diff_set_dx_dy; // Dxy
  std::multiset<differential_t, struct_comp_diff_p> croads_diff_mset_p;	 // Dp
  double p_thres = XDP_ROT_AND_P_THRES;
  //  uint64_t max_cnt = (1ULL << 5); //XDP_ROT_AND_MAX_DIFF_CNT; !!
  uint64_t max_cnt = (1ULL << 5);//XDP_ROT_AND_MAX_DIFF_CNT;
  xdp_rot_and_pddt(&diff_set_dx_dy, &diff_mset_p, lrot_const_s, lrot_const_t, max_cnt, p_thres);

  uint32_t init_round = 0;
  uint32_t dx_in = trail[0].dx;
  //	 uint32_t dy_in = trail[0].dy;
  uint32_t dy_in = trail[1].dx ^ trail[0].dy;//trail[0].dy;
  *dyy_init = dy_in;

  differential_t input_diff = {dx_in, dy_in};

  trail[0].dy = trail[1].dx;

  uint32_t dx_out = trail[trail_len - 1].dx;
  uint32_t dy_out = trail[trail_len - 1].dy;
  differential_t output_diff = {dx_out, dy_out};
  double eps = SIMON_EPS;//1.0 / (double)(1UL << 10);//0.125;//SIMON_EPS

  std::string s_trail = trail_to_string(trail, trail_len);

  differential_t** new_trail;
  new_trail = (differential_t** )calloc(1, sizeof(differential_t*));
  *new_trail = (differential_t*)calloc(trail_len, sizeof(differential_t));
  for(uint32_t i = 0; i < trail_len; i++) {
	 (*new_trail)[i].dx = trail[i].dx;
	 (*new_trail)[i].dy = trail[i].dy;
	 (*new_trail)[i].p = trail[i].p;
  }

  std::pair<std::string, differential_t**> new_pair (s_trail,new_trail);
  trails_hash_map->insert(new_pair);


  printf("[%s:%d] Initial trail:\n", __FILE__, __LINE__);

  simon_print_hash_table(*trails_hash_map, trail_len);

  //	 assert(dyy_init == 0);

  //	 simon_xor_cluster_trails(init_round, trail_len, B, diff, trail, trails_hash_map, dyy_init, input_diff, output_diff, lrot_const_s, lrot_const_t, lrot_const_u, &diff_mset_p, &diff_set_dx_dy, &croads_diff_mset_p, &croads_diff_set_dx_dy, eps);
  simon_xor_cluster_trails(init_round, trail_len, B, diff, trail, trails_hash_map, input_diff, output_diff, lrot_const_s, lrot_const_t, lrot_const_u, &diff_mset_p, &diff_set_dx_dy, &croads_diff_mset_p, &croads_diff_set_dx_dy, eps);
}

// --- 20131029 ---

void simon_xor_cluster_trails_boost(const int n, const int nrounds, 
												const double B[NROUNDS], 
												const differential_t diff_in[NROUNDS], const differential_t best_trail[NROUNDS], 
												//													std::unordered_map<std::string, differential_t**>* trails_hash_map,
												boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, simon_trail_hash, simon_trail_equal_to>* trails_hash_map,
												const differential_t input_diff, const differential_t output_diff, 
												uint32_t lrot_const_s, uint32_t lrot_const_t, uint32_t lrot_const_u,
												std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p, // initial highways
												std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy,
												std::multiset<differential_t, struct_comp_diff_p>* hways_diff_mset_p, // all highways
												std::set<differential_t, struct_comp_diff_dx_dy>* hways_diff_set_dx_dy,
												std::multiset<differential_t, struct_comp_diff_p>* croads_diff_mset_p, // country roads
												std::set<differential_t, struct_comp_diff_dx_dy>* croads_diff_set_dx_dy,
												double eps)
{
#if 1
  double pn = 0.0;

  assert(nrounds > 1);

  // make a local copy of the input diff trail
  differential_t diff[NROUNDS] = {{0, 0, 0, 0.0}};
  for(int i = 0; i < n; i++) {
	 diff[i].dx = diff_in[i].dx;
	 diff[i].dy = diff_in[i].dy;
	 diff[i].p = diff_in[i].p;
  }

  if((n >= 0) && (n != (nrounds - 1))) { // Round-i and not last round
	 uint32_t dx = input_diff.dx;
	 if(n > 0) {
		dx = diff[n - 1].dy; // dx_{i} = dy_{i - 1}
	 }
	 uint32_t dy = 0;					 // gamma

	 differential_t diff_dy;
	 diff_dy.dx = dx;  			  // alpha
	 diff_dy.dy = 0;
	 diff_dy.p = 0.0;

	 std::multiset<differential_t, struct_comp_diff_p> found_mset_p;

	 // p_i >= p_min = Bn / p1 * p2 ... * p{i-1} * B{n-i} 
	 double p_min = 1.0;
	 for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
		p_min *= diff[i].p;
	 }
	 p_min = p_min * 1.0 * B[nrounds - 1 - (n + 1)]; 
	 p_min = (B[nrounds - 1] * eps) / p_min;
	 assert(p_min <= 1.0);

	 // check if the differential is not already in the set
	 std::set<differential_t, struct_comp_diff_dx_dy>::iterator hway_iter = diff_set_dx_dy->lower_bound(diff_dy);
	 bool b_found_in_hways = (hway_iter != diff_set_dx_dy->end()) && (hway_iter->dx == dx);
	 bool b_found_in_croads = false;
	 if((b_found_in_hways) && (hway_iter->p >= p_min)) { // !!
		while(hway_iter->dx == dx) {
		  found_mset_p.insert(*hway_iter);
		  hway_iter++;
		}
	 }

	 croads_diff_set_dx_dy->clear();
	 croads_diff_mset_p->clear();
	 b_found_in_croads = false;
	 std::set<differential_t, struct_comp_diff_dx_dy>::iterator croad_iter;

	 uint32_t dx_prev = input_diff.dx;
	 if(n > 0) {
		dx_prev = diff[n - 1].dx;
	 }
	 assert(diff_set_dx_dy->size() != 0);
	 //	 const uint64_t max_cnt = XDP_ROT_AND_MAX_DIFF_CNT;
	 const uint64_t max_cnt = (1U << 22);// !!!
	 bool b_backto_hway = false;
	 //	 uint32_t cnt_new = xdp_rot_and_dx_pddt(diff_dy.dx, dx_prev, diff_set_dx_dy, diff_mset_p, croads_diff_set_dx_dy, croads_diff_mset_p, lrot_const_s, lrot_const_t, lrot_const_u, max_cnt, p_min, b_backto_hway);
	 uint32_t cnt_new = xdp_rot_and_dx_pddt(diff_dy.dx, dx_prev, diff_set_dx_dy, diff_mset_p, hways_diff_set_dx_dy, hways_diff_mset_p, croads_diff_set_dx_dy, croads_diff_mset_p, lrot_const_s, lrot_const_t, lrot_const_u, max_cnt, p_min, b_backto_hway);

	 if(cnt_new != 0) {
#if 0									  // DEBUG
		printf("\r[%s:%d] [%2d / %2d]: Added %d new country roads: p_min = %f (2^%f). New sizes: Dxy %d, Dp %d.", __FILE__, __LINE__, n, NROUNDS, cnt_new, p_min, log2(p_min), (uint32_t)croads_diff_set_dx_dy->size(), (uint32_t)croads_diff_mset_p->size());
		fflush(stdout);
#endif
		croad_iter = croads_diff_set_dx_dy->lower_bound(diff_dy);
		b_found_in_croads = (croad_iter != croads_diff_set_dx_dy->end()) && (croad_iter->dx == dx);
	 } 

	 if(b_found_in_croads) {
		assert(croad_iter->p >= p_min);
		//		while(croad_iter->dx == dx) {
		while((croad_iter->dx == dx) && (croad_iter->p >= p_min)) {
		  found_mset_p.insert(*croad_iter);
		  croad_iter++;
		}
	 }

	 std::multiset<differential_t, struct_comp_diff_p>::iterator find_iter = found_mset_p.begin();

	 if(find_iter->dx == dx) {
		while((find_iter->dx == dx) && (find_iter != found_mset_p.end())) {
		  assert((find_iter->dx == dx));
		  diff_dy = *find_iter;

		  dx = diff_dy.dx;
		  dy = diff_dy.dy;
		  pn = diff_dy.p;

		  double p = 1.0;
		  for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
			 p *= diff[i].p;
		  }
		  //		  p = p * pn * B[nrounds - 1 - (n + 1)]; 
		  p = p * pn;				  // p[0] * p[1] * p[n-1] * p[n]

		  // !!
		  //			 uint32_t dyy = input_diff.dy;
		  uint32_t dyy = input_diff.dy;
		  if(n > 0) {
			 dyy = diff[n-1].dx; // dy_{i} = dx_{i-1}
		  }
		  uint32_t dxx = dy ^ dyy ^ LROT(dx, lrot_const_u); // dx_{i+1} = gamma ^ dx_{i-1} ^ (alpha <<< 2)

		  diff[n].dx = dx;		  // dx_{i}
		  diff[n].dy = dxx;	  // dx_{i+1}
		  diff[n].p = pn;

		  bool b_penultimate = true;
		  if(n == (nrounds - 2)) {
			 b_penultimate = (diff[n].dy == output_diff.dx);
		  }
		  if(b_penultimate) {
			 simon_xor_cluster_trails_boost(n+1, nrounds, B, diff, best_trail, trails_hash_map, input_diff, output_diff, lrot_const_s, lrot_const_t, lrot_const_u, diff_mset_p, diff_set_dx_dy, hways_diff_mset_p, hways_diff_set_dx_dy, croads_diff_mset_p, croads_diff_set_dx_dy, eps);
		  } else {
#if 0									  // DEBUG
			 printf("\r[%s:%d] Penultimate round does not match output diff: %X vs. %X", __FILE__, __LINE__, diff[n].dy, output_diff.dx);
			 fflush(stdout);
#endif
		  }
		  find_iter++;
		}	// while
	 }		// if
  }

  if((n == (nrounds - 1)) && (nrounds > 1)) {		  // Last round

	 uint32_t dx = diff[n - 1].dy; // dx_{i} = dy_{i - 1}
	 uint32_t dy = 0;					 // gamma

	 pn = max_xdp_rot_and(dx, &dy, lrot_const_s, lrot_const_t);

	 uint32_t dyy = diff[n-1].dx; // dy_{i} = dx_{i-1}
	 uint32_t dxx = dy ^ dyy ^ LROT(dx, lrot_const_u); // dx_{i+1} = gamma ^ dx_{i-1} ^ (alpha <<< 2)

	 double p = 1.0;
	 for(int i = 0; i < n; i++) {
		p *= diff[i].p;
	 }
	 p *= pn;

	 //	 double p_min = B[n] * eps;
	 //	 if((p >= p_min) && (p != 1.0) && (p != 0.0)) { // skip the 0-diff trail (p = 1.0)
	 if((p != 1.0) && (p != 0.0)) { // skip the 0-diff trail (p = 1.0)

		diff[n].dx = dx;
		diff[n].dy = dxx;
		diff[n].p = pn;

		//		assert(diff[0].dx == input_diff.dx);
		//		assert(diff[0].dy == input_diff.dy);

		if((diff[n].dx == output_diff.dx) && (diff[n].dy == output_diff.dy)) {

		  uint32_t trail_len = nrounds;
		  differential_t trail[NROUNDS] = {{0,0,0,0.0}};

		  for(int i = 0; i < nrounds; i++) {
			 trail[i].dx = diff[i].dx;
			 trail[i].dy = diff[i].dy;
			 trail[i].p = diff[i].p;
		  }

		  simon_trail_hash trail_hash;  // trails hash function

		  std::array<differential_t, NROUNDS> trail_array;
		  for(uint32_t i = 0; i < NROUNDS; i++) {
			 trail_array[i].dx = trail[i].dx;
			 trail_array[i].dy = trail[i].dy;
			 trail_array[i].npairs = trail[i].npairs;
			 trail_array[i].p = trail[i].p;
		  }
		  //		  assert(trail_array[0].dx == input_diff.dx);
		  //		  assert(trail_array[0].dy == input_diff.dy);

		  boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, simon_trail_hash, simon_trail_equal_to>::iterator trail_iter 
			 = trails_hash_map->find(trail_array);

		  if(trail_iter == trails_hash_map->end()) { // trail is not in the trail table so add it
#if 0									  // DEBUG
			 printf("[%s:%d] Add new trail: 2^%f | %d\n", __FILE__, __LINE__, log2(p), (uint32_t)trails_hash_map->size());
#endif
			 uint32_t trail_hash_val = trail_hash(trail_array);
			 std::pair<std::array<differential_t, NROUNDS>, uint32_t> new_pair (trail_array, trail_hash_val);
			 trails_hash_map->insert(new_pair);
#if 0									  // old, inefficient
			 simon_boost_print_hash_table(*trails_hash_map, trail_len);
#else									  // NEW, xxx
			 uint32_t dx_in = trail[0].dx;
			 uint32_t dy_in = g_trail[0].dy ^ g_trail[1].dx;

			 uint32_t dx_out = trail[trail_len - 1].dx;
			 uint32_t dy_out = trail[trail_len - 1].dy;

			 //			 printf("%8X %8X, %8X %8X\n", dx_in, dy_in, g_trail[0].dx, (g_trail[0].dy ^ g_trail[1].dx));
			 assert(dx_in == g_trail[0].dx);
			 assert(dy_in == (g_trail[0].dy ^ g_trail[1].dx));

			 simon_boost_new_trail_store_to_file(dx_in, dy_in, trail, trail_len);

			 printf("\r[%s:%d] %2d R (%8X %8X) -> (%8X %8X) : [%10d trails]", __FILE__, __LINE__, trail_len, dx_in, dy_in, dx_out, dy_out, (uint32_t)trails_hash_map->size());
			 fflush(stdout);
#endif
		  }

#if 0									  // DEBUG
		  for(int i = 0; i < nrounds; i++) {
			 printf("[%s:%d] %8X %8X 2^%f\n", __FILE__, __LINE__, trail[i].dx, trail[i].dy, log2(trail[i].p));
		  }
		  printf("\n");
#endif

		} else {
#if 0
		  printf("\r[%s:%d] Does not match output diffs: (%8X,%8X) vs. (%8X,%8X)", __FILE__, __LINE__, 
					diff[n].dx, diff[n].dy, output_diff.dx, output_diff.dy);
		  fflush(stdout);
#endif
		}
	 }
  }
#endif
}

void simon_trail_cluster_search_boost(boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, simon_trail_hash, simon_trail_equal_to>* trails_hash_map,
												  double B[NROUNDS], const differential_t trail_in[NROUNDS], uint32_t trail_len, uint32_t* dyy_init)
{
  printf("[%s:%d] trail_len %d\n", __FILE__, __LINE__, trail_len);
  assert(trail_len >= NROUNDS);

  //	 uint32_t dyy_init = 0;
  differential_t diff[NROUNDS] = {{0,0,0,0.0}};
  differential_t trail[NROUNDS] = {{0, 0, 0, 0.0}}; 
  for(uint32_t i = 0; i < NROUNDS; i++) {
	 trail[i] = {trail_in[i].dx, trail_in[i].dy, trail_in[i].npairs, trail_in[i].p};
  }

  uint32_t lrot_const_s = SIMON_LROT_CONST_S; 
  uint32_t lrot_const_t = SIMON_LROT_CONST_T;
  uint32_t lrot_const_u = SIMON_LROT_CONST_U;
  std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy; // Dxy
  std::multiset<differential_t, struct_comp_diff_p> diff_mset_p;	 // Dp
  std::set<differential_t, struct_comp_diff_dx_dy> croads_diff_set_dx_dy; // Dxy
  std::multiset<differential_t, struct_comp_diff_p> croads_diff_mset_p;	 // Dp
  std::multiset<differential_t, struct_comp_diff_p> dummy_hways_diff_mset_p; //dummy var  all highways
  std::set<differential_t, struct_comp_diff_dx_dy> dummy_hways_diff_set_dx_dy;

  double p_thres = XDP_ROT_AND_P_THRES;
  //  uint64_t max_cnt = (1ULL << 5); //XDP_ROT_AND_MAX_DIFF_CNT; !!
  uint64_t max_cnt = XDP_ROT_AND_MAX_DIFF_CNT;
  xdp_rot_and_pddt(&diff_set_dx_dy, &diff_mset_p, lrot_const_s, lrot_const_t, max_cnt, p_thres);

  // unused!
  dummy_hways_diff_mset_p = diff_mset_p;
  dummy_hways_diff_set_dx_dy = diff_set_dx_dy;

  uint32_t init_round = 0;
  uint32_t dx_in = trail[0].dx;
  //	 uint32_t dy_in = trail[0].dy;
  uint32_t dy_in = trail[1].dx ^ trail[0].dy;//trail[0].dy;
  *dyy_init = dy_in;

  differential_t input_diff = {dx_in, dy_in};

#if 1
  trail[0].dy = trail[1].dx;
#endif

  uint32_t dx_out = trail[trail_len - 1].dx;
  uint32_t dy_out = trail[trail_len - 1].dy;
  differential_t output_diff = {dx_out, dy_out};
  double eps = SIMON_EPS;//1.0 / (double)(1UL << 10);//0.125;//SIMON_EPS

  double p = 1.0;
  simon_trail_hash trail_hash;  // trails hash function
  std::array<differential_t, NROUNDS> trail_array;
  for(uint32_t i = 0; i < NROUNDS; i++) {
	 trail_array[i].dx = trail[i].dx;
	 trail_array[i].dy = trail[i].dy;
	 trail_array[i].npairs = trail[i].npairs;
	 trail_array[i].p = trail[i].p;
	 p *= trail[i].p;
  }
  printf("[%s:%d] Add initial trail: 2^%f | %d\n", __FILE__, __LINE__, log2(p), (uint32_t)trails_hash_map->size());
  uint32_t trail_hash_val = trail_hash(trail_array);
  std::pair<std::array<differential_t, NROUNDS>, uint32_t> new_pair (trail_array, trail_hash_val);
  trails_hash_map->insert(new_pair);
  printf("[%s:%d] Initial trail: %2d R (%8X %8X) -> (%8X %8X) : [%10d trails]  2^%f\n", __FILE__, __LINE__, trail_len, dx_in, dy_in, dx_out, dy_out, (uint32_t)trails_hash_map->size(), log2(p));
  simon_boost_print_hash_table(*trails_hash_map, trail_len);

  simon_xor_cluster_trails_boost(init_round, trail_len, B, diff, trail, trails_hash_map, input_diff, output_diff, lrot_const_s, lrot_const_t, lrot_const_u, &diff_mset_p, &diff_set_dx_dy, &dummy_hways_diff_mset_p, &dummy_hways_diff_set_dx_dy, &croads_diff_mset_p, &croads_diff_set_dx_dy, eps);
}

// --- Simon cluster trails ---}
