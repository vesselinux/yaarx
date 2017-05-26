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
 * \file  xtea-add-threshold-search-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for xtea-add-threshold-search.cc.
 *
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XTEA_H
#include "xtea.hh"
#endif
#ifndef XTEA_ADD_THRESHOLD_SEARCH_H
#include "xtea-add-threshold-search.hh"
#endif

void test_xtea_add_trail_search()
{
  uint32_t round_key[64] = {0};
  uint32_t round_delta[64] = {0};
  uint32_t key[4];
  key[0] = random32() & MASK;
  key[1] = random32() & MASK;
  key[2] = random32() & MASK;
  key[3] = random32() & MASK;
  // Key from the paper (Table 4)
  //  0xE15C838, 0xDC8DBE76, 0xB3BB0110, 0xFFBB0440
#if 0
  key[0] = 0xE15C838;
  key[1] = 0xDC8DBE76;
  key[2] = 0xB3BB0110;
  key[3] = 0xFFBB0440;
#endif

  printf("[%s:%d] key =  %8X %8X %8X %8X\n", __FILE__, __LINE__, key[0], key[1], key[2], key[3]);

  xtea_all_round_keys_and_deltas(key, round_key, round_delta);

#if 0									  // DEBUG
  for(uint32_t i = 0; i < 64; i++) {
	 printf("[%s:%d] %2d: k %8X d %8X | s %8X\n", __FILE__, __LINE__, i, round_key[i], round_delta[i], ADD(round_key[i], round_delta[i]));
  }
#endif

  xtea_add_trail_search(key, round_key, round_delta);
}

int main()
{
  srandom(time(NULL));
  printf("[%s:%d] Computing pDDT. It may take up to 1 minute. Please wait...\n", __FILE__, __LINE__);
  test_xtea_add_trail_search();
  return 0;
}
