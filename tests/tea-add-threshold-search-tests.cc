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
 * \file  tea-add-threshold-search-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for tea-add-threshold-search.cc.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef TEA_H
#include "tea.hh"
#endif
#ifndef TEA_ADD_THRESHOLD_SEARCH_H
#include "tea-add-threshold-search.hh"
#endif

void test_tea_add_trail_search()
{
#if 0
  if(WORD_SIZE == 32) {
	 assert(TEA_LSH_CONST == 4);
	 assert(TEA_RSH_CONST == 5);
  }
#endif
  double B[NROUNDS] = {0.0};
  differential_t trail[NROUNDS] = {{0, 0, 0, 0.0}};
  uint32_t key[4];
  key[0] = random32() & MASK;
  key[1] = random32() & MASK;
  key[2] = random32() & MASK;
  key[3] = random32() & MASK;

  // EBFC4336 D0D3E14E E11CB47B 2FFCBD53
#if 0									  // ok
  key[0] = 0xEBFC4336;
  key[1] = 0xD0D3E14E;
  key[2] = 0xE11CB47B;
  key[3] = 0x2FFCBD53;
#endif

  // D0C6E176  35C21E2 A52FFD16   22075F
#if 0									  // ok
  key[0] = 0xD0C6E176;
  key[1] = 0x35C21E2;
  key[2] = 0xA52FFD16;
  key[3] = 0x22075F;
#endif

#if 0									  // ok
  key[0] = 0xD3DCBA64;
  key[1] = 0xF1ACBEA;
  key[2] = 0x5D98E5A4;
  key[3] = 0xBA65798A;
#endif

#if 0
  key[0] = 0xBE112CCC;
  key[1] = 0xA3FDFBAF;
  key[2] = 0xAA5DFCC8;
  key[3] = 0x403F003E;
#endif
#if 0
  key[0] = 0xD7A62B66;
  key[1] = 0x6E8BE71C;
  key[2] = 0x80ABE91A;
  key[3] = 0x90CF01B8;
#endif
#if 0
  key[0] = 0x1C5FCAD;
  key[1] = 0xE14D8D45;
  key[2] = 0xA3FC4E42;
  key[3] = 0xF275CA37;
#endif
#if 0
  key[0] = 0xE028DF9A;
  key[1] = 0x8819B4C3;
  key[2] = 0x3AB116AF;
  key[3] = 0x3C50723;
#endif
  // Example from the paper (Table 4, left)
#if 1									  // 18 rounds!!
  assert(TEA_LSH_CONST == 4);
  assert(TEA_RSH_CONST == 5);
  assert(WORD_SIZE == 32);
  key[0] = 0x11CAD84E;
  key[1] = 0x96168E6B;
  key[2] = 0x704A8B1C;
  key[3] = 0x57BBE5D3;
#endif
#if 0									  // Raiden
  uint32_t kk[16];
  kk[0] = key[0];
  kk[1] = key[1];
  kk[2] = key[2];
  kk[3] = key[3];
  printf("[%s:%d] key %8X %8X %8X %8X\n", __FILE__, __LINE__, kk[0], kk[1], kk[2], kk[3]);
  for(uint32_t i = 0; i < 16; i++) {
	 kk[i%4] = ((kk[0] + kk[1]) + ((kk[2] + kk[3]) ^ (kk[0] << kk[2])));
	 //	 printf("[%s:%d] key %8X %8X %8X %8X\n", __FILE__, __LINE__, kk[0], kk[1], kk[2], kk[3]);
	 printf("[%s:%d] KEY[%d] %8X\n", __FILE__, __LINE__, i, kk[i]);
  }
#endif

#if 1
  uint32_t nrounds = tea_add_trail_search(key, B, trail);
#else 
  uint32_t nrounds = NROUNDS;
#endif

  differential_t trail_full[NROUNDS] = {{0, 0, 0, 0.0}};
  uint32_t nrounds_full = tea_add_trail_search_full(key, B, trail_full, nrounds);

  printf("[%s:%d] \n----- End search -----\n", __FILE__, __LINE__);
  double p_tot = 1.0;
#if 1									  // DEBUG
  printf("[%s:%d] Final trail:\n", __FILE__, __LINE__);
  double Bn = B[nrounds - 1];
  p_tot = 1.0;
  for(uint32_t i = 0; i < nrounds; i++) {
	 printf("%2d: %8X <- %8X %f (2^%f)\n", i, trail[i].dy, trail[i].dx, trail[i].p, log2(trail[i].p));
	 p_tot *= trail[i].p;
  }
  printf("p_tot = %16.15f = 2^%f, Bn = %f = 2^%f\n", p_tot, log2(p_tot), Bn, log2(Bn));
#endif  // #if 0									  // DEBUG
#if 1									  // DEBUG
  printf("[%s:%d] Final full trail:\n", __FILE__, __LINE__);
  p_tot = 1.0;
  for(uint32_t i = 0; i < nrounds_full; i++) {
	 printf("%2d: %8X <- %8X %f (2^%f)\n", i, trail_full[i].dy, trail_full[i].dx, trail_full[i].p, log2(trail_full[i].p));
	 p_tot *= trail_full[i].p;
  }
  printf("p_tot = %16.15f = 2^%f\n", p_tot, log2(p_tot));
#endif  // #if 0									  // DEBUG
#if 0									  // DEBUG
  printf("[%s:%d] Final bounds:\n", __FILE__, __LINE__);
  for(uint32_t i = 0; i < nrounds; i++) {
	 printf("B[%2d] = 2^%f\n", i, log2(B[i]));
  }
#endif
  printf("[%s:%d] key\n", __FILE__, __LINE__);
  for(uint32_t i = 0; i < 4; i++) {
	 printf("key[%d] = 0x%X;\n", i, key[i]);
  }
  printf("[%s:%d] Print in LaTeX in file log.txt:\n", __FILE__, __LINE__);
  //  FILE* fp = fopen("tea-add-threshold-search.log", "a");
  FILE* fp = fopen("log.txt", "a");
  print_trail_latex(fp, nrounds_full, key, trail_full);
  fclose(fp);
}

/*
Testing a trail for 18 rounds

B[ 0] = 2^0.000000
B[ 1] = 2^-1.388629
B[ 2] = 2^-2.796406
B[ 3] = 2^-6.574552
B[ 4] = 2^-10.708046
B[ 5] = 2^-15.977878
B[ 6] = 2^-21.467738
B[ 7] = 2^-25.755130
B[ 8] = 2^-28.771367
B[ 9] = 2^-33.030613
B[10] = 2^-36.898334
B[11] = 2^-41.822873
B[12] = 2^-45.690400
B[13] = 2^-48.064175
B[14] = 2^-51.793775
B[15] = 2^-54.919260
B[16] = 2^-62.205015
B[17] = 2^-62.966783
pDDT sizes: Dp 68, Dxy 68 | hway 96742, croad 84564
 0: FFFFFFF1 <- FFFFFFFF 0.084351 (2^-3.567458)
 1:        0 <-        0 1.000000 (2^0.000000)
 2: FFFFFFF1 <- FFFFFFFF 0.134033 (2^-2.899338)
 3:        0 <- FFFFFFF1 0.003937 (2^-7.988773)
 4:        F <- FFFFFFFF 0.081879 (2^-3.610369)
 5:        0 <-        0 1.000000 (2^0.000000)
 6: FFFFFFEF <- FFFFFFFF 0.141876 (2^-2.817295)
 7:        2 <- FFFFFFEF 0.001740 (2^-9.167110)
 8:       11 <-        1 0.079834 (2^-3.646853)
 9:        0 <-        0 1.000000 (2^0.000000)
10: FFFFFFF1 <-        1 0.135956 (2^-2.878790)
11: FFFFFFFE <- FFFFFFF1 0.004272 (2^-7.870717)
12:        F <- FFFFFFFF 0.080414 (2^-3.636413)
13:        0 <-        0 1.000000 (2^0.000000)
14:        F <- FFFFFFFF 0.147125 (2^-2.764883)
15:        0 <-        F 0.002655 (2^-8.557057)
16: FFFFFFF1 <- FFFFFFFF 0.084686 (2^-3.561728)
17:        0 <-        0 1.000000 (2^0.000000)
p_tot = 0.000000000000000 = 2^-62.966783, Bn = 0.000000 = 2^-62.966783
*/
void test_trail18()
{
  // \texttt{key} & \texttt{11CAD84E} & & \texttt{96168E6B} & \texttt{704A8B1C} & \texttt{57BBE5D3}
  // 18 rounds!!
  uint32_t key[4];
  key[0] = 0x11CAD84E;
  key[1] = 0x96168E6B;
  key[2] = 0x704A8B1C;
  key[3] = 0x57BBE5D3;

  uint32_t k0 = key[0];
  uint32_t k1 = key[1];
  uint32_t k2 = key[2];
  uint32_t k3 = key[3];

  // avoid compiler warning
  k0 = k0;
  k1 = k1;

/*key[0] = 0x60BDCCD9;
key[1] = 0xDE32E341;
key[2] = 0x2C4E871D;
key[3] = 0x600B7AAD;*/

/*key[0] = 0xC5859CC2;
key[1] = 0x8F83EFF6;
key[2] = 0xCD18691D;
key[3] = 0x57BBE5D3;*/

/*key[0] = 0xCF1E163A;
key[1] = 0x6F34E700;
key[2] = 0xC0E9611D;
key[3] = 0xBCB300A3;*/

  uint32_t cnt_good = 0;
  uint32_t N = 1U << 10;
  double p_rand = 1.0 / (double)(1ULL << ((2 * WORD_SIZE) - 1));
  for(uint32_t n = 0; n < N; n++) {

	 // cnt_good = [1024 / 1024] if k2 and k3 are fixed
	 //	 key[0] = random32() & MASK;
	 //	 key[1] = k1 + key[0] - k0;
	 //	 key[3] = k3 + key[2] - k2;
	 key[0] = random32() & MASK;
	 key[1] = random32() & MASK;
	 key[2] = random32() & MASK;
	 key[3] = random32() & MASK;

	 uint32_t x = 9;//10;
	 uint32_t mask_1 = 0xFFFFFFFF << x;
	 uint32_t mask_2 = 0xFFFFFFFF >> (WORD_SIZE - x) ;
	 key[2] &= mask_1;
	 key[2] |= (k2 & mask_2);
	 //	 key[2] &= 0xFFFFFF0F;			  // set bits [4:7] to 0
	 //	 key[2] |= (((k2 >> 4) & 0xF) << 4);

	 x = 3;
	 mask_1 = 0xFFFFFFFF << x;
	 mask_2 = 0xFFFFFFFF >> (WORD_SIZE - x) ;
	 key[3] &= mask_1;
	 key[3] |= (k3 & mask_2);

	 //	 key[2] &= 0xFFFFFF0F;			  // set bits [4:7] to 0
	 //	 key[2] |= (((k2 >> 4) & 0xF) << 4);

	 //  8: 0.000000 (2^-inf)        2 <- FFFFFFF1 | 2^-inf
	 // - Only five key bits influence the probability of the differential (F -> 0). Those are: k0[4:7] and k1[0].
#if 0
	 // cnt_good = [152 / 1024] : with those restrictions
	 // set bits [4:7] of key[2] to 0x704A8B1C[4:7]
	 key[2] &= 0xFFFFFF0F;			  // set bits [4:7] to 0
	 key[2] |= (((0x704A8B1C >> 4) & 0xF) << 4);

	 // set bit [0] of key[3] to 0x57BBE5D3[0]
	 key[3] &= 0xFFFFFFFE;			  // set bit [0] to 0
	 key[3] |= 1;
#endif
	 uint32_t trail[18][2] = {
		{0xFFFFFFFF,0xF},
		{0,0},
		{0xFFFFFFFF,0xF},
		{0xF,0},
		{0xFFFFFFFF,0xFFFFFFF1},
		{0,0},
		{0xFFFFFFFF,0xFFFFFFF1},
		{0xFFFFFFF1,2},
		{1,0xF},
		{0,0},
		{1,0xFFFFFFF1},
		{0xFFFFFFF1,0xFFFFFFFE},
		{0xFFFFFFFF,0xF},
		{0,0},
		{0xFFFFFFFF,0x11},
		{0x11,0},
		{0xFFFFFFFF,0xFFFFFFEF},
		{0,0}
	 };

	 uint32_t nrounds = 18;
	 uint32_t npairs = 1U << 21;

	 bool b_nzero = true;

	 //  tea_add_verify_trail(nrounds, npairs, key, trail);
	 printf("[%s:%d] Verify P for one round (2^%f CPs)...\n", __FILE__, __LINE__, log2(npairs));
	 double p_tot = 1.0;
	 for(uint32_t i = 0; i < nrounds; i++) {
		uint32_t dx = trail[i][0];
		uint32_t dy = trail[i][1];
		double p_exp = tea_add_diff_adjust_to_key(npairs, i, dx, dy, key);
		if(p_exp == 0.0) {
		  b_nzero = false;
		}
		p_tot *= p_exp;
		printf("%2d: %f (2^%f) %8X <- %8X | 2^%f\n", i+1, p_exp, log2(p_exp), dy, dx, log2(p_tot));
		//		printf("------------------------------------\n");
	 }
	 printf("[%s:%d] Total: 2^%f\n", __FILE__, __LINE__, log2(p_tot));
	 printf("[%s:%d] key\n", __FILE__, __LINE__);
	 for(uint32_t i = 0; i < 4; i++) {
		printf("key[%d] = 0x%X;\n", i, key[i]);
	 }
	 if((b_nzero) && (p_tot >= (p_rand * 0.5))) {
		cnt_good++;
	 }
	 printf("cnt_good = [(%2d) %2d / %2d]\n", cnt_good, n+1, N);
  }
  printf("OK\n");
}

void raiden(unsigned long *data,unsigned long *result,unsigned long *key)
{
  unsigned long b0=data[0], b1=data[1],i,k[4]={key[0],key[1],key[2],key[3]}, sk;
  for(i=0; i< 16; i++) {
	 sk = k[i%4] = ( (k[0] + k[1]) + ((k[2]+k[3]) ^ (k[0]<<k[2])) );
	 b0 += ((sk + b1) << 9) ^ ( (sk - b1) ^ ((sk + b1) >> 14));
	 b1 += ((sk + b0) << 9) ^ ( (sk - b0) ^ ((sk + b0) >> 14));
  }
  result[0] = b0;
  result[1] = b1;
}

int main()
{
  srandom(time(NULL));

  printf("[%s:%d] Computing pDDT. It may take up to 1 minute. Please wait...\n", __FILE__, __LINE__);
#if 1
  test_tea_add_trail_search();
#endif
  //  test_trail18();
}
