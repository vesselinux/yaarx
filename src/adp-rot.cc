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
 * \file  adp-rot.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief The ADD differential probability of (left) rotation (LROT): \f$\mathrm{adp}^{\mathrm{lrot}}\f$ 
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_ROT_H
#include "adp-rot.hh"
#endif

/**
 * For given input difference \p da, generate all four possible 
 * output ADD differences after left rotation together with their 
 * probabilities.
 */
void adp_lrot_odiffs(const WORD_T da, const int r, WORD_T dx[4], double P[4])
{
  if(WORD_SIZE == 64) {
	 assert(r != 0);
  }

  // initialize
  for(WORD_T i = 0; i < 4; i++) {
	 dx[i] = 0;
	 P[i] = 0.0;
  }

  WORD_T n = WORD_SIZE;
  WORD_T da_L = (da >> (n - r)); // r MSBs
  //  WORD_T da_R = (da & ~(0xffffffff << (n - r))); // (n - r) LSBs
  WORD_T da_R = (da & ~(~((WORD_T)0x0) << (n - r))); // (n - r) LSBs
  WORD_T da_lrot = LROT(da, r);

#if 0									  // DEBUG
  printf("r = %d\n", r);
  print_binary(da);
  printf(" = da\n");
  print_binary(da_L);
  printf(" = da_L\n");
  print_binary(da_R);
  printf(" = da_R\n");
#endif

#if (WORD_SIZE < 64)
  uint64_t N = ((WORD_MAX_T)1 << n);		  // 2^n
#else // (WORD_SIZE == 64)
  assert((n % 2) == 0);
  uint64_t N = ((WORD_MAX_T)1 << (n/2));		  // 2^n
#endif // #if (WORD_SIZE < 64)

  //  WORD_T cr = 1;
  //  WORD_T cl = (1UL << r); // 2^r
  //  WORD_T two_r = (1UL << r); // 2^r
  //  WORD_T two_nr = (1UL << (n-r)); // 2^{n-r}
  WORD_T cr = 1;
  WORD_T cl = ((WORD_T)1 << r); // 2^r
  WORD_T two_r = ((WORD_T)1 << r); // 2^r
  WORD_T two_nr = ((WORD_T)1 << (n-r)); // 2^{n-r}
#if 0
  printf("[%s:%d] %lld %lld %lld %016llX\n", __FILE__, __LINE__, 
			(WORD_MAX_T)cr, (WORD_MAX_T)cl, (WORD_MAX_T)two_r, (WORD_MAX_T)two_nr);
#endif
  //  dx[0] = ((da_lrot + 0 - 0) + MOD) % MOD;
  //  dx[1] = ((da_lrot + 0 - cl) + MOD) % MOD;
  //  dx[2] = ((da_lrot + cr - 0) + MOD) % MOD;
  //  dxa[3] = ((da_lrot + cr - cl) + MOD) % MOD;
  dx[0] = SUB(ADD(da_lrot, 0), 0);
  dx[1] = SUB(ADD(da_lrot, 0), cl);
  dx[2] = SUB(ADD(da_lrot, cr), 0);
  dx[3] = SUB(ADD(da_lrot, cr), cl);

#if (WORD_SIZE < 64)
  P[0] = (double)((two_nr - da_R) * (two_r - da_L)) / (double)N; // (2^{n-r} - da_R)(2^r - da_l)
  P[1] = (double)((two_nr - da_R) * da_L) / (double)N; // (2^{n-r} - da_R)(da_l)
  P[2] = (double)(da_R * (two_r - da_L - 1)) / (double)N; // da_R (2^r - da_l - 1)
  P[3] = (double)(da_R * (da_L + 1)) / (double)N; // da_R (da_l + 1)
#else // #if (WORD_SIZE == 64)
  P[0] = (double)((double)SUB(two_nr, da_R) * (double)(two_r - da_L)) / (double)N; // (2^{n-r} - da_R)(2^r - da_l)
  P[1] = (double)((double)SUB(two_nr, da_R) * (double)da_L) / (double)N; // (2^{n-r} - da_R)(da_l)
  P[2] = (double)((double)da_R * (double)SUB(SUB(two_r, da_L), 1)) / (double)N; // da_R (2^r - da_l - 1)
  P[3] = (double)((double)da_R * (double)ADD(da_L, 1)) / (double)N; // da_R (da_l + 1)
#endif // #if (WORD_SIZE < 64)

  //  printf("[%s:%d] %X\n", __FILE__, __LINE__, two_nr);

#if (WORD_SIZE == 64) // N = 1^(-63)
  P[0] /= (double)N;
  P[1] /= (double)N;
  P[2] /= (double)N;
  P[3] /= (double)N;
#endif // #if (WORD_SIZE < 64)

#if 1									  // DEBUG
  for(WORD_T i = 0; i < 4; i++) {
	 printf("[%s:%d] (%2d | %16llX -> %16llX) %f (2^%f)\n", __FILE__, __LINE__, r, (WORD_MAX_T)da, (WORD_MAX_T)dx[i], P[i], log2(P[i]));
	 assert(P[i] >= 0.0);
	 assert(P[i] <= 1.0);
  }
#endif
}

/**
 * The ADD differential probability of (left) rotation (LROT): \f$\mathrm{adp}^{\mathrm{lrot}}\f$ 
 */
double adp_lrot(WORD_T da, WORD_T db, int r)
{
  double p = 0.0;
  double P[4] = {0.0, 0.0, 0.0, 0.0};
  WORD_T dx[4] = {0, 0, 0, 0};

  adp_lrot_odiffs(da, r, dx, P);

  for(WORD_T i = 0; i < 4; i++) {
	 if(db == dx[i]) {
		p += P[i];
	 }
	 assert(P[i] >= 0.0);
	 assert(P[i] <= 1.0);
  }

  return p;
}

/**
 * The ADD differential probability of (left) rotation (LROT): \f$\mathrm{adp}^{\mathrm{lrot}}\f$
 * computed experimentally over all inputs. 
 */
double adp_lrot_exper(const WORD_T da, const WORD_T db, const int r)
{
  double p = 0.0;
#if (WORD_SIZE <= 10)
  uint64_t N = (1ULL << WORD_SIZE);
  WORD_T n = WORD_SIZE;
  assert((uint64_t)r < n);

  uint64_t cnt = 0;

  for(WORD_T i = 0; i < N; i++) {
	 WORD_T a = i;
	 //	 WORD_T aa = (a + da) % MOD;
	 WORD_T aa = ADD(a, da);

	 assert(SUB(aa, a) == da);

	 //	 WORD_T b = (a >> r);
	 //	 WORD_T bb = (aa >> r);
	 WORD_T b = LROT(a, r);
	 WORD_T bb = LROT(aa, r);

	 //	 WORD_T delta = ((bb - b) + MOD) % MOD;
	 WORD_T delta = SUB(bb, b);
#if 1									  // DEBUG
	 // assert(delta == SUBMODN(bb, b, MOD));
	 assert(delta == SUB(bb, b));

	 WORD_T da_L = da >> (n - r); // r MSBs
	 //	 WORD_T da_R = da & ~(0xffffffff << (n - r)); // (n - r) LSBs
	 WORD_T da_R = da & ~(~((WORD_T)0x0) << (n - r)); // (n - r) LSBs
	 WORD_T da_lrot = LROT(da, r);

#if 0									  // print debug info
	 printf("r = %d\n", r);
	 print_binary(da);
	 printf("\n");
	 print_binary(da_L);
	 printf("\n");
	 print_binary(da_R);
	 printf("\n");
#endif

	 // da = da_L * 2^{n-r} + db_R
	 WORD_T t = (da_L * ((WORD_T)0x1 << (n - r)) + da_R);
	 assert(t == da);

	 // da_lrot = da_R * 2^{r} + db_L
	 WORD_T t_lrot = (da_R * ((WORD_T)0x1 << (r)) + da_L);
	 assert(t_lrot == da_lrot);

	 WORD_T cr = 1;
	 WORD_T cl = (1UL << r); // 2^{r}

	 //	 printf("cl = %d, cr = %d\n", cl, cr);
	 //	 WORD_T dx_0 = ((da_lrot + 0 - 0) + MOD) % MOD;
	 //	 WORD_T dx_1 = ((da_lrot + 0 - cl) + MOD) % MOD;
	 //	 WORD_T dx_2 = ((da_lrot + cr - 0) + MOD) % MOD;
	 //	 WORD_T dx_3 = ((da_lrot + cr - cl) + MOD) % MOD;
	 WORD_T dx_0 = SUB(ADD(da_lrot, 0), 0);
	 WORD_T dx_1 = SUB(ADD(da_lrot, 0), cl);
	 WORD_T dx_2 = SUB(ADD(da_lrot, cr), 0);
	 WORD_T dx_3 = SUB(ADD(da_lrot, cr), cl);

	 assert((delta == dx_0) || (delta == dx_1) || (delta == dx_2) || (delta == dx_3));
#endif

	 if(delta == db) {
		cnt++;
#if 0									  // DEBUG
		WORD_T x = a;
		WORD_T x_L = (x >> (n - r)); // r MSBs
		//		WORD_T x_R = (x & ~(0xffffffff << (n - r))); // (n - r) LSBs
		WORD_T x_R = (x & ~(~((WORD_T)0x0) << (n - r))); // (n - r) LSBs
		printf("[%s:%d] #%3lld | (%16llX -> %16llX = %3d) | x_L x_R %3d %3d | b_%d(%3d %3d)\n", __FILE__, __LINE__, 
				 cnt, (WORD_MAX_T)da, (WORD_MAX_T)delta, (WORD_MAX_T)delta, x_L, x_R, r, bb, b);
#endif
	 }
  }
  p = (double)cnt / (double)N;
  assert(p >= 0.0);
  assert(p <= 1.0);
#endif // #if (WORD_SIZE <= 10)
  return p;
}

/**
 * The ADD differential probability of one input \p a
 * left rotated by two constants in parallel:
 * b1 = a <<< r, b2 = a <<< s .
 */
double adp_lrot2_exper(const WORD_T da, const WORD_T db_r, const WORD_T db_s, const int r, const int s)
{
  double p = 0.0;
#if (WORD_SIZE <= 10)
  uint64_t N = (1ULL << WORD_SIZE);
  WORD_T n = WORD_SIZE;
  assert((uint64_t)r < n);

  uint64_t cnt = 0;

  double P_r[4] = {0.0, 0.0, 0.0, 0.0};
  WORD_T dx_r[4] = {0, 0, 0, 0};
  adp_lrot_odiffs(da, r, dx_r, P_r);

  double P_s[4] = {0.0, 0.0, 0.0, 0.0};
  WORD_T dx_s[4] = {0, 0, 0, 0};
  adp_lrot_odiffs(da, s, dx_s, P_s);

  for(WORD_T i = 0; i < N; i++) {
	 WORD_T a = i;
	 //	 WORD_T aa = (a + da) % MOD;
	 WORD_T aa = ADD(a, da);

	 assert(SUB(aa, a) == da);

	 WORD_T b_r = LROT(a, r);
	 WORD_T bb_r = LROT(aa, r);
	 // WORD_T delta_r = ((bb_r - b_r) + MOD) % MOD;
	 WORD_T delta_r = SUB(bb_r, b_r);

	 WORD_T b_s = LROT(a, s);
	 WORD_T bb_s = LROT(aa, s);
	 // WORD_T delta_s = ((bb_s - b_s) + MOD) % MOD;
	 WORD_T delta_s = SUB(bb_s, b_s);

	 assert((delta_r == dx_r[0]) || (delta_r == dx_r[1]) || (delta_r == dx_r[2]) || (delta_r == dx_r[3]));

	 assert((delta_s == dx_s[0]) || (delta_s == dx_s[1]) || (delta_s == dx_s[2]) || (delta_s == dx_s[3]));

	 if((delta_r == db_r) && (delta_s == db_s)) {
		cnt++;
#if 1									  // DEBUG
		WORD_T x = a;
		WORD_T x_L = (x >> (n - r)); // r MSBs
		//		WORD_T x_R = (x & ~(0xffffffff << (n - r))); // (n - r) LSBs
		WORD_T x_R = (x & ~(~((WORD_T)0x0) << (n - r))); // (n - r) LSBs
		printf("[%s:%d] #%3lld | (%16llX -> %16llX %16llX = %3lld %3lld) | x_L x_R %3lld %3lld | b_%lld(%3lld %3lld) b_%lldd(%3lld %3lld)\n", 
				 __FILE__, __LINE__, 
				 (WORD_MAX_T)cnt, (WORD_MAX_T)da, (WORD_MAX_T)delta_r, (WORD_MAX_T)delta_s, (WORD_MAX_T)delta_r, (WORD_MAX_T)delta_s, 
				 (WORD_MAX_T)x_L, (WORD_MAX_T)x_R, (WORD_MAX_T)r, (WORD_MAX_T)bb_r, (WORD_MAX_T)b_r, (WORD_MAX_T)s, (WORD_MAX_T)bb_s, (WORD_MAX_T)b_s);
#endif
	 }
  }
  p = (double)cnt / (double)N;
  assert(p >= 0.0);
  assert(p <= 1.0);
#endif // #if (WORD_SIZE <= 10)
  return p;
}
