/*
 *    Copyright (c) 2012-2014 Luxembourg University,
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
 * \file  adp-rot-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2014
 * \brief Tests for adp-rot.cc.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_ROT_H
#include "adp-rot.hh"
#endif

void test_adp_lrot()
{
  WORD_T da = 0xffffffff;//0x80000000;//xrandom() & MASK;
  WORD_T db = 0xffffffff;//xrandom() & MASK;
  WORD_T r = xrandom() % WORD_SIZE;
  double p_th = adp_lrot(da, db, r);
  printf("[%s:%d] ADP_LROT_TH(%2lld | %16llX -> %16llX) %f (2^%f)\n", __FILE__, __LINE__, 
			(WORD_MAX_T)r, (WORD_MAX_T)da, (WORD_MAX_T)db, p_th, log2(p_th));
#if (WORD_SIZE <= 10)
  double p_ex = adp_lrot_exper(da, db, r);
  printf("[%s:%d] ADP_LROT_EX(%2lld | %16llX -> %16llX) %f (2^%f)\n", __FILE__, __LINE__, 
			(WORD_MAX_T)r, (WORD_MAX_T)da, (WORD_MAX_T)db, p_ex, log2(p_ex));
  assert(p_th == p_ex);
#endif  // #if 0
  printf("\n");
  //  assert(p_ex == p_th);
}

void test_adp_lrot_all()
{
#if(WORD_SIZE <= 10)
  uint64_t N = 1ULL << WORD_SIZE;
  for(WORD_T da = 0; da < N; da++) {
	 for(WORD_T db = 0; db < N; db++) {
		for(WORD_T r = 0; r < WORD_SIZE; r++) {
		  double p_ex = adp_lrot_exper(da, db, r);
		  printf("[%s:%d] ADP_LROT_EX(%2lld | %16llX -> %16llX) %f (2^%f)\n", __FILE__, __LINE__, 
					(WORD_MAX_T)r, (WORD_MAX_T)da, (WORD_MAX_T)db, p_ex, log2(p_ex));
		  double p_th = adp_lrot(da, db, r);
		  printf("[%s:%d] ADP_LROT_TH(%2lld | %16llX -> %16llX) %f (2^%f)\n", __FILE__, __LINE__, 
					(WORD_MAX_T)r, (WORD_MAX_T)da, (WORD_MAX_T)db, p_th, log2(p_th));
		  printf("\n");
		  assert(p_ex == p_th);
		}
	 }
  }
#endif
}

void test_adp_lrot_rand()
{
  printf("[%s:%d] Enter %s()\n", __FILE__, __LINE__, __FUNCTION__);
  uint64_t N = 1ULL << 10;
  for(WORD_T i = 0; i < N; i++) {
	 //	 WORD_T da = gen_sparse(5, WORD_SIZE);
	 //	 WORD_T db = gen_sparse(5, WORD_SIZE);
	 WORD_T da = xrandom() & MASK;//gen_sparse(5, WORD_SIZE);
	 WORD_T db = xrandom() & MASK;//gen_sparse(5, WORD_SIZE);
	 WORD_T r = xrandom() % WORD_SIZE;
	 if((WORD_SIZE == 64) && (r == 0)) // no 0 rot alloed for 64 bits
		continue;
	 double p_th = adp_lrot(da, db, r);
	 printf("[%s:%d] ADP_LROT_TH(%2lld | %16llX -> %16llX) %f (2^%f)\n", __FILE__, __LINE__, (WORD_MAX_T)r, (WORD_MAX_T)da, (WORD_MAX_T)db, p_th, log2(p_th));
#if (WORD_SIZE <= 10)
	 double p_ex = adp_lrot_exper(da, db, r);
	 printf("[%s:%d] ADP_LROT_EX(%2lld | %16llX -> %16llX) %f (2^%f)\n", __FILE__, __LINE__, (WORD_MAX_T)r, (WORD_MAX_T)da, (WORD_MAX_T)db, p_ex, log2(p_ex));
	 assert(p_ex == p_th);
#endif // #if (WORD_SIZE <= 10)
  }
}

void test_adp_lrot2()
{
  uint64_t N = 1ULL << 0;
  for(WORD_T i = 0; i < N; i++) {
	 WORD_T da = 0x19;//xrandom() & MASK;
	 WORD_T db_r = 0x23;//xrandom() & MASK;
	 WORD_T db_s = 0x64;//xrandom() & MASK;
	 WORD_T r = 5;//xrandom() % WORD_SIZE; // 5
	 WORD_T s = 2;//xrandom() % WORD_SIZE; // 2

	 double p_ex = adp_lrot2_exper(da, db_r, db_s, r, s);
	 printf("[%s:%d] ADP_LROT2_EX(%2lld %2lld | %16llX -> %16llX %16llX) %f (2^%f)\n", __FILE__, __LINE__, 
			  (WORD_MAX_T)r, (WORD_MAX_T)s, (WORD_MAX_T)da, (WORD_MAX_T)db_r, (WORD_MAX_T)db_s, p_ex, log2(p_ex));
	 printf("\n");
  }
}

// {--- RC5 related code ---

/**
 * data dependent rotation operation (DDROT)
 * lsb_mask covers log2(WORD_SIZE) LS bits
 */
WORD_T ddrot(WORD_T x, WORD_T lsb_mask)
{
  WORD_T r = x & lsb_mask;
  WORD_T y = LROT(x, r) & MASK;
  return y;
}


/**
 * Compute ADD difference distribution table (DDT) for the data dependent
 * rotation operation (DDROT)
 */
void adp_ddt_ddrot(WORD_T** D, WORD_T D_len)
{
  assert(WORD_SIZE == 8);
  WORD_T lsb_mask = WORD_SIZE - 1;
  for(WORD_T dx = 0; dx < D_len; dx++) {
	 for(WORD_T x = 0; x < D_len; x++) {
		WORD_T xx = ADD(dx, x) & MASK;
		WORD_T y = ddrot(x, lsb_mask) & MASK;
		WORD_T yy = ddrot(xx, lsb_mask) & MASK;
		WORD_T dy = SUB(yy, y) % MASK;
		D[dx][dy]++;
	 }
  }
}

/**
 * Approximated computation of ADD difference distribution table (DDT)
 * for the data dependent rotation operation (DDROT)
 */
void adp_ddt_ddrot_approx(WORD_T** D, WORD_T D_len)
{
  WORD_T lsb_mask = WORD_SIZE - 1;
  uint64_t ntrials = (1ULL << 5);
  for(WORD_T dx = 0; dx < D_len; dx++) {
	 //	 printf("[%s:%d] %llX\n", __FILE__, __LINE__, (WORD_MAX_T)dx);
	 for(WORD_T i = 0; i < ntrials; i++) {
		WORD_T x = xrandom() & MASK;
		WORD_T xx = ADD(dx, x) & MASK;
		WORD_T y = ddrot(x, lsb_mask) & MASK;
		WORD_T yy = ddrot(xx, lsb_mask) & MASK;
		WORD_T dy = SUB(yy, y) % MASK;
		D[dx][dy]++;
	 }
  }
}

/**
 * Approximated computation of XOR difference distribution table (DDT)
 * for the data dependent rotation operation (DDROT)
 */
void xdp_ddt_ddrot_approx(WORD_T** D, WORD_T D_len)
{
  WORD_T lsb_mask = WORD_SIZE - 1;
  uint64_t ntrials = (1ULL << 5);
  for(WORD_T dx = 0; dx < D_len; dx++) {
	 //	 printf("[%s:%d] %llX\n", __FILE__, __LINE__, (WORD_MAX_T)dx);
	 for(WORD_T i = 0; i < ntrials; i++) {
		WORD_T x = xrandom() & MASK;
		WORD_T xx = XOR(dx, x) & MASK;
		WORD_T y = ddrot(x, lsb_mask) & MASK;
		WORD_T yy = ddrot(xx, lsb_mask) & MASK;
		WORD_T dy = XOR(yy, y) % MASK;
		D[dx][dy]++;
	 }
  }
}

/**
 * Compute XOR difference distribution table (DDT) for the data dependent
 * rotation operation (DDROT)
 */
void xdp_ddt_ddrot(WORD_T** D, WORD_T D_len)
{
  assert(WORD_SIZE == 8);
  WORD_T lsb_mask = WORD_SIZE - 1;
  for(WORD_T dx = 0; dx < D_len; dx++) {
	 for(WORD_T x = 0; x < D_len; x++) {
		WORD_T xx = XOR(dx, x) & MASK;
		WORD_T y = ddrot(x, lsb_mask) & MASK;
		WORD_T yy = ddrot(xx, lsb_mask) & MASK;
		WORD_T dy = XOR(yy, y) % MASK;
		D[dx][dy]++;
	 }
  }
}

void print_ddt(WORD_T** D, WORD_T D_len)
{
  for(WORD_T i = 0; i < D_len; i++) {
	 for(WORD_T j = 0; j < D_len; j++) {
		if(D[i][j] >= 7) {
		  double p = (double)D[i][j] / (double)(D_len);
		  printf("%llX -> %llX %lld 2^%4.2f\n", 
					(WORD_MAX_T)i, (WORD_MAX_T)j, (WORD_MAX_T)D[i][j], log2(p));
		} 
	 }
  }
}

/**
 *  test_rc5_dp_ddrot();
 * Test the differential probability (DP) of data dependent rotations
 * (DDROT)
 */
void test_rc5_dp_ddrot()
{
  printf("[%s:%d] Enter %s()\n", __FILE__, __LINE__, __FUNCTION__);
  assert((WORD_SIZE == 8) || (WORD_SIZE == 16));

  uint32_t len = (1ULL << WORD_SIZE);
  WORD_T** add_ddt;
  yaarx_alloc_matrices_2d(&add_ddt, len, len);
#if 1
#if (WORD_SIZE == 8)
#if 1 // ADD
  adp_ddt_ddrot(add_ddt, len);
#else // XOR#
  xdp_ddt_ddrot(add_ddt, len);
#endif // #if 0 // ADD
#endif // #if (WORD_SIZE == 8)
#if (WORD_SIZE == 16)
#if 0 // ADD
  adp_ddt_ddrot_approx(add_ddt, len);
#else // XOR#
  xdp_ddt_ddrot_approx(add_ddt, len);
#endif // #if 0 // ADD
#endif // #if (WORD_SIZE == 16)
  print_ddt(add_ddt, len);
#endif
  yaarx_free_matrices_2d(add_ddt, len, len);

}

// --- RC5 related code ---}

int main()
{
  srandom(time(NULL));
  printf("[%s:%d] WORD_SIZE %2d\n", __FILE__, __LINE__, WORD_SIZE);
  //  test_adp_lrot2();
  test_adp_lrot();
  //  test_adp_lrot_all();
  //  test_adp_lrot_rand();
  //  test_rc5_dp_ddrot();
  return 0;
}

