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
 * \file  xdp-xtea-f-fk.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief The XOR differential probability (XDP) of the F-function of XTEA for a fixed key
 *        and round constants: \f$\mathrm{xdp}^{F}(k, \delta |~ da \rightarrow dd)\f$.
 *
 * \attention The algorithms in this file have complexity that depends on the input and output differences to F. 
 *            It is worst-case exponential in the word size, but is sub-exponential on average.
 *
 * \see adp-xtea-f-fk.cc
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef MAX_XDP_ADD_H
#include "max-xdp-add.hh"
#endif
#ifndef XTEA_H
#include "xtea.hh"
#endif

/**
 * Compute the fixed-key, fixed-constant XOR differential probability of
 * the F-function of block cipher XTEA: 
 * \f$\mathrm{xdp}^{F}(k, \delta |~ dx \rightarrow dy)\f$
 * through exhaustive search over all input values. \b Complexity: \f$O(2^n)\f$.
 *
 * \param da input difference.
 * \param db output difference.
 * \param k round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{xdp}^{F}(k, \delta |~ dx \rightarrow dy)\f$.
 */
double xdp_xtea_f_fk_exper(const uint32_t da, const uint32_t db, 
									const uint32_t k, const uint32_t delta, 
									const uint32_t lsh_const, const uint32_t rsh_const)
{
  uint64_t N = ALL_WORDS;
  uint32_t cnt = 0;

  for(uint32_t a1 = 0; a1 < ALL_WORDS; a1++) {

	 uint32_t a2 = XOR(a1, da);  // !

	 uint32_t b1 = xtea_f(a1, k, delta, lsh_const, rsh_const);
	 uint32_t b2 = xtea_f(a2, k, delta, lsh_const, rsh_const);

	 uint32_t dx = XOR(b2, b1);  // !
	 if(dx == db) {
#if 0									  // DEBUG
		printf("[%s:%d] %4d: a = %8X\n", __FILE__, __LINE__, cnt, a1);
#endif
		cnt++;
	 } 
  }
  double p = (double)cnt / (double)N;
  return p;
}

/**
 * An approximation of the XDP of the XTEA F-function (\ref xtea_f) 
 * obtained over a number of input chosen plaintext pairs chosen uniformly at random.
 *
 * \param ninputs number of input chosen plaintext pairs.
 * \param da input difference.
 * \param db output difference.
 * \param k round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{xdp}^{F}(k, \delta |~ dx \rightarrow dy)\f$.
 */ 
double xdp_xtea_f_fk_approx(const uint32_t ninputs, 
									 const uint32_t da, const uint32_t db, 
									 const uint32_t k, const uint32_t delta, 
									 const uint32_t lsh_const, const uint32_t rsh_const)
{
  uint64_t N = ninputs;
  uint32_t cnt = 0;

  for(uint32_t i = 0; i < N; i++) {

	 uint32_t a1 = xrandom() & MASK;
	 uint32_t a2 = XOR(a1, da);

	 uint32_t b1 = xtea_f(a1, k, delta, lsh_const, rsh_const);
	 uint32_t b2 = xtea_f(a2, k, delta, lsh_const, rsh_const);

	 uint32_t dx = XOR(b2, b1);
	 if(dx == db) {
#if 0									  // DEBUG
		printf("[%s:%d] %4d: a = %8X\n", __FILE__, __LINE__, cnt, a1);
#endif
		cnt++;
	 } 
  }
  double p = (double)cnt / (double)N;
  return p;
}

/**
 * Check if a given value \p x satisfies the XOR differential \f$(dx \rightarrow dy)\f$
 * for the XTEA F-function.
 * 
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \param k round key.
 * \param delta round constant.
 * \param dx input difference.
 * \param dy output difference.
 * \param x input value.
 * \returns TRUE if \f$k, \delta:~ dy = F(x \oplus dx) \oplus F(x)\f$.
 */ 
bool xdp_xtea_f_check_x(const uint32_t lsh_const, const uint32_t rsh_const,
										 const uint32_t k, const uint32_t delta,
										 const uint32_t dx, const uint32_t dy, 
										 const uint32_t x)
{
  uint32_t x1 = x;
  uint32_t x2 = XOR(x, dx);
  uint32_t mask = 0xffffffff;
  uint32_t y1 = xtea_f_i(mask, lsh_const, rsh_const, x1, k, delta);
  uint32_t y2 = xtea_f_i(mask, lsh_const, rsh_const, x2, k, delta);
  uint32_t y_xor = XOR(y2, y1);
  bool b_sat = (dy == y_xor);
  return b_sat;
}

/**
 * Check if the differential \f$(dx \rightarrow dy)\f$ for \p F (\ref xtea_f) is 
 * satisfied on the \p i LS bits of \p x i.e. check if 
 *
 * \f$k, \delta:~ dy[i-1:0] = F(x[i-1:0] \oplus dx[i-1:0]) \oplus F(x[i-1:0])\f$.
 * 
 * \attention \p x must be of size at least \f$(i + R)\f$ bits where \p R is the RSH constant of \p F.
 * 
 * \param mask_i \p i bit mask.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \param k round key.
 * \param delta round constant.
 * \param dx input difference.
 * \param dy output difference.
 * \param x input value of size at least (\p i + \p rsh_const).
 * \returns TRUE if \f$k, \delta:~ dy[i-1:0] = F(x[i-1:0] \oplus dx[i-1:0]) \oplus F(x[i-1:0])\f$.
 *
 */
bool xdp_xtea_f_is_sat(const uint32_t mask_i, const uint32_t lsh_const, const uint32_t rsh_const,
										const uint32_t k, const uint32_t delta,
										const uint32_t dx, const uint32_t dy, const uint32_t x)
{
  //  printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, mask_i, x_in);
  uint32_t x1 = x;// & MASK;
  uint32_t x2 = XOR(x, dx);
  uint32_t y1 = xtea_f_i(mask_i, lsh_const, rsh_const, x1, k, delta);
  uint32_t y2 = xtea_f_i(mask_i, lsh_const, rsh_const, x2, k, delta);
  uint32_t y_xor_i = XOR(y2, y1) & mask_i;
  uint32_t dy_i = (dy & mask_i);
  bool b_sat = (dy_i == y_xor_i);
  //  printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, y_xor_i, dy);
  //  printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, y2, y1);
  //  printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, x2, x1);
  return b_sat;
}

/**
 * Counts the number of values \p x for which the differential \f$(dx \rightarrow dy)\f$
 * for the F-function of XTEA is satisfied. The function operates by recursively assigning
 * the bits of \p x starting from bit position \p i and terminating at the MS bit \p n.
 * The recursion proceeds to bit \f$(i+1)\f$ only if the differential is satisfied
 * on the \p i LS bits. This is checked by applying \ref xdp_xtea_f_is_sat. 
 *
 * \param n word size (terminating bit popsition).
 * \param i current bit position.
 * \param mask_i mask on the \p i LS bits of \p x.
 * \param x input value of size at least (\p i + \p rsh_const).
 * \param key round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \param dx input difference.
 * \param dy output difference.
 * \param x_cnt number of values satisfying \f$(dx \rightarrow dy)\f$.
 * \param prob the fixed-key XOR probability of \p F: \f$\mathrm{xdp}^{F}(k, \delta |~ dx \rightarrow dy)\f$.
 * \returns \p 1 if \f$x[i-1:0]\f$ satisfies \f$(dx[i-1:0] \rightarrow dy[i-1:0])\f$; \p 0 otherwise.
 * \see xdp_xtea_f_fk
 */
uint32_t xdp_xtea_f_assign_bit_x(const uint32_t n, const uint32_t i, const uint32_t mask_i, 
											const uint32_t x, const uint32_t key, const uint32_t  delta, 
											const uint32_t lsh_const, const uint32_t rsh_const, 
											const uint32_t dx, const uint32_t dy, uint32_t* x_cnt, double* prob)
{
  assert(n <= WORD_SIZE);
  assert(n >= (rsh_const * 2));
  assert(i <= (n + rsh_const));
  if(i == (n + rsh_const)) {
#if 0									  // DEBUG
	 double p = *prob;
	 //	 printf("[%s:%d] %2d: # %08X: %8X -> %8X | x = %8X  %f 2^%f\n", __FILE__, __LINE__, n, *x_cnt, dx, dy, x, p, log2(p));
	 printf("\r[%s:%d] %2d: # %08X: %8X -> %8X | x = %8X  %f 2^%f", __FILE__, __LINE__, n, *x_cnt, dx, dy, x, p, log2(p));
	 fflush(stdout);
#endif
	 if(n == WORD_SIZE) {
		bool b_ok = xdp_xtea_f_check_x(lsh_const, rsh_const, key, delta, dx, dy, x);
		assert(b_ok);
	 }
	 return 1;
  }
  bool b_xdp_xtea_f_is_sat = xdp_xtea_f_is_sat(mask_i, lsh_const, rsh_const, key, delta, dx, dy, x); // check x[i]
  if(b_xdp_xtea_f_is_sat) {
	 if(i < (WORD_SIZE - 1)) { // x[30:0] are assigned and we shall assign the last bit x[31]
		uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); // select x[(i+1)-R:0]
		for(uint32_t next_bit = 0; next_bit < 2; next_bit++) {
		  uint32_t new_x = (next_bit << (i + 1)) | x; // assign x[i+1]
		  //		  printf("[%s:%d] x = %8X\n", __FILE__, __LINE__, x);
		  uint32_t ret = xdp_xtea_f_assign_bit_x(n, i + 1, mask_i, new_x, key, delta, lsh_const, rsh_const, dx, dy, x_cnt, prob);
		  *x_cnt += ret;
		  *prob = (double)*x_cnt / (double)ALL_WORDS;
		  //		  printf("[%s:%d] x_cnt = %d\n", __FILE__, __LINE__, *x_cnt);
		}
	 } else {
		uint32_t mask_i = MASK;
		uint32_t new_x = x;
		uint32_t ret =  xdp_xtea_f_assign_bit_x(n, i + 1, mask_i, new_x, key, delta, lsh_const, rsh_const, dx, dy, x_cnt, prob);
		*x_cnt += ret;
		*prob = (double)*x_cnt / (double)ALL_WORDS;
#if 0
		if((i + 1) == (n + rsh_const)) {
		  printf("[%s:%d] x_cnt = %d | %8X | %f 2^%f\n", __FILE__, __LINE__, *x_cnt, x, *prob, log2(*prob));
		}
#endif
	 }
  } else {
	 //	 printf("[%s:%d] Not sat dx[%2d:%2d]\n", __FILE__, __LINE__, n, i);
  }
  return 0;
}

/**
 * Compute the fixed-key, fixed-constant XOR differential probability of
 * the F-function of block cipher XTEA: 
 * \f$\mathrm{xdp}^{F}(k, \delta |~ dx \rightarrow dy)\f$.
 * \b Complexity: \f$ O(n) < c \le O(2^n) \f$.
 *
 * \param n word size.
 * \param dx input difference.
 * \param dy output difference.
 * \param key round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{xdp}^{F}(k, \delta |~ dx \rightarrow dy)\f$.
 * \see xdp_xtea_f_assign_bit_x
 */
double xdp_xtea_f_fk(const uint32_t n, const uint32_t dx, const uint32_t dy, 
							const uint32_t key, const uint32_t  delta, 
							const uint32_t lsh_const, const uint32_t rsh_const)
{
  assert(lsh_const < rsh_const);
  assert(n <= WORD_SIZE);
  assert(n >= (rsh_const * 2));
  // trivial case -- zero input difference
#if 1
  if(dx == 0) {
	 if(dy == 0)
		return 1.0;
	 return 0.0;
  }
#endif
  // number of initial LSB bits
  uint32_t nlsb_init = (rsh_const * 2);
  if(nlsb_init > WORD_SIZE)
	 nlsb_init = WORD_SIZE;
  // all 10-bit values
  uint32_t N = (1U << nlsb_init);
  uint32_t x = 0;
  uint32_t x_cnt = 0;
  double p = 0.0;
  //  const uint32_t n = WORD_SIZE; 
 for(uint32_t l = 0; l < N; l++) {
	 x = l;							  // assign x[9:0]
	 uint32_t i = nlsb_init - 1; // start at x[9]
	 uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); 
#if 1
	 xdp_xtea_f_assign_bit_x(n, i, mask_i, x, key, delta, lsh_const, rsh_const, dx, dy, &x_cnt, &p);
#endif
  }
  return p;
}

/**
 * Compute the fixed-key through exhaustive search over all input values
 * the fixed-constant XOR differential probability of
 * the F-function of block cipher XTEA including the second modular 
 * addition and denoted by \f$F'(xx, x)  = xx + F(x)\f$ (see \ref xtea_f2):
 * \f$\mathrm{xdp}^{F'}(k, \delta |~ dxx, dx \rightarrow dy)\f$.
 * \b Complexity: \f$O(2^{2n})\f$.
 *
 * \param daa first input difference.
 * \param da second input difference.
 * \param db output difference.
 * \param k round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{xdp}^{F'}(k, \delta |~ daa, da \rightarrow dy)\f$.
 */
double xdp_xtea_f2_fk_exper(const uint32_t daa, const uint32_t da, const uint32_t db, 
									 const uint32_t k, const uint32_t delta, 
									 const uint32_t lsh_const, const uint32_t rsh_const)
{
  uint64_t N = ALL_WORDS * ALL_WORDS;
  uint32_t cnt = 0;

  for(uint32_t aa1 = 0; aa1 < ALL_WORDS; aa1++) {
	 for(uint32_t a1 = 0; a1 < ALL_WORDS; a1++) {

		uint32_t a2 = XOR(a1, da);
		uint32_t aa2 = XOR(aa1, daa);

		uint32_t b1 = xtea_f2(aa1, a1, k, delta, lsh_const, rsh_const);
		uint32_t b2 = xtea_f2(aa2, a2, k, delta, lsh_const, rsh_const);

		uint32_t dx = XOR(b2, b1);  // !
		if(dx == db) {
#if 0									  // DEBUG
		  printf("[%s:%d] %4d: a = %8X\n", __FILE__, __LINE__, cnt, a1);
#endif
		  cnt++;
		} 
	 }
  }
  double p = (double)cnt / (double)N;
  return p;
}

/**
 * An approximation of the XDP of the XTEA F-function with 
 * two inputs \f$F'(xx, x)  = xx + F(x)\f$ (see \ref xtea_f2),
 * obtained over a number of input chosen plaintext pairs c
 * hosen uniformly at random.
 *
 * \param ninputs number of input chosen plaintext pairs.
 * \param daa first input difference.
 * \param da second input difference.
 * \param db output difference.
 * \param k round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{xdp}^{F'}(k, \delta |~ daa, da \rightarrow dy)\f$.
 */ 
double xdp_xtea_f2_fk_approx(const uint32_t ninputs, 
									  const uint32_t daa, const uint32_t da, const uint32_t db, 
									  const uint32_t k, const uint32_t delta, 
									  const uint32_t lsh_const, const uint32_t rsh_const)
{
  uint64_t N = ninputs;
  uint32_t cnt = 0;

  for(uint32_t i = 0; i < N; i++) {

	 uint32_t a1 = xrandom() & MASK;
	 uint32_t a2 = XOR(a1, da);

	 uint32_t aa1 = xrandom() & MASK;
	 uint32_t aa2 = XOR(aa1, daa);

	 uint32_t b1 = xtea_f2(aa1, a1, k, delta, lsh_const, rsh_const);
	 uint32_t b2 = xtea_f2(aa2, a2, k, delta, lsh_const, rsh_const);

	 uint32_t dx = XOR(b2, b1);
	 if(dx == db) {
#if 0									  // DEBUG
		printf("[%s:%d] %4d: a = %8X\n", __FILE__, __LINE__, cnt, a1);
#endif
		cnt++;
	 } 
  }
  double p = (double)cnt / (double)N;
  return p;
}

/**
 * Check if given input values \p xx and \p x satisfy 
 * the XOR differential \f$(dxx, dx \rightarrow dy)\f$
 * of the XTEA F-function with two inputs 
 * \f$F'(xx, x)  = xx + F(x)\f$ (see \ref xtea_f2).
 * 
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \param k round key.
 * \param delta round constant.
 * \param dxx first input difference.
 * \param dx second input difference.
 * \param dy output difference.
 * \param xx first input value.
 * \param x second input value.
 * \returns TRUE if \f$k, \delta:~ dy = F'(xx \oplus dxx,~ x \oplus dx) \oplus F'(xx,~ x)\f$.
 */ 
bool xdp_xtea_f2_check_x_xx(const uint32_t lsh_const, const uint32_t rsh_const,
									 const uint32_t k, const uint32_t delta,
									 const uint32_t dxx, const uint32_t dx, const uint32_t dy, 
									 const uint32_t xx, const uint32_t x)
{
  uint32_t x1 = x;
  uint32_t x2 = XOR(x, dx);

  uint32_t xx1 = xx;
  uint32_t xx2 = XOR(xx, dxx);

  uint32_t mask = 0xffffffff;

  uint32_t y1 = xtea_f2_i(mask, lsh_const, rsh_const, xx1, x1, k, delta);
  uint32_t y2 = xtea_f2_i(mask, lsh_const, rsh_const, xx2, x2, k, delta);

  uint32_t y_xor = XOR(y2, y1);
  bool b_sat = (dy == y_xor);
  return b_sat;
}

/**
 * Check if the XOR differential \f$(dxx, dx \rightarrow dy)\f$
 * of the XTEA F-function with two inputs 
 * \f$F'(xx, x)  = xx + F(x)\f$ (see \ref xtea_f2)
 * is satisfied on the \p i LS bits of \p xx and \p x i.e. check if 
 * \f[k, \delta:~ dy[i-1:0] = F(xx[i-1:0], x[i-1:0] \oplus dx[i-1:0]) \oplus F(xx[i-1:0], x[i-1:0])\f]
 * 
 * \param mask_i \p i bit mask.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \param k round key.
 * \param delta round constant.
 * \param dxx first input difference.
 * \param dx second input difference.
 * \param dy output difference.
 * \param xx first input value.
 * \param x second input value of size at least (\p i + \p rsh_const).
 * \returns TRUE if the differential is satisfied; FALSE otherwise.
 * \attention \p x must be of size at least \f$(i + R)\f$ bits where \p R is the RSH constant of \p F.
 *
 */
bool xdp_xtea_f2_is_sat(const uint32_t mask_i, const uint32_t lsh_const, const uint32_t rsh_const,
								const uint32_t k, const uint32_t delta,
								const uint32_t dxx, const uint32_t dx, const uint32_t dy, 
								const uint32_t xx, const uint32_t x)
{
  //  printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, mask_i, x_in);
  uint32_t x1 = x;// & MASK;
  uint32_t x2 = XOR(x, dx);

  uint32_t xx1 = xx;// & MASK;
  uint32_t xx2 = XOR(xx, dxx);

  uint32_t y1 = xtea_f2_i(mask_i, lsh_const, rsh_const, xx1, x1, k, delta);
  uint32_t y2 = xtea_f2_i(mask_i, lsh_const, rsh_const, xx2, x2, k, delta);
  uint32_t y_xor_i = XOR(y2, y1) & mask_i;
  uint32_t dy_i = (dy & mask_i);
  bool b_sat = (dy_i == y_xor_i);
  //  printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, y_xor_i, dy);
  //  printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, y2, y1);
  //  printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, x2, x1);
  //  printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, xx2, xx1);
  return b_sat;
}

/**
 * Counts the number of values \p xx and \p x for which
 * the XOR differential \f$(dxx, dx \rightarrow dy)\f$
 * of the XTEA F-function with two inputs \f$F'(xx, x)  = xx + F(x)\f$ (see \ref xtea_f2)
 * is satisfied. The algorithm operates by recursively assigning
 * the bits of \p xx and \p x starting from bit position \p i and terminating at the MS bit \p n.
 * The recursion proceeds to bit \f$(i+1)\f$ only if the differential is satisfied
 * on the \p i LS bits. This is checked by applying \ref xdp_xtea_f2_is_sat. 
 *
 * \param n word size (terminating bit popsition).
 * \param i current bit position.
 * \param mask_i mask on the \p i LS bits of \p x.
 * \param xx first input value.
 * \param x second input value of size at least (\p i + \p rsh_const).
 * \param key round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \param dxx first input difference.
 * \param dx second input difference.
 * \param dy output difference.
 * \param x_cnt number of values satisfying \f$(dx \rightarrow dy)\f$.
 * \param prob the fixed-key XOR probability of \p F': \f$\mathrm{xdp}^{F'}(k, \delta |~ dx \rightarrow dy)\f$.
 * \returns \p 1 if \f$x[i-1:0]\f$ satisfies \f$(dx[i-1:0] \rightarrow dy[i-1:0])\f$; \p 0 otherwise.
 * \see xdp_xtea_f2_fk
 * 
 * \note x_cnt counts both the values for x and for xx.
 */
uint32_t xdp_xtea_f2_assign_bit_x_xx(const uint32_t n, const uint32_t i, const uint32_t mask_i, 
												 const uint32_t xx, const uint32_t x, 
												 const uint32_t key, const uint32_t  delta, 
												 const uint32_t lsh_const, const uint32_t rsh_const, 
												 const uint32_t dxx, const uint32_t dx, const uint32_t dy, 
												 uint64_t* x_cnt, double* prob)
{
  assert(n <= WORD_SIZE);
  assert(n >= (rsh_const * 2));
  assert(i <= (n + rsh_const));
  if(i == (n + rsh_const)) {
#if 0									  // DEBUG
	 double p = *prob;
	 printf("\r[%s:%d] %2d: # %16LX: XDP-F2(%8X %8X -> %8X) | xx = %8X  x = %8X %f 2^%f", __FILE__, __LINE__, n, *x_cnt, dxx, dx, dy, xx, x, p, log2(p));
	 fflush(stdout);
#endif
	 if(n == WORD_SIZE) {
		bool b_ok = xdp_xtea_f2_check_x_xx(lsh_const, rsh_const, key, delta, dxx, dx, dy, xx, x);
		assert(b_ok);
	 }
	 return 1;
  }
  bool b_xdp_xtea_f2_is_sat = xdp_xtea_f2_is_sat(mask_i, lsh_const, rsh_const, key, delta, dxx, dx, dy, xx, x); // check x[i]
  if(b_xdp_xtea_f2_is_sat) {
	 if(i < (WORD_SIZE - 1)) { // x[30:0] are assigned and we shall assign the last bit x[31]
		uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); // select x[(i+1)-R:0]
		for(uint32_t next_bit_xx = 0; next_bit_xx < 2; next_bit_xx++) {
		  uint32_t new_xx = (next_bit_xx << (i + 1)) | xx; // assign xx[i+1]
		  for(uint32_t next_bit_x = 0; next_bit_x < 2; next_bit_x++) {
			 uint32_t new_x = (next_bit_x << (i + 1)) | x; // assign x[i+1]
			 //		  printf("[%s:%d] x = %8X\n", __FILE__, __LINE__, x);
			 uint32_t ret = xdp_xtea_f2_assign_bit_x_xx(n, i + 1, mask_i, new_xx, new_x, key, delta, lsh_const, rsh_const, dxx, dx, dy, x_cnt, prob);
			 *x_cnt += ret;
			 *prob = (double)*x_cnt / (double)(ALL_WORDS * ALL_WORDS); // two inputs to F
			 //		  printf("[%s:%d] x_cnt = %d\n", __FILE__, __LINE__, *x_cnt);
		  }
		}
	 } else {
		uint32_t mask_i = MASK;
		uint32_t new_x = x;
		uint32_t new_xx = xx;
		uint32_t ret =  xdp_xtea_f2_assign_bit_x_xx(n, i + 1, mask_i, new_xx, new_x, key, delta, lsh_const, rsh_const, dxx, dx, dy, x_cnt, prob);
		*x_cnt += ret;
		*prob = (double)*x_cnt / (double)(ALL_WORDS * ALL_WORDS); // two inputs to F
#if 0
		if((i + 1) == (n + rsh_const)) {
		  printf("[%s:%d] x_cnt = %d | %8X | %f 2^%f\n", __FILE__, __LINE__, *x_cnt, x, *prob, log2(*prob));
		}
#endif
	 }
  } else {
	 //	 printf("[%s:%d] Not sat dx[%2d:%2d]\n", __FILE__, __LINE__, n, i);
  }
  return 0;
}

/**
 * Compute the fixed-key, fixed-constant XOR differential probability of
 * of the XTEA F-function with two inputs 
 * \f$F'(xx, x)  = xx + F(x)\f$ (see \ref xtea_f2):
 * \f$\mathrm{xdp}^{F}(k, \delta |~ dxx, dx \rightarrow dy)\f$.
 * \b Complexity: \f$ O(n) < c \le O(2^{2n}) \f$.
 *
 * \param n word size.
 * \param dxx first input difference.
 * \param dx second input difference.
 * \param dy output difference.
 * \param key round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{xdp}^{F'}(k, \delta |~ dxx, dx \rightarrow dy)\f$.
 * \see xdp_xtea_f2_assign_bit_x_xx
 */
double xdp_xtea_f2_fk(const uint32_t n, const uint32_t dxx, const uint32_t dx, const uint32_t dy, 
							 const uint32_t key, const uint32_t  delta, 
							 const uint32_t lsh_const, const uint32_t rsh_const)
{
  assert(lsh_const < rsh_const);
  assert(n <= WORD_SIZE);
  assert(n >= (rsh_const * 2));
  // trivial case -- zero input difference
#if 1
  if((dxx == 0) && (dx == 0)) {
	 if(dy == 0)
		return 1.0;
	 return 0.0;
  }
#endif
  // number of initial LSB bits
  uint32_t nlsb_init = (rsh_const * 2);
  if(nlsb_init > WORD_SIZE)
	 nlsb_init = WORD_SIZE;
  // all 10-bit values
  uint32_t N = (1U << nlsb_init);
  uint32_t x = 0;
  uint32_t xx = 0;
  uint64_t x_cnt = 0;
  double p = 0.0;
  for(uint32_t ll = 0; ll < N; ll++) {
	 xx = ll;							  // assign xx[9:0]
	 for(uint32_t l = 0; l < N; l++) {
		x = l;							  // assign x[9:0]
		uint32_t i = nlsb_init - 1; // start at x[9]
		uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); 
#if 1
		xdp_xtea_f2_assign_bit_x_xx(n, i, mask_i, xx, x, key, delta, lsh_const, rsh_const, dxx, dx, dy, &x_cnt, &p);
#endif
	 }
  }
  return p;
}

/** 
 * For the XTEA F-function (\ref xtea_f), for fixed input difference \p dx, 
 * compute an output difference \p dy such that the differential \f$(dx \rightarrow dy)\f$
 * has non-zero probability. 
 *
 * \param A transition probability matrices for \f$\mathrm{xdp}^{+}\f$ (\ref xdp_add_sf).
 * \param dx input difference.
 * \param dy output difference.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \return \f$\mathrm{xdp}^{F}(k, \delta |~ dx \rightarrow dy)\f$
 *
 * \b Algorithm \b sketch: 
 *
 * -# Compute the output XOR difference after \ref xtea_f_lxr :
 *    \f$dx_{\mathrm{LXR}} = (((dx \ll 4) \oplus (dx \gg 5))\f$.
 * -# Compute the maximum probability output difference \f$dy\f$ after the modular addition of \ref xtea_f :
 *    \f$p_{\mathrm{max}} = \mathrm{max}_{dy}~\mathrm{xdp}^{+}(dx, dx_\mathrm{LXR} \rightarrow dy)\f$
 *    (see \ref max_xdp_add).
 * -# Store \f$dy\f$ and return \f$p_{\mathrm{max}}\f$.
 *
 * \attention In the computation of \f$\mathrm{max}_{dy}~\mathrm{xdp}\f$ the inputs to the addition
 *            are implicitly assumed to be independent. Clearly they are not
 *            and so the returned probability is only an approximation.
 */
double nz_xdp_xtea_f(gsl_matrix* A[2][2][2], const uint32_t dx, uint32_t* dy,
							uint32_t lsh_const, uint32_t rsh_const)
{
  uint32_t dx_lxr = LSH(dx, lsh_const) ^ RSH(dx, rsh_const);
  //  double p = max_xdp_add(A, dx_lxr, dx, dy);
  double p = max_xdp_add_lm(dx_lxr, dx, dy);

  return p;
}
