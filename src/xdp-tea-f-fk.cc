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
 * \file  xdp-tea-f-fk.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \brief The XOR differential probability (XDP) of the F-function of TEA for a fixed key
 *        and round constants: \f$\mathrm{xdp}^{F}(k_0, k_1, \delta |~ da \rightarrow dd)\f$.
 *
 * \attention The algorithms in this file have complexity that depends on the input and output differences to F. 
 *            It is worst-case exponential in the word size, but is sub-exponential on average.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef TEA_H
#include "tea.hh"
#endif

/**
 * Compute the fixed-key, fixed-constant XOR differential probability of
 * the F-function of block cipher TEA: 
 * \f$\mathrm{xdp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$
 * through exhaustive search over all input values. \b Complexity: \f$O(2^n)\f$.
 *
 * \param da input difference.
 * \param db output difference.
 * \param k0 first round key.
 * \param k1 second round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{xdp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \see xdp_f_fk
 */
double xdp_f_fk_exper(const uint32_t da, const uint32_t db, 
							 const uint32_t k0, const uint32_t k1, const uint32_t delta,
							 uint32_t lsh_const, uint32_t rsh_const)
{
  uint64_t N = ALL_WORDS;
  uint32_t cnt = 0;

  for(uint32_t a1 = 0; a1 < ALL_WORDS; a1++) {

	 uint32_t a2 = XOR(a1, da);

	 uint32_t b1 = tea_f(a1, k0, k1, delta, lsh_const, rsh_const);
	 uint32_t b2 = tea_f(a2, k0, k1, delta, lsh_const, rsh_const);

	 uint32_t dx = XOR(b2, b1);
	 if(dx == db) {
#if DEBUG_XDP_TEA_F_FK
		printf("[%s:%d] %4d: a = %8X\n", __FILE__, __LINE__, cnt, a1);
#endif  // #if DEBUG_XDP_TEA_F_FK
		cnt++;
	 } 
  }
  double p = (double)cnt / (double)N;
  return p;
}

/**
 * For given output difference \p dy, compute the maximum probability 
 * input differences \p dx over all input differences: 
 * \f$\mathrm{max}_{dx} ~\mathrm{xdp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$
 * through exhaustive search over all input values and input differences. 
 * \b Complexity: \f$O(2^{2n})\f$.
 *
 * \param max_dx maximum probability input difference.
 * \param dy output difference.
 * \param k0 first round key.
 * \param k1 second round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{max}_{dx} ~\mathrm{xdp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \see max_dx_xdp_f_fk
 */
double max_xdp_f_fk_dx_exper(uint32_t* max_dx, const uint32_t dy, 
									  const uint32_t k0, const uint32_t k1, const uint32_t delta,
									  uint32_t lsh_const, uint32_t rsh_const)
{
  double max_p = 0.0;
  for(uint32_t dx = 0; dx < ALL_WORDS; dx++) {
	 double p = xdp_f_fk_exper(dx, dy, k0, k1, delta, lsh_const, rsh_const);
	 if((p > max_p) && (p != 1.0)) {
#if DEBUG_XDP_TEA_F_FK
		printf("[%s:%d] Update max %f(%8X) -> %f(%8X)\n", __FILE__, __LINE__, max_p, *max_dx, p, dx);
#endif  // #if DEBUG_XDP_TEA_F_FK
		max_p = p;
		*max_dx = dx;
	 }
  }
  return max_p;
}

/**
 * For given input difference \p dx, compute the maximum probability 
 * output difference \p dy over all output differences: 
 * \f$\mathrm{max}_{dy} ~\mathrm{xdp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$
 * through exhaustive search over all input values and input differences. 
 * \b Complexity: \f$O(2^{2n})\f$.
 *
 * \param dx input difference.
 * \param max_dy maximum probability output difference.
 * \param k0 first round key.
 * \param k1 second round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{max}_{dx} ~\mathrm{xdp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \see max_dy_xdp_f_fk
 */
double max_xdp_f_fk_dy_exper(const uint32_t dx, uint32_t* max_dy, 
									  const uint32_t k0, const uint32_t k1, const uint32_t delta,
									  uint32_t lsh_const, uint32_t rsh_const)
{
  double max_p = 0.0;
  if(dx == 0) {						  // zero input difference
	 *max_dy = 0;
	 return 1.0;
  }
  for(uint32_t dy = 0; dy < ALL_WORDS; dy++) {
	 double p = xdp_f_fk_exper(dx, dy, k0, k1, delta, lsh_const, rsh_const);
	 if((p > max_p) && (p != 1.0)) {
#if DEBUG_XDP_TEA_F_FK
		printf("[%s:%d] Update max %f(%8X) -> %f(%8X)\n", __FILE__, __LINE__, max_p, *max_dx, p, dx);
#endif  // #if DEBUG_XDP_TEA_F_FK
		max_p = p;
		*max_dy = dy;
	 }
  }
  return max_p;
}

/**
 * Check if the differential \f$(dx \rightarrow dy)\f$ for \p F is 
 * satisfied on the \p i LS bits of \p x i.e. check if 
 * \f$k_0, k_1, \delta:~ dy[i-1:0] = F(x[i-1:0] \oplus dx[i-1:0]) \oplus F(x[i-1:0])\f$.
 * 
 * \attention \p x must be of size at least \f$(i + R)\f$ bits where \p R is the RSH constant of \p F.
 * 
 * \param mask_i \p i bit mask.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \param k0 first round key.
 * \param k1 second round key.
 * \param delta round constant.
 * \param dx input difference.
 * \param dy output difference.
 * \param x input value of size at least (\p i + \p rsh_const).
 * \returns TRUE if \f$k_0, k_1, \delta:~ dy[i-1:0] = F(x[i-1:0] \oplus dx[i-1:0]) \oplus F(x[i-1:0)\f$.
 *
 */
bool xdp_f_is_sat(const uint32_t mask_i, const uint32_t lsh_const, const uint32_t rsh_const,
						const uint32_t k0, const uint32_t k1, const uint32_t delta,
						const uint32_t dx, const uint32_t dy, int32_t x)
{
  //  printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, mask_i, x_in);
  uint32_t x1 = x;// & MASK;
  uint32_t x2 = XOR(x, dx);
  uint32_t y1 = tea_f_i(mask_i, k0, k1, delta, lsh_const, rsh_const, x1);
  uint32_t y2 = tea_f_i(mask_i, k0, k1, delta, lsh_const, rsh_const, x2);
  uint32_t y_xor_i = XOR(y2, y1) & mask_i;
  uint32_t dy_i = (dy & mask_i);
  bool b_sat = (dy_i == y_xor_i);
  //  printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, y_xor_i, dy);
  //  printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, y2, y1);
  //  printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, x2, x1);
  return b_sat;
}

/**
 * Check if a given value \p x satisfies the XOR differential \f$(dx \rightarrow dy)\f$
 * for the TEA F-function.
 * 
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \param k0 first round key.
 * \param k1 second round key.
 * \param delta round constant.
 * \param dx input difference.
 * \param dy output difference.
 * \param x input value.
 * \returns TRUE if \f$k_0, k_1, \delta:~ dy = F(x \oplus dx) \oplus F(x)\f$.
 *
 */ 
bool xdp_f_check_x(const uint32_t lsh_const, const uint32_t rsh_const,
						 const uint32_t k0, const uint32_t k1, const uint32_t delta,
						 const uint32_t dx, const uint32_t dy, const uint32_t x)
{
  uint32_t x1 = x;
  uint32_t x2 = XOR(x, dx);
  uint32_t mask = 0xffffffff;
  uint32_t y1 = tea_f_i(mask, k0, k1, delta, lsh_const, rsh_const, x1);
  uint32_t y2 = tea_f_i(mask, k0, k1, delta, lsh_const, rsh_const, x2);
  uint32_t y_sub = XOR(y2, y1);
  bool b_sat = (dy == y_sub);
  return b_sat;
}


/**
 * Counts the number of values \p x for which the differential \f$(dx \rightarrow dy)\f$
 * for the F-function of TEA is satisfied. The function operates by recursively assigning
 * the bits of \p x starting from bit position \p i and terminating at the MS bit \p n.
 * The recursion proceeds to bit \f$(i+1)\f$ only if the differential is satisfied
 * on the \p i LS bits. This is checked by applying \ref xdp_f_is_sat. 
 *
 * \param n word size (terminating bit popsition).
 * \param i current bit position.
 * \param mask_i mask on the \p i LS bits of \p x.
 * \param x input value of size at least (\p i + \p rsh_const).
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \param k0 first round key.
 * \param k1 second round key.
 * \param delta round constant.
 * \param dx input difference.
 * \param dy output difference.
 * \param x_cnt number of values satisfying \f$(dx \rightarrow dy)\f$.
 * \param prob the fixed-key XOR probability of \p F: \f$\mathrm{xdp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \returns \p 1 if \f$x[i-1:0]\f$ satisfies \f$(dx[i-1:0] \rightarrow dy[i-1:0])\f$; \p 0 otherwise.
 * \see xdp_f_fk
 */
uint32_t xdp_f_assign_bit_x(const uint32_t n, const uint32_t i, const uint32_t mask_i, const uint32_t x, 
									 const uint32_t lsh_const, const uint32_t rsh_const,
									 const uint32_t k0, const uint32_t k1, const uint32_t delta,
									 const uint32_t dx, const uint32_t dy, uint32_t* x_cnt, double* prob)
{
  assert(n <= WORD_SIZE);
  assert(n >= (rsh_const * 2));
  assert(i <= (n + rsh_const));
  if(i == (n + rsh_const)) {
#if DEBUG_XDP_TEA_F_FK
	 double p = *prob;
	 printf("[%s:%d] %2d: # %08X: %8X -> %8X | x = %8X  %f 2^%f\n", __FILE__, __LINE__, n, *x_cnt, dx, dy, x, p, log2(p));
#endif  // #if DEBUG_XDP_TEA_F_FK
	 if(n == WORD_SIZE) {
		bool b_ok = xdp_f_check_x(lsh_const, rsh_const, k0, k1, delta, dx, dy, x);
		assert(b_ok);
	 }
	 return 1;
  }
  bool b_xdp_f_is_sat = xdp_f_is_sat(mask_i, lsh_const, rsh_const, k0, k1, delta, dx, dy, x); // check x[i]
  if(b_xdp_f_is_sat) {
	 if(i < (WORD_SIZE - 1)) { // x[30:0] are assigned and we shall assign the last bit x[31]
		uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); // select x[(i+1)-R:0]
		for(uint32_t next_bit = 0; next_bit < 2; next_bit++) {
		  uint32_t new_x = (next_bit << (i + 1)) | x; // assign x[i+1]
		  //		  printf("[%s:%d] x = %8X\n", __FILE__, __LINE__, x);
		  uint32_t ret = xdp_f_assign_bit_x(n, i + 1, mask_i, new_x, lsh_const, rsh_const, k0, k1, delta, dx, dy, x_cnt, prob);
		  *x_cnt += ret;
		  *prob = (double)*x_cnt / (double)ALL_WORDS;
		  //		  printf("[%s:%d] x_cnt = %d\n", __FILE__, __LINE__, *x_cnt);
		}
	 } else {
		uint32_t mask_i = MASK;
		uint32_t new_x = x;
		uint32_t ret =  xdp_f_assign_bit_x(n, i + 1, mask_i, new_x, lsh_const, rsh_const, k0, k1, delta, dx, dy, x_cnt, prob);
		*x_cnt += ret;
		*prob = (double)*x_cnt / (double)ALL_WORDS;
#if DEBUG_XDP_TEA_F_FK
		if((i + 1) == (n + rsh_const)) {
		  printf("[%s:%d] x_cnt = %d | %8X | %f 2^%f\n", __FILE__, __LINE__, *x_cnt, x, *prob, log2(*prob));
		}
#endif  // #if DEBUG_XDP_TEA_F_FK
	 }
  }
  return 0;
}

/**
 * Compute the fixed-key, fixed-constant XOR differential probability of
 * the F-function of block cipher TEA: 
 * \f$\mathrm{xdp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \b Complexity: \f$ O(n) < c \le O(2^n) \f$.
 *
 * \param n word size.
 * \param dx input difference.
 * \param dy output difference.
 * \param k0 first round key.
 * \param k1 second round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{xdp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \see xdp_f_assign_bit_x
 */
double xdp_f_fk(const uint32_t n, const uint32_t dx, const uint32_t dy, 
					 const uint32_t k0, const uint32_t k1, const uint32_t delta,
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
	 xdp_f_assign_bit_x(n, i, mask_i, x, lsh_const, rsh_const, k0, k1, delta, dx, dy, &x_cnt, &p);
  }
  return p;
}

/**
 * For given output difference \p dy, compute all input differences \p dx 
 * and their probabilities, by counting all values \p x that satisfy 
 * the differential \f$(dx \rightarrow dy)\f$ for a fixed key and round constant.
 * At the same time keeps track of the maximum probability input difference.
 *
 * The function works by recursively assigning the bits of \p x and \p dx starting 
 * at bit position \p i and terminating at the MS bit \p n.
 * The recursion proceeds to bit \f$(i+1)\f$ only if the differential is satisfied
 * on the \p i LS bits. This is checked by applying \ref xdp_f_is_sat . 
 *
 * \param n word size (terminating bit popsition).
 * \param i current bit position.
 * \param mask_i mask on the \p i LS bits of \p x.
 * \param x input value of size at least (\p i + \p rsh_const).
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \param k0 first round key.
 * \param k1 second round key.
 * \param delta round constant.
 * \param dx input difference.
 * \param dy output difference.
 * \param x_cnt array of \f$2^n\f$ counters - each one keeps track of the number of values
 *        satisfying \f$(dx \rightarrow dy)\f$ for every \p dx.
 * \param ret_prob the maximum probability over all input differences 
 *        \f$\mathrm{max}_{dx} ~\mathrm{xdp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \param ret_dx the input difference that has maximum probability.
 * \returns \p 1 if \f$x[i-1:0]\f$ satisfies \f$(dx[i-1:0] \rightarrow dy[i-1:0])\f$; \p 0 otherwise.
 *
 * \see xdp_f_assign_bit_x, max_dx_xdp_f_fk
 */
uint32_t xdp_f_assign_bit_x_dx(const uint32_t n, const uint32_t i, const uint32_t mask_i, const uint32_t x, 
										 const uint32_t lsh_const, const uint32_t rsh_const,
										 const uint32_t k0, const uint32_t k1, const uint32_t delta,
										 const uint32_t dx, const uint32_t dy, uint64_t* x_cnt, 
										 double* ret_prob, uint32_t* ret_dx)
{
  assert(n <= WORD_SIZE);
  assert(n >= (rsh_const * 2));
  assert(i <= (n + rsh_const));
  if((i == WORD_SIZE) && (dx == 0)) {
	 double p = 0.0;
	 if(dy == 0) {
		x_cnt[dx] = ALL_WORDS;
		p = 1.0;
	 } else {
		x_cnt[dx] = 0;
		p = 0.0;
	 }
	 if(p >= *ret_prob) {
		*ret_prob = p;
		*ret_dx = dx;
	 }
	 return 0;
  } else {
	 if(i == (n + rsh_const)) {
		assert(dx < MOD);
		if(n == (WORD_SIZE)) {
		  bool b_ok = xdp_f_check_x(lsh_const, rsh_const, k0, k1, delta, dx, dy, x);
		  assert(b_ok);
		}
		return 1;
	 }
  }
  bool b_xdp_f_is_sat = xdp_f_is_sat(mask_i, lsh_const, rsh_const, k0, k1, delta, dx, dy, x); // check x[i]
  if(b_xdp_f_is_sat) {
	 if(i < (WORD_SIZE - 1)) { // x[30:0] are assigned and we shall assign the last bit x[31]
		uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); // select x[(i+1)-R:0]
		for(uint32_t next_bit_dx = 0; next_bit_dx < 2; next_bit_dx++) {
		  uint32_t new_dx = (next_bit_dx << (i + 1)) | dx; // assign dx[i+1]
		  for(uint32_t next_bit_x = 0; next_bit_x < 2; next_bit_x++) {
			 uint32_t new_x = (next_bit_x << (i + 1)) | x; // assign x[i+1]
			 uint32_t ret = 
			 xdp_f_assign_bit_x_dx(n, i + 1, mask_i, new_x, lsh_const, rsh_const, k0, k1, delta, new_dx, dy, x_cnt, ret_prob, ret_dx);
			 x_cnt[new_dx] += ret;
		  }
		}
	 } else {
		uint32_t mask_i = MASK;
		uint32_t new_dx = dx;
		uint32_t new_x = x;
		uint32_t ret =  
		xdp_f_assign_bit_x_dx(n, i + 1, mask_i, new_x, lsh_const, rsh_const, k0, k1, delta, new_dx, dy, x_cnt, ret_prob, ret_dx);
		x_cnt[new_dx] += ret;
		if((i + 1) == (n + rsh_const)) {
		  double p = (double)x_cnt[new_dx] / (double)ALL_WORDS;
		  if(p >= *ret_prob) {
			 *ret_prob = p;
			 *ret_dx = dx;
		  }
#if DEBUG_XDP_TEA_F_FK
		  printf("[%s:%d] %2d: # %8llX: %8X -> %8X | x = %8X  %f 2^%f\n", __FILE__, __LINE__, n, x_cnt[dx], dx, dy, x, *ret_prob, log2(*ret_prob));
#endif  // #if DEBUG_XDP_TEA_F_FK
		}
	 }
  } 
  return 0;
}

/**
 * For given output difference \p dy, compute the maximum probability 
 * input differences \p dx over all input differences: 
 * \f$\mathrm{max}_{dx} ~\mathrm{xdp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \b Complexity: \f$ O(2n) < c \le O(2^{2n}) \f$. \b Memory: \f$4 \cdot 2^n\f$ Bytes.
 *
 * \param n word size.
 * \param ret_dx maximum probability input difference.
 * \param dy output difference.
 * \param k0 first round key.
 * \param k1 second round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{max}_{dx} ~\mathrm{xdp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \see xdp_f_assign_bit_x_dx
 */
double max_dx_xdp_f_fk(const uint32_t n, uint32_t* ret_dx, const uint32_t dy, 
							  const uint32_t k0, const uint32_t k1, const uint32_t delta,
							  const uint32_t lsh_const, const uint32_t rsh_const)
{
#if DEBUG_XDP_TEA_F_FK
  printf("[%s:%d] %s() Input: %d %d %8X %8X %8X \n", __FILE__, __LINE__, __FUNCTION__, 
			lsh_const, rsh_const, k0, k1, delta);
#endif  // #if DEBUG_XDP_TEA_F_FK
  assert(lsh_const < rsh_const);
  assert(n <= WORD_SIZE);
  assert(n >= (rsh_const * 2));
  // number of initial LSB bits
  uint32_t nlsb_init = (rsh_const * 2);
  if(nlsb_init > WORD_SIZE) {
	 nlsb_init = WORD_SIZE;
  }
  // all 10-bit values
  uint32_t N = (1U << nlsb_init);
  uint32_t x = 0;
  uint32_t dx = 0;
  double max_p = 0.0;
  uint32_t max_dx = 0;

  //  uint32_t x_cnt[ALL_WORDS] = {0};
  uint64_t* x_cnt = (uint64_t *)calloc(ALL_WORDS, sizeof(uint64_t));
  if(x_cnt == NULL) {
	 printf("[%s:%d] ERROR: Bad calloc. Not enough memory. Exiting...\n", __FILE__, __LINE__);
	 exit(1);
  }

  //  const uint32_t n = WORD_SIZE; 
  for(uint32_t j = 0; j < N; j++) { // skip the zero difference
	 dx = j;
	 uint32_t dxx = max_dx;
	 double pp = max_p;

#if DEBUG_XDP_TEA_F_FK
	 printf("[%s:%d] dx[%d:0] = %8X\n", __FILE__, __LINE__, (nlsb_init - 1), j);
#endif  // #if DEBUG_XDP_TEA_F_FK

	 for(uint32_t l = 0; l < N; l++) {
		x = l;							  // assign x[9:0]
		uint32_t i = nlsb_init - 1; // start at x[9]
		uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); 
		xdp_f_assign_bit_x_dx(n, i, mask_i, x, lsh_const, rsh_const, k0, k1, delta, dx, dy, x_cnt, &pp, &dxx);
	 }
	 if((pp >= max_p) && (pp != 1.0)) { // skip the zero difference (p == 1.0)
#if DEBUG_XDP_TEA_F_FK
		if(max_dx != dxx) {
		  printf("[%s:%d] Update max dx[%d:0] = %8X | %8X -> %8X %f 2^%f\n", __FILE__, __LINE__, (nlsb_init - 1), j, dxx, dy, pp, log2(pp));
		}
#endif  // #if DEBUG_XDP_TEA_F_FK
		max_p = pp;
		max_dx = dxx;
#if DEBUG_XDP_TEA_F_FK
		printf("\n[%s:%d] Update max %8X -> %8X %f 2^%f\n", __FILE__, __LINE__, max_dx, dy, max_p, log2(max_p));
#endif  // #if DEBUG_XDP_TEA_F_FK
	 }
  }
  free(x_cnt);
  *ret_dx = max_dx;
  return max_p;
}

/**
 * For given input difference \p dx, compute all output differences \p dy 
 * and their probabilities, by counting all values \p x that satisfy 
 * the differential \f$(dx \rightarrow dy)\f$ for a fixed key and round constant.
 * At the same time keeps track of the maximum probability output difference.
 *
 * The function works by recursively assigning the bits of \p x and \p dy starting 
 * at bit position \p i and terminating at the MS bit \p n.
 * The recursion proceeds to bit \f$(i+1)\f$ only if the differential is satisfied
 * on the \p i LS bits. This is checked by applying \ref xdp_f_is_sat. 
 *
 * \param n word size (terminating bit popsition).
 * \param i current bit position.
 * \param mask_i mask on the \p i LS bits of \p x.
 * \param x input value of size at least (\p i + \p rsh_const).
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \param k0 first round key.
 * \param k1 second round key.
 * \param delta round constant.
 * \param dx input difference.
 * \param dy output difference.
 * \param x_cnt array of \f$2^n\f$ counters - each one keeps track of the number of values
 *        satisfying \f$(dx \rightarrow dy)\f$ for every \p dy.
 * \param ret_prob the maximum probability over all output differences 
 *        \f$\mathrm{max}_{dy} ~\mathrm{xdp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \param ret_dy the output difference that has maximum probability.
 * \returns \p 1 if \f$x[i-1:0]\f$ satisfies \f$(dx[i-1:0] \rightarrow dy[i-1:0])\f$; \p 0 otherwise.
 *
 * \see xdp_f_assign_bit_x_dx
 */
uint32_t xdp_f_assign_bit_x_dy(const uint32_t n, const uint32_t i, const uint32_t mask_i, const uint32_t x, 
										 const uint32_t lsh_const, const uint32_t rsh_const,
										 const uint32_t k0, const uint32_t k1, const uint32_t delta,
										 const uint32_t dx, const uint32_t dy, uint64_t* x_cnt, 
										 double* ret_prob, uint32_t* ret_dy)
{
  assert(n <= WORD_SIZE);
  assert(n >= (rsh_const * 2));
  assert(i <= (n + rsh_const));
  if((i == WORD_SIZE) && (dx == 0)) {
	 double p = 0.0;
	 if(dy == 0) {
		x_cnt[dy] = ALL_WORDS;	  // ! dy
		p = 1.0;
	 } else {
		x_cnt[dy] = 0;				  // ! dy
		p = 0.0;
	 }
	 if(p >= *ret_prob) {
		*ret_prob = p;
		*ret_dy = dy;				  // ! dy
	 }
	 return 0;
  } else {
	 if(i == (n + rsh_const)) {
		assert(dy < MOD);
		if(n == (WORD_SIZE)) {
		  bool b_ok = xdp_f_check_x(lsh_const, rsh_const, k0, k1, delta, dx, dy, x);
		  assert(b_ok);
		}
		return 1;
	 }
  }
  bool b_xdp_f_is_sat = xdp_f_is_sat(mask_i, lsh_const, rsh_const, k0, k1, delta, dx, dy, x); // check x[i]
  if(b_xdp_f_is_sat) {
	 if(i < (WORD_SIZE - 1)) { // x[30:0] are assigned and we shall assign the last bit x[31]
		uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); // select x[(i+1)-R:0]
		for(uint32_t next_bit_dy = 0; next_bit_dy < 2; next_bit_dy++) { // ! dy
		  uint32_t new_dy = (next_bit_dy << (i + 1)) | dy; // assign dx[i+1]
		  for(uint32_t next_bit_x = 0; next_bit_x < 2; next_bit_x++) {
			 uint32_t new_x = (next_bit_x << (i + 1)) | x; // assign x[i+1]
			 uint32_t ret = 
			 xdp_f_assign_bit_x_dy(n, i + 1, mask_i, new_x, lsh_const, rsh_const, k0, k1, delta, dx, new_dy, x_cnt, ret_prob, ret_dy);
			 x_cnt[new_dy] += ret;
		  }
		}
	 } else {
		uint32_t mask_i = MASK;
		uint32_t new_dy = dy;
		uint32_t new_x = x;
		uint32_t ret =  
		xdp_f_assign_bit_x_dy(n, i + 1, mask_i, new_x, lsh_const, rsh_const, k0, k1, delta, dx, new_dy, x_cnt, ret_prob, ret_dy);
		x_cnt[new_dy] += ret;
		if((i + 1) == (n + rsh_const)) {
		  double p = (double)x_cnt[new_dy] / (double)ALL_WORDS;
		  if(p >= *ret_prob) {
			 *ret_prob = p;
			 *ret_dy = dy;
		  }
#if DEBUG_XDP_TEA_F_FK
		  printf("[%s:%d] %2d: # %8llX: %8X -> %8X | x = %8X  %f 2^%f\n", __FILE__, __LINE__, n, x_cnt[dy], dx, dy, x, *ret_prob, log2(*ret_prob));
#endif  // #if DEBUG_XDP_TEA_F_FK
		}
	 }
  } 
  return 0;
}

/**
 * For given input difference \p dx, compute the maximum probability 
 * output difference \p dy over all output differences: 
 * \f$\mathrm{max}_{dy} ~\mathrm{xdp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \b Complexity: \f$ O(2n) < c \le O(2^{2n}) \f$. \b Memory \b requirement: \f$4 \cdot 2^n\f$ Bytes.
 *
 * \param n word size.
 * \param dx input difference.
 * \param ret_dy maximum probability output difference.
 * \param k0 first round key.
 * \param k1 second round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{max}_{dy} ~\mathrm{xdp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \see xdp_f_assign_bit_x_dy, max_dy_xdp_f_fk
 */
double max_dy_xdp_f_fk(const uint32_t n, const uint32_t dx, uint32_t* ret_dy,
							  const uint32_t k0, const uint32_t k1, const uint32_t delta,
							  const uint32_t lsh_const, const uint32_t rsh_const)
{
#if DEBUG_XDP_TEA_F_FK
  printf("[%s:%d] %s() Input: %d %d %8X %8X %8X \n", __FILE__, __LINE__, __FUNCTION__, 
			lsh_const, rsh_const, k0, k1, delta);
#endif  // #if DEBUG_XDP_TEA_F_FK
  assert(lsh_const < rsh_const);
  assert(n <= WORD_SIZE);
  assert(n >= (rsh_const * 2));
  if(dx == 0) {					  // zero input difference
	 *ret_dy = 0;
	 return 1.0;
  }
  // number of initial LSB bits
  uint32_t nlsb_init = (rsh_const * 2);
  if(nlsb_init > WORD_SIZE)
	 nlsb_init = WORD_SIZE;
  // all 10-bit values
  uint32_t N = (1U << nlsb_init);
  uint32_t x = 0;
  uint32_t dy = 0;
  double max_p = 0.0;
  uint32_t max_dy = 0;

  //  uint32_t x_cnt[ALL_WORDS] = {0};
  uint64_t* x_cnt = (uint64_t *)calloc(ALL_WORDS, sizeof(uint64_t));
  if(x_cnt == NULL) {
	 printf("[%s:%d] ERROR: Bad calloc. Not enough memory. Exiting...\n", __FILE__, __LINE__);
	 exit(1);
  }

  //  const uint32_t n = WORD_SIZE; 
  for(uint32_t j = 0; j < N; j++) { // skip the zero difference
	 dy = j;
	 uint32_t dyy = max_dy;
	 double pp = max_p;
#if DEBUG_XDP_TEA_F_FK
	 printf("[%s:%d] dy[%d:0] = %8X\n", __FILE__, __LINE__, (nlsb_init - 1), j);
#endif  // #if DEBUG_XDP_TEA_F_FK
	 for(uint32_t l = 0; l < N; l++) {
		x = l;							  // assign x[9:0]
		uint32_t i = nlsb_init - 1; // start at x[9]
		uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); 
		xdp_f_assign_bit_x_dy(n, i, mask_i, x, lsh_const, rsh_const, k0, k1, delta, dx, dy, x_cnt, &pp, &dyy);
#if DEBUG_XDP_TEA_F_FK
		printf("[%s:%d] %8X -> %8X %f 2^%f | max_p = %f\n", __FILE__, __LINE__, dyy, dy, pp, log2(pp), max_p);
#endif  // #if DEBUG_XDP_TEA_F_FK
	 }
	 if((pp >= max_p) && (pp != 1.0)) { // skip the zero difference (p == 1.0)
#if DEBUG_XDP_TEA_F_FK
		if(max_dy != dyy) {
		  printf("[%s:%d] Update max dy[%d:0] = %8X | %8X -> %8X %f 2^%f\n", __FILE__, __LINE__, (nlsb_init - 1), j, dyy, dy, pp, log2(pp));
		}
#endif  // #if DEBUG_XDP_TEA_F_FK
		max_p = pp;
		max_dy = dyy;
#if DEBUG_XDP_TEA_F_FK
		printf("\n[%s:%d] Update max %8X -> %8X %f 2^%f\n", __FILE__, __LINE__, max_dy, dy, max_p, log2(max_p));
#endif  // #if DEBUG_XDP_TEA_F_FK
	 }
  }
  free(x_cnt);
  *ret_dy = max_dy;
  return max_p;
}
