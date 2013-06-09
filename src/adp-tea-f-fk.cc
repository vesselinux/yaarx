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
 * \file  adp-tea-f-fk.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \brief The ADD differential probability of the F-function of TEA for a fixed key
 *        and round constants \f$\mathrm{adp}^{F}(k_0, k_1, \delta |~ da \rightarrow dd)\f$, where
 *        \f$ F(k_0, k_1, \delta |~ x) = ((x \ll 4) + k_0) \oplus (x + \delta) \oplus ((x \gg 5) + k_1)\f$
 *        Complexity: \f$ O(n) < c \le O(2^n) \f$.
 *
 * \attention The algorithms in this file have complexity that depends on the input and output differences to F. 
 *            It is worst-case exponential in the word size, but is sub-exponential on average.
 *
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef TEA_H
#include "tea.hh"
#endif

/**
 * Check if a given value \p x satisfies the ADD differential \f$(dx \rightarrow dy)\f$
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
 * \returns TRUE if \f$k_0, k_1, \delta:~ dy = F(x + dx) - F(x)\f$.
 *
 */ 
bool adp_f_check_x(const uint32_t lsh_const, const uint32_t rsh_const,
						 const uint32_t k0, const uint32_t k1, const uint32_t delta,
						 const uint32_t dx, const uint32_t dy, const uint32_t x)
{
  uint32_t x1 = x;
  uint32_t x2 = ADD(x, dx);
  uint32_t mask = 0xffffffff;
  uint32_t y1 = tea_f_i(mask, k0, k1, delta, lsh_const, rsh_const, x1);
  uint32_t y2 = tea_f_i(mask, k0, k1, delta, lsh_const, rsh_const, x2);
  uint32_t y_sub = SUB(y2, y1);
  bool b_sat = (dy == y_sub);
  return b_sat;
}

/**
 * Check if the differential \f$(dx \rightarrow dy)\f$ for \p F is 
 * satisfied on the \p i LS bits of \p x i.e. check if 
 * \f$k_0, k_1, \delta:~ dy[i-1:0] = F(x[i-1:0] + dx[i-1:0]) - F(x[i-1:0]) ~\mathrm{mod} ~2^{i}\f$.
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
 * \returns TRUE if \f$k_0, k_1, \delta:~ dy[i-1:0] = F(x[i-1:0] + dx[i-1:0]) - F(x[i-1:0]) ~\mathrm{mod} ~2^{i}\f$.
 *
 */
bool adp_f_is_sat(const uint32_t mask_i, const uint32_t lsh_const, const uint32_t rsh_const,
						const uint32_t k0, const uint32_t k1, const uint32_t delta,
						const uint32_t dx, const uint32_t dy, int32_t x)
{
  //  printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, mask_i, x_in);
  uint32_t x1 = x;// & MASK;
  uint32_t x2 = ADD(x, dx);
  uint32_t y1 = tea_f_i(mask_i, k0, k1, delta, lsh_const, rsh_const, x1);
  uint32_t y2 = tea_f_i(mask_i, k0, k1, delta, lsh_const, rsh_const, x2);
  uint32_t y_sub_i = SUB(y2, y1) & mask_i;
  uint32_t dy_i = (dy & mask_i);
  bool b_sat = (dy_i == y_sub_i);
  //  printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, y_sub, dy);
  //  printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, y2, y1);
  //  printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, x2, x1);
  return b_sat;
}

/**
 * Counts the number of values \p x for which the differential \f$(dx \rightarrow dy)\f$
 * for the F-function of TEA is satisfied. The function operates by recursively assigning
 * the bits of \p x starting from bit position \p i and terminating at the MS bit \p n.
 * The recursion proceeds to bit \f$(i+1)\f$ only if the differential is satisfied
 * on the \p i LS bits. This is checked by applying \ref adp_f_is_sat. 
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
 * \param prob the fixed-key ADD probability of \p F: \f$\mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \returns \p 1 if \f$x[i-1:0]\f$ satisfies \f$(dx[i-1:0] \rightarrow dy[i-1:0])\f$; \p 0 otherwise.
 * \see adp_f_fk
 */
uint32_t adp_f_assign_bit_x(const uint32_t n, const uint32_t i, const uint32_t mask_i, const uint32_t x, 
									 const uint32_t lsh_const, const uint32_t rsh_const,
									 const uint32_t k0, const uint32_t k1, const uint32_t delta,
									 const uint32_t dx, const uint32_t dy, uint32_t* x_cnt, double* prob)
{
  //  if(i == 37) {
  //  if(i == (WORD_SIZE + rsh_const)) {
  assert(n <= WORD_SIZE);
  assert(n >= (rsh_const * 2));
  assert(i <= (n + rsh_const));
  if(i == (n + rsh_const)) {
#if DEBUG_ADP_TEA_F_FK
	 double p = *prob;
	 printf("\r[%s:%d] %2d: # %08X: %8X -> %8X | x = %8X  %f 2^%f", __FILE__, __LINE__, n, *x_cnt, dx, dy, x, p, log2(p));
	 fflush(stdout);
#endif  // DEBUG_ADP_TEA_F_FK
	 if(n == WORD_SIZE) {
		bool b_ok = adp_f_check_x(lsh_const, rsh_const, k0, k1, delta, dx, dy, x);
		assert(b_ok);
	 }
	 return 1;
  }
  bool b_adp_f_is_sat = adp_f_is_sat(mask_i, lsh_const, rsh_const, k0, k1, delta, dx, dy, x); // check x[i]
  if(b_adp_f_is_sat) {
	 if(i < (WORD_SIZE - 1)) { // x[30:0] are assigned and we shall assign the last bit x[31]
		uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); // select x[(i+1)-R:0]
		for(uint32_t next_bit = 0; next_bit < 2; next_bit++) {
		  uint32_t new_x = (next_bit << (i + 1)) | x; // assign x[i+1]
		  //		  printf("[%s:%d] x = %8X\n", __FILE__, __LINE__, x);
		  uint32_t ret = adp_f_assign_bit_x(n, i + 1, mask_i, new_x, lsh_const, rsh_const, k0, k1, delta, dx, dy, x_cnt, prob);
		  *x_cnt += ret;
		  *prob = (double)*x_cnt / (double)ALL_WORDS;
		  //		  printf("[%s:%d] x_cnt = %d\n", __FILE__, __LINE__, *x_cnt);
		}
	 } else {
		uint32_t mask_i = MASK;
		uint32_t new_x = x;
		uint32_t ret =  adp_f_assign_bit_x(n, i + 1, mask_i, new_x, lsh_const, rsh_const, k0, k1, delta, dx, dy, x_cnt, prob);
		*x_cnt += ret;
		*prob = (double)*x_cnt / (double)ALL_WORDS;
#if DEBUG_ADP_TEA_F_FK
		if((i + 1) == (n + rsh_const)) {
		  printf("[%s:%d] x_cnt = %d | %8X | %f 2^%f\n", __FILE__, __LINE__, *x_cnt, x, *prob, log2(*prob));
		}
#endif  // DEBUG_ADP_TEA_F_FK
	 }
  } else {
#if DEBUG_ADP_TEA_F_FK
	 printf("[%s:%d] Not sat dx[%2d:%2d]\n", __FILE__, __LINE__, n, i);
#endif  // DEBUG_ADP_TEA_F_FK
  }
  return 0;
}

/**
 * Compute the fixed-key, fixed-constant ADD differential probability of
 * the F-function of block cipher TEA: 
 * \f$\mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
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
 * \returns \f$\mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \see adp_f_assign_bit_x
 */
double adp_f_fk(const uint32_t n, const uint32_t dx, const uint32_t dy, 
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
	 //	 uint32_t i = TEA_RSH_CONST;
	 uint32_t i = nlsb_init - 1; // start at x[9]
	 //	 uint32_t mask_i = ~(0xffffffff << TEA_RSH_CONST); // check x[4:0], x[0]|0000, x[9:5]
	 uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); 
	 adp_f_assign_bit_x(n, i, mask_i, x, lsh_const, rsh_const, k0, k1, delta, dx, dy, &x_cnt, &p);
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
 * on the \p i LS bits. This is checked by applying \ref adp_f_is_sat . 
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
 *        \f$\mathrm{max}_{dx} ~\mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \param ret_dx the input difference that has maximum probability.
 * \returns \p 1 if \f$x[i-1:0]\f$ satisfies \f$(dx[i-1:0] \rightarrow dy[i-1:0])\f$; \p 0 otherwise.
 *
 * \see adp_f_assign_bit_x, max_dx_adp_f_fk
 */
uint32_t adp_f_assign_bit_x_dx(const uint32_t n, const uint32_t i, const uint32_t mask_i, const uint32_t x, 
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
		  bool b_ok = adp_f_check_x(lsh_const, rsh_const, k0, k1, delta, dx, dy, x);
		  assert(b_ok);
		}
		return 1;
	 }
  }
  bool b_adp_f_is_sat = adp_f_is_sat(mask_i, lsh_const, rsh_const, k0, k1, delta, dx, dy, x); // check x[i]
  if(b_adp_f_is_sat) {
	 if(i < (WORD_SIZE - 1)) { // x[30:0] are assigned and we shall assign the last bit x[31]
		uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); // select x[(i+1)-R:0]
		for(uint32_t next_bit_dx = 0; next_bit_dx < 2; next_bit_dx++) {
		  uint32_t new_dx = (next_bit_dx << (i + 1)) | dx; // assign dx[i+1]
		  for(uint32_t next_bit_x = 0; next_bit_x < 2; next_bit_x++) {
			 uint32_t new_x = (next_bit_x << (i + 1)) | x; // assign x[i+1]
			 uint32_t ret = 
			 adp_f_assign_bit_x_dx(n, i + 1, mask_i, new_x, lsh_const, rsh_const, k0, k1, delta, new_dx, dy, x_cnt, ret_prob, ret_dx);
			 x_cnt[new_dx] += ret;
		  }
		}
	 } else {
		uint32_t mask_i = MASK;
		uint32_t new_dx = dx;
		uint32_t new_x = x;
		uint32_t ret =  
		adp_f_assign_bit_x_dx(n, i + 1, mask_i, new_x, lsh_const, rsh_const, k0, k1, delta, new_dx, dy, x_cnt, ret_prob, ret_dx);
		x_cnt[new_dx] += ret;
		if((i + 1) == (n + rsh_const)) {
		  double p = (double)x_cnt[new_dx] / (double)ALL_WORDS;
		  if(p >= *ret_prob) {
			 *ret_prob = p;
			 *ret_dx = dx;
		  }
		}
	 }
  } 
  return 0;
}

/**
 * For given output difference \p dy, compute the maximum probability 
 * input differences \p dx over all input differences: 
 * \f$\mathrm{max}_{dx} ~\mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
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
 * \returns \f$\mathrm{max}_{dx} ~\mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \see adp_f_assign_bit_x_dx
 */
double max_dx_adp_f_fk(const uint32_t n, uint32_t* ret_dx, const uint32_t dy, 
							  const uint32_t k0, const uint32_t k1, const uint32_t delta,
							  const uint32_t lsh_const, const uint32_t rsh_const)
{
#if DEBUG_ADP_TEA_F_FK
  printf("[%s:%d] %s() Input: %d %d %8X %8X %8X \n", __FILE__, __LINE__, __FUNCTION__, 
			lsh_const, rsh_const, k0, k1, delta);
#endif  // DEBUG_ADP_TEA_F_FK
  assert(lsh_const < rsh_const);
  assert(n <= WORD_SIZE);
  assert(n >= (rsh_const * 2));
  // number of initial LSB bits
  uint32_t nlsb_init = (rsh_const * 2);
  if(nlsb_init > WORD_SIZE)
	 nlsb_init = WORD_SIZE;
  // all 10-bit values
  uint32_t N = (1U << nlsb_init);
  uint32_t x = 0;
  uint32_t dx = 0;
  double max_p = 0.0;
  uint32_t max_dx = 0;

  //  uint32_t x_cnt[ALL_WORDS] = {0};
  uint64_t* x_cnt = (uint64_t *)calloc((size_t)ALL_WORDS, sizeof(uint64_t));
  //  assert(x_cnt != NULL);
  if(x_cnt == NULL) {
	 printf("[%s:%d] ERROR: Bad calloc. Not enough memory. Exiting...\n", __FILE__, __LINE__);
	 exit(1);
  }

  //  const uint32_t n = WORD_SIZE; 
  for(uint32_t j = 0; j < N; j++) { // skip the zero difference
	 dx = j;
	 uint32_t dxx = max_dx;
	 double pp = max_p;
#if DEBUG_ADP_TEA_F_FK
	 printf("\r[%s:%d] dx[%d:0] = %8X ", __FILE__, __LINE__, (nlsb_init - 1), j);
	 fflush(stdout);
#endif  // DEBUG_ADP_TEA_F_FK
	 for(uint32_t l = 0; l < N; l++) {
		x = l;							  // assign x[9:0]
		uint32_t i = nlsb_init - 1; // start at x[9]
		uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); 
		adp_f_assign_bit_x_dx(n, i, mask_i, x, lsh_const, rsh_const, k0, k1, delta, dx, dy, x_cnt, &pp, &dxx);
	 }
	 if((pp >= max_p) && (pp != 1.0)) { // skip the zero difference (p == 1.0)
#if DEBUG_ADP_TEA_F_FK
		if(max_dx != dxx) {
		  printf("[%s:%d] Update max dx[%d:0] = %8X | %8X -> %8X %f 2^%f\n", __FILE__, __LINE__, (nlsb_init - 1), j, dxx, dy, pp, log2(pp));
		}
#endif  // DEBUG_ADP_TEA_F_FK
		max_p = pp;
		max_dx = dxx;
#if DEBUG_ADP_TEA_F_FK
		printf("\n[%s:%d] Update max %8X -> %8X %f 2^%f\n", __FILE__, __LINE__, max_dx, dy, max_p, log2(max_p));
#endif  // DEBUG_ADP_TEA_F_FK
	 }
  }
  // print all differences
#if DEBUG_ADP_TEA_F_FK									  // DEBUG
  for(uint32_t i_dx = 0; i_dx < ALL_WORDS; i_dx++) {
	 double i_p = (double)x_cnt[i_dx] / (double)ALL_WORDS;
	 printf("[%s:%d] %8X %f (2^%f)\n", __FILE__, __LINE__, i_dx, i_p, log2(i_p));
  }
#endif  // DEBUG_ADP_TEA_F_FK
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
 * on the \p i LS bits. This is checked by applying \ref adp_f_is_sat. 
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
 *        \f$\mathrm{max}_{dy} ~\mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \param ret_dy the output difference that has maximum probability.
 * \returns \p 1 if \f$x[i-1:0]\f$ satisfies \f$(dx[i-1:0] \rightarrow dy[i-1:0])\f$; \p 0 otherwise.
 *
 * \see adp_f_assign_bit_x_dx
 */
uint32_t adp_f_assign_bit_x_dy(const uint32_t n, const uint32_t i, const uint32_t mask_i, const uint32_t x, 
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
#if DEBUG_ADP_TEA_F_FK
		double p = *ret_prob;
		printf("[%s:%d] %2d: # %8llX: %8X -> %8X | x = %8X  %f 2^%f\n", __FILE__, __LINE__, n, x_cnt[dy], dx, dy, x, p, log2(p));
#endif  // DEBUG_ADP_TEA_F_FK
		assert(dy < MOD);
		if(n == (WORD_SIZE)) {
		  bool b_ok = adp_f_check_x(lsh_const, rsh_const, k0, k1, delta, dx, dy, x);
		  assert(b_ok);
		}
		return 1;
	 }
  }
  bool b_adp_f_is_sat = adp_f_is_sat(mask_i, lsh_const, rsh_const, k0, k1, delta, dx, dy, x); // check x[i]
  if(b_adp_f_is_sat) {
	 if(i < (WORD_SIZE - 1)) { // x[30:0] are assigned and we shall assign the last bit x[31]
		uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); // select x[(i+1)-R:0]
		for(uint32_t next_bit_dy = 0; next_bit_dy < 2; next_bit_dy++) { // ! dy
		  uint32_t new_dy = (next_bit_dy << (i + 1)) | dy; // assign dx[i+1]
		  for(uint32_t next_bit_x = 0; next_bit_x < 2; next_bit_x++) {
			 uint32_t new_x = (next_bit_x << (i + 1)) | x; // assign x[i+1]
			 uint32_t ret = 
			 adp_f_assign_bit_x_dy(n, i + 1, mask_i, new_x, lsh_const, rsh_const, k0, k1, delta, dx, new_dy, x_cnt, ret_prob, ret_dy);
			 x_cnt[new_dy] += ret;
		  }
		}
	 } else {
		uint32_t mask_i = MASK;
		uint32_t new_dy = dy;
		uint32_t new_x = x;
		uint32_t ret =  
		adp_f_assign_bit_x_dy(n, i + 1, mask_i, new_x, lsh_const, rsh_const, k0, k1, delta, dx, new_dy, x_cnt, ret_prob, ret_dy);
		x_cnt[new_dy] += ret;
		if((i + 1) == (n + rsh_const)) {
		  double p = (double)x_cnt[new_dy] / (double)ALL_WORDS;
		  if(p >= *ret_prob) {
			 *ret_prob = p;
			 *ret_dy = dy;
		  }
#if DEBUG_ADP_TEA_F_FK
		  printf("\r[%s:%d] %2d: # %8llX: %8X -> %8X | x = %8X  %f 2^%f", __FILE__, __LINE__, n, x_cnt[dy], dx, dy, x, *ret_prob, log2(*ret_prob));
		  fflush(stdout);
#endif
		}
	 }
  } 
  return 0;
}

/**
 * For given input difference \p dx, compute the maximum probability 
 * output difference \p dy over all output differences: 
 * \f$\mathrm{max}_{dy} ~\mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
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
 * \returns \f$\mathrm{max}_{dy} ~\mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \see adp_f_assign_bit_x_dy, max_dy_adp_f_fk
 */
double max_dy_adp_f_fk(const uint32_t n, const uint32_t dx, uint32_t* ret_dy,
							  const uint32_t k0, const uint32_t k1, const uint32_t delta,
							  const uint32_t lsh_const, const uint32_t rsh_const)
{

#if DEBUG_ADP_TEA_F_FK
  printf("[%s:%d] %s() Input: %d %d %8X %8X %8X \n", __FILE__, __LINE__, __FUNCTION__, 
			lsh_const, rsh_const, k0, k1, delta);
#endif  // DEBUG_ADP_TEA_F_FK

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
  uint64_t* x_cnt = (uint64_t *)calloc((size_t)ALL_WORDS, sizeof(uint64_t));
  if(x_cnt == NULL) {
	 printf("[%s:%d] ERROR: Bad calloc. Not enough memory. Exiting...\n", __FILE__, __LINE__);
	 exit(1);
  }

  //  const uint32_t n = WORD_SIZE; 
  for(uint32_t j = 0; j < N; j++) { // skip the zero difference
	 dy = j;
	 uint32_t dyy = max_dy;
	 double pp = max_p;
#if DEBUG_ADP_TEA_F_FK
	 printf("[%s:%d] dy[%d:0] = %8X\n", __FILE__, __LINE__, (nlsb_init - 1), j);
#endif  // DEBUG_ADP_TEA_F_FK
	 for(uint32_t l = 0; l < N; l++) {
		x = l;							  // assign x[9:0]
		uint32_t i = nlsb_init - 1; // start at x[9]
		uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); 
		adp_f_assign_bit_x_dy(n, i, mask_i, x, lsh_const, rsh_const, k0, k1, delta, dx, dy, x_cnt, &pp, &dyy);
#if DEBUG_ADP_TEA_F_FK
		printf("[%s:%d] %8X -> %8X %f 2^%f | max_p = %f\n", __FILE__, __LINE__, dyy, dy, pp, log2(pp), max_p);
#endif  // DEBUG_ADP_TEA_F_FK
	 }
	 if((pp >= max_p) && (pp != 1.0)) { // skip the zero difference (p == 1.0)
#if DEBUG_ADP_TEA_F_FK
		if(max_dy != dyy) {
		  printf("[%s:%d] Update max dy[%d:0] = %8X | %8X -> %8X %f 2^%f\n", __FILE__, __LINE__, (nlsb_init - 1), j, dyy, dy, pp, log2(pp));
		}
#endif  // DEBUG_ADP_TEA_F_FK
		max_p = pp;
		max_dy = dyy;
	 }
  }
  free(x_cnt);
  *ret_dy = max_dy;
  return max_p;
}

/**
 * For given input difference \p dx, compute all output differences \p dy
 * for the TEA F-function with fixed keys and round constants. Returns 
 * the maximum output probability.
 *
 * \param n word size.
 * \param dx input difference.
 * \param ret_dy maximum probability output difference.
 * \param k0 first round key.
 * \param k1 second round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \param x_cnt array of \f$2^n\f$ counters - each one keeps track of the number of inputs \p x
 *        satisfying \f$(dx \rightarrow dy)\f$ for every \p dy.
 * \returns \f$\mathrm{max}_{dy} ~\mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \see max_dy_adp_f_fk
 *
 */
double all_dy_adp_f_fk(const uint32_t n, const uint32_t dx, uint32_t* ret_dy,
							  const uint32_t k0, const uint32_t k1, const uint32_t delta,
							  const uint32_t lsh_const, const uint32_t rsh_const, uint64_t* x_cnt)
{
#if DEBUG_ADP_TEA_F_FK
  printf("[%s:%d] %s() Input: %d %d %8X %8X %8X \n", __FILE__, __LINE__, __FUNCTION__, 
			lsh_const, rsh_const, k0, k1, delta);
#endif  // DEBUG_ADP_TEA_F_FK
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

  //  const uint32_t n = WORD_SIZE; 
  for(uint32_t j = 0; j < N; j++) { // skip the zero difference
	 dy = j;
	 uint32_t dyy = max_dy;
	 double pp = max_p;
#if DEBUG_ADP_TEA_F_FK
	 printf("[%s:%d] dy[%d:0] = %8X\n", __FILE__, __LINE__, (nlsb_init - 1), j);
#endif  // DEBUG_ADP_TEA_F_FK
	 for(uint32_t l = 0; l < N; l++) {
		x = l;							  // assign x[9:0]
		uint32_t i = nlsb_init - 1; // start at x[9]
		uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); 
		adp_f_assign_bit_x_dy(n, i, mask_i, x, lsh_const, rsh_const, k0, k1, delta, dx, dy, x_cnt, &pp, &dyy);
#if DEBUG_ADP_TEA_F_FK
		printf("[%s:%d] %8X -> %8X %f 2^%f | max_p = %f\n", __FILE__, __LINE__, dyy, dy, pp, log2(pp), max_p);
#endif  // DEBUG_ADP_TEA_F_FK
	 }
	 if((pp >= max_p) && (pp != 1.0)) { // skip the zero difference (p == 1.0)
#if DEBUG_ADP_TEA_F_FK
		if(max_dy != dyy) {
		  printf("[%s:%d] Update max dy[%d:0] = %8X | %8X -> %8X %f 2^%f\n", __FILE__, __LINE__, (nlsb_init - 1), j, dyy, dy, pp, log2(pp));
		}
#endif  // DEBUG_ADP_TEA_F_FK
		max_p = pp;
		max_dy = dyy;
	 }
  }
  *ret_dy = max_dy;
  return max_p;
}

/**
 * For the TEA F-functuion with fixed key and round constant, 
 * compute all differentials \f$(dx \rightarrow dy)\f$ and their probabilities.
 *
 * The function works by recursively assigning the bits of \p x, \p dx and \p dy starting 
 * at bit position \p i and terminating at the MS bit \p n.
 * The recursion proceeds to bit \f$(i+1)\f$ only if the differential is satisfied
 * on the \p i LS bits. This is checked by applying \ref adp_f_is_sat. 
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
 * \param x_cnt array of \f$2^{2n}\f$ differentials \f$(dx \rightarrow dy)\f$ 
 *        and their probabilities. 
 * \param ret_prob the maximum probability over all input and output differences 
 *        \f$\mathrm{max}_{dy,dy} ~\mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \param ret_dx the input difference of the maximum probability differential.
 * \param ret_dy the output difference of the maximum probability differential.
 * \returns \p 1 if \f$x[i-1:0]\f$ satisfies \f$(dx[i-1:0] \rightarrow dy[i-1:0])\f$; \p 0 otherwise.
 *
 * \see adp_f_assign_bit_x_dx, adp_f_assign_bit_x_dy.
 */
uint32_t adp_f_assign_bit_x_dx_dy(const uint32_t n, const uint32_t i, const uint32_t mask_i, const uint32_t x, 
											 const uint32_t lsh_const, const uint32_t rsh_const,
											 const uint32_t k0, const uint32_t k1, const uint32_t delta,
											 const uint32_t dx, const uint32_t dy, differential_t* x_cnt, 
											 double* ret_prob, uint32_t* ret_dx, uint32_t* ret_dy)
{
  assert(n <= WORD_SIZE);
  assert(n >= (rsh_const * 2));
  assert(i <= (n + rsh_const));
  if((i == WORD_SIZE) && (dx == 0)) {
	 double p = 0.0;
	 uint64_t rp = 0;
	 uint64_t dxdy = ((uint64_t)dx << WORD_SIZE) | dy;
	 assert(dxdy < (ALL_WORDS * ALL_WORDS));
	 if(dy == 0) {
		p = 1.0;
		rp = ALL_WORDS;
	 } else {
		p = 0.0;
		rp = 0;
	 }
	 x_cnt[dxdy].p = p;
	 x_cnt[dxdy].npairs = rp;
	 x_cnt[dxdy].dx = dx;
	 x_cnt[dxdy].dy = dy;
	 if(p >= *ret_prob) {
		*ret_prob = p;
		*ret_dx = dx;
		*ret_dy = dy;
	 }
	 return 0;
  } else {
	 if(i == (n + rsh_const)) {
#if DEBUG_ADP_TEA_F_FK
		double p = *ret_prob;
		printf("[%s:%d] %2d: # %8llX: %8X -> %8X | x = %8X  %f 2^%f\n", __FILE__, __LINE__, n, *x_cnt, dx, dy, x, p, log2(p));
#endif  // DEBUG_ADP_TEA_F_FK
		assert(dx < MOD);
		assert(dy < MOD);
		if(n == (WORD_SIZE)) {
		  bool b_ok = adp_f_check_x(lsh_const, rsh_const, k0, k1, delta, dx, dy, x);
		  assert(b_ok);
		}
		return 1;
	 }
  }
  bool b_adp_f_is_sat = adp_f_is_sat(mask_i, lsh_const, rsh_const, k0, k1, delta, dx, dy, x); // check x[i]
  if(b_adp_f_is_sat) {
	 if(i < (WORD_SIZE - 1)) { // x[30:0] are assigned and we shall assign the last bit x[31]
		uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); // select x[(i+1)-R:0]
		for(uint32_t next_bit_dx = 0; next_bit_dx < 2; next_bit_dx++) {
		  uint32_t new_dx = (next_bit_dx << (i + 1)) | dx; // assign dx[i+1]
		  for(uint32_t next_bit_dy = 0; next_bit_dy < 2; next_bit_dy++) {
			 uint32_t new_dy = (next_bit_dy << (i + 1)) | dy; // assign dy[i+1]
			 for(uint32_t next_bit_x = 0; next_bit_x < 2; next_bit_x++) {
				uint32_t new_x = (next_bit_x << (i + 1)) | x; // assign x[i+1]
				uint32_t ret = 
				  adp_f_assign_bit_x_dx_dy(n, i + 1, mask_i, new_x, lsh_const, rsh_const, k0, k1, delta, new_dx, new_dy, x_cnt, ret_prob, ret_dx, ret_dy);
				//				x_cnt[new_dx][new_dy] += ret;
				uint64_t new_dxdy = ((uint64_t)new_dx << WORD_SIZE) | new_dy;
				assert(new_dxdy < (ALL_WORDS * ALL_WORDS));
				//				x_cnt[new_dxdy] += ret;
				x_cnt[new_dxdy].npairs += ret;
				x_cnt[new_dxdy].dx = new_dx;
				x_cnt[new_dxdy].dy = new_dy;
				x_cnt[new_dxdy].p = (double)x_cnt[new_dxdy].npairs / (double)ALL_WORDS;
			 }
		  }
		}
	 } else {
		uint32_t mask_i = MASK;
		uint32_t new_dx = dx;
		uint32_t new_dy = dy;
		uint32_t new_x = x;
		uint32_t ret =  
		  adp_f_assign_bit_x_dx_dy(n, i + 1, mask_i, new_x, lsh_const, rsh_const, k0, k1, delta, new_dx, new_dy, x_cnt, ret_prob, ret_dx, ret_dy);
		//		x_cnt[new_dx][new_dy] += ret;
		uint64_t new_dxdy = ((uint64_t)new_dx << WORD_SIZE) | new_dy;
		assert(new_dxdy < (ALL_WORDS * ALL_WORDS));
		//x_cnt[new_dxdy] += ret;
		x_cnt[new_dxdy].npairs += ret;
		x_cnt[new_dxdy].dx = new_dx;
		x_cnt[new_dxdy].dy = new_dy;
		x_cnt[new_dxdy].p = (double)x_cnt[new_dxdy].npairs / (double)ALL_WORDS;
		if((i + 1) == (n + rsh_const)) {
		  //		  double p = (double)x_cnt[new_dx][new_dy] / (double)ALL_WORDS;
		  double p = (double)x_cnt[new_dxdy].npairs / (double)ALL_WORDS;
		  if(p >= *ret_prob) {
			 *ret_prob = p;
			 *ret_dx = dx;
			 *ret_dy = dy;
		  }
		}
	 }
  } 
  return 0;
}

/**
 * For the TEA F-functuion with fixed key and round constant, 
 * compute the maximum probability differential \f$(dx \rightarrow dy)\f$
 * over all input and output differences.
 * \b Complexity: \f$ O(3n) < c \le O(2^{3n}) \f$. \b Memory: \f$12 \cdot 2^{2n}\f$ Bytes.
 * 
 * \param n word size.
 * \param ret_dx the input difference of the maximum probability differential.
 * \param ret_dy the output difference of the maximum probability differential.
 * \param k0 first round key.
 * \param k1 second round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{max}_{dx,dy} ~\mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \see adp_f_assign_bit_x_dx_dy
 *        
 */
double max_dx_dy_adp_f_fk(const uint32_t n, uint32_t* ret_dx, uint32_t* ret_dy, 
								  const uint32_t k0, const uint32_t k1, const uint32_t delta,
								  const uint32_t lsh_const, const uint32_t rsh_const)
{
#if DEBUG_ADP_TEA_F_FK
  printf("[%s:%d] %s() Input: %d %d %8X %8X %8X \n", __FILE__, __LINE__, __FUNCTION__, 
			lsh_const, rsh_const, k0, k1, delta);
#endif  // DEBUG_ADP_TEA_F_FK
  assert(lsh_const < rsh_const);
  assert(n <= WORD_SIZE);
  assert(n >= (rsh_const * 2));
  // number of initial LSB bits
  uint32_t nlsb_init = (rsh_const * 2);
  if(nlsb_init > WORD_SIZE)
	 nlsb_init = WORD_SIZE;
  // all 10-bit values
  uint32_t N = (1U << nlsb_init);
  uint32_t x = 0;
  uint32_t dx = 0;
  uint32_t dy = 0;
  uint32_t max_dx = 0;
  uint32_t max_dy = 0;
  double max_p = 0.0;

  //  uint32_t* x_cnt = (uint32_t *)calloc((ALL_WORDS * ALL_WORDS), sizeof(uint32_t));
  differential_t* x_cnt = (differential_t *)calloc((size_t)(ALL_WORDS * ALL_WORDS), sizeof(differential_t));

  if(x_cnt == NULL) {
	 printf("[%s:%d] ERROR: Bad calloc. Not enough memory. Exiting...\n", __FILE__, __LINE__);
	 exit(1);
  }

  assert(N < ALL_WORDS);

  //  const uint32_t n = WORD_SIZE; 
  for(uint32_t i_dy = 0; i_dy < N; i_dy++) {
	 dy = i_dy;
	 uint32_t dyy = max_dy;

	 for(uint32_t i_dx = 0; i_dx < N; i_dx++) { // skip the zero difference
		dx = i_dx;
		uint32_t dxx = max_dx;

		double pp = max_p;
#if DEBUG_ADP_TEA_F_FK
		printf("\r[%s:%d] dx[%d:0] = %8X ", __FILE__, __LINE__, (nlsb_init - 1), j);
		fflush(stdout);
#endif  // DEBUG_ADP_TEA_F_FK
		for(uint32_t l = 0; l < N; l++) {
		  x = l;							  // assign x[9:0]
		  uint32_t i = nlsb_init - 1; // start at x[9]
		  uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); 
		  adp_f_assign_bit_x_dx_dy(n, i, mask_i, x, lsh_const, rsh_const, k0, k1, delta, dx, dy, x_cnt, &pp, &dxx, &dyy);
		}
		if((pp >= max_p) && (pp != 1.0)) { // skip the zero difference (p == 1.0)
#if DEBUG_ADP_TEA_F_FK
		  if((max_dx != dxx) && ((max_dy != dyy))) {
			 printf("[%s:%d] Update max %8X -> %8X %f 2^%f\n", __FILE__, __LINE__, dxx, dyy, pp, log2(pp));
		  }
#endif  // DEBUG_ADP_TEA_F_FK
		  max_p = pp;
		  max_dx = dxx;
		  max_dy = dyy;
#if DEBUG_ADP_TEA_F_FK
		  printf("[%s:%d] Update max %8X -> %8X %f 2^%f\n", __FILE__, __LINE__, max_dx, max_dy, max_p, log2(max_p));
#endif  // DEBUG_ADP_TEA_F_FKx
		}
	 }
  }
  // print all differences
#if DEBUG_ADP_TEA_F_FK
  std::sort(x_cnt, x_cnt + (ALL_WORDS * ALL_WORDS), comp_diff_p);
  uint32_t cnt_zero = 0;
  for(uint32_t i = 0; i < (ALL_WORDS * ALL_WORDS); i++) {
	 uint32_t dx = x_cnt[i].dx;
	 uint32_t dy = x_cnt[i].dy;
	 uint32_t rp = x_cnt[i].npairs;
	 double p = x_cnt[i].p;
	 if(rp == 0) {
		assert(p == 0.0);
		cnt_zero++;n
	 }
	 printf("[%s:%d] %5d: %8X %8X %d %f\n", __FILE__, __LINE__, i, dx, dy, rp, p);
  }
  printf("[%s:%d] cnt_zero = %d / %lld\n", __FILE__, __LINE__, cnt_zero, (ALL_WORDS * ALL_WORDS));
#endif  // DEBUG_ADP_TEA_F_FK

  free(x_cnt);
  *ret_dx = max_dx;
  *ret_dy = max_dy;
  return max_p;
}

/**
 * Allocate memory for a 2D array of differentials.
 * \returns 2D array of differentials.
 * \see x_cnt_free
 */
uint64_t*** x_cnt_alloc()
{
  uint64_t*** x_cnt = (uint64_t ***)calloc((size_t)ALL_WORDS, sizeof(uint64_t **));
  for(uint64_t k0 = 0; k0 < ALL_WORDS; k0++) {
	 x_cnt[k0] = (uint64_t **)calloc((size_t)ALL_WORDS, sizeof(uint64_t *));
	 for(uint64_t k1 = 0; k1 < ALL_WORDS; k1++) {
		x_cnt[k0][k1] = (uint64_t *)calloc((size_t)ALL_WORDS, sizeof(uint64_t));
	 }
  }
  return x_cnt;
}

/**
 * Free the memory allocated from a previous call to \ref x_cnt_alloc
 * \param x_cnt 2D array of differentials.
 * \see x_cnt_alloc
 */
void x_cnt_free(uint64_t*** x_cnt)
{
  for(uint32_t k0 = 0; k0 < ALL_WORDS; k0++) {
	 for(uint32_t k1 = 0; k1 < ALL_WORDS; k1++) {
		free(x_cnt[k0][k1]);
	 }
	 free(x_cnt[k0]);
  }
  free(x_cnt);
}

/**
 * Print the elements of a 2D array of differentials.
 * \param x_cnt 2D array of differentials.
 */
void x_cnt_print(uint32_t*** x_cnt)
{
  for(uint32_t k0 = 0; k0 < ALL_WORDS; k0++) {
	 for(uint32_t k1 = 0; k1 < ALL_WORDS; k1++) {
		for(uint32_t dx = 0; dx < ALL_WORDS; dx++) {
		  uint32_t npairs = x_cnt[k0][k1][dx];
		  double p = (double)npairs / (double)ALL_WORDS;
		  printf("[%s:%d] %8X %8X %8X %10d %f 2^%f\n", __FILE__, __LINE__, k0, k1, dx, npairs, p, log2(p));
		}
	 }
  }
}

/**
 * For the TEA F-function with fixed round constant, and for a fixed output difference \p dy, 
 * compute all differentials \f$(dx \rightarrow dy)\f$ and their probabilities
 * for all values of the round keys \p k0, \p k1.
 *
 * The function works by recursively assigning the bits of \p x, \p dx, \p k0 and \p k1 starting 
 * at bit position \p i and terminating at the MS bit \p n.
 * The recursion proceeds to bit \f$(i+1)\f$ only if the differential is satisfied
 * on the \p i LS bits. This is checked by applying \ref adp_f_is_sat. 
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
 * \param x_cnt array of \f$2^{3n}\f$ differentials \f$(dx \rightarrow dy)\f$ 
 *        and their probabilities. 
 * \param ret_prob the maximum probability over all input differences and round keys 
 *        \f$\mathrm{max}_{dx,k_0,k_1} ~\mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \param ret_dx the input difference of the maximum probability differential.
 * \param ret_k0 the first round key for the maximum probability differential.
 * \param ret_k1 the second round key for the maximum probability differential.
 * \returns \p 1 if \f$x[i-1:0]\f$ satisfies \f$(dx[i-1:0] \rightarrow dy[i-1:0])\f$; \p 0 otherwise.
 *
 * \see adp_f_assign_bit_x_dx_key,  adp_f_assign_bit_x_dx_dy.
 */
uint32_t adp_f_assign_bit_x_dx_key(const uint32_t n, const uint32_t i, const uint32_t mask_i, const uint32_t x, 
											  const uint32_t lsh_const, const uint32_t rsh_const,
											  const uint32_t k0, const uint32_t k1, const uint32_t delta,
											  const uint32_t dx, const uint32_t dy, uint64_t*** x_cnt, 
											  double* ret_prob, uint32_t* ret_dx, uint32_t* ret_k0, uint32_t* ret_k1)
{
  assert(n <= WORD_SIZE);
  assert(n >= (rsh_const * 2));
  assert(i <= (n + rsh_const));
  if((i == WORD_SIZE) && (dx == 0)) {
	 if(dy == 0) {
		x_cnt[k0][k1][dx] = ALL_WORDS;
		*ret_prob = 1.0;
	 } else {
		x_cnt[k0][k1][dx] = 0;
		*ret_prob = 0.0;
	 }
	 return 0;
  } else {
	 if(i == (n + rsh_const)) {
		assert(dx < MOD);
		if(n == (WORD_SIZE)) {
		  bool b_ok = adp_f_check_x(lsh_const, rsh_const, k0, k1, delta, dx, dy, x);
		  assert(b_ok);
		}
		return 1;
	 }
  }
  bool b_adp_f_is_sat = adp_f_is_sat(mask_i, lsh_const, rsh_const, k0, k1, delta, dx, dy, x); // check x[i]
  if(b_adp_f_is_sat) {
	 if(i < (WORD_SIZE - 1)) { // x[30:0] are assigned and we shall assign the last bit x[31]
		uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); // select x[(i+1)-R:0]

		for(uint32_t next_bit_k0 = 0; next_bit_k0 < 2; next_bit_k0++) {
		  uint32_t new_k0 = (next_bit_k0 << (i + 1)) | k0; // assign k0[i+1]

		  for(uint32_t next_bit_k1 = 0; next_bit_k1 < 2; next_bit_k1++) {
			 uint32_t new_k1 = (next_bit_k1 << (i + 1)) | k1; // assign k1[i+1]

			 for(uint32_t next_bit_dx = 0; next_bit_dx < 2; next_bit_dx++) {
				uint32_t new_dx = (next_bit_dx << (i + 1)) | dx; // assign dx[i+1]

				for(uint32_t next_bit_x = 0; next_bit_x < 2; next_bit_x++) {
				  uint32_t new_x = (next_bit_x << (i + 1)) | x; // assign x[i+1]

				  uint32_t ret = 
					 adp_f_assign_bit_x_dx_key(n, i + 1, mask_i, new_x, lsh_const, rsh_const, new_k0, new_k1, delta, new_dx, dy, x_cnt, ret_prob, ret_dx, ret_k0, ret_k1);
				  x_cnt[new_k0][new_k1][new_dx] += ret;
				}
			 }
		  }
		}
	 } else {
		uint32_t mask_i = MASK;
		uint32_t new_k0 = k0;
		uint32_t new_k1 = k1;
		uint32_t new_dx = dx;
		uint32_t new_x = x;

		uint32_t ret =  
		  adp_f_assign_bit_x_dx_key(n, i + 1, mask_i, new_x, lsh_const, rsh_const, new_k0, new_k1, delta, new_dx, dy, x_cnt, ret_prob, ret_dx, ret_k0, ret_k1);

		x_cnt[new_k0][new_k1][new_dx] += ret;
		if((i + 1) == (n + rsh_const)) {
		  double p = (double)x_cnt[new_k0][new_k1][new_dx] / (double)ALL_WORDS;
		  if(p > *ret_prob) {
			 *ret_prob = p;
			 *ret_dx = new_dx;
			 *ret_k0 = new_k0;
			 *ret_k1 = new_k1;
#if DEBUG_ADP_TEA_F_FK
			 printf("\r[%s:%d] max %8X %8X %8X -> %8X %f 2^%f", __FILE__, __LINE__, *ret_k0, *ret_k1, *ret_dx, dy, *ret_prob, log2(*ret_prob));
			 fflush(stdout);
#endif  // DEBUG_ADP_TEA_F_FK
		  }
		}
	 }
  } 
  return 0;
}

/**
 * For the TEA F-functuion with fixed key and round constant, 
 * compute the maximum probability differential \f$(dx \rightarrow dy)\f$
 * over all input differences and round keys.
 * \b Complexity: \f$ O(4n) < c \le O(2^{4n}) \f$. \b Memory: \f$12 \cdot 2^{3n}\f$ Bytes.
 * 
 * \param n word size.
 * \param dy output difference.
 * \param ret_dx the input difference of the maximum probability differential.
 * \param ret_k0 the first round key for the maximum probability differential.
 * \param ret_k1 the second round key for the maximum probability differential.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{max}_{dx,k_0,k_1} ~\mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \see adp_f_assign_bit_x_dx_key
 *        
 */
double max_key_dx_adp_f_fk(const uint32_t n, uint32_t* ret_dx, const uint32_t dy, 
									uint32_t* ret_k0, uint32_t* ret_k1, const uint32_t delta,
									const uint32_t lsh_const, const uint32_t rsh_const)
{
#if DEBUG_ADP_TEA_F_FK
  printf("[%s:%d] %s() Input: %d %d %8X %8X %8X \n", __FILE__, __LINE__, __FUNCTION__, 
			lsh_const, rsh_const, k0, k1, delta);
#endif  // DEBUG_ADP_TEA_F_FK
  assert(lsh_const < rsh_const);
  assert(n <= WORD_SIZE);
  assert(n >= (rsh_const * 2));
  // number of initial LSB bits
  uint32_t nlsb_init = (rsh_const * 2);
  if(nlsb_init > WORD_SIZE)
	 nlsb_init = WORD_SIZE;
  // all 10-bit values
  uint32_t N = (1U << nlsb_init);
  uint32_t x = 0;

  uint32_t dx = 0;
  uint32_t k0 = 0;
  uint32_t k1 = 0;

  uint32_t max_dx = 0;
  uint32_t max_k0 = 0;
  uint32_t max_k1 = 0;

  double max_p = 0.0;

  uint64_t*** x_cnt = x_cnt_alloc();

  for(uint32_t i_k0 = 0; i_k0 < N; i_k0++) {
	 k0 = i_k0;
	 uint32_t kk0 = max_k0;
	 for(uint32_t i_k1 = 0; i_k1 < N; i_k1++) {
		k1 = i_k1;
		uint32_t kk1 = max_k1;
		for(uint32_t i_dx = 0; i_dx < N; i_dx++) {
		  dx = i_dx;
		  uint32_t dxx = max_dx;

		  double pp = max_p;
		  for(uint32_t i_x = 0; i_x < N; i_x++) {
			 x = i_x;
			 uint32_t i = nlsb_init - 1; 
			 uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); 
			 adp_f_assign_bit_x_dx_key(n, i, mask_i, x, lsh_const, rsh_const, k0, k1, delta, dx, dy, x_cnt, &pp, &dxx, &kk0, &kk1);
		  }
		  if((pp > max_p) && (pp != 1.0)) { // skip the zero difference (p == 1.0)
			 max_p = pp;
			 max_dx = dxx;
			 max_k0 = kk0;
			 max_k1 = kk1;
#if DEBUG_ADP_TEA_F_FK
			 printf("\n[%s:%d] Update max %8X %8X %8X -> %8X %f 2^%f\n", __FILE__, __LINE__, max_k0, max_k1, max_dx, dy, max_p, log2(max_p));
#endif  // DEBUG_ADP_TEA_F_FK
		  }
		}
	 }
  }
  //  x_cnt_print(x_cnt);
  //  std::vector<finputs_t> x_cnt_vec;
  //  x_cnt_sort(x_cnt, &x_cnt_vec);
  //  x_cnt_vec_print(x_cnt_vec);

  x_cnt_free(x_cnt);
  *ret_dx = max_dx;
  *ret_k0 = max_k0;
  *ret_k1 = max_k1;
  return max_p;
}

/**
 * Compute the fixed-key, fixed-constant ADD differential probability of
 * the F-function of block cipher TEA: 
 * \f$\mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 *
 * The function works by dividing the input to F into independent parts
 * and iterating over the values in each part. The resulting complexity is 
 * equivalent to exhaustive search over all inputs: \f$O(2^n)\f$.
 *
 * \param da input difference.
 * \param dd output difference.
 * \param k0 first round key.
 * \param k1 second round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \see adp_f_fk
 */
double adp_f_fk_v2(const uint32_t da, const uint32_t dd, 
						 const uint32_t k0, const uint32_t k1, const uint32_t delta,
						 const uint32_t lsh_const, const uint32_t rsh_const)
{
  uint32_t cnt = 0;

  //  assert(k0 == 0);
  //  assert(k1 == 0);
  //  assert(delta == 0);

  // da = da_L | da_M | da_R
  uint32_t da_LM = da >> rsh_const;
  uint32_t da_R = da & ~(0xffffffff << rsh_const);

  uint32_t LEFT_LEN = lsh_const;
  uint32_t RIGHT_LEN = rsh_const;
  uint32_t MID_LEN = (WORD_SIZE - LEFT_LEN - RIGHT_LEN);

  uint32_t LEFT_WORDS = (1ULL << LEFT_LEN);
  uint32_t RIGHT_WORDS = (1ULL << RIGHT_LEN);
  uint32_t MID_WORDS = (1ULL << MID_LEN);

  if((LEFT_WORDS * MID_WORDS * RIGHT_WORDS) != ALL_WORDS) {
	 printf("%d %d %d %d %d %lld\n", lsh_const, rsh_const, LEFT_WORDS, RIGHT_WORDS, MID_WORDS, ALL_WORDS);
  }
  assert((LEFT_WORDS * MID_WORDS * RIGHT_WORDS) == ALL_WORDS);

  for(uint32_t a1_L = 0; a1_L < LEFT_WORDS; a1_L++) {
	 for(uint32_t a1_M = 0; a1_M < MID_WORDS; a1_M++) {
		for(uint32_t a1_R = 0; a1_R < RIGHT_WORDS; a1_R++) {

		  // --- differences ---

		  // db
		  uint32_t db = LSH(da, lsh_const);

		  // a1 = a1_LM | a1_R
		  uint32_t a1_LM = (a1_L << MID_LEN) | a1_M;

		  uint32_t carry_LM = 0;
		  uint32_t carry_R = 0;

		  if((a1_R + da_R) < RIGHT_WORDS) {
			 carry_R = 0;
		  } else {
			 carry_R = 1;
		  }

		  if((a1_LM + da_LM + carry_R) < (LEFT_WORDS * MID_WORDS)) {
			 carry_LM = 0;
		  } else {
			 carry_LM = (1ULL << (LEFT_LEN + MID_LEN)); // (LEFT_WORDS * MID_WORDS)
		  }

		  // dc
		  uint32_t dc = da_LM + carry_R - carry_LM;

		  // --- pairs ---

		  // a1 = a1_L | a1_M | a1_R
		  uint32_t a1 = (a1_L << (MID_LEN + RIGHT_LEN)) | (a1_M << RIGHT_LEN) | a1_R;
		  uint32_t a2 = ADD(a1, da);

		  // b1 = a1_M | a1_R | 0*
		  uint32_t b1 = (a1_M << (RIGHT_LEN + LEFT_LEN)) | (a1_R << LEFT_LEN);
		  uint32_t b2 = ADD(b1, db);

		  // c1 = 0* | a1_L | a1_M 
		  uint32_t c1 = a1_LM;	  // (a1_L << MID_LEN) | a1_M
		  uint32_t c2 = ADD(c1, dc);

		  // add keys and constants
		  a1 = ADD(a1, delta);
		  a2 = ADD(a2, delta);

		  b1 = ADD(b1, k0);
		  b2 = ADD(b2, k0);

		  c1 = ADD(c1, k1);
		  c2 = ADD(c2, k1);

		  uint32_t d1 = a1 ^ b1 ^ c1;
		  uint32_t d2 = a2 ^ b2 ^ c2;
		  uint32_t dx = SUB(d2, d1);
		  assert((dx >= 0) && (dx < MOD));
		  if(dx == dd) {
			 cnt++;
		  }

		}
	 }
  }
  double p = (double)cnt / (double)ALL_WORDS;
  return p;
}

/**
 * Compute the S-function for the TEA F function.
 *
 * \param n word size.
 * \param x_word input to F.
 * \param dx_word input difference.
 * \param delta_word round constant.
 * \param k0_word first round key.
 * \param k1_word second round key.
 *
 */ 
void f_sfun(const uint32_t n, 
				const uint32_t x_word, const uint32_t dx_word, const uint32_t delta_word, 
				const uint32_t k0_word, const uint32_t k1_word)
{
  assert(n <= WORD_SIZE);
  uint32_t mask5 = ~(0xffffffff << 5);
  uint32_t r = (((dx_word & mask5) + (x_word & mask5)) >> 5) & 1;

  uint32_t s_b  = 0;				  // s_b[0]
  uint32_t s_a  = 0;				  // s_a[0]
  uint32_t s_c  = 0;				  // s_c[0]

  uint32_t s_bb = 0;				  // s_bb[0]
  uint32_t s_aa = 0;				  // s_aa[0]
  uint32_t s_cc = r;				  // s_cc[0]

  uint32_t S_A[WORD_SIZE + 1] = {0};
  uint32_t S_B[WORD_SIZE + 1] = {0};
  uint32_t S_C[WORD_SIZE + 1] = {0};

  uint32_t S_AA[WORD_SIZE + 1] = {0};
  uint32_t S_BB[WORD_SIZE + 1] = {0};
  uint32_t S_CC[WORD_SIZE + 1] = {0};

  S_A[0] = s_a;
  S_B[0] = s_b;
  S_C[0] = s_c;

  S_AA[0] = s_aa;
  S_BB[0] = s_bb;
  S_CC[0] = s_cc;

  printf("\n");

  for(uint32_t i = 0; i < n; i++) {

	 // b[i]
	 uint32_t x_lsh4 = 0;
	 if(i >= 4) {
		x_lsh4 = (x_word >> (i - 4)) & 1; // x[i-4]
	 }
	 uint32_t k0 = (k0_word >> i) & 1; // k0[i]
	 uint32_t b = x_lsh4 ^ k0 ^ s_b; 
	 s_b = ((x_lsh4 + k0 + s_b) >> 1) & 1; // s_b[i+1]
	 // a[i]
	 uint32_t x = (x_word >> i) & 1; // x[i]
	 uint32_t d = (delta_word >> i) & 1; // delta[i]
	 uint32_t a = x ^ d ^ s_a;
	 s_a = ((x + d + s_a) >> 1) & 1; // s_a[i+1]
	 // c[i]
	 uint32_t x_rsh5 = 0;
	 if(i <= 26) {
		x_rsh5 = (x_word >> (i + 5)) & 1;	  // x[i + 5]
	 }
	 uint32_t k1 = (k1_word >> i) & 1; // k1[i]
	 uint32_t c = x_rsh5 ^ k1 ^ s_c;
	 s_c = ((x_rsh5 + k1 + s_c) >> 1) & 1; // s_c[i+1]
	 // bb[i]
	 uint32_t dx_lsh4 = 0;
	 if(i >= 4) {
		dx_lsh4 = (dx_word >> (i - 4)) & 1; // dx[i-4]
	 }
	 uint32_t bb = b ^ dx_lsh4 ^ s_bb;
	 s_bb = ((b + dx_lsh4 + s_bb) >> 1) & 1; // s_bb[i+1]
	 // aa[i]
	 uint32_t dx = (dx_word >> i) & 1; // dx[i]
	 uint32_t aa = a ^ dx ^ s_aa;
	 s_aa = ((a + dx + s_aa) >> 1) & 1; // s_aa[i+1]
	 // cc[i]
	 uint32_t dx_rsh5 = 0;
	 if(i <= 26) {
		dx_rsh5 = (dx_word >> (i + 5)) & 1;	  // x[i + 5]
	 }
	 uint32_t cc = c ^ dx_rsh5 ^ s_cc;
	 s_cc = ((c + dx_rsh5 + s_cc) >> 1) & 1; // s_cc[i+1]

	 uint32_t y1 = a ^ b ^ c;
	 uint32_t y2 = aa ^ bb ^ cc;

	 assert(y1 == y2);

	 S_A[i+1] = s_a;
	 S_B[i+1] = s_b;
	 S_C[i+1] = s_c;

	 S_AA[i+1] = s_aa;
	 S_BB[i+1] = s_bb;
	 S_CC[i+1] = s_cc;

	 printf("   b[%2d] %d = %d ^ %d* ^ %d\n", i, b, x_lsh4, k0, S_B[i]);
	 printf("   a[%2d] %d = %d ^ %d  ^ %d\n", i, a, x, d, S_A[i]);
	 printf("   c[%2d] %d = %d ^ %d* ^ %d\n", i, c, x_rsh5, k1, S_C[i]);
	 printf(" s_b[%2d] %d\n", i+1, s_b);
	 printf(" s_a[%2d] %d\n", i+1, s_a);
	 printf(" s_c[%2d] %d\n", i+1, s_c);
	 printf("\n");
	 printf("  bb[%2d] %d = %d ^ %d  ^ %d\n", i, bb, b, dx_lsh4, S_BB[i]);
	 printf("  aa[%2d] %d = %d ^ %d  ^ %d\n", i, aa, a, dx, S_AA[i]);
	 printf("  cc[%2d] %d = %d ^ %d  ^ %d\n", i, cc, c, dx_rsh5, S_CC[i]);
	 printf("s_bb[%2d] %d\n", i+1, s_bb);
	 printf("s_aa[%2d] %d\n", i+1, s_aa);
	 printf("s_cc[%2d] %d\n", i+1, s_cc);
	 printf("------------------\n");
	 if(i > 8) {
		assert(s_bb == 0);
		assert(s_aa == 0);
		assert(s_cc == 0);
	 }
  }
}

/**
 * Compute the fixed-key, fixed-constant ADD differential probability of
 * the F-function of block cipher TEA: 
 * \f$\mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$
 * through exhaustive search over all input values. \b Complexity: \f$O(2^n)\f$.
 *
 * \param da input difference.
 * \param db output difference.
 * \param k0 first round key.
 * \param k1 second round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \see adp_f_fk, adp_f_fk_v2.
 */
double adp_f_fk_exper(const uint32_t da, const uint32_t db, 
							 const uint32_t k0, const uint32_t k1, const uint32_t delta,
							 uint32_t lsh_const, uint32_t rsh_const)
{
  uint64_t N = ALL_WORDS;// * ALL_WORDS * ALL_WORDS * ALL_WORDS;
  uint32_t cnt = 0;

  for(uint32_t a1 = 0; a1 < ALL_WORDS; a1++) {

	 uint32_t a2 = ADD(a1, da);

	 uint32_t b1 = tea_f(a1, k0, k1, delta, lsh_const, rsh_const);
	 uint32_t b2 = tea_f(a2, k0, k1, delta, lsh_const, rsh_const);

	 uint32_t dx = SUB(b2, b1);
	 if(dx == db) {
#if DEBUG_ADP_TEA_F_FK
		printf("[%s:%d] %4d: a = %8X\n", __FILE__, __LINE__, cnt, a1);
#endif  // DEBUG_ADP_TEA_F_FK
		cnt++;
	 } 
  }
  double p = (double)cnt / (double)N;
  return p;
}

/**
 * For given output difference \p dy, compute the maximum probability 
 * input differences \p dx over all input differences: 
 * \f$\mathrm{max}_{dx} ~\mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$
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
 * \returns \f$\mathrm{max}_{dx} ~\mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \see max_dx_adp_f_fk
 */
double max_dx_adp_f_fk_exper(uint32_t* max_dx, const uint32_t dy, 
									  const uint32_t k0, const uint32_t k1, const uint32_t delta,
									  uint32_t lsh_const, uint32_t rsh_const)
{
  double max_p = 0.0;
  for(uint32_t dx = 0; dx < ALL_WORDS; dx++) {
	 double p = adp_f_fk_exper(dx, dy, k0, k1, delta, lsh_const, rsh_const);
	 //	 printf("[%s:%d] p(%8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, dx, dy, p, log2(p));
	 if((p > max_p) && (p != 1.0)) {
		max_p = p;
		*max_dx = dx;
	 }
  }
  return max_p;
}

/**
 * For given input difference \p dx, compute the maximum probability 
 * output difference \p dy over all output differences: 
 * \f$\mathrm{max}_{dy} ~\mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$
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
 * \returns \f$\mathrm{max}_{dx} ~\mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \see max_dy_adp_f_fk
 */
double max_dy_adp_f_fk_exper(const uint32_t dx, uint32_t* max_dy, 
									  const uint32_t k0, const uint32_t k1, const uint32_t delta,
									  uint32_t lsh_const, uint32_t rsh_const)
{
  double max_p = 0.0;
  if(dx == 0) {						  // zero input difference
	 *max_dy = 0;
	 return 1.0;
  }
  for(uint32_t dy = 0; dy < ALL_WORDS; dy++) {
	 double p = adp_f_fk_exper(dx, dy, k0, k1, delta, lsh_const, rsh_const);
#if DEBUG_ADP_TEA_F_FK
	 printf("[%s:%d] p(%8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, dx, dy, p, log2(p));
#endif  // DEBUG_ADP_TEA_F_FK
	 if((p > max_p) && (p != 1.0)) {
#if DEBUG_ADP_TEA_F_FK
		printf("[%s:%d] Update max %f(%8X) -> %f(%8X)\n", __FILE__, __LINE__, max_p, *max_dx, p, dx);
#endif  // DEBUG_ADP_TEA_F_FK
		max_p = p;
		*max_dy = dy;
	 }
  }
  return max_p;
}

/**
 * For the TEA F-functuion with fixed key and round constant, 
 * compute the maximum probability differential \f$(dx \rightarrow dy)\f$
 * over all input and output differences.
 * \b Complexity: \f$O(2^{3n})\f$.
 * 
 * \param max_dx the input difference of the maximum probability differential.
 * \param max_dy the output difference of the maximum probability differential.
 * \param k0 first round key.
 * \param k1 second round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{max}_{dx,dy} ~\mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \see max_dx_dy_adp_f_fk
 *        
 */
double max_dx_dy_adp_f_fk_exper(uint32_t* max_dx, uint32_t* max_dy, 
										  const uint32_t k0, const uint32_t k1, const uint32_t delta,
										  uint32_t lsh_const, uint32_t rsh_const)
{
  double max_p = 0.0;
  for(uint32_t dx = 0; dx < ALL_WORDS; dx++) {
	 for(uint32_t dy = 0; dy < ALL_WORDS; dy++) {
		double p = adp_f_fk_exper(dx, dy, k0, k1, delta, lsh_const, rsh_const);
#if DEBUG_ADP_TEA_F_FK
		printf("[%s:%d] p(%8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, dx, dy, p, log2(p));
#endif  // DEBUG_ADP_TEA_F_FK
		if((p > max_p) && (p != 1.0)) {
#if DEBUG_ADP_TEA_F_FK
		  printf("[%s:%d] Update max %f(%8X) -> %f(%8X)\n", __FILE__, __LINE__, max_p, *max_dx, p, dx);
#endif  // DEBUG_ADP_TEA_F_FK
		  max_p = p;
		  *max_dx = dx;
		  *max_dy = dy;
		}
	 }
  }
  return max_p;
}
