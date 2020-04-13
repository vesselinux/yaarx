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
 * \file  adp-xtea-f-fk.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \brief The ADD differential probability of the F-function of XTEA for a fixed key
 *        and round constants \f$\mathrm{adp}^{F}(k, \delta |~ da \rightarrow dd)\f$.
 *        Complexity: \f$ O(n) < c \le O(2^n) \f$.
 *
 * \attention The algorithms in this file have complexity that depends on the input and output differences to F. 
 *            It is worst-case exponential in the word size, but is sub-exponential on average.
 *
 * \see xdp-xtea-f-fk.cc
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR_H
#include "adp-xor.hh"
#endif
#ifndef MAX_ADP_XOR_H
#include "max-adp-xor.hh"
#endif
#ifndef ADP_XOR_FI_H
#include "adp-xor-fi.hh"
#endif
#ifndef MAX_ADP_XOR_FI_H
#include "max-adp-xor-fi.hh"
#endif
#ifndef ADP_SHIFT_H
#include "adp-shift.hh"
#endif
#ifndef XTEA_H
#include "xtea.hh"
#endif

/**
 * Compute the fixed-key, fixed-constant ADD differential probability of
 * the F-function of block cipher XTEA: 
 * \f$\mathrm{adp}^{F}(k, \delta |~ dx \rightarrow dy)\f$
 * through exhaustive search over all input values. \b Complexity: \f$O(2^n)\f$.
 *
 * \param da input difference.
 * \param db output difference.
 * \param k round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{adp}^{F}(k, \delta |~ dx \rightarrow dy)\f$.
 */
double adp_xtea_f_exper(const uint32_t da, const uint32_t db, 
							   const uint32_t k, const uint32_t delta, 
								const uint32_t lsh_const, const uint32_t rsh_const)
{
  uint64_t N = ALL_WORDS;
  uint32_t cnt = 0;

  for(uint32_t a1 = 0; a1 < ALL_WORDS; a1++) {

	 uint32_t a2 = ADD(a1, da);

	 uint32_t b1 = xtea_f(a1, k, delta, lsh_const, rsh_const);
	 uint32_t b2 = xtea_f(a2, k, delta, lsh_const, rsh_const);

	 uint32_t dx = SUB(b2, b1);
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
 * An approximation of the ADP of the XTEA F-function (\ref xtea_f) 
 * obtained over a number of input chosen plaintext pairs chosen uniformly at random.
 *
 * \param ninputs number of chosen plaintext pairs.
 * \param da input difference.
 * \param db output difference.
 * \param k round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{adp}^{F}(k, \delta |~ dx \rightarrow dy)\f$.
 * \note For the exact computation refer to \ref adp_xtea_f
 */ 
double adp_xtea_f_approx(const uint32_t ninputs, 
								 const uint32_t da, const uint32_t db, 
								 const uint32_t k, const uint32_t delta, 
								 const uint32_t lsh_const, const uint32_t rsh_const)
{
  uint64_t N = ninputs;
  uint32_t cnt = 0;

  for(uint32_t i = 0; i < N; i++) {

	 uint32_t a1 = xrandom() & MASK;
	 uint32_t a2 = ADD(a1, da);

	 uint32_t b1 = xtea_f(a1, k, delta, lsh_const, rsh_const);
	 uint32_t b2 = xtea_f(a2, k, delta, lsh_const, rsh_const);

	 uint32_t dx = SUB(b2, b1);
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
 * For given input difference \p dx, compute the maximum probability 
 * output difference \p dy over all output differences: 
 * \f$\mathrm{max}_{dy} ~\mathrm{adp}^{F}(k, \delta |~ dx \rightarrow dy)\f$
 * through exhaustive search over all input values and input differences. 
 * \b Complexity: \f$O(2^{2n})\f$.
 *
 * \param dx input difference.
 * \param dy_max maximum probability output difference.
 * \param k round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{max}_{dx} ~\mathrm{adp}^{F}(k, \delta |~ dx \rightarrow dy)\f$.
 * \see max_dy_adp_f_fk
 */
double max_dy_adp_xtea_f_exper(const uint32_t dx, uint32_t* dy_max, 
										 const uint32_t k, const uint32_t delta, 
										 const uint32_t lsh_const, const uint32_t rsh_const)
{
  double p_max = 0.0;
  for(uint32_t dy = 0; dy < ALL_WORDS; dy++) {
	 double p = adp_xtea_f_exper(dx, dy, k, delta, lsh_const, rsh_const);
	 if(p >= p_max) {
		p_max = p;
		*dy_max = dy;
	 }
  }
  return p_max;
}

/**
 * For given output difference \p dy, compute the maximum probability 
 * input differences \p dx over all input differences: 
 * \f$\mathrm{max}_{dx} ~\mathrm{adp}^{F}(k, \delta |~ dx \rightarrow dy)\f$
 * through exhaustive search over all input values and input differences. 
 * \b Complexity: \f$O(2^{2n})\f$.
 *
 * \param dx_max maximum probability input difference.
 * \param dy output difference.
 * \param k round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{max}_{dx} ~\mathrm{adp}^{F}(k, \delta |~ dx \rightarrow dy)\f$.
 * \see max_dx_adp_f_fk
 */
double max_dx_adp_xtea_f_exper(uint32_t *dx_max, const uint32_t dy, 
										 const uint32_t k, const uint32_t delta, 
										 const uint32_t lsh_const, const uint32_t rsh_const)
{
  double p_max = 0.0;
  for(uint32_t dx = 0; dx < ALL_WORDS; dx++) {
	 double p = adp_xtea_f_exper(dx, dy, k, delta, lsh_const, rsh_const);
	 if((p >= p_max) && (p != 1.0)) { // skip the zero input difference (p == 1.0)
		p_max = p;
		*dx_max = dx;
	 }
  }
  return p_max;
}

/**
 * Compute the ADD differential probability of the \f$f_{\mathrm{LXR}}\f$ (\ref xtea_f_lxr) 
 * component of the F-function of block cipher XTEA,
 * through exhaustive search over all input values. \b Complexity: \f$O(2^n)\f$.
 *
 * \param da input difference.
 * \param db output difference.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \return \f$\mathrm{adp}^{f_\mathrm{LXR}}(da \rightarrow db)\f$
 */
double adp_xtea_f_lxr_exper(const uint32_t da, const uint32_t db, uint32_t lsh_const, uint32_t rsh_const)
{
  uint64_t N = ALL_WORDS;
  uint32_t cnt = 0;

  for(uint32_t a1 = 0; a1 < ALL_WORDS; a1++) {

	 uint32_t a2 = ADD(a1, da);

	 uint32_t b1 = xtea_f_lxr(a1, lsh_const, rsh_const);
	 uint32_t b2 = xtea_f_lxr(a2, lsh_const, rsh_const);

	 uint32_t dx = SUB(b2, b1);
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
 * An approximation of the ADP of \f$f_{\mathrm{LXR}}\f$ (\ref xtea_f_lxr) 
 * obtained over a number of input chosen plaintext pairs chosen uniformly at random.
 *
 * \param ninputs number of input chosen plaintext pairs.
 * \param da input difference.
 * \param db output difference.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \return \f$\mathrm{adp}^{f_\mathrm{LXR}}(da \rightarrow db)\f$
 * \note For the exact computation refer to \ref adp_xtea_f_lxr_exper
 */ 
double adp_xtea_f_lxr_approx(const uint32_t ninputs, const uint32_t da, const uint32_t db, uint32_t lsh_const, uint32_t rsh_const)
{
  uint64_t N = ninputs;
  uint32_t cnt = 0;

  for(uint32_t i = 0; i < N; i++) {

	 uint32_t a1 = xrandom() & MASK;
	 uint32_t a2 = ADD(a1, da);

	 uint32_t b1 = xtea_f_lxr(a1, lsh_const, rsh_const);
	 uint32_t b2 = xtea_f_lxr(a2, lsh_const, rsh_const);

	 uint32_t dx = SUB(b2, b1);
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
 * Check if a given value \p x satisfies the ADD differential \f$(dx \rightarrow dy)\f$
 * for the function \f$f_{\mathrm{LXR}}\f$ (\ref xtea_f_lxr).
 * 
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \param dx input difference.
 * \param dy output difference.
 * \param x input value.
 * \returns TRUE if \f$dy = f_{\mathrm{LXR}}(x + dx) - f_{\mathrm{LXR}}(x)\f$.
 */ 
bool adp_xtea_f_lxr_check_x(const uint32_t lsh_const, const uint32_t rsh_const,
									 const uint32_t dx, const uint32_t dy, const uint32_t x)
{
  uint32_t x1 = x;
  uint32_t x2 = ADD(x, dx);
  uint32_t mask = 0xffffffff;
  uint32_t y1 = xtea_f_lxr_i(mask, lsh_const, rsh_const, x1);
  uint32_t y2 = xtea_f_lxr_i(mask, lsh_const, rsh_const, x2);
  uint32_t y_sub = SUB(y2, y1);
  bool b_sat = (dy == y_sub);
  return b_sat;
}

/**
 * Check if the differential \f$(dx \rightarrow dy)\f$ 
 * for the function \f$f_{\mathrm{LXR}}\f$ (\ref xtea_f_lxr) is
 * satisfied on the \p i LS bits of \p x i.e. check if 
 *
 * \f$dy[i-1:0] = f_{\mathrm{LXR}}(x[i-1:0] + dx[i-1:0]) - f_{\mathrm{LXR}}(x[i-1:0]) ~\mathrm{mod} ~2^{i}\f$.
 * 
 * \attention \p x must be of size at least \f$(i + R)\f$ bits where \p R is the RSH constant of \f$f_{\mathrm{LXR}}\f$.
 * 
 * \param mask_i \p i bit mask.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \param dx input difference.
 * \param dy output difference.
 * \param x input value of size at least (\p i + \p rsh_const).
 * \returns TRUE if \f$dy[i-1:0] = f_{\mathrm{LXR}}(x[i-1:0] + dx[i-1:0]) - f_{\mathrm{LXR}}(x[i-1:0]) ~\mathrm{mod} ~2^{i}\f$.
 *
 */
bool adp_xtea_f_lxr_is_sat(const uint32_t mask_i, const uint32_t lsh_const, const uint32_t rsh_const,
									const uint32_t dx, const uint32_t dy, int32_t x)
{
  //  printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, mask_i, x_in);
  uint32_t x1 = x;// & MASK;
  uint32_t x2 = ADD(x, dx);
  uint32_t y1 = xtea_f_lxr_i(mask_i, lsh_const, rsh_const, x1);
  uint32_t y2 = xtea_f_lxr_i(mask_i, lsh_const, rsh_const, x2);
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
 * for the \f$f_{\mathrm{LXR}}\f$ (\ref xtea_f_lxr) function is satisfied. 
 * The algorithm works by recursively assigning
 * the bits of \p x starting from bit position \p i and terminating at the MS bit \p n.
 * The recursion proceeds to bit \f$(i+1)\f$ only if the differential is satisfied
 * on the \p i LS bits. This is checked by applying \ref adp_xtea_f_lxr_is_sat. 
 *
 * \param n word size (terminating bit popsition).
 * \param i current bit position.
 * \param mask_i mask on the \p i LS bits of \p x.
 * \param x input value of size at least (\p i + \p rsh_const).
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \param dx input difference.
 * \param dy output difference.
 * \param x_cnt number of values satisfying \f$(dx \rightarrow dy)\f$.
 * \param prob the probability \f$\mathrm{adp}^{f_\mathrm{LXR}}(dx \rightarrow dy)\f$.
 * \returns \p 1 if \f$x[i-1:0]\f$ satisfies \f$(dx[i-1:0] \rightarrow dy[i-1:0])\f$; \p 0 otherwise.
 * \see adp_xtea_f_lxr
 */
uint32_t adp_xtea_f_lxr_assign_bit_x(const uint32_t n, const uint32_t i, const uint32_t mask_i, const uint32_t x, 
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
		bool b_ok = adp_xtea_f_lxr_check_x(lsh_const, rsh_const, dx, dy, x);
		assert(b_ok);
	 }
	 return 1;
  }
  bool b_adp_xtea_f_lxr_is_sat = adp_xtea_f_lxr_is_sat(mask_i, lsh_const, rsh_const, dx, dy, x); // check x[i]
  if(b_adp_xtea_f_lxr_is_sat) {
	 if(i < (WORD_SIZE - 1)) { // x[30:0] are assigned and we shall assign the last bit x[31]
		uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); // select x[(i+1)-R:0]
		for(uint32_t next_bit = 0; next_bit < 2; next_bit++) {
		  uint32_t new_x = (next_bit << (i + 1)) | x; // assign x[i+1]
		  //		  printf("[%s:%d] x = %8X\n", __FILE__, __LINE__, x);
		  uint32_t ret = adp_xtea_f_lxr_assign_bit_x(n, i + 1, mask_i, new_x, lsh_const, rsh_const, dx, dy, x_cnt, prob);
		  *x_cnt += ret;
		  *prob = (double)*x_cnt / (double)ALL_WORDS;
		  //		  printf("[%s:%d] x_cnt = %d\n", __FILE__, __LINE__, *x_cnt);
		}
	 } else {
		uint32_t mask_i = MASK;
		uint32_t new_x = x;
		uint32_t ret =  adp_xtea_f_lxr_assign_bit_x(n, i + 1, mask_i, new_x, lsh_const, rsh_const, dx, dy, x_cnt, prob);
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
 * Compute the ADD differential probability of
 * the \f$f_{\mathrm{LXR}}\f$ (\ref xtea_f_lxr) function: 
 * \f$\mathrm{adp}^{f_\mathrm{LXR}}(dx \rightarrow dy)\f$.
 * \b Complexity c: \f$ O(n) < c \le O(2^n) \f$.
 *
 * \param n word size.
 * \param dx input difference.
 * \param dy output difference.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{adp}^{f_\mathrm{LXR}}(dx \rightarrow dy)\f$.
 * \see adp_xtea_f_lxr_assign_bit_x
 */
double adp_xtea_f_lxr(const uint32_t n, const uint32_t dx, const uint32_t dy, 
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
	 adp_xtea_f_lxr_assign_bit_x(n, i, mask_i, x, lsh_const, rsh_const, dx, dy, &x_cnt, &p);
#endif
  }
  return p;
}

/**
 * An approximation of the ADD differential probability (ADP) of the 
 * XTEA F-function (\ref xtea_f) with fixed round key and round cnstant,
 * obtained as the multiplication the 
 * ADP of its \f$f_{\mathrm{LXR}}\f$ component (\ref adp_xtea_f_lxr) and
 * the ADP of XOR with one fixed input (\ref adp_xor_fixed_input):
 *
 * \f$\mathrm{adp}^{F}(k, \delta |~ dx \rightarrow dy)
 *  = \mathrm{adp}^{f_\mathrm{LXR}}(dx \rightarrow dt) \cdot 
 *    \mathrm{adp}^{\oplus}_{\mathrm{FI}}(k + \delta, dx + dt \rightarrow dy)\f$.
 * 
 * Algorithm sketch:
 *   -# Compute \f$dz\f$ s.t. \f$p_1 = \mathrm{max}_{dz}~\mathrm{adp}^{\oplus}_{\mathrm{FI}}(k + \delta, dy \rightarrow dz)\f$.
 * \note Note that \f$\mathrm{adp}^{\oplus}_{\mathrm{FI}}(k + \delta, dy \rightarrow dz) = 
 *       \mathrm{adp}^{\oplus}_{\mathrm{FI}}(k + \delta, dz \rightarrow dy)\f$.        
 *   -# Compute the output from \f$f_{\mathrm{LXR}}\f$ : \f$dt = dz - dx\f$.
 *   -# Compute \f$p_2 = \mathrm{adp}^{f_\mathrm{LXR}}(dx \rightarrow dt)\f$.
 *   -# Compute \f$\mathrm{adp}^{F}(k, \delta |~ dx \rightarrow dy) = p_1 \cdot p_2\f$.
 *
 * \param n word size.
 * \param A transition probability matrices for \f$\mathrm{adp}^{\oplus}\f$ with FI (\ref adp_xor_fixed_input_sf).
 * \param dx input difference.
 * \param dy output difference.
 * \param k round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{adp}^{f_\mathrm{LXR}} \cdot \mathrm{adp}^{\oplus}_{\mathrm{FI}}\f$.
 * \note For the exact computation refer to \ref adp_xtea_f.
 */ 
double adp_xtea_f_approx(const uint32_t n, gsl_matrix* A[2][2][2],
								 const uint32_t dx, const uint32_t dy, 
								 const uint32_t k, const uint32_t delta, 
								 const uint32_t lsh_const, const uint32_t rsh_const)
{
  uint32_t a = ADD(delta, k); // fixed input: delta + key
  uint32_t dz = 0;				// one input to the xor
  double p_f_xor = max_adp_xor_fixed_input(A, a, dy, &dz);
  double p_test = adp_xor_fixed_input(A, a, dz, dy);
  assert(p_f_xor == p_test);

  uint32_t dt = SUB(dz, dx);	  // dt + dx = dz
  double p_f_lxr = adp_xtea_f_lxr(n, dx, dt, lsh_const, rsh_const);
  double p_f = (p_f_lxr * p_f_xor);
  return p_f;
}

/**
 * Check if a given value \p x satisfies the ADD differential \f$(dx \rightarrow dy)\f$
 * for the XTEA F-function.
 * 
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \param k round key.
 * \param delta round constant.
 * \param dx input difference.
 * \param dy output difference.
 * \param x input value.
 * \returns TRUE if \f$k, \delta:~ dy = F(x + dx) - F(x)\f$.
 */ 
bool adp_xtea_f_check_x(const uint32_t lsh_const, const uint32_t rsh_const,
								const uint32_t k, const uint32_t delta,
								const uint32_t dx, const uint32_t dy, 
								const uint32_t x)
{
  uint32_t x1 = x;
  uint32_t x2 = ADD(x, dx);
  uint32_t mask = 0xffffffff;
  uint32_t y1 = xtea_f_i(mask, lsh_const, rsh_const, x1, k, delta);
  uint32_t y2 = xtea_f_i(mask, lsh_const, rsh_const, x2, k, delta);
  uint32_t y_sub = SUB(y2, y1);
  bool b_sat = (dy == y_sub);
  return b_sat;
}

/**
 * Check if the differential \f$(dx \rightarrow dy)\f$ for \p F (\ref xtea_f) is 
 * satisfied on the \p i LS bits of \p x i.e. check if 
 *
 * \f$k, \delta:~ dy[i-1:0] = F(x[i-1:0] + dx[i-1:0]) - F(x[i-1:0]) ~\mathrm{mod} ~2^{i}\f$.
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
 * \returns TRUE if \f$k, \delta:~ dy[i-1:0] = F(x[i-1:0] + dx[i-1:0]) - F(x[i-1:0]) ~\mathrm{mod} ~2^{i}\f$.
 *
 */
bool adp_xtea_f_is_sat(const uint32_t mask_i, const uint32_t lsh_const, const uint32_t rsh_const,
							  const uint32_t k, const uint32_t delta,
							  const uint32_t dx, const uint32_t dy, const uint32_t x)
{
  //  printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, mask_i, x_in);
  uint32_t x1 = x;// & MASK;
  uint32_t x2 = ADD(x, dx);
  uint32_t y1 = xtea_f_i(mask_i, lsh_const, rsh_const, x1, k, delta);
  uint32_t y2 = xtea_f_i(mask_i, lsh_const, rsh_const, x2, k, delta);
  uint32_t y_sub_i = SUB(y2, y1) & mask_i;
  uint32_t dy_i = (dy & mask_i);
  bool b_sat = (dy_i == y_sub_i);
  //  printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, y_sub_i, dy);
  //  printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, y2, y1);
  //  printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, x2, x1);
  return b_sat;
}

/**
 * Counts the number of values \p x for which the differential \f$(dx \rightarrow dy)\f$
 * for the F-function of XTEA is satisfied. The function operates by recursively assigning
 * the bits of \p x starting from bit position \p i and terminating at the MS bit \p n.
 * The recursion proceeds to bit \f$(i+1)\f$ only if the differential is satisfied
 * on the \p i LS bits. This is checked by applying \ref adp_xtea_f_is_sat. 
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
 * \param prob the fixed-key ADD probability of \p F: \f$\mathrm{adp}^{F}(k, \delta |~ dx \rightarrow dy)\f$.
 * \returns \p 1 if \f$x[i-1:0]\f$ satisfies \f$(dx[i-1:0] \rightarrow dy[i-1:0])\f$; \p 0 otherwise.
 * \see adp_f_fk
 */
uint32_t adp_xtea_f_assign_bit_x(const uint32_t n, const uint32_t i, const uint32_t mask_i, 
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
		bool b_ok = adp_xtea_f_check_x(lsh_const, rsh_const, key, delta, dx, dy, x);
		assert(b_ok);
	 }
	 return 1;
  }
  bool b_adp_xtea_f_is_sat = adp_xtea_f_is_sat(mask_i, lsh_const, rsh_const, key, delta, dx, dy, x); // check x[i]
  if(b_adp_xtea_f_is_sat) {
	 if(i < (WORD_SIZE - 1)) { // x[30:0] are assigned and we shall assign the last bit x[31]
		uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); // select x[(i+1)-R:0]
		for(uint32_t next_bit = 0; next_bit < 2; next_bit++) {
		  uint32_t new_x = (next_bit << (i + 1)) | x; // assign x[i+1]
		  //		  printf("[%s:%d] x = %8X\n", __FILE__, __LINE__, x);
		  uint32_t ret = adp_xtea_f_assign_bit_x(n, i + 1, mask_i, new_x, key, delta, lsh_const, rsh_const, dx, dy, x_cnt, prob);
		  *x_cnt += ret;
		  *prob = (double)*x_cnt / (double)ALL_WORDS;
		  //		  printf("[%s:%d] x_cnt = %d\n", __FILE__, __LINE__, *x_cnt);
		}
	 } else {
		uint32_t mask_i = MASK;
		uint32_t new_x = x;
		uint32_t ret =  adp_xtea_f_assign_bit_x(n, i + 1, mask_i, new_x, key, delta, lsh_const, rsh_const, dx, dy, x_cnt, prob);
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
 * \param key round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \param dx input difference.
 * \param dy output difference.
 * \param x_cnt array of \f$2^n\f$ counters - each one keeps track of the number of values
 *        satisfying \f$(dx \rightarrow dy)\f$ for every \p dx.
 * \param ret_prob the maximum probability over all input differences 
 *        \f$\mathrm{max}_{dx} ~\mathrm{adp}^{F}(k, \delta |~ dx \rightarrow dy)\f$.
 * \param ret_dx the input difference that has maximum probability.
 * \returns \p 1 if \f$x[i-1:0]\f$ satisfies \f$(dx[i-1:0] \rightarrow dy[i-1:0])\f$; \p 0 otherwise.
 *
 * \see adp_f_assign_bit_x
 */
// 
// XTEA: Assigns the i-th bit of x and dx
// This function is used to compute the maximum probability input difference dx
// for a given output difference dx (max_dx_adp_xtea_f())
// 
// See also: adp_xtea_f_assign_bit_x_dy() and adp-tea-f-fixed-key.cc:adp_f_assign_bit_x_dx()
// 
uint32_t adp_xtea_f_assign_bit_x_dx(const uint32_t n, const uint32_t i, const uint32_t mask_i, const uint32_t x, 
												const uint32_t lsh_const, const uint32_t rsh_const,
												const uint32_t key, const uint32_t delta,
												const uint32_t dx, const uint32_t dy, uint64_t* x_cnt, 
												double* ret_prob, uint32_t* ret_dx)
{
  assert(n <= WORD_SIZE);
  assert(n >= (rsh_const * 2));
  assert(i <= (n + rsh_const));
#if 0
  printf("[%s:%d] --- ENTER : --- %2d: # %8llX: %8X -> %8X | x = %8X  %f 2^%f\n", __FILE__, __LINE__, n, x_cnt[dx], dx, dy, x, *ret_prob, log2(*ret_prob));
#endif
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
#if 0
	 printf("[%s:%d] --- EXIT 1: --- %2d: # %8llX: %8X -> %8X | x = %8X  %f 2^%f\n", __FILE__, __LINE__, n, x_cnt[dx], dx, dy, x, *ret_prob, log2(*ret_prob));
#endif
	 return 0;
  } else {
	 if(i == (n + rsh_const)) {
#if 0
		double p = *ret_prob;
		printf("[%s:%d] %2d: # %8llX: %8X -> %8X | x = %8X  %f 2^%f\n", __FILE__, __LINE__, n, x_cnt[dx], dx, dy, x, p, log2(p));
#endif
		assert(dx < MOD);
		if(n == (WORD_SIZE)) {
		  bool b_ok = adp_xtea_f_check_x(lsh_const, rsh_const, key, delta, dx, dy, x);
		  assert(b_ok);
		}
#if 0
		printf("[%s:%d] --- EXIT 2: --- %2d: # %8llX: %8X -> %8X | x = %8X  %f 2^%f\n", __FILE__, __LINE__, n, x_cnt[dx], dx, dy, x, *ret_prob, log2(*ret_prob));
#endif
		return 1;
	 }
  }
  bool b_adp_xtea_f_is_sat = adp_xtea_f_is_sat(mask_i, lsh_const, rsh_const, key, delta, dx, dy, x); // check x[i]
  if(b_adp_xtea_f_is_sat) {
	 if(i < (WORD_SIZE - 1)) { // x[30:0] are assigned and we shall assign the last bit x[31]
		uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); // select x[(i+1)-R:0]
		for(uint32_t next_bit_dx = 0; next_bit_dx < 2; next_bit_dx++) { // ! dx
		  uint32_t new_dx = (next_bit_dx << (i + 1)) | dx; // assign dx[i+1]
		  for(uint32_t next_bit_x = 0; next_bit_x < 2; next_bit_x++) {
			 uint32_t new_x = (next_bit_x << (i + 1)) | x; // assign x[i+1]
			 uint32_t ret = 
			 adp_xtea_f_assign_bit_x_dx(n, i + 1, mask_i, new_x, lsh_const, rsh_const, key, delta, new_dx, dy, x_cnt, ret_prob, ret_dx);
			 x_cnt[new_dx] += ret;
		  }
		}
	 } else {
		uint32_t mask_i = MASK;
		uint32_t new_dx = dx;
		uint32_t new_x = x;
		uint32_t ret =  
		adp_xtea_f_assign_bit_x_dx(n, i + 1, mask_i, new_x, lsh_const, rsh_const, key, delta, new_dx, dy, x_cnt, ret_prob, ret_dx);
		x_cnt[new_dx] += ret;
		if((i + 1) == (n + rsh_const)) {
		  double p = (double)x_cnt[new_dx] / (double)ALL_WORDS;
		  if(p >= *ret_prob) {
			 *ret_prob = p;
			 *ret_dx = dx;
		  }
#if 0
		  //		  printf("[%s:%d] %2d: # %8llX: %8X -> %8X | x = %8X  %f 2^%f\n", __FILE__, __LINE__, n, x_cnt[dy], dx, dy, x, *ret_prob, log2(*ret_prob));
		  printf("\r[%s:%d] %2d: # %8llX: %8X -> %8X | x = %8X  %f 2^%f", __FILE__, __LINE__, n, x_cnt[dx], dx, dy, x, *ret_prob, log2(*ret_prob));
		  fflush(stdout);
#endif
		}
	 }
  } 
#if 0
  printf("[%s:%d] --- EXIT 3: --- %2d: # %8llX: %8X -> %8X | x = %8X  %f 2^%f\n", __FILE__, __LINE__, n, x_cnt[dx], dx, dy, x, *ret_prob, log2(*ret_prob));
#endif
  return 0;
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
 * \param key round key.
 * \param delta round constant.
 * \param dx input difference.
 * \param dy output difference.
 * \param x_cnt array of \f$2^n\f$ counters - each one keeps track of the number of values
 *        satisfying \f$(dx \rightarrow dy)\f$ for every \p dy.
 * \param ret_prob the maximum probability over all output differences 
 *        \f$\mathrm{max}_{dy} ~\mathrm{adp}^{F}(k, \delta |~ dx \rightarrow dy)\f$.
 * \param ret_dy the output difference that has maximum probability.
 * \returns \p 1 if \f$x[i-1:0]\f$ satisfies \f$(dx[i-1:0] \rightarrow dy[i-1:0])\f$; \p 0 otherwise.
 *
 * \see adp_f_assign_bit_x_dx
 */
// 
// XTEA: Assigns the i-th bit of x and dy
// This function is used to compute the maximum probability output difference dy
// for a given input difference dx (max_dy_adp_xtea_f())
// 
// See also: adp-tea-f-fixed-key.cc:adp_f_assign_bit_x_dy()
// 
uint32_t adp_xtea_f_assign_bit_x_dy(const uint32_t n, const uint32_t i, const uint32_t mask_i, const uint32_t x, 
												const uint32_t lsh_const, const uint32_t rsh_const,
												const uint32_t key, const uint32_t delta,
												const uint32_t dx, const uint32_t dy, uint64_t* x_cnt, 
												double* ret_prob, uint32_t* ret_dy)
{
  assert(n <= WORD_SIZE);
  assert(n >= (rsh_const * 2));
  assert(i <= (n + rsh_const));
#if 0
  printf("[%s:%d] --- ENTER : --- %2d: # %8llX: %8X -> %8X | x = %8X  %f 2^%f\n", __FILE__, __LINE__, n, x_cnt[dy], dx, dy, x, *ret_prob, log2(*ret_prob));
#endif
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
#if 0
	 printf("[%s:%d] --- EXIT 1: --- %2d: # %8llX: %8X -> %8X | x = %8X  %f 2^%f\n", __FILE__, __LINE__, n, x_cnt[dy], dx, dy, x, *ret_prob, log2(*ret_prob));
#endif
	 return 0;
  } else {
	 if(i == (n + rsh_const)) {
#if 0
		double p = *ret_prob;
		printf("[%s:%d] %2d: # %8llX: %8X -> %8X | x = %8X  %f 2^%f\n", __FILE__, __LINE__, n, x_cnt[dy], dx, dy, x, p, log2(p));
#endif
		assert(dy < MOD);
		if(n == (WORD_SIZE)) {
		  bool b_ok = adp_xtea_f_check_x(lsh_const, rsh_const, key, delta, dx, dy, x);
		  assert(b_ok);
		}
#if 0
		printf("[%s:%d] --- EXIT 2: --- %2d: # %8llX: %8X -> %8X | x = %8X  %f 2^%f\n", __FILE__, __LINE__, n, x_cnt[dy], dx, dy, x, *ret_prob, log2(*ret_prob));
#endif
		return 1;
	 }
  }
  bool b_adp_xtea_f_is_sat = adp_xtea_f_is_sat(mask_i, lsh_const, rsh_const, key, delta, dx, dy, x); // check x[i]
  if(b_adp_xtea_f_is_sat) {
	 if(i < (WORD_SIZE - 1)) { // x[30:0] are assigned and we shall assign the last bit x[31]
		uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); // select x[(i+1)-R:0]
		for(uint32_t next_bit_dy = 0; next_bit_dy < 2; next_bit_dy++) { // ! dy
		  uint32_t new_dy = (next_bit_dy << (i + 1)) | dy; // assign dx[i+1]
		  for(uint32_t next_bit_x = 0; next_bit_x < 2; next_bit_x++) {
			 uint32_t new_x = (next_bit_x << (i + 1)) | x; // assign x[i+1]
			 uint32_t ret = 
			 adp_xtea_f_assign_bit_x_dy(n, i + 1, mask_i, new_x, lsh_const, rsh_const, key, delta, dx, new_dy, x_cnt, ret_prob, ret_dy);
			 x_cnt[new_dy] += ret;
		  }
		}
	 } else {
		uint32_t mask_i = MASK;
		uint32_t new_dy = dy;
		uint32_t new_x = x;
		uint32_t ret =  
		adp_xtea_f_assign_bit_x_dy(n, i + 1, mask_i, new_x, lsh_const, rsh_const, key, delta, dx, new_dy, x_cnt, ret_prob, ret_dy);
		x_cnt[new_dy] += ret;
		if((i + 1) == (n + rsh_const)) {
		  double p = (double)x_cnt[new_dy] / (double)ALL_WORDS;
		  if(p >= *ret_prob) {
			 *ret_prob = p;
			 *ret_dy = dy;
		  }
#if 0
		  //		  printf("[%s:%d] %2d: # %8llX: %8X -> %8X | x = %8X  %f 2^%f\n", __FILE__, __LINE__, n, x_cnt[dy], dx, dy, x, *ret_prob, log2(*ret_prob));
		  printf("\r[%s:%d] %2d: # %8llX: %8X -> %8X | x = %8X  %f 2^%f", __FILE__, __LINE__, n, x_cnt[dy], dx, dy, x, *ret_prob, log2(*ret_prob));
		  fflush(stdout);
#endif
		}
	 }
  } 
#if 0
  printf("[%s:%d] --- EXIT 3: --- %2d: # %8llX: %8X -> %8X | x = %8X  %f 2^%f\n", __FILE__, __LINE__, n, x_cnt[dy], dx, dy, x, *ret_prob, log2(*ret_prob));
#endif
  return 0;
}

/**
 * Compute the fixed-key, fixed-constant ADD differential probability of
 * the F-function of block cipher XTEA: 
 * \f$\mathrm{adp}^{F}(k, \delta |~ dx \rightarrow dy)\f$.
 * \b Complexity: \f$ O(n) < c \le O(2^n) \f$.
 *
 * \param n word size.
 * \param dx input difference.
 * \param dy output difference.
 * \param key round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{adp}^{F}(k, \delta |~ dx \rightarrow dy)\f$.
 * \see adp_f_assign_bit_x
 */
double adp_xtea_f(const uint32_t n, const uint32_t dx, const uint32_t dy, 
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
	 adp_xtea_f_assign_bit_x(n, i, mask_i, x, key, delta, lsh_const, rsh_const, dx, dy, &x_cnt, &p);
#endif
  }
  return p;
}

/**
 * For given input difference \p dx, compute the maximum probability 
 * output difference \p dy over all output differences: 
 * \f$\mathrm{max}_{dy} ~\mathrm{adp}^{F}(k, \delta |~ dx \rightarrow dy)\f$.
 * \b Complexity: \f$ O(2n) < c \le O(2^{2n}) \f$. \b Memory \b requirement: \f$4 \cdot 2^n\f$ Bytes.
 *
 * \param n word size.
 * \param dx input difference.
 * \param ret_dy maximum probability output difference.
 * \param key round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{max}_{dx} ~\mathrm{adp}^{F}(k, \delta |~ dx \rightarrow dy)\f$.
 * \see adp_f_assign_bit_x_dy, max_dx_adp_f_fk
 */
// For the XTEA F-function, for given input ADD difference dx
// compute an output ADD difference dy such that 
// 
// max_{i} P(dx -> dy_i) = P(dx -> dy) = p
// 
// Return dy and p
// 
// See also: adp-tea-f-fixed-key.cc:max_dy_adp_f_fk()
// 
double max_dy_adp_xtea_f(const uint32_t n, const uint32_t dx, uint32_t* ret_dy,
								 const uint32_t key, const uint32_t delta,
								 const uint32_t lsh_const, const uint32_t rsh_const)
{
#if 0
  printf("[%s:%d] %s() Input: %d %d %8X %8X \n", __FILE__, __LINE__, __FUNCTION__, 
			lsh_const, rsh_const, key, delta);
#endif
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
#if 0
	 printf("[%s:%d] dy[%d:0] = %8X\n", __FILE__, __LINE__, (nlsb_init - 1), j);
	 //	 fflush(stdout);
#endif
	 for(uint32_t l = 0; l < N; l++) {
		x = l;							  // assign x[9:0]
		uint32_t i = nlsb_init - 1; // start at x[9]
		uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); 
		adp_xtea_f_assign_bit_x_dy(n, i, mask_i, x, lsh_const, rsh_const, key, delta, dx, dy, x_cnt, &pp, &dyy);
#if 0									  // DEBUG
		printf("[%s:%d] %8X -> %8X %f 2^%f | max_p = %f\n", __FILE__, __LINE__, dyy, dy, pp, log2(pp), max_p);
#endif
	 }
	 if((pp >= max_p) && (pp != 1.0)) { // skip the zero difference (p == 1.0)
#if 0
		if(max_dy != dyy) {
		  printf("[%s:%d] Update max dy[%d:0] = %8X | %8X -> %8X %f 2^%f\n", __FILE__, __LINE__, (nlsb_init - 1), j, dyy, dy, pp, log2(pp));
		}
#endif
		max_p = pp;
		max_dy = dyy;
#if 0
		printf("\n[%s:%d] Update max %8X -> %8X %f 2^%f\n", __FILE__, __LINE__, max_dy, dy, max_p, log2(max_p));
#endif
	 }
  }
  free(x_cnt);
  *ret_dy = max_dy;
  return max_p;
}

/**
 * For given output difference \p dy, compute the maximum probability 
 * input differences \p dx over all input differences: 
 * \f$\mathrm{max}_{dx} ~\mathrm{adp}^{F}(k, \delta |~ dx \rightarrow dy)\f$
 * through exhaustive search over all input values and input differences. 
 * \b Complexity: \f$O(2^{2n})\f$.
 *
 * \param n word size.
 * \param ret_dx maximum probability input difference.
 * \param dy output difference.
 * \param key round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{max}_{dx} ~\mathrm{adp}^{F}(k, \delta |~ dx \rightarrow dy)\f$.
 * \see max_dx_adp_f_fk
 */
double max_dx_adp_xtea_f(const uint32_t n, uint32_t* ret_dx, const uint32_t dy,
								 const uint32_t key, const uint32_t delta,
								 const uint32_t lsh_const, const uint32_t rsh_const)
{
#if 0
  printf("[%s:%d] %s() Input: %d %d %8X %8X \n", __FILE__, __LINE__, __FUNCTION__, 
			lsh_const, rsh_const, key, delta);
#endif
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
  if(x_cnt == NULL) {
	 printf("[%s:%d] ERROR: Bad calloc. Not enough memory. Exiting...\n", __FILE__, __LINE__);
	 exit(1);
  }

  //  const uint32_t n = WORD_SIZE; 
  for(uint32_t j = 0; j < N; j++) { // skip the zero difference
	 dx = j;
	 uint32_t dxx = max_dx;
	 double pp = max_p;
#if 0
	 printf("[%s:%d] dy[%d:0] = %8X\n", __FILE__, __LINE__, (nlsb_init - 1), j);
	 //	 fflush(stdout);
#endif
	 for(uint32_t l = 0; l < N; l++) {
		x = l;							  // assign x[9:0]
		uint32_t i = nlsb_init - 1; // start at x[9]
		uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); 
		adp_xtea_f_assign_bit_x_dx(n, i, mask_i, x, lsh_const, rsh_const, key, delta, dx, dy, x_cnt, &pp, &dxx);
#if 0									  // DEBUG
		printf("[%s:%d] %8X -> %8X %f 2^%f | max_p = %f\n", __FILE__, __LINE__, dxx, dy, pp, log2(pp), max_p);
#endif
	 }
	 if((pp >= max_p) && (pp != 1.0)) { // skip the zero difference (p == 1.0)
#if 0
		if(max_dx != dxx) {
		  printf("[%s:%d] Update max dx[%d:0] = %8X | %8X -> %8X %f 2^%f\n", __FILE__, __LINE__, (nlsb_init - 1), j, dxx, dy, pp, log2(pp));
		}
#endif
		max_p = pp;
		max_dx = dxx;
#if 0
		printf("\n[%s:%d] Update max %8X -> %8X %f 2^%f\n", __FILE__, __LINE__, max_dx, dx, max_p, log2(max_p));
#endif
	 }
  }
  free(x_cnt);
  *ret_dx = max_dx;
  return max_p;
}

/** 
 * For the XTEA F-function (\ref xtea_f), for fixed input difference \p da, 
 * compute an arbitrary \p dd such that the differential \f$(da \rightarrow dd)\f$
 * has non-zero probability. 
 *
 * The procedure approximates the ADP of the TEA F-function as a multiplication of the ADP
 * of its three non-linear components (w.r.t. ADD differences): the two XOR operations
 * and the RSH operation (see \ref xtea_f):
 *
 * \f$\mathrm{adp}^{F}(k, \delta |~ dx \rightarrow dy) = \mathrm{adp}^{\oplus} \cdot 
 * \mathrm{adp}^{\gg} \cdot \mathrm{adp}^{\oplus}_{\mathrm{FI}}\f$
 * 
 * \b Algorithm \b sketch: 
 * 
 *   -# Compute \f$ dy: \mathrm{max}_{dc[i]}~\mathrm{adp}^{\oplus}(db, dc[i] \rightarrow dy) \f$,
 *      where \f$dc[i] \in \{(da \gg 5), (da \gg 5) + 1, (da \gg 5) - 2^{n-5}, (da \gg 5) - 2^{n-5} + 1\}\f$,
 *      is one of the four possible ADD differences after RSH (\ref adp_rsh).
 *   -# Compute \f$dt = dy + da\f$.
 *   -# Compute \f$ dd:\mathrm{max}_{dd}~\mathrm{adp}^{\oplus}((k + \delta), dt \rightarrow dd)\f$.
 *   -# For the computed \p da and \p dd experimenttaly re-adjust the probability using \ref adp_xtea_f_approx. 
 *      \note At this step the \em exact probability can also be computed with \ref adp_xtea_f
 *      which is more accurate but less efficient.
 *   -# Return the adjusted probability \p p and \p dd.
 * 
 * \attention it is still possible that p = 0.0 for some \p da.
 *
 * \param A transition probability matrices for \f$\mathrm{adp}^{\oplus}\f$ (\ref adp_xor_sf).
 * \param AA transition probability matrices for \f$\mathrm{adp}^{\oplus}\f$ with FI (\ref adp_xor_fixed_input_sf).
 * \param key round key.
 * \param delta round constant.
 * \param da input difference.
 * \param ret_dd output difference.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \return \f$\mathrm{adp}^{F}(k, \delta |~ da \rightarrow dd)\f$
 *
 */ 
double first_nz_adp_xtea_f(gsl_matrix* A[2][2][2], gsl_matrix* AA[2][2][2], 
									const uint32_t key, const uint32_t delta,
									const uint32_t da, uint32_t* ret_dd, 
									uint32_t lsh_const, uint32_t rsh_const)
{
  //  uint32_t n = WORD_SIZE;		  // final bit position (MSB)
  // init C
  gsl_vector* C = gsl_vector_calloc(ADP_XOR_MSIZE);
  gsl_vector_set(C, ADP_XOR_ISTATE, 1.0);

  uint32_t db = LSH(da, lsh_const);
  uint32_t dc = 0;
  uint32_t dx[4] = {0, 0, 0, 0};
  adp_rsh_odiffs(dx, da, rsh_const);

  double ret_p = 0.0;

  for(int i = 0; i < 4; i++) {
	 dc = dx[i];
	 uint32_t dd = 0;

	 uint32_t dy = 0;
	 double p_xor_1 = max_adp_xor(A, db, dc, &dy);

	 uint32_t dz = ADD(dy, da);
	 uint32_t val = ADD(key, delta); // fixed input = delta + key <- fixed value, not a difference!
	 double p_xor_2 = max_adp_xor_fixed_input(AA, val, dz, &dd);

#if 0									  // exact computation
	 double p_f = adp_xtea_f(WORD_SIZE, da, dd, key, delta, lsh_const, rsh_const);
#else	 // approximation
	 uint32_t ninputs = (1U << 15);
	 double p_f = adp_xtea_f_approx(ninputs, da, dd, key, delta, lsh_const, rsh_const);
#endif
#if 0									  // DEBUG
	 printf("[%s:%d] %8X %8X %8X -> %8X 2^%f 2^%f 2^%f\n", __FILE__, __LINE__, val, dz, dy, dd, log2(p_xor_1), log2(p_xor_2), log2(p_f));
#else	 // prevent compilation warnings
	 p_xor_1 = p_xor_1;
	 p_xor_2 = p_xor_2;
#endif

#if 1									  // if 0 we adopt the approximation
	 if(p_f == 0.0) {
		p_f = p_xor_1 * p_xor_2;
	 }
#endif

	 if(p_f >= ret_p) {
		ret_p = p_f;
		*ret_dd = dd;
	 }
  }

  gsl_vector_free(C);
  return ret_p;
}
