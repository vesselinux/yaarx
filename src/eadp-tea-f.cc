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
 * \file  eadp-tea-f.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \brief The expected additive differential probability (EADP) of the F-function of TEA, 
 *        averaged over all round keys and constants: \f$\mathrm{eadp}^{F}(da \rightarrow dd)\f$.
 *        Complexity: \f$O(n)\f$.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR3_H
#include "adp-xor3.hh"
#endif
#ifndef MAX_ADP_XOR3_SET_H
#include "max-adp-xor3-set.hh"
#endif
#ifndef ADP_SHIFT_H
#include "adp-shift.hh"
#endif
#ifndef TEA_H
#include "tea.hh"
#endif
#ifndef EADP_TEA_F_H
#include "eadp-tea-f.hh"
#endif

/**
 * Computing the expected additive differential probability (EADP) of the F-function of TEA 
 * (see \ref eadp_tea_f), experimentally over all round keys and constants. 
 *
 * \b Complexity: \f$O(2^{4n})\f$.
 *
 * \param dx input difference.
 * \param dy output difference.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \return \f$\mathrm{eadp}^{F}(da \rightarrow db)\f$.
 *
 * \see eadp_tea_f
 */
double eadp_tea_f_exper(const uint32_t dx, const uint32_t dy, uint32_t lsh_const, uint32_t rsh_const)
{
  uint64_t cnt = 0;
  for(uint32_t x1 = 0; x1 < ALL_WORDS; x1++) {
	 for(uint32_t k0 = 0; k0 < ALL_WORDS; k0++) {
		for(uint32_t k1 = 0; k1 < ALL_WORDS; k1++) {
		  for(uint32_t delta = 0; delta < ALL_WORDS; delta++) {
			 uint32_t x2 = ADD(x1, dx);
			 uint32_t y1 = tea_f(x1, k0, k1, delta, lsh_const, rsh_const);
			 uint32_t y2 = tea_f(x2, k0, k1, delta, lsh_const, rsh_const);
#if 1									  // DEBUG
			 uint32_t cr = 1;
			 uint32_t cl = (1UL << (WORD_SIZE - rsh_const)); // 2^{n-r}
			 uint32_t dr[4] = {0, 0, 0, 0};
			 uint32_t dx_l = dx >> rsh_const; // (n - r) MSBs
			 dr[0] = ((dx_l + 0 - 0) + MOD) % MOD;
			 dr[1] = ((dx_l + 0 - cl) + MOD) % MOD;
			 dr[2] = ((dx_l + cr - 0) + MOD) % MOD;
			 dr[3] = ((dx_l + cr - cl) + MOD) % MOD;

			 uint32_t x1_rsh = RSH(x1, rsh_const);
			 uint32_t x2_rsh = RSH(x2, rsh_const);

			 // add key
			 x1_rsh = ADD(x1_rsh, k1);
			 x2_rsh = ADD(x2_rsh, k1);

			 uint32_t dx_rsh = SUB(x2_rsh, x1_rsh);

			 //			 printf("%x | %x %x %x %x\n", dx_rsh, dr[0], dr[1], dr[2], dr[3]);
			 assert((dx_rsh == dr[0]) || (dx_rsh == dr[1]) || (dx_rsh == dr[2]) || (dx_rsh == dr[3]));
#endif
			 uint32_t y_sub = SUB(y2, y1);
			 if(y_sub == dy) {
				cnt++;
			 }
		  }
		}
	 }
  }
  uint64_t N = ALL_WORDS * ALL_WORDS * ALL_WORDS * ALL_WORDS;
  double p = (double)cnt / (double)(N);
  return p;
}


// 
// given input and output difference da and db to the F function of TEA,
// compute the probability with which da propagates to db through F
// Multiply two probabilities: (ADP3-XOR x ADP-RSH)
// 
//       db ---- << 4 ----
//        |               |
// dd <- xor -- da ------------ da 
//        |               |
//       dc ---- >> 5 ----
// 
// 
/**
 * Computing the expected additive differential probability (EADP) of the F-function of TEA, 
 * averaged over all round keys and constants. For fixed input and output
 * differences resp. \p da and \p db, it is defined as:
 *
 * \f$\mathrm{eadp}^{F}(da \rightarrow db) = 2^{-4n}~\{\#(k_0,k_1,\delta,x) : F(x + da) - F(x) = db\}\f$.
 *
 * \b Complexity: \f$O(n)\f$.
 *
 * \b Algorithm \b sketch: \f$\mathrm{eadp}^{F}\f$ is computed as the multiplication of ADP-s of the two
 * non-linear (w.r.t. ADD differences) components of F, namely XOR and LSH:
 * 
 * \f[\mathrm{eadp}^{F}(da \rightarrow db) = 
 * (\sum^3_{i=0} (\mathrm{adp}^{\gg 5}(da, dc_i)))~ \cdot~ 
 * \mathrm{adp}^{3\oplus}_{\mathrm{SET}}((da \ll 4), da, \{dc_0, dc_1, dc_2, dc_3\} \rightarrow db)\f]
 *
 * where \f$dc_i \in \{(da \gg 5), (da \gg 5) + 1, (da \gg 5) - 2^{n-5}, (da \gg 5) - 2^{n-5} + 1\}\f$
 * are the four possible ADD differences after RSH (see \ref adp_rsh)
 * and \f$\mathrm{adp}^{3\oplus}_{\mathrm{SET}}\f$ is the ADP of XOR with three inputs
 * where one of the inputs may satisfy any difference from a given \em set (\ref max_adp_xor3_set). 
 *
 * \param A transition probability matrices for \f$\mathrm{adp}^{3\oplus}\f$ (\ref adp_xor3_sf).
 * \param da input difference.
 * \param db output difference.
 * \param prob_db the expected DP of F.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \return \f$\mathrm{eadp}^{F}(da \rightarrow db)\f$.
 *
 */
double eadp_tea_f(gsl_matrix* A[2][2][2][2], const uint32_t da, const uint32_t db, double* prob_db,
						uint32_t lsh_const, uint32_t rsh_const)
{
  assert(rsh_const < WORD_SIZE);
  assert(lsh_const < WORD_SIZE);

  // RIGHT shift (>> 5)
  uint32_t da_l = da >> rsh_const; // (n - r) MSBs
  double p[4] = {0.0, 0.0, 0.0, 0.0};

  uint32_t cr = 1;
  uint32_t cl = (1ULL << (WORD_SIZE - rsh_const)); // 2^{n-r}
  uint32_t dx[4] = {0, 0, 0, 0};

  // possible differences after (>> 5)
  dx[0] = ((da_l + 0 - 0) + MOD) % MOD;
  dx[1] = ((da_l + 0 - cl) + MOD) % MOD;
  dx[2] = ((da_l + cr - 0) + MOD) % MOD;
  dx[3] = ((da_l + cr - cl) + MOD) % MOD;

  // LEFT shift (<< 4)
  //  uint32_t da_r = (da << lsh_const) & MASK; // only possible diff after (<< 4)
  uint32_t da_r = LSH(da, lsh_const);

  // for each of the four possible output differences after the RSH operation
  // compute the total probability
  for(int i = 0; i < 4; i++) {

	 double p1 = adp_rsh(da, dx[i], rsh_const);
	 double p2 = adp_xor3(A, da, dx[i], da_r, db);

	 p[i] = p1 * p2;

#if 0									  // DEBUG
	 printf("[%s:%d] ADP_RSH  [%d] %8X %31.30f\n", __FILE__, __LINE__, i, dx[i], p1);
	 printf("[%s:%d] ADP_XOR3 [%d] %8X %31.30f\n", __FILE__, __LINE__, i, db, p2);
#endif
  }

  *prob_db = 0.0;

  for(int i = 0; i < 4; i++) {
	 *prob_db += p[i];
  }
#if 0								  // DEBUG
  printf("[%s:%d] Sum %31.30f\n", __FILE__, __LINE__, *prob_db);
#endif

  // if the right rot const is zero then cl = 0 and dx[0] = dx[1] and dx[2] == dx[3]
  // therefore we count two differences twice and thus we must divide the probability by two
  if(rsh_const == 0) {
	 //	 *prob_db /= 2.0;
	 *prob_db *= 0.5;
  }
  return *prob_db;
}

/**
 * For fixed input difference \p da, compute an output difference \p dd that has
 * maximum expected additive differential probability (EADP) averaged over 
 * all round keys and constants of the F-function of TEA:
 *
 * \f$\mathrm{max}_{dd}~\mathrm{eadp}^{F}(da \rightarrow dd) 
 * = 2^{-4n}~\{\#(k_0,k_1,\delta,x) : F(x + da) - F(x) = dd\}\f$.
 *
 * \b Complexity: \f$O(n)\f$.
 *
 * \b Algorithm \b sketch: \f$\mathrm{eadp}^{F}\f$ is computed as the multiplication of ADP-s of the two
 * non-linear (w.r.t. XOR differences) components of F, namely XOR and LSH:
 * 
 * \f[\mathrm{eadp}^{F}(da \rightarrow dd) = 
 * (\sum^3_{i=0} (\mathrm{adp}^{\gg 5}(da, dc_i)))~ \cdot~ 
 * \mathrm{max}_{dd}~\mathrm{adp}^{3\oplus}_{\mathrm{SET}}((da \ll 4), da, \{dc_0, dc_1, dc_2, dc_3\} \rightarrow dd)\f]
 *
 * where \f$dc_i \in \{(da \gg 5), (da \gg 5) + 1, (da \gg 5) - 2^{n-5}, (da \gg 5) - 2^{n-5} + 1\}\f$
 * are the four possible ADD differences after RSH (see \ref adp_rsh)
 * and \f$\mathrm{max}_{dd}~\mathrm{adp}^{3\oplus}_{\mathrm{SET}}\f$ is the maximum ADP 
 * over all outpt differences, of XOR with three inputs
 * where one of the inputs may satisfy any difference from a given \em set (\ref max_adp_xor3_set). 
 *
 * \param A transition probability matrices for \f$\mathrm{adp}^{3\oplus}\f$ (\ref adp_xor3_sf).
 * \param da input difference.
 * \param dd_max maximum probability output difference.
 * \param prob_max maximum expected DP of F over all output differences.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \return \f$\mathrm{max}_{db}~\mathrm{eadp}^{F}(da \rightarrow dd)\f$.
 *
 */
double max_eadp_tea_f(gsl_matrix* A[2][2][2][2], const uint32_t da, uint32_t* dd_max, double* prob_max,
							  uint32_t lsh_const, uint32_t rsh_const)
{
#if 0
  printf("\r[%s:%d] %s() %8X", __FILE__, __LINE__, __FUNCTION__, da);
  fflush(stdout);
#endif
  assert(rsh_const < WORD_SIZE);
  assert(lsh_const < WORD_SIZE);
  assert(ADP_XOR3_SET_SIZE == 4);

  uint32_t db = LSH(da, lsh_const);
  uint32_t dc[ADP_XOR3_SET_SIZE] = {0, 0, 0, 0};
  uint32_t dx[ADP_XOR3_SET_SIZE] = {0, 0, 0, 0};
  //  uint32_t dd = 0;

  // RIGHT shift (>> 5)
  uint32_t cr = 1;
  uint32_t cl = (1UL << (WORD_SIZE - rsh_const)); // 2^{n-r}
  uint32_t da_l = da >> rsh_const; // (n - r) MSBs

  // possible differences after (>> 5)
  dx[0] = ((da_l + 0 - 0) + MOD) % MOD;
  dx[1] = ((da_l + 0 - cl) + MOD) % MOD;
  dx[2] = ((da_l + cr - 0) + MOD) % MOD;
  dx[3] = ((da_l + cr - cl) + MOD) % MOD;

  double p_dc[ADP_XOR3_SET_SIZE] = {0.0, 0.0, 0.0, 0.0};

  uint32_t set_size = 0; 	  // number of non-zero prob differences ion the set
  for(int i = 0; i < ADP_XOR3_SET_SIZE; i++) {
	 double p_rsh = adp_rsh(da, dx[i], rsh_const);
	 if(p_rsh != 0.0) {
		p_dc[set_size] = p_rsh;
		dc[set_size] = dx[i];
		set_size++;
	 }
  }
  assert(set_size > 0);
#if 1									  // DEBUG
  for(int i = 0; i < (int)set_size; i++) {
	 double p_rsh = adp_rsh(da, dc[i], rsh_const);
	 //	 printf("[%s:%d] %d %08x %31.30f\n", __FUNCTION__, __LINE__, i, dc[i], p_rsh);
	 assert(p_rsh != 0.0);
	 assert(p_rsh == p_dc[i]);
  }
#endif
  *prob_max = max_adp_xor3_set(A, da, db, dc, p_dc, dd_max);

  if(rsh_const == 0) {
	 *prob_max *= 0.5;
  }
#if 0									  // DEBUG
  double p_f = eadp_tea_f(A, da, *dd_max, &p_f, lsh_const, rsh_const);
#if 0									  // CHECK for float precision
  if((*prob_max != p_f)) {
	 printf("[%s:%d] WARNING! Float precision: %8X -> %8X %31.30f (2^%f), %31.30f (2^%f)\n", __FILE__, __LINE__, da, *dd_max, *prob_max, log2(*prob_max), p_f, log2(p_f));
  }
  assert(float_equals(*prob_max, p_f));
#endif
#endif

#if DEBUG									  // DEBUG
  printf("[%s:%d] %8X (%f)\n", __FILE__, __LINE__, *dd_max, *prob_max);
#endif
  return *prob_max;
}

/**
 * Computing the maximum expected additive differential probability (EADP) of the F-function of TEA 
 * (see \ref eadp_tea_f), experimentally over all round keys, round constants and output differences.
 *
 * \b Complexity: \f$O(2^{5n})\f$.
 *
 * \param A transition probability matrices for \f$\mathrm{adp}^{3\oplus}\f$ (\ref adp_xor3_sf).
 * \param da input difference.
 * \param dd_max output difference.
 * \param prob_max the maximum expected DP of F.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \return \f$\mathrm{eadp}^{F}(da \rightarrow db)\f$.
 *
 * \see max_eadp_tea_f
 */
double max_eadp_tea_f_exper(gsl_matrix* A[2][2][2][2], const uint32_t da, uint32_t* dd_max, double* prob_max,
									 uint32_t lsh_const, uint32_t rsh_const)
{
  double p_max = 0.0;
  for(uint32_t dd = 0; dd < ALL_WORDS; dd++) {
	 double p = eadp_tea_f(A, da, dd, &p, lsh_const, rsh_const);
	 if(p >= p_max) {
		p_max =p;
		*dd_max = dd;
	 }
  }
  return p_max;
}

/**
 * 
 * For fixed input diffferences \p da, \p db and \p dc, to the XOR
 * operation with three inputs in the TEA F-function, generate an arbitrary output difference \p dd
 * for which the expected DP of F is nonzero i.e. \f$\mathrm{eadp}^{F}(da \rightarrow dd) > 0\f$.
 *
 * \b Complexity c: \f$O(n) \le c \ll O(2^n)\f$.
 *
 * \b Algorithm \b sketch: 
 *
 * The function works recursively starting from the LS bit \p k = 0
 * and terminating at the MS bit \p n. At every bit position i
 * it assigns values to the i-th bit of the output difference \p dd
 * and evaluates the probability of the resulting partial (i+1)-bit differential:
 * \f$(da[i:0], db[i:0], dc[i:0] \rightarrow dd[i:0])\f$. The recursion
 * proceeds only if this probability is not less than the threshold \p p_thres.
 * When i = n, the difference \f$dd[n-1:0]\f$ is stored as the result
 * and the probability \f$\mathrm{eadp}^{F}(da \rightarrow dd)\f$ is returned.
 *
 * \note Note that the threshold \p p_thres is initialized to 0.0, but is
 *       dynamically updated during the execution as soon as a higher value is found.
 *
 * \attention Although the resulting differential \f$(da \rightarrow dd)\f$
 *            is guaranteed to have expected probability, averaged over all keys and constants, 
 *            strictly bigger than zero, its probability may still be zero for some fixed
 *            value of the round keys and \f$\delta\f$ constants.
 *
 * \param k current bit position in the recursion.
 * \param n word size.
 * \param A transition probability matrices for \f$\mathrm{adp}^{3\oplus}\f$ (\ref adp_xor3_sf).
 * \param C unit column vector for computing \f$\mathrm{adp}^{3\oplus}\f$ (\ref adp_xor3). 
 * \param da first input difference to XOR3.
 * \param db second input difference to XOR3.
 * \param dc third input difference to XOR3.
 * \param dd output difference from XOR3 (and F).
 * \param p probability of the differential \f$(da[k:0], db[k:0], dc[k:0] \rightarrow dd[k:0])\f$.
 * \param p_thres probability threshold.
 * \param ret_dd output difference that is returned as result.
 * \param ret_p the EDP \f$\mathrm{eadp}^{F}(da \rightarrow dd)\f$.
 * \param cnt number of output differences generated so far.
 * \param max_cnt maximum number of output differences allowed (typically 1).
 *
 * \see adp_xor_ddt
 */ 
void nz_eadp_tea_f_i(const uint32_t k, const uint32_t n, 
								gsl_matrix* A[2][2][2][2], gsl_vector* C, 
								const uint32_t da, const uint32_t db, const uint32_t dc, uint32_t* dd, 
								double* p, double* p_thres, uint32_t* ret_dd, double* ret_p, uint32_t* cnt, uint32_t max_cnt)
{
  if((k == n) && (*cnt < max_cnt)) {
	 double p_f = eadp_tea_f(A, da, *dd, &p_f, TEA_LSH_CONST, TEA_RSH_CONST);
	 assert(p_f != 0.0);
	 if(p_f > *p_thres) {
		*ret_dd = *dd;
		*ret_p = p_f;
		*p_thres = p_f;
#if 0									  // DEBUG
		printf("[%s:%d] Added new %8X -> %8X  | %f = 2^%f | p_thres = 2^%f | %4d\n", __FILE__, __LINE__, da, *ret_dd, *ret_p, log2(*ret_p), log2(*p_thres), *cnt);
#endif
		(*cnt)++;
	 }
	 return;
  }

  // init L
  gsl_vector* L = gsl_vector_calloc(ADP_XOR3_MSIZE);
  gsl_vector_set_all(L, 1.0);

  // get the k-th bit of da, db, dc
  uint32_t x = (da >> k) & 1;
  uint32_t y = (db >> k) & 1;
  uint32_t z = (dc >> k) & 1;
  for(uint32_t t = 0; t < 2; t++) {

	 // temp
	 gsl_vector* R = gsl_vector_calloc(ADP_XOR3_MSIZE);
	 double new_p = 0.0;

	 // L A C
	 gsl_blas_dgemv(CblasNoTrans, 1.0, A[x][y][z][t], C, 0.0, R);
	 gsl_blas_ddot(L, R, &new_p);

	 //			 if(new_p != 0.0) {
	 if((new_p > *p_thres) && (*cnt < max_cnt)) {
		uint32_t new_dd = *dd | (t << k);
		//		mmult_f_first_nz(k+1, n, A, R, da, db, dc, &new_dd, &new_p, p_thres, ret_dd, ret_p, cnt, max_cnt);
		nz_eadp_tea_f_i(k+1, n, A, R, da, db, dc, &new_dd, &new_p, p_thres, ret_dd, ret_p, cnt, max_cnt);
	 }
	 gsl_vector_free(R);
  }
  gsl_vector_free(L);
}

/**
 * For fixed input diffference \p da to the TEA F-function, 
 * generate an arbitrary output difference \p dd for which the expected DP of F 
 * is above a fixed threshold i.e. \f$\mathrm{eadp}^{F}(da \rightarrow dd) > p_{\mathrm{thres}}\f$.
 *
 * \param A transition probability matrices for \f$\mathrm{adp}^{3\oplus}\f$ (\ref adp_xor3_sf).
 * \param p_thres probability threshold.
 * \param da first input difference to XOR3.
 * \param ret_dd output difference that is returned as result.
 * \return \f$\mathrm{eadp}^{F}(da \rightarrow dd)\f$.
 *
 * \attention Although the resulting differential \f$(da \rightarrow dd)\f$
 *            is guaranteed to have expected probability, averaged over all keys and constants, 
 *            strictly bigger than zero, its probability may still be zero for some fixed
 *            value of the round keys and \f$\delta\f$ constants.
 * 
 * \see nz_eadp_tea_f_i
 */
double nz_eadp_tea_f(gsl_matrix* A[2][2][2][2], double p_thres, uint32_t da, uint32_t* ret_dd)
{
  //  double p_thres = 0.0;//0.00000001;
  uint32_t max_cnt = 1;//10;//20;
  uint32_t k = 0;
  uint32_t n = WORD_SIZE;
  double p = 0.0;

  // init C
  gsl_vector* C = gsl_vector_calloc(ADP_XOR3_MSIZE);
  gsl_vector_set(C, ADP_XOR3_ISTATE, 1.0);

  uint32_t db = LSH(da, TEA_LSH_CONST);
  uint32_t dc = 0;
  uint32_t dx[4] = {0, 0, 0, 0};
  adp_rsh_odiffs(dx, da, TEA_RSH_CONST);
  double p_max = 0.0;
  for(int i = 0; i < 4; i++) {
	 double p_i = adp_rsh(da, dx[i], TEA_RSH_CONST);
	 if(p_i > p_max) {
		dc = dx[i];					  // set the nax prob to dc
	 }
  }

  uint32_t cnt = 0;
  double ret_p = 0.0;
  uint32_t dd = 0;
  nz_eadp_tea_f_i(k, n, A, C, da, db, dc, &dd, &p, &p_thres, ret_dd, &ret_p, &cnt, max_cnt);

  gsl_vector_free(C);
  return ret_p;
}
