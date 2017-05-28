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
 * \file  adp-xor-pddt.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Compute a partial difference distribution table (pDDT) for \f$\mathrm{adp}^{\oplus}\f$.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR_H
#include "adp-xor.hh"
#endif

/** 
 * Compute a partial DDT for \f$\mathrm{adp}^{\oplus}\f$ by exhasutive search
 * over all input and output differences.
 *
 * \param diff_set set of all differentials with probability not less than the threshold (the pDDT)
 * \param p_thres probability threshold.
 * \returns number of elements in the pDDT.
 * \see adp_xor_pddt_i
 */
uint32_t adp_xor_ddt_exper(std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_set, double p_thres)
{
  assert(WORD_SIZE < 9);
  uint32_t cnt = 0;

  gsl_matrix* A[2][2][2];
  adp_xor_alloc_matrices(A);
  adp_xor_sf(A);
  adp_xor_normalize_matrices(A);

  for(uint32_t da = 0; da < ALL_WORDS; da++) {
	 for(uint32_t db = 0; db < ALL_WORDS; db++) {
		for(uint32_t dc = 0; dc < ALL_WORDS; dc++) {
		  double p = adp_xor(A, da, db, dc);
		  if(p >= p_thres) {
			 differential_3d_t i_diff;
			 i_diff.dx = da;
			 i_diff.dy = db;
			 i_diff.dz = dc;
			 i_diff.p = p;
			 diff_set->insert(i_diff);
			 cnt++;
		  }
		}
	 }
  }
  adp_xor_free_matrices(A);
  return cnt;
}

/** 
 * Recursively compute all ADD differentials \f$(da, db \rightarrow dc)\f$ 
 * for XOR that have probability \f$\mathrm{adp^{\oplus}}\f$ larger 
 * than a fixed probability threshold \p p_thres.
 *
 * The function works recursively starting from the LS bit \p k = 0
 * and terminating at the MS bit \p n. At every bit position i
 * it assigns values to the i-th bits of the differences \p da, \p db, \p dc
 * and evaluates the probability of the resulting partial (i+1)-bit differential:
 * \f$(da[i:0], db[i:0] \rightarrow dc[i:0])\f$. The recursion
 * proceeds only if this probability is not less than the threshold \p p_thres.
 * When i = n, the differential \f$(da[n-1:0], db[n-1:0] \rightarrow dc[n-1:0])\f$
 * is stored in an STL multiset structure (internally implemented as a Red-Black tree).
 *
 * The \b complexity is strongly dependent on the threshold and is worst-case
 * exponential in the word size: \f$O(2^{3n})\f$.
 * 
 * \note If \p p_thres = 0.0 then the full DDT is computed.
 * \note Can be used also to compute all differentials that have non-zero probability 
 *       by setting p_thres > 0.0 .
 * \note For 32 bit words, recommended values for the threshold are p_thres >= 0.5.
 * 
 * \param k current bit position in the recursion.
 * \param n word size.
 * \param p_thres probability threshold.
 * \param A transition probability matrices for \f$\mathrm{adp}^{\oplus}\f$.
 * \param C unit column vector for computing \f$\mathrm{adp}^{\oplus}\f$ (\ref adp_xor). 
 * \param da first input difference.
 * \param db second input difference.
 * \param dc output difference.
 * \param p probability of the differential \f$(da[k:0], db[k:0] \rightarrow dc[k:0])\f$.
 * \param diff_set set of all differentials with probability not less than the threshold (the pDDT)
 *
 */ 
void adp_xor_pddt_i(const uint32_t k, const uint32_t n, const double p_thres, 
						 gsl_matrix* A[2][2][2], gsl_vector* C, 
						 uint32_t* da, uint32_t* db, uint32_t* dc,
						 double* p, std::multiset<differential_3d_t, struct_comp_diff_3d_p> *diff_set)
{
  if(k == n) {
	 double p_the = adp_xor(A, *da, *db, *dc);
#if 0									  // DEBUG
	 printf("[%s:%d] Add %8X %8X -> %8X : %f = 2^%4.2f\n", __FILE__, __LINE__, *da, *db, *dc, *p, log2(*p));
#endif
#if 0									  // DEBUG
	 printf("[%s:%d] ADP_XOR_THE[(%8X,%8X)->%8X] = %6.5f\n", 
			  __FILE__, __LINE__, *da, *db, *dc, p_the);
	 printf("[%s:%d] ADP_XOR_REC[(%8X,%8X)->%8X] = %6.5f\n", 
			  __FILE__, __LINE__, *da, *db, *dc, *p);
#endif
	 if(p_thres > 0.0) {
		assert(*p > 0.0);
	 }
	 assert(*p == p_the);
	 assert(*p >= p_thres);
#if 1									  // store the difference
	 differential_3d_t i_diff;
	 i_diff.dx = *da;
	 i_diff.dy = *db;
	 i_diff.dz = *dc;
	 i_diff.p = *p;
	 diff_set->insert(i_diff);
#endif  // #if 0									  // do not store the difference
	 return;
  }

  // init L
  gsl_vector* L = gsl_vector_calloc(ADP_XOR_MSIZE);
  gsl_vector_set_all(L, 1.0);

  for(uint32_t x = 0; x < 2; x++) {
	 for(uint32_t y = 0; y < 2; y++) {
		for(uint32_t z = 0; z < 2; z++) {

		  // temp
		  gsl_vector* R = gsl_vector_calloc(ADP_XOR_MSIZE);
		  double new_p = 0.0;

		  // L A C
		  gsl_blas_dgemv(CblasNoTrans, 1.0, A[x][y][z], C, 0.0, R);
		  gsl_blas_ddot(L, R, &new_p);

		  //			 if(new_p != 0.0) {
		  if(new_p >= p_thres) {
			 uint32_t new_da = *da | (x << k);
			 uint32_t new_db = *db | (y << k);
			 uint32_t new_dc = *dc | (z << k);
			 adp_xor_pddt_i(k+1, n, p_thres, A, R, &new_da, &new_db, &new_dc, &new_p, diff_set);
		  }
		  gsl_vector_free(R);
		}
	 }
  }
  gsl_vector_free(L);
}

/** 
 * Compute a partial DDT for \f$\mathrm{adp}^{\oplus}\f$: wrapper function
 * of \ref adp_xor_pddt_i.
 *
 * \param n word size.
 * \param p_thres probability threshold.
 * \see adp_xor_pddt_i.
 */
void adp_xor_ddt(uint32_t n, double p_thres)
{
  //  uint32_t n = WORD_SIZE;
  //  double p_thres = P_THRES;
  uint32_t k = 0;
  double p = 0.0;

  // init A
  gsl_matrix* A[2][2][2];
  adp_xor_alloc_matrices(A);
  adp_xor_sf(A);
  adp_xor_normalize_matrices(A);

  // init C
  gsl_vector* C = gsl_vector_calloc(ADP_XOR_MSIZE);
  gsl_vector_set(C, ADP_XOR_ISTATE, 1.0);

  uint32_t da = 0;
  uint32_t db = 0;
  uint32_t dc = 0;

  std::multiset<differential_3d_t, struct_comp_diff_3d_p> diff_set;
  adp_xor_pddt_i(k, n, p_thres, A, C, &da, &db, &dc, &p, &diff_set);

  printf("[%s:%d] p_thres = %f (2^%f), n = %d, #diffs = %d\n", __FILE__, __LINE__, 
			p_thres, log2(p_thres), WORD_SIZE, diff_set.size());
  uint32_t cnt = 0;
  std::multiset<differential_3d_t, struct_comp_diff_3d_p>::iterator set_iter;
  for(set_iter = diff_set.begin(); set_iter != diff_set.end(); set_iter++) {
	 differential_3d_t i_diff = *set_iter;
	 double p_the = adp_xor(A, i_diff.dx, i_diff.dy, i_diff.dz);
#if 0									  // print all
	 printf("[%s:%d] %4d: ADP_XOR_THRES[(%8X,%8X)->%8X] = %6.5f\n", 
			  __FILE__, __LINE__, cnt, i_diff.dx, i_diff.dy, i_diff.dz, i_diff.p);
#endif				 // #if 0
	 assert(p_the == i_diff.p);
	 cnt++;
  }
  std::multiset<differential_3d_t, struct_comp_diff_3d_p> diff_set_exper;
#if (WORD_SIZE < 10)
  adp_xor_ddt_exper(&diff_set_exper, p_thres);
  printf("[%s:%d] THE #%d, EXP #%d\n", __FILE__, __LINE__, diff_set.size(), diff_set_exper.size());
  assert(diff_set.size() == diff_set_exper.size());
#endif // #if (WORD_SIZE < 10)
  
  gsl_vector_free(C);
  adp_xor_free_matrices(A);
}
