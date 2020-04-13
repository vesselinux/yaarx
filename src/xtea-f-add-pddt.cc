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
 * \file  xtea-f-add-pddt.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Computing an ADD partial difference distribution table (pDDT) for the F-function of block cipher XTEA.
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
#ifndef MAX_ADP_XOR_FI_H
#include "max-adp-xor-fi.hh"
#endif
#ifndef ADP_SHIFT_H
#include "adp-shift.hh"
#endif
#ifndef TEA_F_ADD_PDDT_H
#include "tea-f-add-pddt.hh"
#endif
#ifndef XTEA_H
#include "xtea.hh"
#endif
#ifndef ADP_XTEA_F_FK_H
#include "adp-xtea-f-fk.hh"
#endif

/**
 * Computes an ADD partial difference distribution table (pDDT) for
 * the F-function of block cipher TEA.
 *
 * \param k current bit position in the recursion.
 * \param n word size (default is \ref WORD_SIZE).
 * \param key round key.
 * \param delta round constant.
 * \param lsh_const \ref LSH constant (\ref TEA_LSH_CONST).
 * \param rsh_const \ref RSH constant (\ref TEA_RSH_CONST).
 * \param A transition probability matrices for XOR \f$\mathrm{adp}^{\oplus}\f$ (\ref adp_xor_sf).
 * \param AA transition probability matrices for XOR with fixed input
 *        \f$\mathrm{adp}^{\oplus}_{\mathrm{FI}}\f$ (\ref
 *        adp_xor_fixed_input_sf).
 * \param C unit column vector for computing \f$ \mathrm{adp}^{\oplus}\f$ (\ref adp_xor). 
 * \param da input difference to the F-function of XTEA.
 * \param db output difference from the LSH operation in F.
 * \param dc output difference from the RSH operation in F.
 * \param dd output difference from the XOR operation in F.
 * \param p probability of the partially constructed differential
 *        \f$(db[k:0], dc[k:0] \rightarrow dd[k:0])\f$ for the XOR
 *        operation in F.
 * \param p_thres probability threshold (default is \ref XTEA_ADD_P_THRES).
 * \param diff_set_dx_dy set of differentials \f$(dx \rightarrow
 *        dy)\f$ in the pDDT ordered by index \f$i = (dx~ 2^{n} +
 *        dy)\f$; stored in an STL set structure, internally
 *        implemented as a Red-Black binary search tree.
 *
 * \b Algorithm \b Outline:
 * 
 * -# Recursively construct all differentials for the XOR operation in
 *    the \f$f_{\mathrm{LXR}}\f$ component of the F-function of XTEA
 *    (see \ref xtea_f_lxr): \f$ f_{\mathrm{LXR}}(a) = (((a \ll 4)
 *    \oplus (a \gg 5)) \f$.  Note that when doing this, we treat the
 *    two inputs \f$(a \ll 4)\f$ and \f$(a \gg 5)\f$ as independent
 *    inputs, denoted respectively by \f$b\f$ and \f$c\f$. At every
 *    bit position in the recursion we require the corresponding
 *    partially constructed input differences \f$da,db,dc\f$ and the
 *    output difference \f$dd\f$ to satisfy conditions \ref
 *    lsh_condition_is_sat and \ref rsh_condition_is_sat. As a result,
 *    after the MSB is processed and \f$k = n\f$ the so constructed
 *    differences satisfy the following constions (see \ref
 *    tea_f_add_pddt_i):
 *       -# \f$\mathrm{adp}^{3\oplus}(db, dc \rightarrow dd) > p_\mathrm{thres}\f$.
 *       -# \f$db = da \ll 4\f$.
 *       -# \f$dc \in {(da \ll R), (da \ll R) + 1, (da \ll R) -
 *          2^{n-R}, (da \ll R) - 2^{n-R} + 1}\f$, so that \f$dc = (da
 *          \ll R)\f$ where \f$R =\f$\ref TEA_RSH_CONST.
 * -# Set \f$dz = da + dd\f$ according to the feed-forward operation
 *    in F (see \ref xtea_f) and compute the maximum probability
 *    output difference \f$dy\f$ for the ADD operation with round key
 *    and \f$\delta\f$ (see \ref xtea_f) with one fixed input:
 *    \f$\mathrm{max}~\mathrm{adp}^{\oplus}_{\mathrm{FI}}((\mathrm{key}
 *    + \delta),~dz \rightarrow dy)\f$.
 * -# Experimentally adjust the probability of the differential
 *     \f$\mathrm{adp}^{F}(da \rightarrow dy)\f$ to the full function
 *     F using \ref adp_xtea_f_approx . Set the adjusted probability
 *     to \f$\hat{p}\f$.
 * -# Store \f$(da, dy, \hat{p})\f$ in the pDDT.
 *
 * \see tea_f_add_pddt_i
 * 
 */
void xtea_f_add_pddt_i(const uint32_t k, const uint32_t n, const uint32_t key, const uint32_t delta,
							  const uint32_t lsh_const,  const uint32_t rsh_const,
							  gsl_matrix* A[2][2][2], gsl_matrix* AA[2][2][2], gsl_vector* C, 
							  uint32_t* da, uint32_t* db, uint32_t* dc, uint32_t* dd, 
							  double* p, const double p_thres, 
							  std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy)
{
  if(k == n) {
	 // check for property (1)
	 double p_xor_1 = adp_xor(A, *db, *dc, *dd);
	 assert((p_xor_1 >= 0.0) && (p_xor_1 <= 1.0));
	 assert(p_xor_1 == *p);
	 bool b_xor = (*p >= p_thres);
	 assert(b_xor);
	 // check for property (2)
	 bool b_lsh = (*db) == (LSH(*da, lsh_const));
	 assert(b_lsh);
	 // check for property (3)
	 uint32_t dx[4] = {0, 0, 0, 0};
	 adp_rsh_odiffs(dx, *da, rsh_const);
	 bool b_rsh = (*dc == dx[0]) || (*dc == dx[1]) || (*dc == dx[2]) || (*dc == dx[3]);
	 assert(b_rsh);

	 bool b_is_valid = (b_xor && b_lsh && b_rsh);
	 assert(b_is_valid);
	 if(b_is_valid) {

		double p_rsh = adp_rsh(*da, *dc, rsh_const);

		// compute the maximum probability dy for the second XOR operation in F:
		uint32_t dz = ADD(*dd, *da);
		//		uint32_t dk = 0;			  // the difference in the key and delta is zero
		//		double p_xor_2 = max_adp_xor(A, dk, dz, &dy); 
		uint32_t dy = 0;			  // output from the second XOR
		uint32_t val = ADD(key, delta); // fixed input = delta + key
		double p_xor_2 = max_adp_xor_fixed_input(AA, val, dz, &dy);
		*dd = dy;					  // set the output of the F-function to the maximum found dy

		//		double p_f = adp_xtea_f(n, *da, *dd, key, delta, TEA_LSH_CONST, TEA_RSH_CONST); // exact probability -- exponential
		double p_f = p_rsh * p_xor_1 * p_xor_2; // averaed over all keys
#if 1														 // adjust to key
		p_f = adp_xtea_f_approx(NPAIRS, *da, *dd, key, delta, TEA_LSH_CONST, TEA_RSH_CONST); // approximate probability
#endif
#if 0									  // DEBUG
		uint32_t npairs = NPAIRS;
		uint32_t key = random32() & MASK;
		uint32_t delta = random32() & MASK;
		double p_approx = adp_xtea_f_approx(npairs, *da, *dd, key, delta, lsh_const, rsh_const);
		printf("[%s:%d] 2^%f 2^%f\n", __FILE__, __LINE__, log2(p_f), log2(p_approx));
#endif
		if((p_f >= p_thres) && (diff_set_dx_dy->size() < XTEA_ADD_MAX_PDDT_SIZE)) {
		  differential_t diff;
		  diff.dx = *da;
		  diff.dy = *dd;
		  diff.p = p_f;
#if 1									  // DEBUG
		  bool b_found = (diff_set_dx_dy->find(diff) != diff_set_dx_dy->end());
		  if(!b_found) {
		    printf("[%s:%d] Dxy add %8X -> %8X  | %f = 2^%4.2f | %15d\n", __FILE__, __LINE__, diff.dx, diff.dy, diff.p, log2(diff.p), (WORD_T)diff_set_dx_dy->size());
		  }
#endif
		  diff_set_dx_dy->insert(diff);
		}
	 }
	 return;
  }

  // init L
  gsl_vector* L = gsl_vector_calloc(ADP_XOR_MSIZE);
  gsl_vector_set_all(L, 1.0);

  for(uint32_t x = 0; x < 2; x++) { // da
	 for(uint32_t y = 0; y < 2; y++) { // db
		for(uint32_t z = 0; z < 2; z++) { // dc
		  for(uint32_t t = 0; t < 2; t++) { // dd

			 // temp
			 gsl_vector* R = gsl_vector_calloc(ADP_XOR_MSIZE);
			 double new_p = 0.0;

			 // L A C
			 gsl_blas_dgemv(CblasNoTrans, 1.0, A[y][z][t], C, 0.0, R);
			 gsl_blas_ddot(L, R, &new_p);

			 // 
			 // For the averaged case adp-f (no-fixed-key) a sufficient condition
			 // for adp-f(da->dd) >= p_thres is adp-xor(da,db,dc_i->dd) >= p_thres
			 // for every dc_i : dc_i = RSH(da);
			 //			 if(new_p != 0.0) { // <- this finds all differences, but is slow
			 if((new_p >= p_thres) && (diff_set_dx_dy->size() < XTEA_ADD_MAX_PDDT_SIZE)) {
				uint32_t new_da = *da | (x << k);
				uint32_t new_db = *db | (y << k);
				uint32_t new_dc = *dc | (z << k);
				uint32_t new_dd = *dd | (t << k);

				bool b_lsh_con = lsh_condition_is_sat(k, new_da, new_db);
				bool b_rsh_con = rsh_condition_is_sat(k, new_da, new_dc);

				if(b_lsh_con && b_rsh_con) {
				  xtea_f_add_pddt_i(k+1, n, key, delta, lsh_const, rsh_const, A, AA, R, &new_da, &new_db, &new_dc, &new_dd, &new_p, p_thres, diff_set_dx_dy);
				}
			 }
			 gsl_vector_free(R);

		  } // t
		}	 // z
	 }		 // y
  }		 // x

  gsl_vector_free(L);
}

/** 
 * Compute a partial DDT (pDDT) for the XTEA F-function: wrapper function
 * of \ref xtea_f_add_pddt_i . By definition a pDDT contains
 * only differentials that have probability above a fixed
 * probability thershold.
 *
 * \param n word size (default is \ref WORD_SIZE).
 * \param p_thres probability threshold (default is \ref XTEA_ADD_P_THRES).
 * \param lsh_const \ref LSH constant (\ref TEA_LSH_CONST).
 * \param rsh_const \ref RSH constant (\ref TEA_RSH_CONST).
 * \param A transition probability matrices for \f$\mathrm{adp}^{\oplus}\f$ (\ref adp_xor_sf).
 * \param AA transition probability matrices for XOR with fixed input
 *        \f$\mathrm{adp}^{\oplus}_{\mathrm{FI}}\f$ (\ref
 *        adp_xor_fixed_input_sf).
 * \param C unit column vector for computing \f$ \mathrm{adp}^{\oplus}\f$ (\ref adp_xor). 
 * \param key round key.
 * \param delta round constant.
 * \param diff_set_dx_dy set of differentials \f$(dx \rightarrow
 *        dy)\f$ in the pDDT ordered by index \f$i = (dx~ 2^{n} +
 *        dy)\f$; stored in an STL set structure, internally
 *        implemented as a Red-Black binary search tree.
 *
 * \see tea_f_add_pddt_i.
 *
 */
void xtea_f_add_pddt(uint32_t n, double p_thres, uint32_t lsh_const, uint32_t rsh_const,
							gsl_matrix* A[2][2][2], gsl_matrix* AA[2][2][2], gsl_vector* C, 
							uint32_t key, uint32_t delta, 
							std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy)
{
  assert(n == WORD_SIZE);

  uint32_t k = 0;
  double p = 0.0;

  // init A
  //  gsl_matrix* A[2][2][2];
  //  adp_xor_alloc_matrices(A);
  //  adp_xor_sf(A);
  //  adp_xor_normalize_matrices(A);

  // init C
  //  gsl_vector* C = gsl_vector_calloc(ADP_XOR_MSIZE);
  //  gsl_vector_set(C, ADP_XOR_ISTATE, 1.0);

  uint32_t da = 0;
  uint32_t db = 0;
  uint32_t dc = 0;
  uint32_t dd = 0;

  // compute Dxy
  xtea_f_add_pddt_i(k, n, key, delta, lsh_const, rsh_const, A, AA, C, &da, &db, &dc, &dd, &p, p_thres, diff_set_dx_dy);

  //  gsl_vector_free(C);
  //  adp_xor_free_matrices(A);
}

/**
 * From a pDDT represented in the from of a set of differentials
 * ordered by index, compute a pDDT as a set of differentials ordered
 * by probability.
 *
 * \param diff_mset_p output pDDT: set of differentials \f$(dx \rightarrow dy)\f$
 *        ordered by probability; stored in an STL multiset structure,
 *        internally implemented as a Red-Black binary search tree.
 * \param diff_set_dx_dy input pDDT: set of differentials \f$(dx \rightarrow
 *        dy)\f$ ordered by index \f$i = (dx~ 2^{n} + dy)\f$; stored
 *        in an STL set structure, internally implemented as a
 *        Red-Black binary search tree.
 *
 * \see tea_f_add_pddt_dxy_to_dp
 */
void xtea_add_pddt_dxy_to_dp(std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p,
									  const std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy)
{
  // fill the Dp array
  std::set<differential_t, struct_comp_diff_dx_dy>::iterator set_iter;
  for(set_iter = diff_set_dx_dy.begin(); set_iter != diff_set_dx_dy.end(); set_iter++) {
		differential_t diff;
		diff.dx = set_iter->dx;
		diff.dy = set_iter->dy;
		diff.p = set_iter->p;
		diff_mset_p->insert(diff);
  }
  assert(diff_set_dx_dy.size() == diff_mset_p->size());
}
