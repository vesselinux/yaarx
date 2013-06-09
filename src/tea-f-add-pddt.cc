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
 * \file  tea-f-add-pddt.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Computing an ADD partial difference distribution table (pDDT) for the F-function of block cipher TEA.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR3_H
#include "adp-xor3.hh"
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
#ifndef ADP_TEA_F_FK_H
#include "adp-tea-f-fk.hh"
#endif

/**
 * 
 * Check if two differences \f$da\f$ and \f$dc\f$, partially
 * constructed up to bit \f$k\f$ (\ref WORD_SIZE \f$> k \ge 0\f$), are
 * valid input and output difference respectively, for the \ref RSH
 * operation. From the partial information for \f$dc\f$, the algorithm
 * estimates if \f$dc\f$ belongs to one of the four possible
 * differences after the \ref RSH operation (see \ref adp_rsh): \f$\{(da
 * \gg R),~ (da \gg R) + 1,~ (da \gg R) - 2^{n-R},~ (da \gg R) -
 * 2^{n-R} + 1\}\f$, where \f$R\f$ is the \ref RSH constant (\ref
 * TEA_RSH_CONST).
 * 
 * \param k bit position: \ref WORD_SIZE \f$> k \ge 0\f$.
 * \param new_da input difference to \ref RSH partially constructed up to bit \f$k\f$.
 * \param new_dc output difference from \ref RSH partially constructed up to bit \f$k\f$.
 * \return TRUE if \f$dc\f$, after being fully constructed, will
 *         be a valid output difference from \ref RSH, given the
 *         input difference \f$da\f$; FALSE otherwise.
 *
 * \attention The function is \em not optimal, meaning that it is
 * overly-restrictive: all diferences \f$(da,dc)\f$ which pass the
 * checks are valid, but there also exist valid differences that do
 * not pass the checks. The reason is that it is hard to detect all
 * valid differences before they have been fully constructed.
 *
 * \b More \b Details:
 * 
 * Given are two differences \f$da\f$ and \f$dc\f$, that are only partially
 * constructed up to bit \f$k\f$ (counting from the LSB \f$k = 0\f$). \ref
 * rsh_condition_is_sat performs checks on \f$da\f$ and \f$dc\f$ and outputs
 * if \f$dc\f$ is such that \f$dc = da \gg R\f$, where \f$R\f$ = \ref
 * TEA_RSH_CONST. The idea is to be able to discard pairs of
 * diferences \f$(da, dc)\f$ before they have been fully constructed. This
 * allows to more efficiently constrct a list of valid differentials
 * for the TEA F-function recursively. We use these conditions in \ref
 * tea_f_add_pddt_i to discard invalid entries early in the recursion.
 * 
 * To perform the checks, the following relations are used:
 * 
 * \f$dc = (da \gg R) \Longrightarrow dc \in \{dc_0, dc_1, dc_2, dc_3\}\f$ where:
 * 
 * - \f$dc_0 = (da \gg R)\f$.
 * - \f$dc_2 = (da \gg R) - 2^{n-R}\f$.
 * - \f$dc_1 = (da \gg R) + 1\f$.
 * - \f$dc_3 = (da \gg R) - 2^{n-R} + 1\f$.
 * 
 * Depending on the bit position \f$k\f$ (some of) the following checks are performed:
 * 
 * -# If \f$(k \ge R)\f$ perform check on the \f$(k-R)\f$ LS bits.
 *    If \f$(k >= R)\f$ we check if the first \f$(k-R)\f$ LSB bits of
 *    \f$(da \gg R)\f$ are equal to the first \f$(k-R)\f$ bits of
 *    \f$dc_i,~ 0 \le i < 4\f$ according to the above equations. So we
 *    check if any of the following four equations hold:
 *   - \f$(da \gg R)[0:(k - R)] = (dc_0)[0:(k - R)]\f$.
 *   - \f$(da \gg R)[0:(k - R)] = (dc_0 + 2^{n-R})[0:(k - R)]\f$.
 *   - \f$(da \gg R)[0:(k - R)] = (dc_0 - 1)[0:(k - R)]\f$.
 *   - \f$(da \gg R)[0:(k - R)] = (dc_0 + 2^{n-R} - 1)[0:(k - R)]\f$.
 * -# Check that the \f$R\f$ LS bits of \f$da\f$ are not zero \f$da[(r-1):0] \neq 0\f$.
 * -# If \f$(k >= R) \wedge (k > (n - R))\f$ check the \f$(n-R)\f$ MS bits.
 *   When \f$(k > (n - R))\f$, \f$(da \gg R)[k] = 0\f$ and we check the top
 *   \f$(n-R)\f$ MS bits of \f$dc\f$. More specifically, we check if the
 *   initial four equations hold for the \f$(n-R)\f$ MS bits of the operands:
 *   - \f$dc_0[(n-1):(n-R+1)] = (da \gg R)[(n-1):(n-R+1)]\f$.
 *   - \f$dc_1[(n-1):(n-R+1)] = ((da \gg R) + 1)[(n-1):(n-R+1)]\f$.
 *   - \f$dc_2[(n-1):(n-R+1)] = ((da \gg R) - 2^{n-R})[(n-1):(n-R+1)]\f$.
 *   - \f$dc_3[(n-1):(n-R+1)] = ((da \gg R) - 2^{n-R} + 1)[(n-1):(n-R+1)]\f$.
 *
 */
bool rsh_condition_is_sat(const uint32_t k, const uint32_t new_da, const uint32_t new_dc)
{
  assert(TEA_RSH_CONST > TEA_LSH_CONST);

  uint32_t R = TEA_RSH_CONST;
  uint32_t n = WORD_SIZE;

  bool b_issat_rsh = true;

  bool b_dc_0 = true;
  bool b_dc_1 = true;
  bool b_dc_2 = true;
  bool b_dc_3 = true;

  bool b_dc_lsb_0 = true;
  bool b_dc_lsb_1 = true;
  bool b_dc_lsb_2 = true;
  bool b_dc_lsb_3 = true;

  bool b_dc_msb_0 = true;
  bool b_dc_msb_1 = true;
  bool b_dc_msb_2 = true;
  bool b_dc_msb_3 = true;

  bool b_da_rlsb = true;

  uint32_t alpha = (1ULL << (n - R)); // 2^{n-R}

  if(k >= R) {
	 // mask for the lower (k - R + 1) LSBits
	 uint32_t mask_krlsb = (0xffffffff >> (32 - (k - R + 1)));
#if 0									  // DEBUG
	 printf("[%s:%d] %d %8X\n", __FILE__, __LINE__, k - R, mask_krlsb);
#endif

	 // Check-1 : (k - R) LSBits
	 // this checks the first (k-R) LSBits of dc
	 uint32_t da_rsh_k_sub_R = (new_da >> R) & mask_krlsb; // (da >> R)[0:(k-R)]
	 uint32_t da_0 = (new_dc - 0) & mask_krlsb;            // (dc)[0:(k-R)]
	 uint32_t da_1 = (new_dc + alpha) & mask_krlsb;        // (dc + 2^{n-r})[0:(k-R)]
	 uint32_t da_2 = (new_dc - 1) & mask_krlsb;	          // (dc - 1)[0:(k-R)]
	 uint32_t da_3 = (new_dc + alpha - 1) & mask_krlsb;    // (dc + 2^{n-r} - 1)[0:(k-R)]

	 b_dc_lsb_0 = (da_0 == da_rsh_k_sub_R);
	 b_dc_lsb_1 = (da_1 == da_rsh_k_sub_R);
	 b_dc_lsb_2 = (da_2 == da_rsh_k_sub_R);
	 b_dc_lsb_3 = (da_3 == da_rsh_k_sub_R);

	 // Check-2
#if 0
	 uint32_t da_rlsb = new_da & ~(0xffffffff << R); // R LSB_s
	 b_da_rlsb = (da_rlsb != 0);
#endif

	 // Check-3 : (n - R) MSBits
	 //	 if(k >= (n - R)) {			  // makes it faster
	 if(k > (n - R)) {
		// mask for the top (n - R) LSBits
		uint32_t mask_msb = (0xffffffff << (n - R)) & MASK; // mask for R MSB
		uint32_t dc_k = new_dc & mask_msb;

		uint32_t da_rsh_k = (new_da >> R);// & mask_msb;
		uint32_t dc_0 = (da_rsh_k + 0)               & mask_msb;
		uint32_t dc_1 = (da_rsh_k + MOD - alpha + 0) & mask_msb;
		uint32_t dc_2 = (da_rsh_k + 1)               & mask_msb;
		uint32_t dc_3 = (da_rsh_k + MOD - alpha + 1) & mask_msb;

		b_dc_msb_0 = (dc_0 == dc_k);
		b_dc_msb_1 = (dc_1 == dc_k);
		b_dc_msb_2 = (dc_2 == dc_k);
		b_dc_msb_3 = (dc_3 == dc_k);
	 }

  }

  b_dc_0 = (b_dc_lsb_0 && b_dc_msb_0);
  b_dc_1 = (b_dc_lsb_1 && b_dc_msb_1);
  b_dc_2 = (b_dc_lsb_2 && b_dc_msb_2 && b_da_rlsb);
  b_dc_3 = (b_dc_lsb_3 && b_dc_msb_3 && b_da_rlsb);

  b_issat_rsh = b_dc_0 || b_dc_1 || b_dc_2 || b_dc_3;

#if 1
  if(k == (n - 1)) {
	 uint32_t dx[4] = {0, 0, 0, 0};
	 adp_rsh_odiffs(dx, new_da, TEA_RSH_CONST);
	 bool b_rsh = (new_dc == dx[0]) || (new_dc == dx[1]) || (new_dc == dx[2]) || (new_dc == dx[3]);
	 assert(b_issat_rsh == b_rsh);
	 //	 b_issat_rsh = b_rsh;
  }
#endif

  return b_issat_rsh;
}

/**
 * 
 * Check if two differences \f$da\f$ and \f$dc\f$, partially
 * constructed up to bit \f$k\f$ (\ref WORD_SIZE \f$> k \ge 0\f$), are
 * valid input and output difference respectively, for the \ref LSH
 * operation.
 * 
 * \param k bit position: \ref WORD_SIZE \f$> k \ge 0\f$.
 * \param new_da input difference to \ref LSH partially constructed up to bit \f$k\f$.
 * \param new_db output difference from \ref LSH partially constructed up to bit \f$k\f$.
 * \return TRUE if \f$dc\f$, after being fully constructed, will
 *         be a valid output difference from \ref LSH, given the
 *         input difference \f$da\f$; FALSE otherwise.
 *
 * \b More \b Details:
 *
 * -# If \f$ k < L \f$: check if \f$db[k:0] = 0\f$.
 * -# If \f$k \ge L\f$: check if \f$(db \gg L)[n-(k-L+1):0] = da[n-(k-L+1):0]\f$.
 * 
 * where \f$L =\f$\ref TEA_LSH_CONST, \f$n=\f$\ref WORD_SIZE.
 *
 * \see rsh_condition_is_sat
 */
bool lsh_condition_is_sat(const uint32_t k, const uint32_t new_da, const uint32_t new_db)
{
  assert(TEA_RSH_CONST > TEA_LSH_CONST);

  bool b_issat_lsh = true;
  uint32_t L = TEA_LSH_CONST;
  if(k < L) { // db[k] == 0
	 b_issat_lsh = (new_db == 0);
  } else {				  // db[k] == da[k - lsh_const]
	 uint32_t mask_lsb_k = 0xffffffff >> (32 - (k - L + 1));
	 uint32_t da_lsb = new_da & mask_lsb_k;
	 uint32_t db_msb = (new_db >> L) & mask_lsb_k;
	 b_issat_lsh = (da_lsb == db_msb);
  }
  return b_issat_lsh;
}

/**
 * Computes a partial difference distribution table (pDDT) for the
 * F-function of block cipher TEA.
 *
 *
 * \param k current bit position in the recursion.
 * \param n word size (default is \ref WORD_SIZE).
 * \param lsh_const \ref LSH constant (default is 4).
 * \param rsh_const \ref RSH constant (default is 5).
 * \param A transition probability matrices for \f$\mathrm{adp}^{3\oplus}\f$ (\ref adp_xor3_sf).
 * \param C unit column vector for computing \f$ \mathrm{adp}^{3\oplus}\f$ (\ref adp_xor3). 
 * \param da first input difference to the XOR operation in F.
 * \param db second input difference to the XOR operation in F.
 * \param dc third input difference to the XOR operation in F.
 * \param dd output difference from the XOR operation in F.
 * \param p probability of the partially constructed differential
 *        \f$(da[k:0], db[k:0], dc[k:0] \rightarrow dd[k:0])\f$.
 * \param p_thres probability threshold (default is \ref TEA_ADD_P_THRES).
 * \param diff_set_dx_dy set of differentials \f$(dx \rightarrow
 *        dy)\f$ in the pDDT ordered by index \f$i = (dx~ 2^{n} +
 *        dy)\f$; stored in an STL set structure, internally
 *        implemented as a Red-Black binary search tree.
 * 
 * \attention The computed pDDT is based on the expected additive
 * differential probability of the TEA F-function (\ref eadp_tea_f),
 * averaged over all round keys and round constants \f$\delta\f$ and
 * therefore contains average (as opposed to fixed-key fixed-constants
 * \ref adp_f_fk) probabilities.
 *
 * \b Algorithm \b Outline:
 * 
 * Applies conceptually the same logic as \ref adp_xor_pddt_i. It
 * recursively constructs all differentials for the XOR operation with
 * three inputs \f$(da, db, dc \rightarrow dd)\f$, with the additional
 * requirement that they must satisfy the following properties:
 * 
 * -# \f$\mathrm{adp}^{3\oplus}(da, db, dc \rightarrow dd) > p_\mathrm{thres}\f$.
 * -# \f$db = da \ll 4\f$.
 * -# \f$dc \in {(da \ll R), (da \ll R) + 1, (da \ll R) - 2^{n-R}, (da
 *     \ll R) - 2^{n-R} + 1}\f$, so that \f$dc = (da \ll R)\f$ where
 *     \f$R =\f$\ref TEA_RSH_CONST.
 * 
 * Only the entries for which \f$\mathrm{eadp}^{F}(da \rightarrow dd) > p_\mathrm{thres}\f$ are stored.
 * 
 * \see adp_xor_pddt_i, lsh_condition_is_sat, rsh_condition_is_sat.
 * 
 */
void tea_f_add_pddt_i(const uint32_t k, const uint32_t n, 
							 const uint32_t lsh_const,  const uint32_t rsh_const,
							 gsl_matrix* A[2][2][2][2], gsl_vector* C, 
							 uint32_t* da, uint32_t* db, uint32_t* dc, uint32_t* dd, 
							 double* p, const double p_thres, 
							 std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy)
{
  if(k == n) {
	 // check for property (1)
	 double p_xor3 = adp_xor3(A, *da, *db, *dc, *dd);
	 assert((p_xor3 >= 0.0) && (p_xor3 <= 1.0));
	 assert(p_xor3 == *p);
	 bool b_xor3 = (*p >= p_thres);
	 assert(b_xor3);
	 // check for property (2)
	 bool b_lsh = (*db) == (LSH(*da, lsh_const));
	 assert(b_lsh);
	 // check for property (3)
	 uint32_t dx[4] = {0, 0, 0, 0};
	 adp_rsh_odiffs(dx, *da, rsh_const);
	 bool b_rsh = (*dc == dx[0]) || (*dc == dx[1]) || (*dc == dx[2]) || (*dc == dx[3]);
	 assert(b_rsh);

	 bool b_is_valid = (b_xor3 && b_lsh && b_rsh);
	 assert(b_is_valid);

	 double p_f = eadp_tea_f(A, *da, *dd, &p_f, lsh_const, rsh_const); // eadp_tea_f
	 if(p_f >= p_thres) {

		differential_t diff;
		diff.dx = *da;
		diff.dy = *dd;
		diff.p = p_f;

		if(diff_set_dx_dy->size() < TEA_ADD_MAX_PDDT_SIZE) {
#if 0									  // DEBUG
		  bool b_found = (diff_set_dx_dy->find(diff) != diff_set_dx_dy->end());
		  if(!b_found) {
			 printf("[%s:%d] Dxy add %8X -> %8X  | %f = 2^%4.2f | %15d\n", __FILE__, __LINE__, diff.dx, diff.dy, diff.p, log2(diff.p), diff_set_dx_dy->size());
		  }
#endif
		  diff_set_dx_dy->insert(diff);
		}
	 }
	 return;
  }

  // init L
  gsl_vector* L = gsl_vector_calloc(ADP_XOR3_MSIZE);
  gsl_vector_set_all(L, 1.0);

  for(uint32_t x = 0; x < 2; x++) {
	 for(uint32_t y = 0; y < 2; y++) {
		for(uint32_t z = 0; z < 2; z++) {
		  for(uint32_t t = 0; t < 2; t++) {
			 gsl_vector* R = gsl_vector_calloc(ADP_XOR3_MSIZE);
			 double new_p = 0.0;

			 // L A C
			 gsl_blas_dgemv(CblasNoTrans, 1.0, A[x][y][z][t], C, 0.0, R);
			 gsl_blas_ddot(L, R, &new_p);

			 // 
			 // For the averaged case adp-f (no-fixed-key) a sufficient condition
			 // for adp-f(da->dd) >= p_thres is adp-xor3(da,db,dc_i->dd) >= p_thres
			 // for every dc_i : dc_i = RSH(da);
			 //			 if(new_p != 0.0) { // <- this finds all differences, but is *slow*
			 if(new_p >= p_thres) {
				uint32_t new_da = *da | (x << k);
				uint32_t new_db = *db | (y << k);
				uint32_t new_dc = *dc | (z << k);
				uint32_t new_dd = *dd | (t << k);

				bool b_lsh_con = lsh_condition_is_sat(k, new_da, new_db);
				bool b_rsh_con = rsh_condition_is_sat(k, new_da, new_dc);

				if(b_lsh_con && b_rsh_con) {
				  tea_f_add_pddt_i(k+1, n, lsh_const, rsh_const, A, R, &new_da, &new_db, &new_dc, &new_dd, &new_p, p_thres, diff_set_dx_dy);
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
 * Compute a partial DDT (pDDT) for the TEA F-function: wrapper function
 * of \ref tea_f_add_pddt_i . By definition a pDDT contains
 * only differentials that have probability above a fixed
 * probability thershold.
 *
 * \param n word size (default is \ref WORD_SIZE).
 * \param p_thres probability threshold (default is \ref TEA_ADD_P_THRES).
 * \param lsh_const \ref LSH constant (\ref TEA_LSH_CONST).
 * \param rsh_const \ref RSH constant (\ref TEA_RSH_CONST).
 * \param diff_set_dx_dy set of differentials \f$(dx \rightarrow
 *        dy)\f$ in the pDDT ordered by index \f$i = (dx~ 2^{n} +
 *        dy)\f$; stored in an STL set structure, internally
 *        implemented as a Red-Black binary search tree.
 *
 * \see tea_f_add_pddt_i.
 *
 */
void tea_f_add_pddt(uint32_t n, double p_thres, uint32_t lsh_const, uint32_t rsh_const,
						  std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy)
{
  assert(n == WORD_SIZE);

  uint32_t k = 0;
  double p = 0.0;

  // init A
  gsl_matrix* A[2][2][2][2];
  adp_xor3_alloc_matrices(A);
  adp_xor3_sf(A);
  adp_xor3_normalize_matrices(A);

  // init C
  gsl_vector* C = gsl_vector_calloc(ADP_XOR3_MSIZE);
  gsl_vector_set(C, ADP_XOR3_ISTATE, 1.0);

  uint32_t da = 0;
  uint32_t db = 0;
  uint32_t dc = 0;
  uint32_t dd = 0;

  // compute Dxy
  tea_f_add_pddt_i(k, n, lsh_const, rsh_const, A, C, &da, &db, &dc, &dd, &p, p_thres, diff_set_dx_dy);

  gsl_vector_free(C);
  adp_xor3_free_matrices(A);
}

/**
 *
 * Adjust the probabailities of the differentials in a pDDT computed
 * with \ref tea_f_add_pddt , to the value of a fixed key by
 * performing one-round TEA encryptions over a number of chosen
 * plaintext pairs drawn uniformly at random.
 * 
 * \param nrounds total number of rounds (\ref NROUNDS).
 * \param npairs number of chosen plaintext pairs (\ref NPAIRS).
 * \param key cryptographic key of TEA.
 * \param p_thres probability threshold (\ref TEA_ADD_P_THRES).
 * \param diff_set_dx_dy set of differentials (the pDDT) ordered by index
 *        \f$i = (dx~ 2^{n} + dy)\f$ - smallest first.
 */ 
void tea_f_add_pddt_adjust_to_key(uint32_t nrounds, uint32_t npairs, uint32_t key[4], double p_thres,
											 std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy)
{
  std::set<differential_t, struct_comp_diff_dx_dy>::iterator set_iter;
  for(set_iter = diff_set_dx_dy->begin(); set_iter != diff_set_dx_dy->end(); set_iter++) {
	 uint32_t dx = set_iter->dx;
	 uint32_t dy = set_iter->dy;

	 double p_min = 1.0;
	 for(uint32_t round_idx = 0; round_idx < nrounds; round_idx++) { 
		double p = tea_add_diff_adjust_to_key(npairs, round_idx, dx, dy, key); 
		if(p < p_min) {
		  p_min = p;
		}
	 }
	 differential_t diff;
	 diff.dx = dx;
	 diff.dy = dy;
	 diff.p = p_min;
	 diff_set_dx_dy->erase(set_iter);
	 if(diff.p >= p_thres) {
		diff_set_dx_dy->insert(diff);
	 }
  }
}

/**
 * From a pDDT represented in the form of a set of differentials
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
 */
void tea_f_add_pddt_dxy_to_dp(std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p,
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

/**
 * Experimentally compute the full DDT of the TEA F-function
 * containining expected probabilities, averaged over all keys and
 * round constants. An exhautive search is performed over all input
 * and output differences. \b Complexity: \f$O(2^{2n})\f$.
 *
 * \param A transition probability matrices for \f$\mathrm{adp}^{3\oplus}\f$ (\ref adp_xor3_sf).
 * \param n word size (default is \ref WORD_SIZE).
 * \param p_thres probability threshold (default is \ref TEA_ADD_P_THRES).
 * \param lsh_const \ref LSH constant (\ref TEA_LSH_CONST).
 * \param rsh_const \ref RSH constant (\ref TEA_RSH_CONST).
 * \param diff_mset_p set of differentials \f$(dx \rightarrow dy)\f$
 *        ordered by probability (the DDT).
 *
 */ 
void tea_f_add_pddt_exper(gsl_matrix* A[2][2][2][2], uint32_t n, double p_thres,
								  uint32_t lsh_const, uint32_t rsh_const, 
								  std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p)
{
  assert(n <= 10);				  // infeasibe for large word size
  diff_mset_p->clear();
  for(uint32_t da = 0; da < ALL_WORDS; da++) {
	 for(uint32_t dd = 0; dd < ALL_WORDS; dd++) {
		double p = eadp_tea_f(A, da, dd, &p, lsh_const, rsh_const);
		if(p >= p_thres) {
		  differential_t diff;
		  diff.dx = da;
		  diff.dy = dd;
		  diff.p = p;
		  diff_mset_p->insert(diff);
		}
	 }
  }
}

/**
 * Experimentally compute the full DDT of the TEA F-function
 * containining probabilities for a fixed key and round constant.
 * An exhautive search is performed over all input
 * and output differences. \b Complexity: \f$O(2^{2n})\f$.
 *
 * \param n word size (default is \ref WORD_SIZE).
 * \param p_thres probability threshold (default is \ref TEA_ADD_P_THRES).
 * \param delta round constant.
 * \param k0 first round key.
 * \param k1 second round key.
 * \param lsh_const \ref LSH constant (\ref TEA_LSH_CONST).
 * \param rsh_const \ref RSH constant (\ref TEA_RSH_CONST).
 * \param diff_mset_p set of differentials \f$(dx \rightarrow dy)\f$
 *        ordered by probability (the DDT).
 *
 */ 
void tea_f_add_pddt_fk_exper(uint32_t n, double p_thres, 
									  uint32_t delta, uint32_t k0, uint32_t k1,
									  uint32_t lsh_const, uint32_t rsh_const,
									  std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p)
{
  assert(n <= 10);				  // infeasibe for large word size
  diff_mset_p->clear();
  for(uint32_t da = 0; da < ALL_WORDS; da++) {
	 for(uint32_t dd = 0; dd < ALL_WORDS; dd++) {
		double p = adp_f_fk(n, da, dd, k0, k1, delta, lsh_const, rsh_const);
		if(p >= p_thres) {
		  differential_t diff;
		  diff.dx = da;
		  diff.dy = dd;
		  diff.p = p;
		  diff_mset_p->insert(diff);
		}
	 }
  }
}

// {--- 20130411

/**
 * For a given difference dx, check if in the
 * list of differentials set_dx_dy exists an entry (dx -> dy)
 */
bool is_dx_in_set_dx_dy(uint32_t dy, uint32_t dx_prev, std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy)
{
  assert(diff_set_dx_dy.size() != 0);
  bool b_is_inset = false;
  std::set<differential_t, struct_comp_diff_dx_dy>::iterator set_iter = diff_set_dx_dy.begin();;
  while((set_iter != diff_set_dx_dy.end()) && (!b_is_inset)) {
	 uint32_t dz = ADD(dy, dx_prev);
	 b_is_inset = (dz == set_iter->dx);
	 set_iter++;
  }
  assert(diff_set_dx_dy.size() != 0);
  return b_is_inset;
}

/**
 * Same as \ref is_dx_in_set_dx_dy but on the mask_i LSBs .
 */
bool is_dx_in_set_dx_dy_mask_i(uint32_t mask_i, 
										 const uint32_t dy, const uint32_t dx_prev, std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy)
{
  //  printf("[%s:%d] Enter %s()\n", __FILE__, __LINE__, __FUNCTION__);
  bool b_is_inset = false;
  std::set<differential_t, struct_comp_diff_dx_dy>::iterator set_iter = diff_set_dx_dy.begin();;
  while((set_iter != diff_set_dx_dy.end()) && (!b_is_inset)) {
	 uint32_t dy_mask = dy & mask_i;
	 //	 uint32_t dx_prev_mask = dx_prev & mask_i;
	 uint32_t dz_mask = ADD(dy_mask, dx_prev) & mask_i;
#if 0									  // DEBUG
	 printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, dz_mask, (set_iter->dx & mask_i));
#endif
	 b_is_inset = (dz_mask == (set_iter->dx & mask_i));
	 set_iter++;
  }
  return b_is_inset;
}

/**
 *
 * \param k current bit position in the recursion.
 * \param n word size (default is \ref WORD_SIZE).
 * \param lsh_const \ref LSH constant (default is 4).
 * \param rsh_const \ref RSH constant (default is 5).
 * \param A transition probability matrices for \f$\mathrm{adp}^{3\oplus}\f$ (\ref adp_xor3_sf).
 * \param C unit column vector for computing \f$ \mathrm{adp}^{3\oplus}\f$ (\ref adp_xor3). 
 * \param da first input difference to the XOR operation in F.
 * \param db second input difference to the XOR operation in F.
 * \param dc third input difference to the XOR operation in F.
 * \param dd output difference from the XOR operation in F.
 * \param p probability of the partially constructed differential
 *        \f$(da[k:0], db[k:0], dc[k:0] \rightarrow dd[k:0])\f$.
 * \param p_thres probability threshold (default is \ref TEA_ADD_P_THRES).
 * \param da_prev input difference to the previous round.
 * \param hways_diff_mset_p set of differentials \f$(dx,dy,p)\f$ (Highways)
 *        ordered by probability p.
 * \param hways_diff_set_dx_dy set of differentials \f$(dx,dy,p)\f$ (Highways)
 *        ordered by index \f$i = (dx~ 2^{n} + dy)\f$.
 * \param diff_mset_p temporrary set of differentials \f$(dx,dy,p)\f$ (Countryroads)
 *        ordered by probability p.
 * \param diff_set_dx_dy set of differentials \f$(dx,dy,p)\f$ (Countryroads)
 *        ordered by index \f$i = (dx~ 2^{n} + dy)\f$.
 * \param cnt_new number of output differences that were added .
 *
 * For a fixed input difference \f$\alpha_r\f$ to round \f$r\f$
 * compute a list of output differences \f$\beta_r\f$ that satisfy the
 * following conditions:
 *
 * -# The probability of the differential \f$(\alpha_r \rightarrow
 * \beta_r)\f$ is bigger than a pre-defined threshold \p p_thres .  
 * -# The input difference \f$\alpha_{r+1} = \alpha_{r-1} +
 * \beta_{r}\f$ to the next round has a matching entry in the
 * pre-computed pDDT \p hways_diff_set_dx_dy.
 * 
 * \see tea_f_add_pddt_i , tea_add_threshold_search_full
 *
 */
void tea_f_da_db_dc_add_pddt_i(const uint32_t k, const uint32_t n, 
										 const uint32_t lsh_const,  const uint32_t rsh_const,
										 gsl_matrix* A[2][2][2][2], gsl_vector* C,
										 const uint32_t da, const uint32_t db, const uint32_t dc, uint32_t* dd, 
										 double* p, const double p_thres, uint32_t da_prev, 
										 std::set<differential_t, struct_comp_diff_dx_dy>* hways_diff_set_dx_dy,
										 std::multiset<differential_t, struct_comp_diff_p>* hways_diff_mset_p,
										 std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy,
										 std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p,
										 uint32_t* cnt_new)
{
  if(k == n) {
#if 0									  // DEBUG
	 // check for property (1)
	 double p_xor3 = adp_xor3(A, da, db, dc, *dd);
	 assert((p_xor3 >= 0.0) && (p_xor3 <= 1.0));
	 assert(p_xor3 == *p);
	 bool b_xor3 = (*p >= p_thres);
	 assert(b_xor3);
	 // check for property (2)
	 bool b_lsh = (db) == (LSH(da, lsh_const));
	 assert(b_lsh);
	 // check for property (3)
	 uint32_t dx[4] = {0, 0, 0, 0};
	 adp_rsh_odiffs(dx, da, rsh_const);
	 bool b_rsh = (dc == dx[0]) || (dc == dx[1]) || (dc == dx[2]) || (dc == dx[3]);
	 assert(b_rsh);
	 bool b_is_valid = (b_xor3 && b_lsh && b_rsh);
	 assert(b_is_valid);
#endif

	 // check if the output difference *dd is in the Highway set 
#define RESTRICT_CROADS
#ifdef RESTRICT_CROADS
	 bool b_is_inset = is_dx_in_set_dx_dy(*dd, da_prev, *hways_diff_set_dx_dy);
#else
	 bool b_is_inset = true;
#endif
	 double p_f = eadp_tea_f(A, da, *dd, &p_f, lsh_const, rsh_const); // eadp_tea_f

	 //	 printf("[%s:%d] (%8X, %8X, %8X) -> %8X, 2^%f, 2^%f\n", __FILE__, __LINE__, da, db, dc, *dd, log2(p_f), log2(p_thres));

	 if((p_f >= p_thres) && (b_is_inset)){

		differential_t diff;
		diff.dx = da;
		diff.dy = *dd;
		diff.p = p_f;

		if(diff_set_dx_dy->size() < TEA_ADD_MAX_PDDT_SIZE) {
		  bool b_found = (diff_set_dx_dy->find(diff) != diff_set_dx_dy->end());
		  if(!b_found) {
			 // add in Dp only if it is not found in Dxy
			 diff_mset_p->insert(diff);
			 diff_set_dx_dy->insert(diff);
			 (*cnt_new)++;
		  }
		}
	 }
	 return;
  }

#if 0									  // DEBUG
  printf("\r[%s:%d] %s() [%2d]: 2^%f >? 2%f", __FILE__, __LINE__, __FUNCTION__, k, log2(*p), log2(p_thres));
  fflush(stdout);
#endif

  // init L
  gsl_vector* L = gsl_vector_calloc(ADP_XOR3_MSIZE);
  gsl_vector_set_all(L, 1.0);

  uint32_t x = (da >> k) & 1;
  uint32_t y = (db >> k) & 1;
  uint32_t z = (dc >> k) & 1;

  for(uint32_t t = 0; t < 2; t++) {
	 gsl_vector* R = gsl_vector_calloc(ADP_XOR3_MSIZE);
	 double new_p = 0.0;

	 // L A C
	 gsl_blas_dgemv(CblasNoTrans, 1.0, A[x][y][z][t], C, 0.0, R);
	 gsl_blas_ddot(L, R, &new_p);

	 if(new_p >= p_thres) {
		uint32_t new_da = da;//*da | (x << k);
		uint32_t new_db = db;//*db | (y << k);
		uint32_t new_dc = dc;//*dc | (z << k);
		uint32_t new_dd = *dd | (t << k);

#ifdef RESTRICT_CROADS
		uint32_t mask_i = 0xffffffff >> (WORD_SIZE - k);
		bool b_is_inset_mask = is_dx_in_set_dx_dy_mask_i(mask_i, new_dd, da_prev, *hways_diff_set_dx_dy);
		if(b_is_inset_mask) {
		  tea_f_da_db_dc_add_pddt_i(k+1, n, lsh_const, rsh_const, A, R, new_da, new_db, new_dc, &new_dd, &new_p, p_thres, da_prev, hways_diff_set_dx_dy, hways_diff_mset_p, diff_set_dx_dy, diff_mset_p, cnt_new);
		}
#else
		tea_f_da_db_dc_add_pddt_i(k+1, n, lsh_const, rsh_const, A, R, new_da, new_db, new_dc, &new_dd, &new_p, p_thres, da_prev, hways_diff_set_dx_dy, hways_diff_mset_p, diff_set_dx_dy, diff_mset_p, cnt_new);
#endif
	 }
	 gsl_vector_free(R);

  } // t
  gsl_vector_free(L);
}

/**
 * Wrapper for \ref tea_f_da_db_dc_add_pddt_i . Returns the number of
 * new entries that were added .
 *
 * \param n word size (default is \ref WORD_SIZE).
 * \param p_thres probability threshold (default is \ref TEA_ADD_P_THRES).
 * \param lsh_const \ref LSH constant (default is \ref TEA_LSH_CONST).
 * \param rsh_const \ref RSH constant (default is \ref TEA_RSH_CONST).
 * \param da input difference to F.
 * \param da_prev input difference to the previous round.
 * \param hways_diff_set_dx_dy set of differentials \f$(dx,dy,p)\f$ (Highways)
 *        ordered by index \f$i = (dx~ 2^{n} + dy)\f$.
 * \param hways_diff_mset_p set of differentials \f$(dx,dy,p)\f$ (Highways)
 *        ordered by probability p.
 * \param diff_set_dx_dy set of differentials \f$(dx,dy,p)\f$ (Countryroads)
 *        ordered by index \f$i = (dx~ 2^{n} + dy)\f$.
 * \param diff_mset_p temporrary set of differentials \f$(dx,dy,p)\f$ (Countryroads)
 *        ordered by probability p.
 * \returns number of output differences that were added to \p diff_set_dx_dy .
 *
 */
uint32_t tea_f_da_add_pddt(uint32_t n, double p_thres, 
									uint32_t lsh_const, uint32_t rsh_const, const uint32_t da, const uint32_t da_prev,
									std::set<differential_t, struct_comp_diff_dx_dy>* hways_diff_set_dx_dy,
									std::multiset<differential_t, struct_comp_diff_p>* hways_diff_mset_p,
									std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy,
									std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p)
{
#if 0									  // DEBUG
  printf("[%s:%d] %s() enter... dx %8X, p_min 2^%f\n", __FILE__, __LINE__, __FUNCTION__, da, log2(p_thres));
#endif
  assert(n == WORD_SIZE);

  uint32_t k = 0;
  double p = 0.0;
  uint32_t cnt_new = 0;

  // init A
  gsl_matrix* A[2][2][2][2];
  adp_xor3_alloc_matrices(A);
  adp_xor3_sf(A);
  adp_xor3_normalize_matrices(A);

  // init C
  gsl_vector* C = gsl_vector_calloc(ADP_XOR3_MSIZE);
  gsl_vector_set(C, ADP_XOR3_ISTATE, 1.0);

  uint32_t dx[4] = {0, 0, 0, 0};
  adp_rsh_odiffs(dx, da, rsh_const);

  uint32_t db = (LSH(da, lsh_const));

  assert(hways_diff_set_dx_dy->size() != 0);
  for(uint32_t i = 0; i < 4; i++) {

	 uint32_t dc = dx[i];
	 uint32_t dd = 0;

	 // compute Dxy
#if 1
	 tea_f_da_db_dc_add_pddt_i(k, n, lsh_const, rsh_const, A, C, da, db, dc, &dd, &p, p_thres, da_prev, hways_diff_set_dx_dy, hways_diff_mset_p, diff_set_dx_dy, diff_mset_p, &cnt_new);
#endif
  }

  gsl_vector_free(C);
  adp_xor3_free_matrices(A);
#if 0									  // DEBUG
  //  printf("[%s:%d] %s() exit...\n", __FILE__, __LINE__, __FUNCTION__);
  printf("[%s:%d] %s() exit... dx %8X, p_min 2^%f\n", __FILE__, __LINE__, __FUNCTION__, da, log2(p_thres));
#endif
  return cnt_new;
}

// 20130411 ---}
