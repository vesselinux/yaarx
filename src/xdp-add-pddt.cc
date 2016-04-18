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
 * \file  xdp-add-pddt.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Compute a partial difference distribution table (pDDT) for \f$\mathrm{xdp}^{+}\f$.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_ADD_H
#include "xdp-add.hh"
#endif

/** 
 * Compute a partial DDT for \f$\mathrm{xdp}^{+}\f$ by exhasutive search
 * over all input and output differences.
 *
 * \param diff_mset_p set of all differentials with probability not less than the threshold (the pDDT)
 * \param p_thres probability threshold.
 * \returns number of elements in the pDDT.
 * \see xdp_add_pddt_i
 */
uint32_t xdp_add_pddt_exper(std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_mset_p, double p_thres)
{
  assert(WORD_SIZE < 9);
  uint32_t cnt = 0;

  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  for(uint32_t da = 0; da < ALL_WORDS; da++) {
	 for(uint32_t db = 0; db < ALL_WORDS; db++) {
		for(uint32_t dc = 0; dc < ALL_WORDS; dc++) {
		  double p = xdp_add(A, da, db, dc);
		  if(p >= p_thres) {
			 differential_3d_t i_diff;
			 i_diff.dx = da;
			 i_diff.dy = db;
			 i_diff.dz = dc;
			 i_diff.p = p;
			 diff_mset_p->insert(i_diff);
			 cnt++;
		  }
		}
	 }
  }
  xdp_add_free_matrices(A);
  return cnt;
}

/** 
 * Recursively compute all XOR differentials \f$(da, db \rightarrow dc)\f$ 
 * for ADD that have probability \f$\mathrm{xdp^{+}}\f$ larger 
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
 * \note For 32 bit words, recommended values for the threshold are p_thres >= 0.7.
 * 
 * \param k current bit position in the recursion.
 * \param n word size.
 * \param p_thres probability threshold.
 * \param A transition probability matrices for \f$\mathrm{xdp}^{+}\f$ (\ref xdp_add_sf).
 * \param C unit column vector for computing \f$\mathrm{xdp}^{+}\f$ (\ref xdp_add). 
 * \param da first input difference.
 * \param db second input difference.
 * \param dc output difference.
 * \param p probability of the differential \f$(da[k:0], db[k:0] \rightarrow dc[k:0])\f$.
 * \param diff_mset_p set of all differentials with probability not less than the threshold (the pDDT)
 *
 */ 
void xdp_add_pddt_i(const uint32_t k, const uint32_t n, const double p_thres, 
						  gsl_matrix* A[2][2][2], gsl_vector* C, 
						  uint32_t* da, uint32_t* db, uint32_t* dc, double* p, 
						  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* diff_set_dx_dy_dz,
						  std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_mset_p,
						  uint64_t max_size)
{
  if(k == n) {
	 double p_the = xdp_add(A, *da, *db, *dc);
#if 0									  // DEBUG
	 printf("[%s:%d] XDP_ADD_THE[(%8X,%8X)->%8X] = %6.5f\n", 
			  __FILE__, __LINE__, *da, *db, *dc, p_the);
	 printf("[%s:%d] XDP_ADD_REC[(%8X,%8X)->%8X] = %6.5f\n", 
			  __FILE__, __LINE__, *da, *db, *dc, *p);
#endif
	 if(p_thres > 0.0) {
		assert(*p > 0.0);
	 }
	 assert(*p == p_the);
	 assert(*p >= p_thres);
	 uint64_t len = diff_set_dx_dy_dz->size();
	 bool b_back_to_hway = true;
	 if((*p > p_thres) && (len < max_size) && (b_back_to_hway)) {
#if 1									  // store the difference
		differential_3d_t i_diff;
		i_diff.dx = *da;
		i_diff.dy = *db;
		i_diff.dz = *dc;
		i_diff.p = *p;
		diff_set_dx_dy_dz->insert(i_diff);
		diff_mset_p->insert(i_diff);
#endif  // #if 0									  // do not store the difference
#if 0									  // DEBUG
		printf("\r[%s:%d] %10lld / %10lld | Add %8X %8X -> %8X : %f 2^%4.2f | 2^%4.2f", __FILE__, __LINE__, len, max_size, *da, *db, *dc, *p, log2(*p), log2(p_thres));
		fflush(stdout);
#endif
	 }
	 return;
  }

  if(diff_set_dx_dy_dz->size() == max_size)
	 return;

  // init L
  gsl_vector* L = gsl_vector_calloc(XDP_ADD_MSIZE);
  gsl_vector_set_all(L, 1.0);

  for(uint32_t x = 0; x < 2; x++) {
	 for(uint32_t y = 0; y < 2; y++) {
		for(uint32_t z = 0; z < 2; z++) {

		  // temp
		  gsl_vector* R = gsl_vector_calloc(XDP_ADD_MSIZE);
		  double new_p = 0.0;

		  // L A C
		  gsl_blas_dgemv(CblasNoTrans, 1.0, A[x][y][z], C, 0.0, R);
		  gsl_blas_ddot(L, R, &new_p);

		  //			 if(new_p != 0.0) {
		  if(new_p >= p_thres) {
			 uint32_t new_da = *da | (x << k);
			 uint32_t new_db = *db | (y << k);
			 uint32_t new_dc = *dc | (z << k);
			 xdp_add_pddt_i(k+1, n, p_thres, A, R, &new_da, &new_db, &new_dc, &new_p, diff_set_dx_dy_dz, diff_mset_p, max_size);
		  }
		  gsl_vector_free(R);
		}
	 }
  }
  gsl_vector_free(L);
}

/** 
 * Compute a partial DDT for \f$\mathrm{xdp}^{+}\f$: wrapper function
 * of \ref xdp_add_pddt_i.
 *
 * \param n word size.
 * \param p_thres probability threshold.
 * \see xdp_add_pddt_i.
 */
void xdp_add_pddt(uint32_t n, double p_thres, const uint64_t max_size,
						std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* diff_set_dx_dy_dz,
						std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_mset_p)
{
  //  uint32_t n = WORD_SIZE;
  //  double p_thres = P_THRES;
  uint32_t k = 0;
  double p = 0.0;

  // init A
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  // init C
  gsl_vector* C = gsl_vector_calloc(XDP_ADD_MSIZE);
  gsl_vector_set(C, XDP_ADD_ISTATE, 1.0);

  uint32_t da = 0;
  uint32_t db = 0;
  uint32_t dc = 0;

  xdp_add_pddt_i(k, n, p_thres, A, C, &da, &db, &dc, &p, diff_set_dx_dy_dz, diff_mset_p, max_size);
#if 0									  // DEBUG
  printf("[%s:%d] p_thres = %f (2^%f), n = %d, #diffs = %d\n", __FILE__, __LINE__, 
			p_thres, log2(p_thres), WORD_SIZE, diff_mset_p->size());
#endif
  assert(diff_set_dx_dy_dz->size() == diff_mset_p->size());

  gsl_vector_free(C);
  xdp_add_free_matrices(A);
}

// See speck.cc

/**
 * For given input differences dx,dy, check if in the
 * list of differentials set_dx_dy_dz exists an entry (dx,dy->dz)
 */
bool xdp_add_is_dz_in_set_dx_dy_dz(uint32_t dx, uint32_t dy,
											  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz> diff_set_dx_dy_dz)
{
  assert(diff_set_dx_dy_dz.size() != 0);
  bool b_is_inset = false;
  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>::iterator set_iter = diff_set_dx_dy_dz.begin();;
  while((set_iter != diff_set_dx_dy_dz.end()) && (!b_is_inset)) {
	 b_is_inset = ((dx == set_iter->dx) && (dy == set_iter->dy));
	 set_iter++;
  }
  assert(diff_set_dx_dy_dz.size() != 0);
  return b_is_inset;
}

/**
 * \see xdp_add_dx_dy_pddt
 */
void xdp_add_dx_dy_pddt_i(const uint32_t k, const uint32_t n, gsl_matrix* A[2][2][2], gsl_vector* C, 
								  const uint32_t da, const uint32_t db, uint32_t* dc, double* p, 
								  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* hways_diff_set_dx_dy_dz,
								  std::multiset<differential_3d_t, struct_comp_diff_3d_p>* hways_diff_mset_p,
								  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* croads_diff_set_dx_dy_dz,
								  std::multiset<differential_3d_t, struct_comp_diff_3d_p>* croads_diff_mset_p,
								  uint32_t right_rot_const, uint32_t left_rot_const,
								  const double p_thres, uint32_t max_size)
{
  if(k == n) {
	 double p_the = xdp_add(A, da, db, *dc);
#if 0									  // DEBUG
	 printf("[%s:%d] XDP_ADD_THE[(%8X,%8X)->%8X] = %6.5f\n", 
			  __FILE__, __LINE__, *da, *db, *dc, p_the);
	 printf("[%s:%d] XDP_ADD_REC[(%8X,%8X)->%8X] = %6.5f\n", 
			  __FILE__, __LINE__, *da, *db, *dc, *p);
#endif
	 if(p_thres > 0.0) {
		assert(*p > 0.0);
	 }
	 assert(*p == p_the);
	 assert(*p >= p_thres);
	 uint32_t len = croads_diff_set_dx_dy_dz->size();

	 if((*p >= p_thres) && (len < max_size)) {

		differential_3d_t i_diff;
		i_diff.dx = da;
		i_diff.dy = db;
		i_diff.dz = *dc;
		i_diff.p = *p;

		bool b_is_inset = true;
#if 1									  // !!!
		uint32_t dx_next = i_diff.dz;
		uint32_t dy_next = LROT(i_diff.dy, left_rot_const) ^ i_diff.dz;
		b_is_inset = xdp_add_is_dz_in_set_dx_dy_dz(dx_next, dy_next, *hways_diff_set_dx_dy_dz);
#endif
		if(b_is_inset) {
		  uint32_t num_croads = croads_diff_set_dx_dy_dz->size();
		  croads_diff_set_dx_dy_dz->insert(i_diff);
		  if(num_croads < croads_diff_set_dx_dy_dz->size()) { // if a new croad was added, add it also in the other list
			 croads_diff_mset_p->insert(i_diff);
#if 1									  // DEBUG
			 printf("\r[%s:%d] %10d / %10d | Add %8X %8X -> %8X : %f 2^%4.2f | 2^%4.2f", __FILE__, __LINE__, len, max_size, da, db, *dc, *p, log2(*p), log2(p_thres));
#endif
		  }
		}
	 }
	 return;
  }

  if(croads_diff_set_dx_dy_dz->size() == max_size)
	 return;

  // init L
  gsl_vector* L = gsl_vector_calloc(XDP_ADD_MSIZE);
  gsl_vector_set_all(L, 1.0);

  uint32_t x = (da >> k) & 1;
  uint32_t y = (db >> k) & 1;

  for(uint32_t z = 0; z < 2; z++) {

	 // temp
	 gsl_vector* R = gsl_vector_calloc(XDP_ADD_MSIZE);
	 double new_p = 0.0;

	 // L A C
	 gsl_blas_dgemv(CblasNoTrans, 1.0, A[x][y][z], C, 0.0, R);
	 gsl_blas_ddot(L, R, &new_p);

	 if(new_p >= p_thres) {
		uint32_t new_dc = (*dc) | (z << k);
		//			 xdp_add_pddt_i(k+1, n, p_thres, A, R, &new_da, &new_db, &new_dc, &new_p, diff_set_dx_dy_dz, diff_mset_p, max_size);
		xdp_add_dx_dy_pddt_i(k+1, n, A, R, da, db, &new_dc, &new_p, hways_diff_set_dx_dy_dz, hways_diff_mset_p, croads_diff_set_dx_dy_dz, croads_diff_mset_p, right_rot_const, left_rot_const, p_thres, max_size);
	 }
	 gsl_vector_free(R);
  }
  gsl_vector_free(L);
}

/** 
 * For given input XOR differences da,db to ADD compute a pDDT of
 * differentials (da,db->dc) with probability above a fixed threshold
 * p_thres. 
 * 
 * right_rot_const and left_rot_const are the rotation constants of
 * block cipher Speck \ref speck.cc . 
 *
 */ 
uint32_t xdp_add_dx_dy_pddt(uint32_t da, uint32_t db, 
									 std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* hways_diff_set_dx_dy_dz,
									 std::multiset<differential_3d_t, struct_comp_diff_3d_p>* hways_diff_mset_p,
									 std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* croads_diff_set_dx_dy_dz,
									 std::multiset<differential_3d_t, struct_comp_diff_3d_p>* croads_diff_mset_p,
									 uint32_t right_rot_const, uint32_t left_rot_const,
									 double p_thres, uint32_t max_size)
{
  uint32_t n = WORD_SIZE;
  uint32_t k = 0;
  double p = 0.0;

  // init A
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  // init C
  gsl_vector* C = gsl_vector_calloc(XDP_ADD_MSIZE);
  gsl_vector_set(C, XDP_ADD_ISTATE, 1.0);

  uint32_t dc = 0;

  uint32_t old_size = croads_diff_set_dx_dy_dz->size();

  //  xdp_add_pddt_i(k, n, p_thres, A, C, &da, &db, &dc, &p, diff_set_dx_dy_dz, diff_mset_p, max_size);
  xdp_add_dx_dy_pddt_i(k, n, A, C, da, db, &dc, &p, hways_diff_set_dx_dy_dz, hways_diff_mset_p, croads_diff_set_dx_dy_dz, croads_diff_mset_p, right_rot_const, left_rot_const, p_thres, max_size);

  assert(croads_diff_set_dx_dy_dz->size() == croads_diff_mset_p->size());
  uint32_t new_size = croads_diff_set_dx_dy_dz->size();

#if 0									  // DEBUG
  printf("[%s:%d] p_thres = %f (2^%f), n = %d, #diffs = %d\n", __FILE__, __LINE__, 
			p_thres, log2(p_thres), WORD_SIZE, croads_diff_mset_p->size());
#endif
  assert(croads_diff_set_dx_dy_dz->size() == croads_diff_mset_p->size());

  gsl_vector_free(C);
  xdp_add_free_matrices(A);

  return (new_size - old_size);
}
