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
 * \file  xtea-f-xor-pddt.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Computing an XOR partial difference distribution table (pDDT) for the F-function of block cipher XTEA.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_ADD_H
#include "xdp-add.hh"
#endif
#ifndef XTEA_H
#include "xtea.hh"
#endif
#ifndef XDP_XTEA_F_FK_H
#include "xdp-xtea-f-fk.hh"
#endif

/**
 * Computes an ADD partial difference distribution table (pDDT) for
 * the F-function of block cipher TEA.
 *
 * \param k current bit position in the recursion.
 * \param n word size (default is \ref WORD_SIZE).
 * \param lsh_const \ref LSH constant (\ref TEA_LSH_CONST).
 * \param rsh_const \ref RSH constant (\ref TEA_RSH_CONST).
 * \param A transition probability matrices for ADD \f$\mathrm{xdp}^{+}\f$ (\ref xdp_add_sf).
 * \param C unit column vector for computing \f$\mathrm{xdp}^{+}\f$ (\ref xdp_add). 
 * \param da input difference to the F-function of XTEA.
 * \param db output difference from the \f$f_\mathrm{LXR}\f$ component
 *        of F ((\ref xtea_f_lxr)).
 * \param dc output difference from the F-function of XTEA.
 * \param p probability of the partially constructed differential
 *        \f$(da[k:0], db[k:0] \rightarrow dc[k:0])\f$ for the ADD
 *        operation in F.
 * \param p_thres probability threshold (default is \ref XTEA_XOR_P_THRES).
 * \param diff_set_dx_dy set of differentials \f$(dx \rightarrow
 *        dy)\f$ in the pDDT ordered by index \f$i = (dx~ 2^{n} +
 *        dy)\f$; stored in an STL set structure, internally
 *        implemented as a Red-Black binary search tree.
 * 
 * \b Algorithm \b Outline:
 * 
 * -# Treat the two inputs to the ADD operation: \f$a\f$ and \f$b = ((a << 4)
 *    ^ (a >> 5))\f$ as independent.
 * -# Recursively construct a list of differentials \f$(da, db \rightarrow dc)\f$ for
 *    the ADD operation in F with probability bigger than
 *    \f$p_{\mathrm{thres}}\f$ (see \ref xdp_add_pddt_i).
 * -# Of the constructed differentials store in an pDDT only those for
 *    which it holds \f$db = (da \ll 4) \oplus (da \gg 5)\f$.
 * -# Return pDDT.
 *
 * \see xtea_f_xor_pddt
 * 
 */
void xtea_f_xor_pddt_i(const uint32_t k, const uint32_t n, 
							  const uint32_t lsh_const,  const uint32_t rsh_const,
							  gsl_matrix* A[2][2][2], gsl_vector* C, 
							  uint32_t* da, uint32_t* db, uint32_t* dc,
							  double* p, const double p_thres, 
							  std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy)
{
  if(k == n) {
	 double p_the = xdp_add(A, *da, *db, *dc);
	 if(p_thres != 0.0) {
		assert(*p != 0.0);
	 }
	 assert(*p == p_the);
	 assert(*p >= p_thres);


	 // store the difference in the vector
#if 1								 // !!!
	 bool b_is_valid = (*db == ((LSH(*da, lsh_const)) ^ RSH(*da, rsh_const)));
#else
	 bool b_is_valid = true;//(*db == ((LSH(*da, lsh_const)) ^ RSH(*da, rsh_const)));
#endif
	 if((b_is_valid) && (p_the != 0.0)) {
		differential_t diff;
		diff.dx = *da;
		diff.dy = *dc;
		diff.p = p_the;

		if(diff_set_dx_dy->size() < XTEA_XOR_MAX_PDDT_SIZE) {
#if 1									  // DEBUG
		  bool b_found = (diff_set_dx_dy->find(diff) != diff_set_dx_dy->end());
		  if(!b_found) {
			 //			 printf("[%s:%d] Dxy add %8X -> %8X  | %f = 2^%4.2f | %15d\n", __FILE__, __LINE__, diff.dx, diff.dy, diff.p, log2(diff.p), diff_set_dx_dy->size());
			 printf("\r[%s:%d] Dxy add %8X -> %8X  | %f = 2^%4.2f | %15d", __FILE__, __LINE__, diff.dx, diff.dy, diff.p, log2(diff.p), diff_set_dx_dy->size());
			 fflush(stdout);
		  }
#endif
		  diff_set_dx_dy->insert(diff);
		}
	 }
	 return;
  }

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

		  if((new_p >= p_thres) && (diff_set_dx_dy->size() < XTEA_XOR_MAX_PDDT_SIZE)) {
			 uint32_t new_da = *da | (x << k);
			 uint32_t new_db = *db | (y << k);
			 uint32_t new_dc = *dc | (z << k);

			 xtea_f_xor_pddt_i(k+1, n, lsh_const, rsh_const, A, R, &new_da, &new_db, &new_dc, &new_p, p_thres, diff_set_dx_dy);
		  }
		  gsl_vector_free(R);

		}
	 }
  }
  gsl_vector_free(L);
}
 
/** 
 * Compute an XOR partial DDT (pDDT) for the XTEA F-function: wrapper
 * function of \ref xtea_f_xor_pddt_i . By definition a pDDT contains
 * only differentials that have probability above a fixed probability
 * thershold.
 *
 * \param n word size (default is \ref WORD_SIZE).
 * \param p_thres probability threshold (default is \ref XTEA_XOR_P_THRES).
 * \param lsh_const \ref LSH constant (\ref TEA_LSH_CONST).
 * \param rsh_const \ref RSH constant (\ref TEA_RSH_CONST).
 * \param diff_set_dx_dy set of differentials \f$(dx \rightarrow
 *        dy)\f$ in the pDDT ordered by index \f$i = (dx~ 2^{n} +
 *        dy)\f$; stored in an STL set structure, internally
 *        implemented as a Red-Black binary search tree.
 *
 * \note The compuation of the pDDT is based on the ADD operation in
 *       the XTEA F-function: the only non-linear componenet with
 *       respect to XOR differences.
 *
 * \see xtea_f_xor_pddt_i.
 */
void xtea_f_xor_pddt(uint32_t n, double p_thres, uint32_t lsh_const, uint32_t rsh_const,
							std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy)
{
  assert(n == WORD_SIZE);

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

  // compute Dxy
  xtea_f_xor_pddt_i(k, n, lsh_const, rsh_const, A, C, &da, &db, &dc, &p, p_thres, diff_set_dx_dy);

  gsl_vector_free(C);
  xdp_add_free_matrices(A);
}


/**
 * For a given difference dx, check if in the
 * list of differentials set_dx_dy exists an entry (dx -> dy)
 * \see is_dx_in_set_dx_dy
 */
bool xtea_is_dx_in_set_dx_dy(uint32_t dy, uint32_t dx_prev, 
									  std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy)
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
 * \see is_dx_in_set_dx_dy_mask_i
 */
bool xtea_is_dx_in_set_dx_dy_mask_i(uint32_t mask_i, 
												const uint32_t dy, const uint32_t dx_prev, 
												std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy)
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
 * Add entries to the pDDT for fixed input diference da and a given prob. threshold. 
 * The same as \ref xtea_f_xor_pddt_i, but da is fixed .
 * \see tea_f_da_db_dc_add_pddt_i, xtea_f_xor_pddt_i
 */
void xtea_f_da_db_xor_pddt_i(const uint32_t k, const uint32_t n, 
									  const uint32_t lsh_const,  const uint32_t rsh_const,
									  gsl_matrix* A[2][2][2], gsl_vector* C, 
									  const uint32_t da_prev, const uint32_t da, const uint32_t db, uint32_t* dc,
									  double* p, const double p_thres, 
									  std::set<differential_t, struct_comp_diff_dx_dy>* hways_diff_set_dx_dy,
										 std::multiset<differential_t, struct_comp_diff_p>* hways_diff_mset_p,
									  std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy,
									  uint32_t* cnt_new)
{
#define RESTRICT_CROADS 1

  if(k == n) {
	 double p_the = xdp_add(A, da, db, *dc);
#if !RESTRICT_CROADS
	 if(p_thres != 0.0) {
		assert(*p != 0.0);
	 }
#endif  // #if RESTRICT_CROADS
	 assert(*p == p_the);
	 assert(*p >= p_thres);

	 // store the difference in the vector
	 bool b_is_valid = (db == ((LSH(da, lsh_const)) ^ RSH(da, rsh_const)));
	 assert(b_is_valid);
	 assert(p_the >= p_thres);

#if RESTRICT_CROADS
	 bool b_is_inset = xtea_is_dx_in_set_dx_dy(*dc, da_prev, *hways_diff_set_dx_dy);
#else
	 bool b_is_inset = true;
#endif

	 differential_t diff;
	 diff.dx = da;
	 diff.dy = *dc;
	 diff.p = p_the;

	 // Update highway tables with missing entries
	 if((b_is_valid) && (p_the >= XTEA_XOR_P_THRES)) {
		bool b_found = (hways_diff_set_dx_dy->find(diff) != hways_diff_set_dx_dy->end());
		if(!b_found) {
		  uint32_t old_size = hways_diff_set_dx_dy->size();
		  hways_diff_set_dx_dy->insert(diff);
		  uint32_t new_size = hways_diff_set_dx_dy->size();
		  if(old_size != new_size) {
			 hways_diff_mset_p->insert(diff);
		  }
		}
	 }

	 if((b_is_valid) && (p_the != 0.0) && (b_is_inset)) {
		if(diff_set_dx_dy->size() < XTEA_XOR_MAX_PDDT_SIZE) {
#if 0									  // DEBUG
		  bool b_found = (diff_set_dx_dy->find(diff) != diff_set_dx_dy->end());
		  if(!b_found) {
			 printf("[%s:%d] Dxy add %8X -> %8X  | %f = 2^%4.2f | %15d\n", __FILE__, __LINE__, diff.dx, diff.dy, diff.p, log2(diff.p), diff_set_dx_dy->size());
		  }
#endif
		  //		  printf("[%s:%d] Dxy add %8X -> %8X  | %f = 2^%4.2f | %15d\n", __FILE__, __LINE__, diff.dx, diff.dy, diff.p, log2(diff.p), diff_set_dx_dy->size());
		  diff_set_dx_dy->insert(diff);
		  (*cnt_new)++;
		}
	 }
	 return;
  }

  // init L
  gsl_vector* L = gsl_vector_calloc(XDP_ADD_MSIZE);
  gsl_vector_set_all(L, 1.0);

  uint32_t x = (da >> k) & 1;
  uint32_t y = (db >> k) & 1;

  //  for(uint32_t x = 0; x < 2; x++) {
  //	 for(uint32_t y = 0; y < 2; y++) {
  for(uint32_t z = 0; z < 2; z++) {

	 // temp
	 gsl_vector* R = gsl_vector_calloc(XDP_ADD_MSIZE);
	 double new_p = 0.0;

	 // L A C
	 gsl_blas_dgemv(CblasNoTrans, 1.0, A[x][y][z], C, 0.0, R);
	 gsl_blas_ddot(L, R, &new_p);

	 if((new_p >= p_thres) && (diff_set_dx_dy->size() < XTEA_XOR_MAX_PDDT_SIZE)) {
		uint32_t new_da = da;
		uint32_t new_db = db;
		uint32_t new_dc = *dc | (z << k);

#if RESTRICT_CROADS
#if 0				 // do not restrict before full word size
		uint32_t mask_i = 0xffffffff >> (WORD_SIZE - k);
		bool b_is_inset_mask = xtea_is_dx_in_set_dx_dy_mask_i(mask_i, new_dc, da_prev, *hways_diff_set_dx_dy);
#else
		bool b_is_inset_mask = true;
#endif
		if(b_is_inset_mask) {
		  xtea_f_da_db_xor_pddt_i(k+1, n, lsh_const, rsh_const, A, R, da_prev, new_da, new_db, &new_dc, &new_p, p_thres, hways_diff_set_dx_dy, hways_diff_mset_p, diff_set_dx_dy, cnt_new);
		}
#else
		xtea_f_da_db_xor_pddt_i(k+1, n, lsh_const, rsh_const, A, R, da_prev, new_da, new_db, &new_dc, &new_p, p_thres, hways_diff_set_dx_dy, hways_diff_mset_p, diff_set_dx_dy, cnt_new);
#endif		 
	 }
	 gsl_vector_free(R);

  }
		//	 }
		//  }
  gsl_vector_free(L);
}

/**
 * Wrapper for \ref xtea_f_da_db_xor_pddt_i
 * \see tea_f_da_add_pddt
 */ 
uint32_t xtea_f_da_db_xor_pddt(uint32_t n, double p_thres, 
										 uint32_t lsh_const, uint32_t rsh_const, const uint32_t da_prev, const uint32_t da_in, 
										 std::set<differential_t, struct_comp_diff_dx_dy>* hways_diff_set_dx_dy,
										 std::multiset<differential_t, struct_comp_diff_p>* hways_diff_mset_p,
										 std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy)
{
  assert(n == WORD_SIZE);

  uint32_t k = 0;
  double p = 0.0;
  uint32_t cnt_new = 0;

  // init A
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  // init C
  gsl_vector* C = gsl_vector_calloc(XDP_ADD_MSIZE);
  gsl_vector_set(C, XDP_ADD_ISTATE, 1.0);

  uint32_t da = da_in;
  uint32_t db = ((LSH(da, lsh_const)) ^ RSH(da, rsh_const));
  uint32_t dc = 0;

  // compute Dxy
  xtea_f_da_db_xor_pddt_i(k, n, lsh_const, rsh_const, A, C, da_prev, da, db, &dc, &p, p_thres, hways_diff_set_dx_dy, hways_diff_mset_p, diff_set_dx_dy, &cnt_new);

  gsl_vector_free(C);
  xdp_add_free_matrices(A);
  return cnt_new;
}

// 
// Adjust the probabailities of the pDDT Dxy of XTEA with XOR to a  
// fixed key by performing N number of one-round encryptions 
// 
// See also: tea_f_add_pddt_adjust_to_key
// 
/**
 *
 * Adjust the probabailities of the differentials in a pDDT computed
 * with \ref xtea_f_xor_pddt , to the value of a fixed key by
 * performing one-round TEA encryptions over a number of chosen
 * plaintext pairs drawn uniformly at random.
 * 
 * \param nrounds total number of rounds (\ref NROUNDS).
 * \param npairs number of chosen plaintext pairs (\ref NPAIRS).
 * \param lsh_const \ref LSH constant (\ref TEA_LSH_CONST).
 * \param rsh_const \ref RSH constant (\ref TEA_RSH_CONST).
 * \param key round key.
 * \param delta round constant.
 * \param p_thres probability threshold (\ref XTEA_XOR_P_THRES).
 * \param diff_set_dx_dy set of differentials \f$(dx \rightarrow dy)\f$
 *        in the pDDT ordered by index \f$i = (dx~ 2^{n} + dy)\f$.
 */ 
void xtea_xor_pddt_adjust_to_key(uint32_t nrounds, uint32_t npairs, uint32_t lsh_const, uint32_t rsh_const,
											uint32_t key, uint32_t delta, double p_thres,
											std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy)
{
  std::set<differential_t, struct_comp_diff_dx_dy>::iterator set_iter;
  for(set_iter = diff_set_dx_dy->begin(); set_iter != diff_set_dx_dy->end(); set_iter++) {
	 uint32_t dx = set_iter->dx;
	 uint32_t dy = set_iter->dy;

	 double p_exp = xdp_xtea_f_fk_approx(npairs, dx, dy, key, delta, lsh_const, rsh_const);

	 differential_t diff;
	 diff.dx = dx;
	 diff.dy = dy;
	 diff.p = p_exp;
	 diff_set_dx_dy->erase(set_iter);
	 if(diff.p >= p_thres) {
		diff_set_dx_dy->insert(diff);
	 }
  }
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
 * \see xtea_add_pddt_dxy_to_dp
 */
void xtea_xor_pddt_dxy_to_dp(std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p,
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
