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
 * \file  xdp-add-diff-set.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Functions for working with sets of XOR differences w.r.t.
 *        addition: \f$\mathrm{xdp}^{+}(A,B \rightarrow C)\f$ (See
 *        also: \ref xdp-add.cc).
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR_H
#include "adp-xor.hh"
#endif
#ifndef XDP_ADD_H
#include "xdp-add.hh"
#endif
#ifndef MAX_XDP_ADD_H
#include "max-xdp-add.hh"
#endif
#ifndef XDP_ADD_DIFF_SET_H
#include "xdp-add-diff-set.hh"
#endif

/**
 * \f$da[0] ^ db[0] ^ dc[0] = 0 : (da[0],db[0],dc[0]) \in \{000, 011, 101, 110\}\f$.
 */ 
uint32_t XDP_ADD_DSET_ISTATES[XDP_ADD_DSET_NISTATES] = {0,3,5,6};

/**
 * Compute the number of XOR differencces in the set \p da_set .
 *
 * \param da_set a set of input differences.
 * \return Number of elements in \p da_set .
 */
uint64_t xdp_add_dset_size(diff_set_t da_set)
{
  //  uint32_t mask = (0xffffffff >> (32 - (WORD_SIZE - 1)));
  return (1ULL << (hw32(da_set.fixed) & MASK));
}

/**
 * Check if two sets of XOR differences are equal.
 * 
 * \param da_set set of XOR differences.
 * \param db_set set of XOR differences.
 */
bool is_dset_equal(const diff_set_t da_set, const diff_set_t db_set)
{
  return ((da_set.diff == db_set.diff) && 
			 (da_set.fixed == db_set.fixed));
}

/**
 * From two fixed input differences \p da and \p db to the \ref ADD operation,
 * compute a set of output differences \p C such that
 * \f$\mathrm{xdp}^{+}(da, db \rightarrow C) \ge
 * \mathrm{max}_{dc}\mathrm{xdp}^{+}(da, db \rightarrow dc)\f$.
 * The algorithm is based on \ref max_xdp_add_lm . It sets 
 * \f$dc[i]=\f$ \ref STAR if \f$da[i] \neq db[i]\f$ and
 * \f$dc[i] = da[i] = db[i]\f$ otherwise.
 *
 * \param da input XOR difference.
 * \param db input XOR difference.
 * \param dc_set set of output XOR differences.
 */
void xdp_add_input_diff_to_output_dset(uint32_t da, uint32_t db, 
													diff_set_t* dc_set)
{
  uint32_t n = WORD_SIZE;
  uint32_t dc = 0;

  // if fixed[i] = 1, dc[i] can be anything, if fixed[i] = 0, dc[i] is fixed
  uint32_t fixed = 0;

  dc |= (da & 1) ^ (db & 1);

  for(uint32_t i = 1; i < n; i++) {

	 uint32_t da_prev = (da >> (i - 1)) & 1;
	 uint32_t db_prev = (db >> (i - 1)) & 1;
	 uint32_t dc_prev = (dc >> (i - 1)) & 1;
	 uint32_t da_this = (da >> i) & 1;
	 uint32_t db_this = (db >> i) & 1;
	 uint32_t dc_this = 0;		  // to be determined
	 uint32_t fixed_this = 0;		  // is this bit fixed or no
	 if(is_eq(da_prev, db_prev, dc_prev)) {
		dc_this = (da_this ^ db_this ^ da_prev);
		fixed_this = FIXED;				  // fixed
	 } else {
		dc_this = da_this;		  // so that it is possible to have da_this = db_this = dc_this
		fixed_this = STAR;			  // can be 0/1 
	 }
	 dc |= (dc_this << i);
	 fixed |= (fixed_this << i);
  }

#if 0									  // DEBUG
  printf("[%s:%d] %8X %8X (%8X %8X)\n", __FILE__, __LINE__, da, db, dc, fixed);
#endif

  dc_set->diff = dc;
  dc_set->fixed = fixed;
}

/**
 * From given sets of input XOR differences \f$A\f$ and \f$B\f$
 * compute a set of output differences \f$C\f$
 * by greedily bitwise maximizing the ratio:
 * \f$r = p / s\f$ where \f$p = \mathrm{xdp}^{+}(A, B \rightarrow C)\f$ 
 * and \f$s\f$ is the size of the output set \f$C\f$.
 * \note Does NOT find the actual maximum.
 * 
 * \param AA transition probability matrices for
 *           \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$, computed
 *           with \ref xdp_add_dset_gen_matrix .
 * \param da_set set of input XOR differences.
 * \param db_set set of input XOR differences.
 * \param dc_set set of output XOR differences.
 */
void xdp_add_input_dset_to_output_dset(gsl_matrix* AA[2][2][2],
													const diff_set_t da_set, 
													const diff_set_t db_set,
													diff_set_t* dc_set)
{
  dc_set->diff = 0;
  dc_set->fixed = 0;

  for(uint32_t i = 0; i < WORD_SIZE; i++) {

	 uint32_t word_size = WORD_SIZE;//i + 1; // bits 0, 1, ..., i
	 double r_max = 0.0;
	 diff_set_t dc_set_max = {0, 0};

	 for(int j = 2; j >= 0; j--) {
		diff_set_t dc_set_i = {dc_set->diff, dc_set->fixed};
		if((j == 0) || (j == 1)){				  // -
		  dc_set_i.diff |= (j << i);
		  dc_set_i.fixed |= (FIXED << i);
		}
		if(j == 2) {				  // *
		  dc_set_i.diff |= (0 << i);
		  dc_set_i.fixed |= (STAR << i);
		}
		double p = xdp_add_dset(AA, word_size, da_set, db_set, dc_set_i);
		uint32_t s = xdp_add_dset_size(dc_set_i);
		double r = p / (double)s;
		if(r > r_max) {
		  r_max = r;
		  dc_set_max = {dc_set_i.diff, dc_set_i.fixed};
		}
		//		printf("[%s:%d] %d|%d: %f %d  %f\n", __FILE__, __LINE__, i, j, p, s, r);
	 }

	 *dc_set = {dc_set_max.diff, dc_set_max.fixed};
  }

}

/**
 * From given sets of input XOR differences \f$A\f$ and \f$B\f$
 * compute a set of output differences \f$C\f$
 * that maximizes the ratio:
 * \f$r = p / s\f$ where \f$p = \mathrm{xdp}^{+}(A, B \rightarrow C)\f$ 
 * and \f$s\f$ is the size of the output set \f$C\f$:
 * \f$C : \mathrm{max}_{r}\mathrm{xdp}^{+}(A, B \rightarrow C)\f$.
 * 
 * \note Finds the exact maximum, but is not efficient. A more
 *       efficient variant is \ref rmax_xdp_add_dset_bounds .
 * 
 * \param AA transition probability matrices for
 *           \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$, computed
 *           with \ref xdp_add_dset_gen_matrix .
 * \param da_set set of input XOR differences.
 * \param db_set set of input XOR differences.
 * \param dc_set_in set of output XOR differences.
 * \param r_in ratio  \f$r = p / s = \mathrm{xdp}^{+}(A, B \rightarrow C) / \#C\f$.
 * \param dc_set_max output set \f$C\f$ that maximizes \f$r\f$.
 * \param r_max the maximum ratio \f$r\f$.
 *
 * \sa xdp_add_input_dset_to_output_dset_rec, xdp_add_input_dset_to_output_dset .
 */
void xdp_add_input_dset_to_output_dset_i(uint32_t i, gsl_matrix* AA[2][2][2],
													  const diff_set_t da_set, 
													  const diff_set_t db_set,
													  diff_set_t* dc_set_in, double* r_in, 
													  diff_set_t* dc_set_max, double* r_max)
{
  diff_set_t dc_set = {dc_set_in->diff, dc_set_in->fixed};
  double r = *r_in;

  if(i == WORD_SIZE) {
	 if(r > *r_max) {
		*r_max = r;
		*dc_set_max = {dc_set.diff, dc_set.fixed};
#if 0								  // EDBUG
		printf("[%s:%d] Update: ", __FILE__, __LINE__);
		xdp_add_dset_print_set(*dc_set_max);
		printf(" | %f (2^%f)\n", *r_max, log2(*r_max));
#endif
	 }
	 return;
  }

  //  for(int j = 0; j < 3; j++) {
  for(int j = 2; j >= 0; j--) {
	 // re-init
	 dc_set = {dc_set_in->diff, dc_set_in->fixed};
	 r = *r_in;

	 if((j == 0) || (j == 1)) {	// -
		dc_set.diff |= (j << i);
		dc_set.fixed |= (FIXED << i);
	 }
	 if(j == 2) {				   // *
		dc_set.diff |= (0 << i);
		dc_set.fixed |= (STAR << i);
	 }
	 //	 if(i > 0) {
	 uint32_t word_size = (i + 1);
	 //	 }
	 double p = xdp_add_dset(AA, word_size, da_set, db_set, dc_set);
	 uint64_t s = xdp_add_dset_size(dc_set);
	 r = p / (double)s;
#if 0									  // DEBUG
	 printf("[%s:%d] %d|%d: %f %lld  %f %f\n", __FILE__, __LINE__, i, j, p, s, r, *r_max);
#endif
	 //	 if(r > 0.0) {
	 if((r >= *r_max) && (r != 0.0)) {
		xdp_add_input_dset_to_output_dset_i(i+1, AA, da_set, db_set, &dc_set, &r, dc_set_max, r_max);
	 }
  }
  return;
}

/** 
 * Wrapper function for \ref xdp_add_input_dset_to_output_dset_i .
 *
 * \param AA transition probability matrices for
 *           \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$, computed
 *           with \ref xdp_add_dset_gen_matrix .
 * \param da_set set of input XOR differences.
 * \param db_set set of input XOR differences.
 * \param dc_set_max output set \f$C\f$ that maximizes the ratio
 *        \f$r = p / s = \mathrm{xdp}^{+}(A, B \rightarrow C) / \#C\f$.
 */ 
void xdp_add_input_dset_to_output_dset_rec(gsl_matrix* AA[2][2][2],
														 const diff_set_t da_set, 
														 const diff_set_t db_set,
														 diff_set_t* dc_set_max)
{
  uint32_t i = 0;
  diff_set_t dc_set = {0, 0};
  double r_max = 0;
  double r = 0;
  *dc_set_max = {0, 0};
  xdp_add_input_dset_to_output_dset_i(i, AA, da_set, db_set, &dc_set, &r, dc_set_max, &r_max);
}

/**
 * Generate all XOR differences that belong to a given input set \f$C\f$.
 *
 * \param da_set set of input XOR differences in compact represenatation \ref diff_set_t .
 * \param dc_set_all a vector of all XOR differences that compose \f$C\f$ in explicit form.
 */
void xdp_add_dset_gen_diff_all(const diff_set_t dc_set, 
										 std::vector<uint32_t>* dc_set_all)
{
  uint32_t nfree = hw32(dc_set.fixed & MASK);	  // number of free (non-fixed) positions
  uint32_t N = (1U << (nfree));
  double logN = log2(N);

#if 0  // DEBUG
  printf("[%s:%d] %8X %8X %d %d\n", __FILE__, __LINE__, dc_set.diff, dc_set.fixed, nfree, N);
#endif // #if 1  // DEBUG

  for(uint32_t i = 0; i < N; i++) { // all values of the free positions

#if 0  // DEBUG
	 printf("[%s:%d] %d: ", __FILE__, __LINE__, i);
#endif // #if 1  // DEBUG

	 uint32_t dc_new = dc_set.diff;
	 uint32_t i_pos = 0;				  // counting the bit position within the log2(N)-bit value i

	 for(uint32_t j = 0; j < WORD_SIZE; j++) {
		uint32_t is_fixed = (dc_set.fixed >> j) & 1;

		if(is_fixed == STAR) {		  // the position is free
		  uint32_t val = (i >> i_pos) & 1;
		  //		  dc_new |= (val << j);
		  dc_new ^= (val << j);	  // flip the bit at the free position
		  assert((double)i_pos < logN);
		  i_pos++;

#if 0  // DEBUG
		  printf("%d ", val);
#endif // #if 1  // DEBUG

		}
	 }
	 dc_set_all->push_back(dc_new);
#if 0  // DEBUG
	 printf(" | %8X", dc_new);
	 printf("\n");
#endif // #if 1  // DEBUG
	 assert(i_pos == log2(N));
  }
  assert(dc_set_all->size() == N);
}

/**
 * From input sets \f$A\f$ and \f$B\f$ for \f$\mathrm{xdp}^{+}\f$,
 * generate two pairs of input differences: \f$(da^0 \in A, db^0 \in B)\f$
 * and \f$(da^1 \in A, db^1 \in B)\f$ such that 
 * \f$da^{j}[i] = db^{j}[i] = j\f$ if \f$A[i] = B[i] =\f$\ref STAR
 * and \f$da^{j}[i] = A[i]\f$, \f$db^{j}[i] = B[i]\f$ otherwise; \f$j = 0, 1\f$.
 *
 * \param da_set set of input XOR differences.
 * \param db_set set of input XOR differences.
 * \param output XOR differences \f$da^0, da^1\f$.
 * \param output XOR differences \f$db^0, db^1\f$.
 */
void xdp_add_input_dsets_to_input_diffs(const diff_set_t da_set, 
													 const diff_set_t db_set,
													 uint32_t da[2], uint32_t db[2])
{

  for(uint32_t j = 0; j <= 1; j++) {

	 // initialize
	 da[j] = 0;
	 db[j] = 0;

	 for(uint32_t i = 0; i < WORD_SIZE; i++) {

		uint32_t da_diff_i = (da_set.diff >> i) & 1; 
		uint32_t da_fixed_i = (da_set.fixed >> i) & 1;

		uint32_t db_diff_i = (db_set.diff >> i) & 1; 
		uint32_t db_fixed_i = (db_set.fixed >> i) & 1;

		if((da_fixed_i == STAR) && (db_fixed_i == STAR)) { // (*,*)
		  // da[i] = db[i] = j
		  da[j] |= (j << i);
		  db[j] |= (j << i);
		} 
		if((da_fixed_i == FIXED) && (db_fixed_i == STAR)) { // (-,*)
		  // da[i] = db[i] = da_set[i]
		  da[j] |= (da_diff_i << i);
		  db[j] |= (da_diff_i << i);
		} 
		if((da_fixed_i == STAR) && (db_fixed_i == FIXED)) { // (*,-)
		  // da[i] = db[i] = db_set[i]
		  da[j] |= (db_diff_i << i);
		  db[j] |= (db_diff_i << i);
		} 
		if((da_fixed_i == FIXED) && (db_fixed_i == FIXED)) { // (-,-)
		  // da[i] = da_set[i], db[i] = db_set[i]
		  da[j] |= (da_diff_i << i);
		  db[j] |= (db_diff_i << i);
		} 
	 }

  }
}

/**
 * Allocate memory for the transition probability matrices for 
 * \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$.
 *
 * \param A transition probability matrices for \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$.
 * \see xdp_add_dset_alloc_matrices .
 */
void xdp_add_dset_alloc_matrices(gsl_matrix* A[2][2][2])
{
  for(int i = 0; i < XDP_ADD_DSET_NMATRIX; i++){
	 int t = i;
	 int a = t & 1;
	 t /= 2;
	 int b = t & 1;
	 t /= 2;
	 int c = t & 1;
	 t /= 2;
	 //			 printf("%d%d%d \n", c, b, a);
	 A[a][b][c] = gsl_matrix_calloc(XDP_ADD_DSET_MSIZE, XDP_ADD_DSET_MSIZE);
  }
}

/**
 * Free memory reserved by a previous call to \ref xdp_add_dset_alloc_matrices .
 *
 * \param A transition probability matrices for \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$.
 */
void xdp_add_dset_free_matrices(gsl_matrix* A[2][2][2])
{
  for(int i = 0; i < XDP_ADD_DSET_NMATRIX; i++){
	 int t = i;
	 int a = t & 1;
	 t /= 2;
	 int b = t & 1;
	 t /= 2;
	 int c = t & 1;
	 t /= 2;
	 //			 printf("%d%d%d \n", c, b, a);
	 //			 if(A[a][b][c] != NULL)
	 gsl_matrix_free(A[a][b][c]);
  }
}

/**
 * Generate the transition probability matrices for 
 * \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$.
 *
 * \param A transition probability matrices for \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$.
 */
void xdp_add_dset_gen_matrices(gsl_matrix* A[2][2][2])
{
  for(int i = 0; i < XDP_ADD_DSET_MSIZE; i++) {
	 int x = i;
	 int da_in = x & 1;
	 x /= 2;
	 int db_in = x & 1;
	 x /= 2;
	 int dc_in = x & 1;
	 x /= 2;

	 //	 printf("[%s:%d] %d = (%d,%d,%d)\n", __FILE__, __LINE__, i, da_in, db_in, dc_in);
	 for(int j = 0; j < XDP_ADD_DSET_MSIZE; j++) {
		int y = j;
		int da_out = y & 1;
		y /= 2;
		int db_out = y & 1;
		y /= 2;
		int dc_out = y & 1;
		y /= 2;

		double e = 0.0;
		// 
		// An xdp-add differential is possible if:
		// da[i] = db[i] = dc[i] => da[i+1] ^ db[i+1] ^ dc[i+1] ^ da[i] = 0
		// 
		bool b_is_possible = ((is_eq(da_in, db_in, dc_in) & 
									  (da_out ^ db_out ^ dc_out ^ db_in)) == 0);
		if(b_is_possible) {
		  //		  if((!is_eq(da_out, db_out, dc_out))) { // not equal
		  if((!is_eq(da_in, db_in, dc_in))) { // not equal
			 e = 0.5;
		  } else {
			 e = 1.0;
		  }
		}
		uint32_t col = i;
		uint32_t row = j;
		gsl_matrix_set(A[da_in][db_in][dc_in], row, col, e);
		//		printf("[%s:%d] %d%d%d: in(%d)->out(%d)\n", __FILE__, __LINE__, da_in, db_in, dc_in, col, row);
	 }
  }
}

/**
 * Print all matrices for 
 * \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$.
 *
 * \param A transition probability matrices for
 *        \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$.
 */
void xdp_add_dset_print_matrices(gsl_matrix* A[2][2][2])
{
  for(int i = 0; i < XDP_ADD_DSET_NMATRIX; i++) {
	 int a = (i >> 0) & 1;
	 int b = (i >> 1) & 1;
	 int c = (i >> 2) & 1;

	 printf("A%d%d%d \n", c, b, a);
	 for(int row = 0; row < XDP_ADD_DSET_MSIZE; row++) {
		for(int col = 0; col < XDP_ADD_DSET_MSIZE; col++) {
		  double e = gsl_matrix_get(A[a][b][c], row, col);
		  printf("%3.2f, ", e);
		}
		printf("\n");
	 }
	 printf("\n");
  }
}

/**
 * Print a single matrix for 
 * \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$.
 *
 * \param A transition probability matrix for \f$\mathrm{xdp}^{+}(A, B
 *        \rightarrow C)\f$.
 * \seexdp_add_dset_print_matrices .
 */
void xdp_add_dset_print_matrix(gsl_matrix* A)
{
  for(int row = 0; row < XDP_ADD_DSET_MSIZE; row++) {
	 for(int col = 0; col < XDP_ADD_DSET_MSIZE; col++) {
		double e = gsl_matrix_get(A, row, col);
		printf("%3.2f, ", e);
	 }
	 printf("\n");
  }
  printf("\n");
}

/**
 * Print a vector for 
 * \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$.
 *
 * \param C vector of size \ref XDP_ADD_DSET_MSIZE .
 */
void xdp_add_dset_print_vector(gsl_vector* C)
{
  for(uint32_t i = 0; i < XDP_ADD_DSET_MSIZE; i++) {
	 double val = gsl_vector_get(C, i);
	 printf("%3.2f ", val);
  }
}

/**
 * Initialize the states at position \p pos depending on the
 * values of the sets at this position. \p pos can be 
 * 0 or (\ref WORD_SIZE - 1). If it is 0, valid states are
 * 0, 3, 5, 6 (cf. \ref XDP_ADD_DSET_ISTATES), otherwise
 * all states are valid.
 * 
 * \param pos bit position: 0 or (\ref WORD_SIZE - 1).
 * \param C column vector of size \ref XDP_ADD_DSET_MSIZE .
 * \param da_set set of input XOR differences.
 * \param db_set set of input XOR differences.
 * \param dc_set_in set of output XOR differences.
 */
void xdp_add_dset_init_states(const uint32_t pos,
										gsl_vector* C,											
										const diff_set_t da_set,
										const diff_set_t db_set,
										const diff_set_t dc_set)
{
  uint32_t nda = 0;				  // number of possibilities for da[0]
  uint32_t ndb = 0;				  // number of possibilities for db[0]
  uint32_t ndc = 0;				  // number of possibilities for dc[0]

  uint32_t da_0 = 0;
  uint32_t db_0 = 0;
  uint32_t dc_0 = 0;

  bool b_da_is_fixed = (((da_set.fixed >> pos) & 1) == FIXED);
  bool b_db_is_fixed = (((db_set.fixed >> pos) & 1) == FIXED);
  bool b_dc_is_fixed = (((dc_set.fixed >> pos) & 1) == FIXED);

  if(b_da_is_fixed) {
	 nda = 1;
  } else {
	 nda = 2;
  }
  if(b_db_is_fixed) {
	 ndb = 1;
  } else {
	 ndb = 2;
  }
  if(b_dc_is_fixed) {
	 ndc = 1;
  } else {
	 ndc = 2;
  }
  for(uint32_t i = 0; i < nda; i++) {
	 if(i == 0) {
		da_0 = (da_set.diff >> pos) & 1;
	 } else {
		da_0 = (1 ^ da_0) & 1;	  // flip the bit
	 }
	 for(uint32_t j = 0; j < ndb; j++) {
		if(j == 0) {
		  db_0 = (db_set.diff >> pos) & 1;
		} else {
		  db_0 = (1 ^ db_0) & 1;	  // flip the bit
		}
		for(uint32_t k = 0; k < ndc; k++) {
		  if(k == 0) {
			 dc_0 = (dc_set.diff >> pos) & 1;
		  } else {
			 dc_0 = (1 ^ dc_0) & 1;	  // flip the bit
		  }
		  bool b_is_valid = true; // always true if not LSB
		  if(pos == 0) {			  // LSB
			 b_is_valid = ((da_0 ^ db_0 ^ dc_0) == 0);
		  } 
		  if(b_is_valid) {
			 uint32_t idx = (dc_0 << 2) | (db_0 << 1) | da_0;
			 double val = 1.0;
			 gsl_vector_set(C, idx, val);
			 if(pos == 0) {	
				assert((idx == 0)||(idx == 3)||(idx == 5)||(idx == 6));
			 }
		  }
		}
	 }
  }
#if 0									  // DEBUG
  printf("[%s:%d] i = %d: nda ndb ndc %d %d %d | %f\n", __FILE__, __LINE__, pos, nda, ndb, ndc, scale_fact);
  xdp_add_dset_print_vector(C);
  printf("\n");
#endif
}

/**
 * Allocate memory for all transition probability matrices for 
 * \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$.
 *
 * \param A all transition probability matrices for \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$.
 * \see xdp_add_dset_alloc_matrices .
 */
void xdp_add_dset_alloc_matrices_all(gsl_matrix* A[3][3][3])
{
  for(int c = 0; c < XDP_ADD_DSET_NVALUES; c++){
	 for(int b = 0; b < XDP_ADD_DSET_NVALUES; b++){
		for(int a = 0; a < XDP_ADD_DSET_NVALUES; a++){
		  //		  printf("%d%d%d \n", c, b, a);
		  A[a][b][c] = gsl_matrix_calloc(XDP_ADD_DSET_MSIZE, XDP_ADD_DSET_MSIZE);
		}
	 }
  }
}

/**
 * Free memory reserved by a previous call to \ref xdp_add_dset_alloc_matrices_all .
 *
 * \param A all transition probability matrices for \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$.
 */
void xdp_add_dset_free_matrices_all(gsl_matrix* A[3][3][3])
{
  for(int c = 0; c < XDP_ADD_DSET_NVALUES; c++){
	 for(int b = 0; b < XDP_ADD_DSET_NVALUES; b++){
		for(int a = 0; a < XDP_ADD_DSET_NVALUES; a++){
		  //			 printf("%d%d%d \n", c, b, a);
		  //			 if(A[a][b][c] != NULL)
		  gsl_matrix_free(A[a][b][c]);
		}
	 }
  }
}

/**
 * Print all matrices for 
 * \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$.
 *
 * \param A all transition probability matrices for
 *        \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$.
 */
void xdp_add_dset_print_matrices_all(gsl_matrix* A[3][3][3])
{
  for(int c = 0; c < XDP_ADD_DSET_NVALUES; c++){
	 for(int b = 0; b < XDP_ADD_DSET_NVALUES; b++){
		for(int a = 0; a < XDP_ADD_DSET_NVALUES; a++){

		  printf("A%d%d%d \n", c, b, a);
		  for(int row = 0; row < XDP_ADD_DSET_MSIZE; row++) {
			 for(int col = 0; col < XDP_ADD_DSET_MSIZE; col++) {
				double e = gsl_matrix_get(A[a][b][c], row, col);
				printf("%3.2f, ", e);
			 }
			 printf("\n");
		  }
		  printf("\n");
		}
	 }
  }
}

/**
 * Generate all matrices for
 * \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$.
 * from all valid matrices for this position
 * precomputed with \ref xdp_add_dset_gen_matrices .
 * 
 * \param AA all transition probability matrices for
 *        \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$.
 * \param A transition probability matrices for \f$\mathrm{xdp}^{+}(A,
 *        B \rightarrow C)\f$.
 */ 
void xdp_add_dset_gen_matrices_all(gsl_matrix* AA[3][3][3],
												gsl_matrix* A[2][2][2])

{
  for(int i = 0; i < 3; i++) {

	 diff_set_t da_set = {0, 0};
	 if((i == 0) || (i == 1)) {  // 0,1
		da_set.diff = i;
		da_set.fixed = FIXED;
	 }
	 if(i == 2) {				     // *
		da_set.diff = 0;
		da_set.fixed = STAR;
	 }

	 for(int j = 0; j < 3; j++) {
		diff_set_t db_set = {0, 0};
		if((j == 0) || (j == 1)) {  // 0,1
		  db_set.diff = j;
		  db_set.fixed = FIXED;
		}
		if(j == 2) {				     // *
		  db_set.diff = 0;
		  db_set.fixed = STAR;
		}

		for(int k = 0; k < 3; k++) {
		  diff_set_t dc_set = {0, 0};
		  if((k == 0) || (k == 1)) {  // 0,1
			 dc_set.diff = k;
			 dc_set.fixed = FIXED;
		  }
		  if(k == 2) {				     // *
			 dc_set.diff = 0;
			 dc_set.fixed = STAR;
		  }

		  uint32_t nda = 0;				  // number of possibilities for da[0]
		  uint32_t ndb = 0;				  // number of possibilities for db[0]
		  uint32_t ndc = 0;				  // number of possibilities for dc[0]

		  uint32_t da_i = 0;
		  uint32_t db_i = 0;
		  uint32_t dc_i = 0;

		  bool b_da_is_fixed = (((da_set.fixed) & 1) == FIXED);
		  bool b_db_is_fixed = (((db_set.fixed) & 1) == FIXED);
		  bool b_dc_is_fixed = (((dc_set.fixed) & 1) == FIXED);

		  if(b_da_is_fixed) {
			 nda = 1;
		  } else {
			 nda = 2;
		  }
		  if(b_db_is_fixed) {
			 ndb = 1;
		  } else {
			 ndb = 2;
		  }
		  if(b_dc_is_fixed) {
			 ndc = 1;
		  } else {
			 ndc = 2;
		  }
		  double scale_fact = (double)1.0 / (double)(nda * ndb);
		  for(uint32_t r = 0; r < nda; r++) {
			 if(r == 0) {
				da_i = (da_set.diff) & 1;
			 } else {
				da_i = (1 ^ da_i) & 1;	  // flip the bit
			 }
			 for(uint32_t s = 0; s < ndb; s++) {
				if(s == 0) {
				  db_i = (db_set.diff) & 1;
				} else {
				  db_i = (1 ^ db_i) & 1;	  // flip the bit
				}
				for(uint32_t t = 0; t < ndc; t++) {
				  if(t == 0) {
					 dc_i = (dc_set.diff) & 1;
				  } else {
					 dc_i = (1 ^ dc_i) & 1;	  // flip the bit
				  }
#if 0 // DEBUG
				  printf("[%s:%d] A%d%d%d\n", __FILE__, __LINE__, da_i, db_i, dc_i);
				  xdp_add_dset_print_matrix(A[da_i][db_i][dc_i]);
#endif // #if 0 // DEBUG
				  gsl_matrix_add(AA[i][j][k], A[da_i][db_i][dc_i]);
#if 0 // DEBUG
				  printf("\n[%s:%d] AA%d%d%d\n", __FILE__, __LINE__, i, j, k);
				  xdp_add_dset_print_matrix(AA[i][j][k]);
				  printf("\n");
#endif  // #if 0 // DEBUG
				}
			 }
		  }
		  gsl_matrix_scale(AA[i][j][k], scale_fact);
#if 0									  // DEBUG
		  printf("[%s:%d] i = %d: nda ndb ndc %d %d %d | %f\n", __FILE__, __LINE__, i, nda, ndb, ndc, scale_fact);
		  xdp_add_dset_print_matrix(AA[i][j][k]);
#endif
		}
	 }
  }
}

/**
 * Generate the matrix for the i-th bit position, as the sum
 * of all valid matrices for this position
 *
 * \param i bit postion: \f$0 \le i <\f$\ref WORD_SIZE.
 * \param M composite transition probability matrix compued as a sum
 *        of some matrices A depending on the values of the set st
 *        at this bit popsition: \f$A[i], B[i], C[i]\f$.
 * \param A transition probability matrices for \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$.
 * \param da_set set of input XOR differences.
 * \param db_set set of input XOR differences.
 * \param dc_set set of output XOR differences.
 */ 
void xdp_add_dset_gen_matrix(const uint32_t i, 
									  gsl_matrix* M, 
									  gsl_matrix* A[2][2][2],
									  const diff_set_t da_set,
									  const diff_set_t db_set,
									  const diff_set_t dc_set)
{
  gsl_matrix_set_all(M, 0.0);
  //  gsl_matrix* AA = gsl_matrix_calloc(XDP_ADD_DSET_MSIZE, XDP_ADD_DSET_MSIZE);

  uint32_t nda = 0;				  // number of isibilities for da[0]
  uint32_t ndb = 0;				  // number of isibilities for db[0]
  uint32_t ndc = 0;				  // number of isibilities for dc[0]

  uint32_t da_i = 0;
  uint32_t db_i = 0;
  uint32_t dc_i = 0;

  bool b_da_is_fixed = (((da_set.fixed >> i) & 1) == FIXED);
  bool b_db_is_fixed = (((db_set.fixed >> i) & 1) == FIXED);
  bool b_dc_is_fixed = (((dc_set.fixed >> i) & 1) == FIXED);

  if(b_da_is_fixed) {
	 nda = 1;
  } else {
	 nda = 2;
  }
  if(b_db_is_fixed) {
	 ndb = 1;
  } else {
	 ndb = 2;
  }
  if(b_dc_is_fixed) {
	 ndc = 1;
  } else {
	 ndc = 2;
  }
  double scale_fact = (double)1.0 / (double)(nda * ndb);
  for(uint32_t r = 0; r < nda; r++) {
	 if(r == 0) {
		da_i = (da_set.diff >> i) & 1;
	 } else {
		da_i = (1 ^ da_i) & 1;	  // flip the bit
	 }
	 for(uint32_t s = 0; s < ndb; s++) {
		if(s == 0) {
		  db_i = (db_set.diff >> i) & 1;
		} else {
		  db_i = (1 ^ db_i) & 1;	  // flip the bit
		}
		for(uint32_t t = 0; t < ndc; t++) {
		  if(t == 0) {
			 dc_i = (dc_set.diff >> i) & 1;
		  } else {
			 dc_i = (1 ^ dc_i) & 1;	  // flip the bit
		  }
#if 0 // DEBUG
		  printf("[%s:%d] A%d%d%d\n", __FILE__, __LINE__, da_i, db_i, dc_i);
		  xdp_add_dset_print_matrix(A[da_i][db_i][dc_i]);
#endif // #if 0 // DEBUG
		  gsl_matrix_add(M, A[da_i][db_i][dc_i]);
#if 0 // DEBUG
		  printf("\n[%s:%d] M\n", __FILE__, __LINE__);
		  xdp_add_dset_print_matrix(M);
		  printf("\n");
#endif  // #if 0 // DEBUG
		}
	 }
  }
  gsl_matrix_scale(M, scale_fact);
#if 0									  // DEBUG
  printf("[%s:%d] i = %d: nda ndb ndc %d %d %d | %f\n", __FILE__, __LINE__, i, nda, ndb, ndc, scale_fact);
  xdp_add_dset_print_matrix(M);
#endif
}

/**
 * Normalize the final states in XDP-ADD diff set since
 * for the MSB the matrices A have different transition probabilities;
 * L is the final row vector.
 *
 * \param L final row vector of size \ref XDP_ADD_DSET_MSIZE .
 * \param b_da_msb_is_fixed Boolean flag indicating if the MSB of the input set \f$A\f$ is \ref FIXED .
 * \param b_db_msb_is_fixed Boolean flag indicating if the MSB of the input set \f$B\f$ is \ref FIXED .
 * \param b_dc_msb_is_fixed Boolean flag indicating if the MSB of the output set \f$C\f$ is \ref FIXED .
 */ 
void xdp_add_dset_final_states_norm(gsl_vector* L, 
												bool b_da_msb_is_fixed, bool b_db_msb_is_fixed, bool b_dc_msb_is_fixed)
{
  gsl_vector* V = gsl_vector_calloc(XDP_ADD_DSET_MSIZE);

  // three STAR => divide by 4
  if((!b_da_msb_is_fixed && !b_db_msb_is_fixed && !b_dc_msb_is_fixed)) {
	 gsl_vector_set_all(V, 1.0);
	 double e = 0.25;
	 gsl_vector_set(V, 0, e);
	 gsl_vector_set(V, 1, e);
	 gsl_vector_set(V, 2, e);
	 gsl_vector_set(V, 3, e);
	 gsl_vector_set(V, 4, e);
	 gsl_vector_set(V, 5, e);
	 gsl_vector_set(V, 6, e);
	 gsl_vector_set(V, 7, e);
	 gsl_vector_mul(L, V);
  }
  // two STAR => divide by 2
  if((!b_da_msb_is_fixed && !b_db_msb_is_fixed && b_dc_msb_is_fixed) ||
	  (b_da_msb_is_fixed && !b_db_msb_is_fixed && !b_dc_msb_is_fixed) ||
	  (!b_da_msb_is_fixed && b_db_msb_is_fixed && !b_dc_msb_is_fixed)) {
	 gsl_vector_set_all(V, 1.0);
	 double e = 0.5;
	 gsl_vector_set(V, 0, e);
	 gsl_vector_set(V, 1, e);
	 gsl_vector_set(V, 2, e);
	 gsl_vector_set(V, 3, e);
	 gsl_vector_set(V, 4, e);
	 gsl_vector_set(V, 5, e);
	 gsl_vector_set(V, 6, e);
	 gsl_vector_set(V, 7, e);
	 gsl_vector_mul(L, V);
  }
  // one STAR => leave matrix as it is
  if((!b_da_msb_is_fixed && b_db_msb_is_fixed && b_dc_msb_is_fixed) ||
	  (b_da_msb_is_fixed && !b_db_msb_is_fixed && b_dc_msb_is_fixed) ||
	  (b_da_msb_is_fixed && b_db_msb_is_fixed && !b_dc_msb_is_fixed)) {
	 ;
  }
  // all fixed (no STAR) => set 0.5 to 1.0
  if(b_da_msb_is_fixed && b_db_msb_is_fixed && b_dc_msb_is_fixed) { 
	 gsl_vector_set_all(V, 1.0);
	 double e = 2.0;
	 gsl_vector_set(V, 1, e);
	 gsl_vector_set(V, 2, e);
	 gsl_vector_set(V, 3, e);
	 gsl_vector_set(V, 4, e);
	 gsl_vector_set(V, 5, e);
	 gsl_vector_set(V, 6, e);
	 gsl_vector_mul(L, V);
  }
  gsl_vector_free(V);
}

/**
 * The XOR probability of \ref ADD with respect to sets of XOR differences \ref diff_set_t .
 * This is probability with which input sets \f$A, B\f$ propagate to
 * output set \f$C\f$: \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$ .
 *
 * \param AA transition probability matrices for
 *           \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$, computed
 *           with \ref xdp_add_dset_gen_matrix .
 * \param word_size the length of words in bits (cf. \ref  WORD_SIZE).
 * \param da_set set of input XOR differences \f$A\f$.
 * \param db_set set of input XOR differences \f$B\f$.
 * \param dc_set set of output XOR differences \f$C\f$.
 * \return \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$.
 */
double xdp_add_dset(gsl_matrix* A[2][2][2], 
						  const uint32_t word_size,
						  const diff_set_t da_set,
						  const diff_set_t db_set,
						  const diff_set_t dc_set)
{
  double p_ret = 0.0;
  gsl_vector* C = gsl_vector_calloc(XDP_ADD_DSET_MSIZE);
  gsl_vector* L = gsl_vector_calloc(XDP_ADD_DSET_MSIZE);
  gsl_vector* R = gsl_vector_calloc(XDP_ADD_DSET_MSIZE);
  gsl_matrix* M = gsl_matrix_calloc(XDP_ADD_DSET_MSIZE, XDP_ADD_DSET_MSIZE);

  uint32_t start_pos = 0;
  xdp_add_dset_init_states(start_pos, C, da_set, db_set, dc_set);
  gsl_vector_set_all(L, 0.0);
  gsl_vector_set_all(R, 0.0);

#if 0 // DEBUG
  printf("[%s:%d] C[%d] = ", __FILE__, __LINE__, -1);
  xdp_add_dset_print_vector(C);
  printf("\n");
#endif  // #if 0 // DEBUG

  for(uint32_t i = 0; i < word_size; i++) {
	 gsl_vector_set_all(R, 0.0);
	 gsl_matrix_set_all(M, 0.0);
	 xdp_add_dset_gen_matrix(i, M, A, da_set, db_set, dc_set);
	 gsl_blas_dgemv(CblasNoTrans, 1.0, M, C, 0.0, R);
	 gsl_vector_memcpy(C, R);

#if 0 // DEBUG
	 printf("[%s:%d] C[%d] = ", __FILE__, __LINE__, i);
	 xdp_add_dset_print_vector(C);
	 printf("\n");
#endif  // #if 0 // DEBUG
  }

  uint32_t end_pos = (word_size - 1);
  xdp_add_dset_init_states(end_pos, L, da_set, db_set, dc_set);

  bool b_da_msb_is_fixed = (((da_set.fixed >> (word_size - 1)) & 1) == FIXED); 
  bool b_db_msb_is_fixed = (((db_set.fixed >> (word_size - 1)) & 1) == FIXED); 
  bool b_dc_msb_is_fixed = (((dc_set.fixed >> (word_size - 1)) & 1) == FIXED); 

  xdp_add_dset_final_states_norm(L, b_da_msb_is_fixed, b_db_msb_is_fixed, b_dc_msb_is_fixed);

#if 0									  // DEBUG
  printf("[%s:%d] L[%d] = ", __FILE__, __LINE__, word_size);
  xdp_add_dset_print_vector(L);
  printf("\n");
#endif

  gsl_blas_ddot(L, C, &p_ret);

  gsl_matrix_free(M);
  gsl_vector_free(C);
  gsl_vector_free(L);
  gsl_vector_free(R);
  return p_ret;
}

/**
 * The XOR probability of \ref ADD with respect to sets of XOR 
 * differences \ref diff_set_t output set \f$C\f$: 
 * \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$ .
 *
 * \note Functionally the same as \ref xdp_add_dset but uses all
 * transition probability matrices precomputed in advance
 * using \ref xdp_add_dset_gen_matrices_all
 *
 * \param AA transition probability matrices for
 *           \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$, computed
 *           with \ref xdp_add_dset_gen_matrices_all .
 * \param word_size the length of words in bits (cf. \ref  WORD_SIZE).
 * \param da_set set of input XOR differences \f$A\f$.
 * \param db_set set of input XOR differences \f$B\f$.
 * \param dc_set set of output XOR differences \f$C\f$.
 * \return \f$\mathrm{xdp}^{+}(A, B \rightarrow C)\f$.
 */
double xdp_add_dset_all(gsl_matrix* AA[3][3][3], 
								const uint32_t word_size,
								const diff_set_t da_set,
								const diff_set_t db_set,
								const diff_set_t dc_set)
{
  double p_ret = 0.0;
  gsl_vector* C = gsl_vector_calloc(XDP_ADD_DSET_MSIZE);
  gsl_vector* L = gsl_vector_calloc(XDP_ADD_DSET_MSIZE);
  gsl_vector* R = gsl_vector_calloc(XDP_ADD_DSET_MSIZE);

  uint32_t start_pos = 0;
  xdp_add_dset_init_states(start_pos, C, da_set, db_set, dc_set);
  gsl_vector_set_all(L, 0.0);
  gsl_vector_set_all(R, 0.0);

#if 0 // DEBUG
  printf("[%s:%d] C[%d] = ", __FILE__, __LINE__, -1);
  xdp_add_dset_print_vector(C);
  printf("\n");
#endif  // #if 0 // DEBUG

  for(uint32_t i = 0; i < word_size; i++) {
	 gsl_vector_set_all(R, 0.0);

	 uint32_t da_i = 0;
	 uint32_t db_i = 0;
	 uint32_t dc_i = 0; 

	 bool b_da_is_fixed = (((da_set.fixed >> i) & 1) == FIXED);
	 if(b_da_is_fixed) {
		da_i = ((da_set.diff >> i) & 1);
	 } else {
		da_i = STAR_VALUE;
	 }
	 bool b_db_is_fixed = (((db_set.fixed >> i) & 1) == FIXED);
	 if(b_db_is_fixed) {
		db_i = ((db_set.diff >> i) & 1);
	 } else {
		db_i = STAR_VALUE;
	 }
	 bool b_dc_is_fixed = (((dc_set.fixed >> i) & 1) == FIXED);
	 if(b_dc_is_fixed) {
		dc_i = ((dc_set.diff >> i) & 1);
	 } else {
		dc_i = STAR_VALUE;
	 }

	 //	 xdp_add_dset_gen_matrix(i, M, A, da_set, db_set, dc_set); // TODO:
	 gsl_blas_dgemv(CblasNoTrans, 1.0, AA[da_i][db_i][dc_i], C, 0.0, R);
	 gsl_vector_memcpy(C, R);

#if 0 // DEBUG
	 printf("[%s:%d] C[%d] = ", __FILE__, __LINE__, i);
	 xdp_add_dset_print_vector(C);
	 printf("\n");
#endif  // #if 0 // DEBUG
  }

  uint32_t end_pos = (word_size - 1);
  xdp_add_dset_init_states(end_pos, L, da_set, db_set, dc_set);

  bool b_da_msb_is_fixed = (((da_set.fixed >> (word_size - 1)) & 1) == FIXED); 
  bool b_db_msb_is_fixed = (((db_set.fixed >> (word_size - 1)) & 1) == FIXED); 
  bool b_dc_msb_is_fixed = (((dc_set.fixed >> (word_size - 1)) & 1) == FIXED); 

  xdp_add_dset_final_states_norm(L, b_da_msb_is_fixed, b_db_msb_is_fixed, b_dc_msb_is_fixed);

#if 0									  // DEBUG
  printf("[%s:%d] L[%d] = ", __FILE__, __LINE__, word_size);
  xdp_add_dset_print_vector(L);
  printf("\n");
#endif

  gsl_blas_ddot(L, C, &p_ret);

  gsl_vector_free(C);
  gsl_vector_free(L);
  gsl_vector_free(R);
  return p_ret;
}

/**
 * \ref max_xdp_add_i
 */
void rmax_xdp_add_dset_i(const uint32_t k_init, const uint32_t k, const uint32_t n, 
								 double* r, double* p, diff_set_t* dc_set,
								 gsl_matrix* A[3][3][3], gsl_vector* B[WORD_SIZE + 1], gsl_vector* C_in,  
								 const diff_set_t da_set, const diff_set_t db_set, diff_set_t* dc_set_max, 
								 double* r_max, double* p_max, bool b_single_diff)
{
  if(k == n) {
	 assert(*r > *r_max);
	 *r_max = *r;
	 *p_max = *p;
	 *dc_set_max = {dc_set->diff, dc_set->fixed};
	 if(b_single_diff == true) {
		assert(dc_set_max->fixed == 0);
	 }
#if 0									  // DEBUG
	 if(k_init == 0) {
		printf("[%s:%d] Update bound [%2d]: r %f (%f), p %f (%f) | ", __FILE__, __LINE__, 
				 k_init, *r_max, log2(*r_max), *p_max, log2(*p_max));
#if 0
		printf("\n");
		xdp_add_dset_print_set(da_set);
		printf("\n");
		xdp_add_dset_print_set(db_set);
		printf("\n");
#endif
		xdp_add_dset_print_set(*dc_set_max);
		printf("\n");
	 }
#endif
	 return;
  } 

  // get the k-th bit of da_set, db_set
  uint32_t x = 2;					  // *
  bool b_da_is_fixed = (((da_set.fixed >> k) & 1) == FIXED);
  if(b_da_is_fixed) {
	 x = ((da_set.diff >> k) & 1); // 0 or 1
  }
  uint32_t y = 2;					  // *
  bool b_db_is_fixed = (((db_set.fixed >> k) & 1) == FIXED);
  if(b_db_is_fixed) {
	 y = ((db_set.diff >> k) & 1); // 0 or 1
  }

  // cycle over the possible values of the k-th bits of *dc
  uint32_t nstar = hw32(dc_set->fixed);
  uint32_t nstar_max = WORD_SIZE;//5;//3;
  int hi = 1;
  int lo = 0;
  if((k_init == 0) && (nstar < nstar_max)) {				  // LSB
	 hi = 2;
  }
  if(b_single_diff == true) {	  // we want one output diff. instead of set
	 hi = 1;
  }

  uint32_t z_val[3] = {1, 0, 2};

  for(int i_z = hi; i_z >= lo; i_z--) { 

	 uint32_t z = z_val[i_z];

	 diff_set_t new_dc_set = {dc_set->diff, dc_set->fixed};

	 // set the k-th bit of dc_set
	 if((z == 0) || (z == 1)) {	// -
		new_dc_set.diff |= (z << k);
		new_dc_set.fixed |= (FIXED << k);
	 }
	 if(z == 2) {				   // *
		new_dc_set.diff |= (0 << k);
		new_dc_set.fixed |= (STAR << k);
	 }

	 // temp
	 gsl_vector* R = gsl_vector_calloc(XDP_ADD_DSET_MSIZE);
	 double new_p = 0.0;

	 gsl_vector* C = gsl_vector_calloc(XDP_ADD_DSET_MSIZE);
	 gsl_vector_memcpy(C, C_in);

	 if(k == (WORD_SIZE - 1)) {  // L
		bool b_da_msb_is_fixed = (((da_set.fixed >> k) & 1) == FIXED); 
		bool b_db_msb_is_fixed = (((db_set.fixed >> k) & 1) == FIXED); 
		bool b_dc_msb_is_fixed = (((new_dc_set.fixed >> k) & 1) == FIXED); 
		gsl_vector_set_all(B[k + 1], 0.0);
		xdp_add_dset_init_states(k, B[k + 1], da_set, db_set, new_dc_set);
		xdp_add_dset_final_states_norm(B[k + 1], b_da_msb_is_fixed, b_db_msb_is_fixed, b_dc_msb_is_fixed);
	 }
	 if(k == 0) {  // C
		gsl_vector_set_all(C, 0.0);
		xdp_add_dset_init_states(k, C, da_set, db_set, new_dc_set);
	 }

	 // L A C
	 gsl_blas_dgemv(CblasNoTrans, 1.0, A[x][y][z], C, 0.0, R);
	 gsl_blas_ddot(B[k + 1], R, &new_p);

	 double new_r = new_p;
	 if(k == (WORD_SIZE - 1)) {  // MSB => divide by the set size
		uint64_t s = xdp_add_dset_size(new_dc_set);
		new_r = new_p / (double)s;
	 }

	 // continue only if the probability so far is still bigger than the max. prob.
	 if(new_r > *r_max) {
		rmax_xdp_add_dset_i(k_init, k+1, n, &new_r, &new_p, &new_dc_set, 
								  A, B, R, da_set, db_set, dc_set_max, r_max, p_max, b_single_diff);
	 }

	 gsl_vector_free(C);
	 gsl_vector_free(R);
  }
  return;
}

/**
 * Uses: \ref rmax_xdp_add_dset_i .
 * See also: \ref max_xdp_add_bounds .
 */
void rmax_xdp_add_dset_bounds(gsl_matrix* A[3][3][3], gsl_vector* B[WORD_SIZE + 1],
										const diff_set_t da_set, const diff_set_t db_set, 
										diff_set_t* dd_set_max)
{
  bool b_single_diff = false;
  gsl_vector_set_all(B[WORD_SIZE], 0.0);

  for(uint32_t k = (WORD_SIZE - 1); k > 0; k--) {

	 for(uint32_t i = 0; i < XDP_ADD_DSET_MSIZE; i++) {

		gsl_vector* C = gsl_vector_calloc(XDP_ADD_DSET_MSIZE);
		gsl_vector_set(C, i, 1.0);

		//		double f = (1U << (((da_set.fixed >> k) & 1) + ((db_set.fixed >> k) & 1)));
		//		gsl_vector_scale(C, f);
#if 1
		uint32_t n = WORD_SIZE;
		diff_set_t dc_set_init = {0, 0};
		double p_init = gsl_vector_get(B[k], i);
		double r_init = 0.0;
		double p_max_i = 0.0;
		double r_max_i = 0.0;
		uint32_t k_init = k;
		rmax_xdp_add_dset_i(k_init, k, n, &r_init, &p_init, &dc_set_init, A, B, C, 
								  da_set, db_set, dd_set_max, &r_max_i, &p_max_i, b_single_diff);
		//		p_max_i /= f;
		//		gsl_vector_set(B[k], i, p_max_i);
		gsl_vector_set(B[k], i, r_max_i);
#endif
		gsl_vector_free(C);
	 }
#if 0									  // DEBUG
	 printf("[%s:%d] B[%d] ", __FILE__, __LINE__, k);
	 xdp_add_dset_print_vector(B[k]);
	 printf("\n");
#endif
  }
}

double rmax_xdp_add_dset(gsl_matrix* A[3][3][3],
								 const diff_set_t da_set, const diff_set_t db_set,
								 diff_set_t* dc_set_max, bool b_single_diff)
{
  gsl_vector* C = gsl_vector_calloc(XDP_ADD_DSET_MSIZE);
  gsl_vector* B[WORD_SIZE + 1];
  for(uint32_t i = 0; i < WORD_SIZE + 1; i++) {
	 B[i] = gsl_vector_calloc(XDP_ADD_DSET_MSIZE);
  }

  rmax_xdp_add_dset_bounds(A, B, da_set, db_set, dc_set_max);

  uint32_t n = WORD_SIZE;
  uint32_t k = 0;					  // LSB
  diff_set_t dc_set_init = {0, 0};
  double p_init = 0.0;
  double r_init = 0.0;
  double p_max = 0.0;
  double r_max = 0.0;
  uint32_t start_pos = 0;
  //  diff_set_t dc_set_tmp = {0, 0};
  //  xdp_add_dset_init_states(start_pos, C, da_set, db_set, dc_set_tmp);
  rmax_xdp_add_dset_i(start_pos, k, n, &r_init, &p_init, &dc_set_init, 
							 A, B, C, da_set, db_set, dc_set_max, &r_max, &p_max, b_single_diff);

#if 1									  // DEBUG
  double p_the = xdp_add_dset_all(A, WORD_SIZE, da_set, db_set, *dc_set_max);
  if(p_the != p_max) {
	 printf("[%s:%d] %f %f\n", __FILE__, __LINE__, p_the, p_max);
	 printf("[%s:%d]\n", __FILE__, __LINE__);
	 printf("\n da = ");
	 xdp_add_dset_print_set(da_set);
	 printf("\n db = ");
	 xdp_add_dset_print_set(db_set);
	 printf("\n dc = ");
	 xdp_add_dset_print_set(*dc_set_max);
	 printf("\n");
  }
  assert(p_max == p_the);
#endif

  for(uint32_t i = 0; i < WORD_SIZE + 1; i++) {
	 gsl_vector_free(B[i]);
  }
  gsl_vector_free(C);
  return p_max;
}

// 
// MAX-XDP-ADD: Given input sets da_set, db_set
// Note: the max. probability is always 1, but
// the output set is different for different inputs.
// More specifically part of the LSBs may be fixed.
// 
double max_xdp_add_dset(const diff_set_t da_set,
								const diff_set_t db_set,
								diff_set_t* dc_set)
{
  // initially all bits of dc are not fixed (STAR)
  dc_set->diff = 0;
  dc_set->fixed = 0xFFFFFFFF & MASK; // all STAR
  double p = 1.0;
  uint32_t i = 0;

  // lsb
  bool b_da_i_is_fixed = (((da_set.fixed >> i) & 1) == FIXED); 
  bool b_db_i_is_fixed = (((db_set.fixed >> i) & 1) == FIXED); 
  uint32_t da_i = (da_set.diff >> i) & 1; // lsb
  uint32_t db_i = (db_set.diff >> i) & 1; // lsb

  // at least one lsb is not fixed
  if(!b_da_i_is_fixed || !b_db_i_is_fixed) {
	 return p;
  }
  // both lsb-s are fixed
  uint32_t dc_i = (da_i ^ db_i) & 1;
  dc_set->diff |= (dc_i << i);
  dc_set->fixed ^= (1 << i); // flip STAR to FIXED

  b_da_i_is_fixed = (((da_set.fixed >> (i+1)) & 1) == FIXED); 
  b_db_i_is_fixed = (((db_set.fixed >> (i+1)) & 1) == FIXED); 
  while(is_eq(da_i, db_i, dc_i) && (i < WORD_SIZE) && (b_da_i_is_fixed) && (b_db_i_is_fixed)) {
	 uint32_t da_prev = da_i;
	 i++;
	 da_i = (da_set.diff >> i) & 1;
	 db_i = (db_set.diff >> i) & 1;
	 dc_i = (da_i ^ db_i ^ da_prev) & 1;
	 dc_set->diff |= (dc_i << i);
	 dc_set->fixed ^= (1 << i);  // flip the STAR to FIXED
	 if(i < (WORD_SIZE - 1)) {
		b_da_i_is_fixed = (((da_set.fixed >> (i+1)) & 1) == FIXED); 
		b_db_i_is_fixed = (((db_set.fixed >> (i+1)) & 1) == FIXED); 
	 } else {
		b_da_i_is_fixed = false;
		b_db_i_is_fixed = false;
	 }
  }
  dc_set->diff &= MASK;
  dc_set->fixed &= MASK;
  return p;
}


// 
// XDP-ADD-DSET exper
// 
double xdp_add_dset_exper(gsl_matrix* A[2][2][2],
								  const diff_set_t da_set,
								  const diff_set_t db_set,
								  const diff_set_t dc_set)
{
  double p_tot = 0.0;

  std::vector<uint32_t> da_set_all;
  xdp_add_dset_gen_diff_all(da_set, &da_set_all);
  std::vector<uint32_t>::iterator da_iter = da_set_all.begin();

  std::vector<uint32_t> db_set_all;
  xdp_add_dset_gen_diff_all(db_set, &db_set_all);
  std::vector<uint32_t>::iterator db_iter = db_set_all.begin();

  std::vector<uint32_t> dc_set_all;
  xdp_add_dset_gen_diff_all(dc_set, &dc_set_all);
  std::vector<uint32_t>::iterator dc_iter = dc_set_all.begin();

  for(da_iter = da_set_all.begin(); da_iter != da_set_all.end(); da_iter++) {
	 for(db_iter = db_set_all.begin(); db_iter != db_set_all.end(); db_iter++) {
		for(dc_iter = dc_set_all.begin(); dc_iter != dc_set_all.end(); dc_iter++) {

		  uint32_t da_i = *da_iter;
		  uint32_t db_i = *db_iter;
		  uint32_t dc_i = *dc_iter;
		  double p = xdp_add(A, da_i, db_i, dc_i);
		  p_tot += p;
#if 0									  // DEBUG
		  printf("[%s:%d] XDP_ADD(%8X, %8X -> %8X) = %f\n", __FILE__, __LINE__, da_i, db_i, dc_i, p);
#endif
		}
	 }
  }

  uint32_t ninput_diffs = da_set_all.size() * db_set_all.size();
  p_tot /= (double)ninput_diffs;
  //  printf("[%s:%d] ninput_diffs %d\n", __FILE__, __LINE__, ninput_diffs);
  return p_tot;
}

// 
// MAX-ADP-XOR exper
// 
double max_xdp_add_dset_exper(gsl_matrix* A[2][2][2],
										const diff_set_t da_set,
										const diff_set_t db_set,
										diff_set_t* max_dc_set)
{
  double p_max = 0.0;

  std::vector<uint32_t> da_set_all;
  xdp_add_dset_gen_diff_all(da_set, &da_set_all);
  std::vector<uint32_t>::iterator da_iter = da_set_all.begin();

  std::vector<uint32_t> db_set_all;
  xdp_add_dset_gen_diff_all(db_set, &db_set_all);
  std::vector<uint32_t>::iterator db_iter = db_set_all.begin();

  for(uint32_t i_diff = 0; i_diff < ALL_WORDS; i_diff++) {
	 for(uint32_t i_fixed = 0; i_fixed < ALL_WORDS; i_fixed++) {

		double p_tot = 0.0;
		diff_set_t dc_set = {i_diff, i_fixed};

		std::vector<uint32_t> dc_set_all;
		xdp_add_dset_gen_diff_all(dc_set, &dc_set_all);
		std::vector<uint32_t>::iterator dc_iter = dc_set_all.begin();

		for(da_iter = da_set_all.begin(); da_iter != da_set_all.end(); da_iter++) {
		  for(db_iter = db_set_all.begin(); db_iter != db_set_all.end(); db_iter++) {
			 for(dc_iter = dc_set_all.begin(); dc_iter != dc_set_all.end(); dc_iter++) {

				uint32_t da_i = *da_iter;
				uint32_t db_i = *db_iter;
				uint32_t dc_i = *dc_iter;
				double p = xdp_add(A, da_i, db_i, dc_i);
				p_tot += p;
#if 0									  // DEBUG
				printf("[%s:%d] XDP_ADD(%8X, %8X -> %8X) = %f\n", __FILE__, __LINE__, da_i, db_i, dc_i, p);
#endif
			 }
		  }
		}

		uint32_t ninput_diffs = da_set_all.size() * db_set_all.size();
		p_tot /= (double)ninput_diffs;

		if(p_tot > p_max) {
		  p_max = p_tot;
		  max_dc_set->diff = dc_set.diff;
		  max_dc_set->fixed = dc_set.fixed;
		}

	 }
  }
  return p_max;
}

// 
// Print a set in */0/1 representation
// 
void xdp_add_dset_print_set(const diff_set_t da_set)
{
  for(int i = (WORD_SIZE - 1); i >= 0; i--) {
	 uint32_t diff = (da_set.diff >> i) & 1;
	 uint32_t fixed = (da_set.fixed >> i) & 1;
	 if(fixed == FIXED) {
		printf("%d", diff);
	 } else {
		printf("*");
	 }
  }
}

diff_set_t xor_dset(diff_set_t da_set_in, diff_set_t db_set_in) 
{
  diff_set_t da_set = {da_set_in.diff, da_set_in.fixed};
  diff_set_t db_set = {db_set_in.diff, db_set_in.fixed};
  diff_set_t dc_set = {0, 0};
  dc_set.fixed = (da_set.fixed | db_set.fixed) & MASK;
  dc_set.diff = ((~dc_set.fixed) & (XOR(da_set.diff, db_set.diff))) & MASK;;
  return dc_set;
}

diff_set_t lrot_dset(diff_set_t da_set, uint32_t rot_const)
{
  diff_set_t db_set = {0, 0};
  db_set.diff = LROT(da_set.diff, rot_const);
  db_set.fixed = LROT(da_set.fixed, rot_const);
  return db_set;
}

// Check if an input difference belongs to a given set
// 
// 
bool is_inset(uint32_t da, diff_set_t da_set)
{
  bool b_inset = ((~(da_set.fixed) & da_set.diff) == (~(da_set.fixed) & da));

#if 0									  // DEBUG
  if(da_set.fixed != 0) {
	 printf("[%s:%d]%s()\n", __FILE__, __LINE__, __FUNCTION__);
	 printf("da_set\n");
	 printf(" ");
	 xdp_add_dset_print_set(da_set);
	 printf("\nda\n");
	 print_binary(da);
	 printf("\nset mask\n");
	 print_binary((~(da_set.fixed) & da_set.diff));
	 printf("\nda mask\n");
	 print_binary((~(da_set.fixed) & da));
	 printf("\n Return %d\n", b_inset);
  }
#endif
  if((da_set.fixed == 0) && (da_set.diff == da)) {
	 assert(b_inset == true);
  }
  return b_inset;
}

// --- Salsa20 ---

