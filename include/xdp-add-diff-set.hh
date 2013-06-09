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
 * \file  xdp-add-diff-set.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for xdp-add-diff-set.cc: \copybrief xdp-add-diff-set.cc.
 */ 
#ifndef XDP_ADD_DIFF_SET_H
#define XDP_ADD_DIFF_SET_H

#ifndef XDP_ADD_DSET_MSIZE
#define XDP_ADD_DSET_MSIZE 8 /**< \f$(A, B, C)\f$ */ 
#endif
#ifndef XDP_ADD_DSET_NMATRIX
#define XDP_ADD_DSET_NMATRIX 8 /**< \f$(A, B, C)\f$ */ 
#endif
#ifndef XDP_ADD_DSET_NMATRIX_ALL
#define XDP_ADD_DSET_NMATRIX_ALL 27 /**< \f$(A, B, C)\f$ */ 
#endif
#ifndef XDP_ADD_DSET_NISTATES
#define XDP_ADD_DSET_NISTATES 4
#endif

extern uint32_t XDP_ADD_DSET_ISTATES[XDP_ADD_DSET_NISTATES];

/**
 * If a bit in the member \p fixed in a \ref diff_set_t structure is set
 * to \ref STAR, then the corresponding bit in the difference \p diff
 * can be either 1 or 0.
 */
#define STAR 1

/**
 * If a bit in the member \p fixed in a \ref diff_set_t structure is set
 * to \ref FIXED, then the corresponding bit in the difference \p diff
 * is fixed to its given value.
 */
#define FIXED 0

#define STAR_VALUE 2 						  // indicates that the bit can be 0 or 1
#define XDP_ADD_DSET_NVALUES 3			  // 0, 1, *

/**
 * A set of differences:
 *   - If \p fixed[i] = 0, then the i-th bit of the difference is fixeded to \p diff[i].
 *   - If \p fixed[i] = 1, then \p diff[i] can be either 0 and 1.
 * 
 */
struct diff_set_t
{
  uint32_t diff;
  uint32_t fixed; /**< 0 means fixed; 1 means not fixed. */
};

bool is_dset_equal(const diff_set_t da_set, const diff_set_t db_set);

uint64_t xdp_add_dset_size(diff_set_t da_set);

void xdp_add_input_diff_to_output_dset(uint32_t da, uint32_t db, diff_set_t* dc_set);

void xdp_add_dset_gen_diff_all(const diff_set_t dc_set, std::vector<uint32_t>* dc_set_all);

void xdp_add_input_dsets_to_input_diffs(const diff_set_t da_set, 
													 const diff_set_t db_set,
													 uint32_t da[2], uint32_t db[2]);

void xdp_add_input_dset_to_output_dset(gsl_matrix* AA[2][2][2],
													const diff_set_t da_set, 
													const diff_set_t db_set,
													diff_set_t* dc_set);

void xdp_add_input_dset_to_output_dset_i(uint32_t i, gsl_matrix* AA[2][2][2],
													  const diff_set_t da_set, 
													  const diff_set_t db_set,
													  diff_set_t* dc_set_in, double* r_in, 
													  diff_set_t* dc_set_max, double* r_max);

void xdp_add_input_dset_to_output_dset_rec(gsl_matrix* AA[2][2][2],
														 const diff_set_t da_set, 
														 const diff_set_t db_set,
														 diff_set_t* dc_set_max);

void xdp_add_dset_alloc_matrices(gsl_matrix* A[2][2][2]);

void xdp_add_dset_alloc_matrices_all(gsl_matrix* A[3][3][3]);

void xdp_add_dset_free_matrices(gsl_matrix* A[2][2][2]);

void xdp_add_dset_free_matrices_all(gsl_matrix* A[3][3][3]);

void xdp_add_dset_gen_matrices(gsl_matrix* A[2][2][2]);

void xdp_add_dset_gen_matrices_all(gsl_matrix* AA[3][3][3],
												gsl_matrix* A[2][2][2]);

void xdp_add_dset_print_matrices(gsl_matrix* A[2][2][2]);

void xdp_add_dset_print_matrices_all(gsl_matrix* A[3][3][3]);

void xdp_add_dset_print_matrix(gsl_matrix* A);

void xdp_add_dset_gen_matrix(const uint32_t i, 
									  gsl_matrix* M, 
									  gsl_matrix* A[2][2][2],
									  const diff_set_t da_set,
									  const diff_set_t db_set,
									  const diff_set_t dc_set);

void xdp_add_dset_init_states(const uint32_t pos,
										gsl_vector* C,											
										const diff_set_t da_set,
										const diff_set_t db_set,
										const diff_set_t dc_set);

double xdp_add_dset(gsl_matrix* A[2][2][2],
						  const uint32_t word_size, 
						  const diff_set_t da_set,
						  const diff_set_t db_set,
						  const diff_set_t dc_set);

double xdp_add_dset_all(gsl_matrix* AA[3][3][3], 
								 const uint32_t word_size,
								 const diff_set_t da_set,
								 const diff_set_t db_set,
								 const diff_set_t dc_set);

void xdp_add_dset_print_set(const diff_set_t da_set);

double xdp_add_dset_exper(gsl_matrix* A[2][2][2],
								  const diff_set_t da_set,
								  const diff_set_t db_set,
								  const diff_set_t dc_set);

void rmax_xdp_add_dset_i(const uint32_t k_init, const uint32_t k, const uint32_t n, 
								 double* r, double* p, diff_set_t* dc_set,
								 gsl_matrix* A[3][3][3], gsl_vector* B[WORD_SIZE + 1], gsl_vector* C_in,  
								 const diff_set_t da_set, const diff_set_t db_set, diff_set_t* dc_set_max, 
								 double* r_max, double* p_max, bool b_single_diff);

double rmax_xdp_add_dset(gsl_matrix* A[3][3][3],
								 const diff_set_t da_set, const diff_set_t db_set,
								 diff_set_t* dc_set_max, bool b_single_diff);

double max_xdp_add_dset_exper(gsl_matrix* A[2][2][2],
										const diff_set_t da_set,
										const diff_set_t db_set,
										diff_set_t* max_dc_set);

double max_xdp_add_dset(const diff_set_t da_set,
								const diff_set_t db_set,
								diff_set_t* dc_set);

//diff_set_t xor_dset(diff_set_t da_set_in, diff_set_t db_set_in, double* p, bool b_single_diff);
diff_set_t xor_dset(diff_set_t da_set, diff_set_t db_set);

diff_set_t lrot_dset(diff_set_t da_set, uint32_t rot_const);

bool is_inset(uint32_t da, diff_set_t da_set);

#endif  // #ifndef XDP_ADD_DIFF_SET_H
