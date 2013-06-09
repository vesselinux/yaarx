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
 * \file  salsa.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for salsa.cc: \copybrief salsa.cc .
 */ 
#ifndef SALSA_H
#define SALSA_H

#define MAX_NROUNDS 20

/**
 * Apply the feed-forward with the input state? Yes = 1, No = 0.
 */
#define SALSA_FEED_FORWARD 0

/**
 * Apply random shift constants.
 */
#define SALSA_RAND_ROT_CONST 0

/**
 * Number of words in the state.
 */
#define SALSA_STATE 16

extern uint32_t E[SALSA_STATE + SALSA_STATE][5];

void salsa20(const uint32_t e[SALSA_STATE + SALSA_STATE][5], 
				 const uint32_t r_start, const uint32_t r_end, 
				 const uint32_t X_in[SALSA_STATE], uint32_t Y_in[SALSA_STATE]);

void salsa_gen_rand_input_state(uint32_t X[SALSA_STATE]);

void salsa_print_state_uint32(const uint32_t X[SALSA_STATE]);

void salsa_print_state_uint8(const uint8_t X[4 * SALSA_STATE]);

void salsa_uint8_to_uint32(const uint8_t X[4], uint32_t* Y);

void salsa_uint32_to_uint8(uint8_t X[4], const uint32_t Y);

void salsa_state_uint8_to_uint32(const uint8_t X[4 * SALSA_STATE], uint32_t Y[SALSA_STATE]);

void salsa_state_uint32_to_uint8(uint8_t X[4 * SALSA_STATE], const uint32_t Y[SALSA_STATE]);

void salsa_print_trail(uint32_t nrounds, diff_set_t DT[MAX_NROUNDS][SALSA_STATE], double P[MAX_NROUNDS][SALSA_STATE]);

void salsa_print_prob(double P[SALSA_STATE]);

void salsa_print_prob_vs_rand(double P[SALSA_STATE], double P_rand[SALSA_STATE]);

double xdp_add_dset_salsa20(const uint32_t e[SALSA_STATE + SALSA_STATE][5], 
									 const uint32_t r_start, const uint32_t r_end, gsl_matrix* A[3][3][3],
									 const diff_set_t DX_in[SALSA_STATE], diff_set_t DY_in[SALSA_STATE],
									 diff_set_t DT[MAX_NROUNDS][SALSA_STATE], double P[MAX_NROUNDS][SALSA_STATE]);

double xdp_add_dset_salsa20_exper(const uint32_t e[SALSA_STATE + SALSA_STATE][5], 
											 const uint32_t r_start, const uint32_t r_end, uint32_t npairs,
											 const diff_set_t DX_set[SALSA_STATE], diff_set_t DY_set[SALSA_STATE],
											 double PW[SALSA_STATE]);

void salsa_gen_rand_shift_const(uint32_t E[SALSA_STATE + SALSA_STATE][5]);

void salsa_gen_word_deps(const uint32_t nrounds, 
								 const uint32_t e[SALSA_STATE + SALSA_STATE][5], 
								 uint32_t dep[MAX_NROUNDS][SALSA_STATE]);

void salsa_word_probs(const uint32_t nrounds,
							 const uint32_t e[SALSA_STATE + SALSA_STATE][5], 
							 double PT[MAX_NROUNDS][SALSA_STATE],
							 uint32_t D[MAX_NROUNDS][SALSA_STATE],
							 double P[SALSA_STATE]);

void salsa_word_probs_v2(const uint32_t r_start, const uint32_t r_end, 
								 const uint32_t e[SALSA_STATE + SALSA_STATE][5], 
								 double PT[MAX_NROUNDS][SALSA_STATE],
								 double P[SALSA_STATE]);

void salsa_compute_prob_rand(const diff_set_t Y[SALSA_STATE], double P[SALSA_STATE]);

double xdp_add_dset_salsa_arx(gsl_matrix* A[3][3][3], 
										diff_set_t dx, 
										diff_set_t dy, 
										diff_set_t dz, 
										diff_set_t* dt,
										uint32_t k, 
										bool b_single_diff);

#endif  // #ifndef SALSA_H
