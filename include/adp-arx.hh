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
 * \file  adp-arx.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for adp-arx.cc: \copybrief adp-arx.cc.
 */ 
#ifndef ADP_ARX_H
#define ADP_ARX_H

#ifndef ADP_ARX_MSIZE
#define ADP_ARX_MSIZE 8 /**< Number of state values in the \f$\mathrm{adp}^{\mathrm{ARX}}\f$ S-function. */
#endif
#ifndef ADP_ARX_NMATRIX
#define ADP_ARX_NMATRIX 8 /**< Number of \f$\mathrm{adp}^{\mathrm{ARX}}\f$ matrices. */
#endif
#ifndef ADP_ARX_NINPUTS
#define ADP_ARX_NINPUTS 2 /**< Number of inputs to the ARX operation. */
#endif
#ifndef ADP_ARX_COLSUM
#define ADP_ARX_COLSUM 4 /**< Sum of non-zero elements in one column of the \f$\mathrm{adp}^{\mathrm{ARX}}\f$ matrices. */
#endif
/** 
 * Number of special bit positions for the \f$\mathrm{adp}^{\mathrm{ARX}}\f$ 
 * matrices - two: \f$j=0\f$ if \f$(i+r)=0\f$ and \f$j=1\f$ otherwise. 
 */
#ifndef ADP_ARX_NSPOS
#define ADP_ARX_NSPOS 2 
#endif
#ifndef ADP_ARX_NORM
#define ADP_ARX_NORM 1.0 /(double)ADP_ARX_COLSUM /**< Normalization factor for the \f$\mathrm{adp}^{\mathrm{ARX}}\f$ matrices. */
#endif
/**
 * Number of initial states for the 
 * \f$\mathrm{adp}^{\mathrm{ARX}}\f$ S-function; 
 * To every initial state out of all \ref ADP_ARX_NISTATES, 
 * corresponds a set of \ref ADP_ARX_FSTATES final states.
 * \see ADP_ARX_ISTATES, ADP_ARX_FSTATES.
 */
#ifndef ADP_ARX_NISTATES
#define ADP_ARX_NISTATES 4
#endif
/**
 * Number of final states for the 
 * \f$\mathrm{adp}^{\mathrm{ARX}}\f$ S-function; 
 * To every initial state out of all \ref ADP_ARX_NISTATES, 
 * corresponds a set of \ref ADP_ARX_FSTATES final states.
 * \see ADP_ARX_ISTATES, ADP_ARX_FSTATES.
 */
#ifndef ADP_ARX_NFSTATES
#define ADP_ARX_NFSTATES 2
#endif

extern uint32_t ADP_ARX_ISTATES[ADP_ARX_NISTATES];

extern uint32_t ADP_ARX_FSTATES[ADP_ARX_NISTATES][ADP_ARX_NFSTATES];

void adp_arx_alloc_matrices(gsl_matrix* A[2][2][2][2]);

void adp_arx_free_matrices(gsl_matrix* A[2][2][2][2]);

void adp_arx_normalize_matrices(gsl_matrix* A[2][2][2][2]);

void adp_arx_print_matrices(gsl_matrix* A[2][2][2][2]);

void adp_arx_sf(gsl_matrix* A[2][2][2][2]);

double adp_arx(gsl_matrix* A[2][2][2][2], uint32_t rot_const, 
					uint32_t da, uint32_t db, uint32_t dd, uint32_t de);

double adp_arx_exper(uint32_t r, uint32_t da, uint32_t db, uint32_t dd, uint32_t de);



#endif  // #ifndef ADP_ARX_H
