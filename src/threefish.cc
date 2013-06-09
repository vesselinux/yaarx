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
 * \file  threefish.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \brief Analysis of block cipher Threefish.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef MAX_XDP_ADD_H
#include "max-xdp-add.hh"
#endif
#ifndef XDP_ADD_DIFF_SET_H
#include "xdp-add-diff-set.hh"
#endif
#ifndef THREEFISH_H
#include "threefish.hh"
#endif

// 
// Example rotation constants for 32-bit version of Threefish.
// 
uint32_t g_threefish_rot_const[12][2] = {
  { 7,  9},
  {26, 28},
  {11, 20},
  { 3, 17},
  {13, 19},
  {24,  6},
  {28, 12},
  {3, 14},
  {12, 6},
  {7, 5},
  {22, 18},
  {6, 14}
};

void xdp_add_dset_threefish_mix(gsl_matrix* A[3][3][3], 
										  diff_set_t DX[4], diff_set_t DY[4], double P[4],
										  uint32_t rot_const_0, uint32_t rot_const_1,
										  bool b_single_diff)
{
#if 0									  // DEBUG
  for(uint32_t j = 0; j < 4; j++) { // copy output to input
	 printf("[%s:%d] ", __FILE__, __LINE__);
	 xdp_add_dset_print_set(DX[j]);
	 printf("\n");
  }
#endif

  // MIX 0/0
  P[0] = rmax_xdp_add_dset(A, DX[0], DX[1], &DY[0], b_single_diff);
#if 1									  // TEST
  if((b_single_diff == false) && (DX[0].fixed == 0) && (DX[1].fixed == 0)) {
	 uint32_t da = DX[0].diff;
	 uint32_t db = DX[1].diff;
	 uint32_t dc_max = 0;
	 double p_max = max_xdp_add_lm(da, db, &dc_max);
	 p_max *= xdp_add_dset_size(DY[0]);
	 printf("%8X %8X | %f %f (%8X %8X) %8X\n", DX[0].diff, DX[1].diff, p_max, P[0], DY[0].diff, DY[0].fixed, dc_max);
	 assert(p_max == P[0]);
  }
#endif
  DX[1] = lrot_dset(DX[1], rot_const_0);
  DY[1] = xor_dset(DX[1], DY[0]);
  P[1] = 1.0;
  printf("\n");


  // MIX 0/1
  P[2] = rmax_xdp_add_dset(A, DX[2], DX[3], &DY[2], b_single_diff);
  DX[3] = lrot_dset(DX[3], rot_const_1);
  DY[3] = xor_dset(DX[3], DY[2]);
  P[3] = 1.0;
  printf("\n");

#if 0									  // DEBUG
  printf("\n");
  for(uint32_t j = 0; j < 4; j++) { // copy output to input
	 printf("[%s:%d] ", __FILE__, __LINE__);
	 xdp_add_dset_print_set(DY[j]);
	 printf("\n");
  }
#endif
}

void threefish_print_dset(diff_set_t DX[4])
{
  for(uint32_t i = 0; i < 4; i++) {
	 printf("DX[%d] = ", i);
	 xdp_add_dset_print_set(DX[i]);
	 printf("\n");
  }
}

void threefish_print_prob(double P[4])
{
  for(uint32_t i = 0; i < 4; i++) {
	 printf("%f (2^%f) ", P[i], log2(P[i]));
  }
  printf("\n");
}

void threefish_print_trail(uint32_t nrounds, diff_set_t DT[MAX_NROUNDS][4], double P[MAX_NROUNDS][4])
{
  assert((nrounds + 1) < MAX_NROUNDS);
  for(int i = 0; i < (int)(nrounds + 1); i++) {
	 printf("R[%2d] ", i - 1);
	 for(uint32_t j = 0; j < 4; j++) {
		xdp_add_dset_print_set(DT[i][j]);
		printf(" %f (2^%f) | ", P[i][j], log2(P[i][j]));
	 }
	 printf("\n");
  }
}

double xdp_add_dset_threefish(uint32_t nrounds, uint32_t rot_const[MAX_NROUNDS][2], gsl_matrix* A[3][3][3],
										diff_set_t DX_in[4], diff_set_t DY_in[4], // differential
										diff_set_t DT[MAX_NROUNDS][4], double P[MAX_NROUNDS][4]) // trail
{
  double p = 1.0;
  printf("[%s:%d] %s()\n", __FILE__, __LINE__, __FUNCTION__);
  assert(nrounds < MAX_NROUNDS);
  assert((nrounds + 1) < MAX_NROUNDS);

  diff_set_t DX[4] = {{0,0}}; 
  diff_set_t DY[4] = {{0,0}};

  // copy diff sets to local variables
  uint32_t round_zero = 0;
  for(uint32_t i = 0; i < 4; i++) {
	 P[round_zero][i] = 1.0;
	 DT[round_zero][i] = {DX_in[i].diff, DX_in[i].fixed};
	 DX[i] = {DX_in[i].diff, DX_in[i].fixed};
	 DY[i] = {0, 0};
  }

  for(uint32_t i = 0; i < nrounds; i++) {

	 for(uint32_t j = 0; j < 4; j++) { // init input probabilities
		P[i + 1][j] = 1.0;
	 }

	 printf("-------- Round#[%2d] --------\n", i);
#if 1	// DEBUG
	 printf("[%2d] Input:\n", i);
	 threefish_print_dset(DX);
	 threefish_print_prob(P[i]);
#endif

	 bool b_single_diff = false;
#if 1
	 if(i >= (nrounds - 1)) {	  // set to true for the last round
		b_single_diff = true;
	 }
#endif
	 xdp_add_dset_threefish_mix(A, DX, DY, P[i + 1], rot_const[i][0], rot_const[i][1], b_single_diff);

	 if(i != (nrounds - 1)) {	  // if not last round => permute
		// permute
		std::swap(DY[1], DY[3]);
		std::swap(P[i + 1][1], P[i + 1][3]);
	 } else {
		for(uint32_t j = 0; j < 4; j++) { // store final  output
		  DY_in[j] = {DY[j].diff, DY[j].fixed};
		}
	 }

	 for(uint32_t j = 0; j < 4; j++) { // copy output to input
		DT[i + 1][j] = {DY[j].diff, DY[j].fixed}; // store differences in trail
		DX[j].diff = DY[j].diff;
		DX[j].fixed = DY[j].fixed;
		DY[j] = {0, 0}; // init output
		p *= P[i + 1][j]; // compute probabilities
	 }

#if 1 // DEBUG
	 printf("[%2d] Output:\n", i);
	 threefish_print_dset(DX);
	 threefish_print_prob(P[i + 1]);
#endif
  }
  return p;
}

void threefish_mix(uint32_t X[4], uint32_t rot_const_0, uint32_t rot_const_1)
{
  // MIX 0/0
  X[0] = ADD(X[0], X[1]); 
  X[1] = LROT(X[1], rot_const_0); 
  X[1] = XOR(X[1], X[0]);

  // MIX 0/1
  X[2] = ADD(X[2], X[3]); 
  X[3] = LROT(X[3], rot_const_1); 
  X[3] = XOR(X[3], X[2]);
}

/**
 * Two rounds of reduced-word (RW) Threefish-256 
 * with reduced word-size = 32 bits.
 * Reference source code: http://www.schneier.com/code/threefish.zip
 */
void threefish256_rw(uint32_t nrounds, uint32_t rot_const[MAX_NROUNDS][2], uint32_t X[4], uint32_t Y[4])
{
  assert(nrounds < MAX_NROUNDS);

  for(uint32_t i = 0; i < nrounds; i++) {
	 threefish_mix(X, rot_const[i][0], rot_const[i][1]);
	 if(i != (nrounds - 1)) {	  // not last round
		std::swap(X[1], X[3]);
	 } else {						  // last round
		for(uint32_t j = 0; j < 4; j++) {
		  Y[j] = X[j];
		}
	 }
  }
}

// 
// A fixed input difference goes to an output set.
// 
double xdp_add_dset_threefish_exper(uint32_t nrounds, uint32_t rot_const[8][2], uint32_t npairs,
												uint32_t DX[4], diff_set_t DY_set[4])
{
  uint32_t cnt = 0;
  for(uint32_t i = 0; i < npairs; i++) {
	 uint32_t X1[4] = {0};
	 uint32_t X2[4] = {0};
	 uint32_t Y1[4] = {0};
	 uint32_t Y2[4] = {0};
	 for(uint32_t j = 0; j < 4; j++) {
		X1[j] = random32() & MASK;
		X2[j] = XOR(X1[j], DX[j]);
	 }
	 threefish256_rw(nrounds, rot_const, X1, Y1);
	 threefish256_rw(nrounds, rot_const, X2, Y2);
	 uint32_t DY[4] = {0};
	 for(uint32_t j = 0; j < 4; j++) {
		DY[j] = XOR(Y1[j], Y2[j]);
		//		printf("[%d] %8X %8X\n", j, DY[j], DYY[j]);
	 }
	 //	 printf("\n");
	 bool b_is_equal = (is_inset(DY[0], DY_set[0]) && 
							  is_inset(DY[1], DY_set[1]) &&
							  is_inset(DY[2], DY_set[2]) &&
							  is_inset(DY[3], DY_set[3]));
	 if(b_is_equal) {
		cnt++;
	 }
  }
  double p = (double)cnt / (double)npairs;
  return p;
}
