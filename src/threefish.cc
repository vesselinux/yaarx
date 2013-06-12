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
 * \brief Analysis of block cipher Threefish -- common routines.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_ADD_DIFF_SET_H
#include "xdp-add-diff-set.hh"
#endif
#ifndef THREEFISH_H
#include "threefish.hh"
#endif

/**
 * Example rotation constants for 32-bit version of Threefish.
 */ 
uint32_t g_threefish32_rot_const[12][2] = {
  { 7,  9},
  {26, 28},
  {11, 20},
  { 3, 17},
  {13, 19},
  {24,  6},
  {28, 12},
  { 3, 14},
  {12,  6},
  { 7,  5},
  {22, 18},
  { 6, 14}
};

/**
 * The MIX primitive of 32-bit Threefish.
 */
void threefish32_mix(uint32_t X[4], uint32_t rot_const_0, uint32_t rot_const_1)
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
 * Threefish-256 with 32-bit word size
 * Reference source code: http://www.schneier.com/code/threefish.zip
 */
void threefish32(uint32_t nrounds, uint32_t rot_const[THREEFISH_MAX_NROUNDS][2], uint32_t X[4], uint32_t Y[4])
{
  assert(nrounds < THREEFISH_MAX_NROUNDS);

  for(uint32_t i = 0; i < nrounds; i++) {
	 threefish32_mix(X, rot_const[i][0], rot_const[i][1]);
	 if(i != (nrounds - 1)) {	  // not last round
		std::swap(X[1], X[3]);
	 } else {						  // last round
		for(uint32_t j = 0; j < 4; j++) {
		  Y[j] = X[j];
		}
	 }
  }
}

/**
 * Rotation constants for the 64-bit version of Threefish (the original version).
 */ 
uint32_t g_threefish64_rot_const[8][2] = {
  {14, 16},
  {52, 57},
  {23, 40},
  { 5, 37},
  {25, 33},
  {46, 12},
  {58, 22},
  {32, 32},
};

/**
 * The MIX primitive of 64-bit Threefish.
 */
void threefish64_mix(uint64_t X[4], uint64_t rot_const_0, uint64_t rot_const_1)
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
 * Threefish-256 with 64-bit word size
 * Reference source code: http://www.schneier.com/code/threefish.zip
 */
void threefish64(uint64_t nrounds, uint32_t rot_const[8][2], uint64_t X[4], uint64_t Y[4])
{
  assert(nrounds < THREEFISH_MAX_NROUNDS);

  for(uint64_t i = 0; i < nrounds; i++) {
	 threefish64_mix(X, rot_const[i][0], rot_const[i][1]);
	 if(i != (nrounds - 1)) {	  // not last round
		std::swap(X[1], X[3]);
	 } else {						  // last round
		for(uint64_t j = 0; j < 4; j++) {
		  Y[j] = X[j];
		}
	 }
  }
}

void threefish32_print_dset(diff_set_t DX[4])
{
  for(uint32_t i = 0; i < 4; i++) {
	 printf("DX[%d] = ", i);
	 xdp_add_dset_print_set(DX[i]);
	 printf("\n");
  }
}

void threefish32_print_prob(double P[4])
{
  for(uint32_t i = 0; i < 4; i++) {
	 printf("%f (2^%f) ", P[i], log2(P[i]));
  }
  printf("\n");
}

void threefish32_print_dset_trail(uint32_t nrounds, 
											 diff_set_t DT[THREEFISH_MAX_NROUNDS][4], 
											 double P[THREEFISH_MAX_NROUNDS][4])
{
  assert((nrounds + 1) < THREEFISH_MAX_NROUNDS);
  for(int i = 0; i < (int)(nrounds + 1); i++) {
	 printf("R[%2d] ", i - 1);
	 for(uint32_t j = 0; j < 4; j++) {
		xdp_add_dset_print_set(DT[i][j]);
		printf(" %f (2^%f) | ", P[i][j], log2(P[i][j]));
	 }
	 printf("\n");
  }
}

