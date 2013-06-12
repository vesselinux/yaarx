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
 * \file  threefish-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for threefish.cc .
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
#ifndef THREEFISH_XOR_H
#include "threefish-xor.hh"
#endif

void test_xdp_add_dset_threefish32()
{
  uint32_t nrounds = 12;
  gsl_matrix* AA[2][2][2];		  // xdp-add-dset
  xdp_add_dset_alloc_matrices(AA);
  xdp_add_dset_gen_matrices(AA);

  gsl_matrix* A[3][3][3];		  // xdp-add-dset-full
  xdp_add_dset_alloc_matrices_all(A);
  xdp_add_dset_gen_matrices_all(A, AA);

  uint32_t rot_const[THREEFISH_MAX_NROUNDS][2] = {{0,0}};
  for(uint32_t i = 0; i < THREEFISH_MAX_NROUNDS; i++) {
	 while(rot_const[i][0] == 0) {
		rot_const[i][0] = {random32() % WORD_SIZE};
	 }
	 while(rot_const[i][1] == 0) {
		rot_const[i][1] = {random32() % WORD_SIZE};
	 }
  }

#if 1									  // fixed constants
  for(uint32_t i = 0; i < nrounds; i++) {
	 rot_const[i][0] = g_threefish32_rot_const[i][0];
	 rot_const[i][1] = g_threefish32_rot_const[i][1];
  }
#endif

#if 1									  // DEBUG
  for(uint32_t i = 0; i < nrounds; i++) {
	 printf("[%s:%d] rot_const[%2d] %2d %2d\n", __FILE__, __LINE__, i, rot_const[i][0], rot_const[i][1]);
  }
#endif

  uint32_t DX[4] = {0};
  //  uint32_t DY[4] = {0};
  double p_exp = 0.0;

  diff_set_t DX_set[4];
  diff_set_t DY_set[4];
  //  double P_set[4] = {0.0};

  for(uint32_t i = 0; i < 4; i++) {
	 DX_set[i] = {0, 0};
	 DY_set[i] = {0, 0};
	 //	 P_set[i] = 1.0;
	 DX_set[i].diff = 0;
	 DX_set[i].fixed = 0;
  }

  DX_set[0].diff = (1U << (WORD_SIZE - 1)); 
  // DX_set[0].diff = 1U << random32() % WORD_SIZE;
  // DX_set[0].diff = random32() & MASK;
  // DX_set[0].diff = gen_sparse(1, WORD_SIZE);
  // DX_set[1].diff = gen_sparse(1, WORD_SIZE);
  // DX_set[2].diff = gen_sparse(1, WORD_SIZE);
  // DX_set[2].diff = (1U << (WORD_SIZE - 1)); 
  // DX_set[3].diff = gen_sparse(1, WORD_SIZE);
  // DX_set[1].diff = random32() & MASK;
  // DX_set[2].diff = random32() & MASK;
  // DX_set[3].diff = random32() & MASK;

  diff_set_t DT[THREEFISH_MAX_NROUNDS][4] = {{{0,0}}};
  double PT[THREEFISH_MAX_NROUNDS][4] = {{0.0}};

  double p_set = xdp_add_dset_threefish32(nrounds, rot_const, A, DX_set, DY_set, DT, PT);

  printf("[%s:%d] Dset trail prob %f (2^%f)\n", __FILE__, __LINE__, p_set, log2(p_set));
  threefish32_print_dset_trail(nrounds, DT, PT);

#if 1									  // DEBUG
  printf("[%s:%d]      Input diff: ", __FILE__, __LINE__);
  for(uint32_t j = 0; j < 4; j++) {
	 DX[j] = DX_set[j].diff;
	 //	 printf("%8X ", DX[j]);
	 xdp_add_dset_print_set(DX_set[j]);
	 printf(" | ");
	 assert(DX_set[j].fixed == 0);
  }
  printf("\n");
  printf("[%s:%d] Output diff set: ", __FILE__, __LINE__);
  for(uint32_t j = 0; j < 4; j++) {
	 xdp_add_dset_print_set(DY_set[j]);
	 printf(" | ");
  }
  printf("\n");
#endif

  uint32_t npairs = (1U << 20);
  p_exp = xdp_add_dset_threefish32_exper(nrounds, rot_const, npairs, DX, DY_set);
  printf("[%s:%d] Experimental prob: %f (2^%f)\n", __FILE__, __LINE__, p_exp, log2(p_exp));
  printf("[%s:%d]\n THE %f (2^%f),\n EXP %f (2^%f), NPAIRS 2^%f\n", __FILE__, __LINE__, p_set, log2(p_set), p_exp, log2(p_exp), log2(npairs));

  xdp_add_dset_free_matrices_all(A);
  xdp_add_dset_free_matrices(AA);
}

/**
 * Main function of the tests.
 */
int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %8X\n", __FILE__, __LINE__, WORD_SIZE, MASK);
  srandom(time(NULL));

  test_xdp_add_dset_threefish32();
  return 0;
}
