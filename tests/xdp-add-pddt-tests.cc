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
 * \file  xdp-add-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for xdp-add.cc.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR_H
#include "xdp-add.hh"
#endif
#ifndef XDP_ADD_PDDT_H
#include "xdp-add-pddt.hh"
#endif

void test_xdp_add_pddt()
{
  uint32_t n = WORD_SIZE;
  double p_thres = 0.1;
  //  uint32_t max_size = (1ULL << 20);
  uint64_t max_size = (1ULL << 32); // Maximum number of elements stored in the pDDT

  // init A
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  // init C
  gsl_vector* C = gsl_vector_calloc(XDP_ADD_MSIZE);
  gsl_vector_set(C, XDP_ADD_ISTATE, 1.0);

  std::multiset<differential_3d_t, struct_comp_diff_3d_p> diff_mset_p;
  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz> diff_set_dx_dy_dz;
  xdp_add_pddt(n, p_thres, max_size, &diff_set_dx_dy_dz, &diff_mset_p);
  printf("[%s:%d] p_thres = %f (2^%f), n = %d, #diffs = %d %d\n", __FILE__, __LINE__, 
			p_thres, log2(p_thres), WORD_SIZE, diff_set_dx_dy_dz.size(), diff_mset_p.size());
  assert(diff_set_dx_dy_dz.size() == diff_mset_p.size());
  uint32_t cnt = 0;

  std::multiset<differential_3d_t, struct_comp_diff_3d_p>::iterator set_iter;
  for(set_iter = diff_mset_p.begin(); set_iter != diff_mset_p.end(); set_iter++) {
	 differential_3d_t i_diff = *set_iter;
	 double p_the = xdp_add(A, i_diff.dx, i_diff.dy, i_diff.dz);
#if 0									  // print all
	 printf("[%s:%d] %4d: XDP_ADD_THRES[(%8X,%8X)->%8X] = %6.5f\n", 
			  __FILE__, __LINE__, cnt, i_diff.dx, i_diff.dy, i_diff.dz, i_diff.p);
#endif				 // #if 0
	 assert(p_the == i_diff.p);
	 cnt++;
  }
#if (WORD_SIZE < 10)  
  std::multiset<differential_3d_t, struct_comp_diff_3d_p> diff_mset_p_exper;
  xdp_add_pddt_exper(&diff_mset_p_exper, p_thres);
  printf("[%s:%d] THE #%d, EXP #%d\n", __FILE__, __LINE__, diff_mset_p.size(), diff_mset_p_exper.size());
  assert(diff_mset_p.size() == diff_mset_p_exper.size());
#endif // #if (WORD_SIZE < 10)  
  
  gsl_vector_free(C);
  xdp_add_free_matrices(A);
}

/**
 * Main function of XDP-ADD-PDDT tests.
 */
int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %llX\n", __FILE__, __LINE__, WORD_SIZE, (WORD_MAX_T)MASK);
  //  assert(WORD_SIZE <= 10);
  srandom(time(NULL));
  test_xdp_add_pddt();
  return 0;
}
