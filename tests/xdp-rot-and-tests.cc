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
 * \file  xdp-rot-and-tests.cc 
 * \author A.Roy, V.Velichkov, arnab.roy@uni.lu, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for XDP of of the sequence of ROT and AND: \f$b = f(a)
 * = (a \mathrm{lrot} s) \wedge (a \mathrm{lrot} t)\f$: \f$\mathrm{xdp}^{\mathrm{lrot}\wedge}(da
 * \rightarrow db)\f$.  \brief Tests for \f$\mathrm{xdp}^{\wedge}\f$.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_AND_H
#include "xdp-and.hh"
#endif
#ifndef XDP_ROT_AND_H
#include "xdp-rot-and.hh"
#endif

void test_xdp_rot_and_print_graph()
{
  assert(WORD_SIZE == 5);
  uint32_t s = 1;
  uint32_t t = 3;
  uint32_t delta = 0x1F;//random32();
  uint32_t da = LROT(delta, s);
  uint32_t db = LROT(delta, t);
  uint32_t dc = 0;
  uint32_t i_start = 0;
  uint32_t cycle_len = WORD_SIZE;
  assert(s == 1);
  assert(t == 3);
  uint32_t da_idx[WORD_SIZE] = {0, 2, 4, 1, 3};
  uint32_t db_idx[WORD_SIZE] = {3, 0, 2, 4, 1};
  gsl_matrix* A[WORD_SIZE];
  xdp_rot_and_alloc_matrices(A);
  xdp_rot_and_compute_graph(A, i_start, cycle_len, da_idx, db_idx, da, db, dc);
  xdp_rot_and_print_graph(A);
  xdp_rot_and_free_matrices(A);
}


double test_xdp_rot_and_lucks(const uint32_t da, const uint32_t db,
										const uint32_t s, const uint32_t t)
{
  assert(t >= s);
  uint32_t da_lrot = LROT(da, (t - s));
  uint32_t da_rrot = RROT(da, (t - s));
  uint32_t db_lrot = LROT(db, (t - s));
  // p_i[LEFT][RIGHT]
  double p_arr[2][2] = {
	 {1.0,  0.0},						  // 00, 01
	 {0.25, 0.75}						  // 10, 11
  }; 
  double p_tot = 1.0;
  for(uint32_t i = 0; i < WORD_SIZE; i++) {
	 uint32_t da_i  = (da >> i) & 1;
	 uint32_t da_lrot_i  = (da_lrot >> i) & 1;
	 uint32_t da_rrot_i  = (da_rrot >> i) & 1;
	 uint32_t db_i  = (db_lrot >> i) & 1;
	 double p_i = 0.0;

	 //	 da_i = da_lrot_i & da_rrot_i;

	 if(da_i == 0) {
		if(db_i == 0) {
		  p_i = 1.0;
		}
		if(db_i == 1) {
		  p_i = 0.0;
		}
	 }
	 if(da_i == 1) {
		//		if((da_lrot_i == 0) && (da_rrot_i == 0)) {
		if(da_lrot_i & da_rrot_i) {
		  p_i = 0.25;
		} else {
		  p_i = 0.75;
		}
	 }
	 p_tot *= p_i;
	 if((da_i == 0) && (db_i != 0)) {
		return -1.0;
	 }
	 //	 p_tot *= p_i[da_i][db_i];
#if 1								  // DEBUG
	 //	 printf("%2d: p(db %d| da %d) %f\n", i, db_i, da_i, p_arr[da_i][db_i]);
	 printf("%2d: p(db %d| da %d) %f\n", i, db_i, da_i, p_i);
#endif
  }
  return p_tot;
}


double test_xdp_rot_and_lucks_v2(const uint32_t da, const uint32_t db,
										const uint32_t s, const uint32_t t)
{
  assert(t >= s);
  //  uint32_t da_lrot = LROT(da, (t - s));
  // p_arr[LEFT][RIGHT]
  double p_arr[2][2] = {
	 {1.0,  0.0},						  // 00, 01
	 {0.25, 0.75}						  // 10, 11
  }; 
  double p_tot = 1.0;
  for(uint32_t i = 0; i < WORD_SIZE; i++) {
	 uint32_t da_i  = (da >> i) & 1;
	 uint32_t db_i  = (db >> i) & 1;
	 p_tot *= p_arr[da_i][db_i];
#if 1								  // DEBUG
	 printf("%2d: p(db %d| da %d) %f\n", i, db_i, da_i, p_arr[da_i][db_i]);
	 //	 printf("%2d: p(db %d| da %d) %f\n", i, db_i, da_i, p_i);
#endif
	 if((da_i == 0) && (db_i != 0)) {
		return -1.0;
	 }
  }
  return p_tot;
}

void test_xdp_rot_and()
{
  uint32_t s = 1;
  uint32_t t = 8 % WORD_SIZE;
  uint32_t da = 1;//random32() & MASK;
  uint32_t dc = 2;//random32() & MASK;
  double p1= xdp_rot_and(da, dc, s, t); 
  printf("[%s:%d] %d %d | XDP_AND_TH[%8X->%8X] = %6.5f\n", 
			__FILE__, __LINE__, s, t, da, dc, p1);
#if 1
  double p2= xdp_rot_and_exper(da, dc, s, t);
  printf("[%s:%d] %d %d | XDP_AND_EX[%8X->%8X] = %6.5f\n", 
			__FILE__, __LINE__, s, t, da, dc, p2);
  assert(p1 == p2);
#endif
#if 1
  double p3 = test_xdp_rot_and_lucks(da, dc, s, t);
  printf("[%s:%d] %d %d | XDP_AND_EX[%8X->%8X] = %6.5f\n", 
			__FILE__, __LINE__, s, t, da, dc, p3);
#endif
}

void test_xdp_rot_and_all()
{
  uint32_t s = 1;//random32() % WORD_SIZE;//1;
  uint32_t t = 3;//random32() % WORD_SIZE;//3;

  if(s == t) {
	 t = (s + 1) % WORD_SIZE;
  }
  //#define ALL_ROT_CONST
#ifdef ALL_ROT_CONST
  for(s = 0; s < WORD_SIZE; s++) {
	 for(t = 0; t < WORD_SIZE; t++) {
		if(s == t)
		  continue;
#endif
		for(uint32_t da = 1; da < ALL_WORDS; da++) {
		  for(uint32_t dc = 0; dc < ALL_WORDS; dc++) {
			 double p1 = xdp_rot_and(da, dc, s, t);
			 double p2 = xdp_rot_and_exper(da, dc, s, t);
			 printf("[%s:%4d] %d %d | XDP_AND_TH[%8X->%8X] = %6.5f\n", 
					  __FILE__, __LINE__, s, t, da, dc, p1);
			 printf("[%s:%4d] %d %d | XDP_AND_EX[%8X->%8X] = %6.5f\n", 
					  __FILE__, __LINE__, s, t, da, dc, p2);
			 printf("\n");
			 assert(p1 == p2);
#if 1
			 double p3 = test_xdp_rot_and_lucks(da, dc, s, t);
			 printf("[%s:%4d] %d %d | XDP_AND_LS[%8X->%8X] = %6.5f\n", 
					  __FILE__, __LINE__, s, t, da, dc, p3);
			 if(p3 != -1.0) {
				assert(p3 == p2);
			 }
#endif
		  }
		}
#ifdef ALL_ROT_CONST
	 }
  }
#endif
  printf("[%s:%d] OK\n", __FILE__, __LINE__);
}

void test_xdp_rot_and_rand()
{
  uint32_t N = (1U << 20);

  for(uint32_t i = 0; i < N; i++) {
	 uint32_t s = random32() % WORD_SIZE;//1;
	 uint32_t t = random32() % WORD_SIZE;//3;
	 uint32_t da = random32() & MASK;
	 uint32_t dc = random32() & MASK;

	 if(s == t)
		continue;

	 double p1= xdp_rot_and(da, dc, s, t);
	 if(p1) {
		printf("[%s:%d] %2d %2d | XDP_AND_TH[%8X->%8X] = %6.5f 2^%f\n", 
				 __FILE__, __LINE__, s, t, da, dc, p1, log2(p1));
	 }
#if(WORD_SIZE < 20)
	 double p2= xdp_rot_and_exper(da, dc, s, t);
	 if(p2) {
		printf("[%s:%d] %2d %2d | XDP_AND_EX[%8X->%8X] = %6.5f 2^%f\n", 
				 __FILE__, __LINE__, s, t, da, dc, p2, log2(p1));
	 }
	 assert(p1 == p2);
#endif
  }
  printf("[%s:%d] OK\n", __FILE__, __LINE__);
}

void test_xdp_rot_and_vs_xdp_and_all()
{

  uint32_t A[2][2][2] = {{{0}}};
  xdp_and_bf(A);

  uint32_t r1 = 1;
  uint32_t r2 = 3;//8;

  for(uint32_t delta = 0; delta < ALL_WORDS; delta++) {
	 uint32_t da = LROT(delta, r1);
	 uint32_t db = LROT(delta, r2);

	 for(uint32_t dc = 0; dc < ALL_WORDS; dc++) {

		bool is_possible = xdp_and_is_nonzero(da, db, dc);//(((~da & MASK) & (~db & MASK) & dc) == 0);
#if 0																  // DEBUG
		print_binary(da);
		printf("\n");
		print_binary(db);
		printf("\n");
		print_binary(dc);
		printf("\n");
		printf("Is possible: %d\n", is_possible);
#endif
		double p1 = xdp_and(A, da, db, dc);
		double p2 = xdp_rot_and_exper(delta, dc, r1, r2);

		assert((p1 != 0) == (is_possible == true));
		assert((p1 >= 0.0) && (p1 <= 1.0));
		assert((p2 >= 0.0) && (p2 <= 1.0));

		printf("[%s:%d] XDP_AND_TH[(%8X,%8X)->%8X] = %6.5f\n", 
				 __FILE__, __LINE__, da, db, dc, p1);
		printf("[%s:%d] XDP_AND_EX[(%8X,%8X)->%8X] = %6.5f\n", 
				 __FILE__, __LINE__, da, db, dc, p2);
		printf("\n");

		if((is_possible == false)) {
		  assert(p2 == 0);
		}

		//  assert(p1 == p2);
	 }
  }
}

// test the alignment of the bits between two rotations of x: (x <<< s) and (x <<< t)
void test_rot_rot_x()
{
  bool w[WORD_SIZE] = {false};
  uint32_t s = 1;//1;//random32() % WORD_SIZE;
  uint32_t t = 3;//8;//random32() % WORD_SIZE;

  if(s > t) {
	 std::swap(s, t);
  }

  printf("[%s:%d] (s, t) = %2d %2d\n", __FILE__, __LINE__, s, t);
  uint32_t x[WORD_SIZE] = {0};
  uint32_t x_s[WORD_SIZE] = {0};
  uint32_t x_t[WORD_SIZE] = {0};
  for(uint32_t i = 0; i < WORD_SIZE; i++) {
	 x[i] = WORD_SIZE - i - 1;
	 printf("%2d ", x[i]);
  }
  printf("\n");
  for(uint32_t i = 0; i < WORD_SIZE; i++) {
	 uint32_t idx_s = (i + s) % WORD_SIZE;
	 x_s[x[i]] =  x[idx_s];
	 printf("%2d ", x[idx_s]);
  }
  printf("\n");
  for(uint32_t i = 0; i < WORD_SIZE; i++) {
	 uint32_t idx_t = (i + t) % WORD_SIZE;
	 x_t[x[i]] =  x[idx_t];
	 printf("%2d ", x[idx_t]);
  }
  printf("\n");

  assert(s <= t);

  uint32_t n = WORD_SIZE;
  uint32_t l_s = (s - t + n) % n;//((n - t - 1) - (n - s) + 1) % n;
  uint32_t l_t = (t - s) % n;//((n - s - 1) - (n - t) + 1) % n;
  uint32_t u = 0;					  // both bits are assigned
  uint32_t v = 0;					  // one bit is assigned
  uint32_t m = 0;					  // no bits are assigned

  if(l_t >= l_s) {
	 u = l_s;
	 v = l_t - l_s;
	 m = n - l_t;
  } else {
	 u = l_t;
	 v = l_s - l_t;
	 m = n - l_s;
  }

  printf("(l_s, l_t) = (%2d %2d) | (u, v, m) = (%2d %2d %2d)\n", l_s, l_t, u, v, m);
  assert((u + v + m) == n);

  for(uint32_t i = 0; i < WORD_SIZE; i++) {
	 uint32_t idx_s = x_s[i];
	 uint32_t idx_t = x_t[i];
	 printf("%2d: ", i);
	 if(!w[idx_s]) {
		w[idx_s] = true;
		printf("%2d ", idx_s);
	 } else {
		printf(" - ");
	 }
	 if(!w[idx_t]) {
		w[idx_t] = true;
		printf("%2d ", idx_t);
	 } else {
		printf(" - ");
	 }
	 if(i == (l_s - 1)) {
		printf(" <- l_s = %d", l_s);
	 }
	 if(i == (l_t - 1)) {
		printf(" <- l_t = %d", l_t);
	 }
	 printf("\n");
  }
}

void test_xdp_and_rot_indices()
{
  uint32_t s = 0;
  uint32_t t = 2;
  uint32_t n = WORD_SIZE;					  // word size

  assert(s <= t);

  uint32_t r = (t - s);

  if(r == 0) {
	 r = 1;
  }

  uint32_t msb = n - 1;

  uint32_t i_start = 0;//n - 1 - (r - 1);
  uint32_t i = i_start;
  uint32_t cnt = 0;
  printf("[%s:%d] %d %d\n", __FILE__, __LINE__, msb, i);
  do {
	 printf("%d ", i);
	 i = (i + r) % n; 
	 cnt++;  
  } while((cnt != n) && (i != i_start));
  printf("\n");
}

void test_max_xdp_rot_and_is_max()
{
  uint32_t s = 1;
  uint32_t t = 8 % WORD_SIZE;
  uint32_t delta = random32() & MASK;
  uint32_t dc = 0;
  uint32_t dc_exper = 0;

  double p1 = max_xdp_rot_and(delta, &dc, s, t);
  double p2 = xdp_rot_and(delta, dc, s, t); 
  double p3 = max_xdp_rot_and_exper(delta, &dc_exper, s, t);

  printf("[%s:%d] %d %d | MAX_XDP_AND_TH[%8X->%8X] = %6.5f\n", 
			__FILE__, __LINE__, s, t, delta, dc, p1);
  printf("[%s:%d] %d %d |     XDP_AND_TH[%8X->%8X] = %6.5f\n", 
			__FILE__, __LINE__, s, t, delta, dc, p2);
  printf("[%s:%d] %d %d | MAX_XDP_AND_EX[%8X->%8X] = %6.5f\n", 
			__FILE__, __LINE__, s, t, delta, dc_exper, p3);

  //  printf("[%s:%d] %d %d | %8X -> %8X %f\n", __FILE__, __LINE__, s, t, delta, dc, p);

}

void test_max_xdp_rot_and_is_max_all()
{
  uint32_t s = 2;//1;
  uint32_t t = 4;//8 % WORD_SIZE;
  uint32_t dc = 0;

#if 1									  // s,t
  for(s = 0; s < WORD_SIZE; s++) {
	 for(t = 0; t < WORD_SIZE; t++) {
		if(s == t)
		  continue;
#endif
		//  uint32_t delta = random32() & MASK;
		for(uint32_t delta = 0; delta < ALL_WORDS; delta++) {

		  double p1 = max_xdp_rot_and(delta, &dc, s, t);
		  double p2 = xdp_rot_and(delta, dc, s, t); 
		  printf("[%s:%d] %d %d | MAX_XDP_AND_TH[%8X->%8X] = %6.5f 2^%f\n", 
					__FILE__, __LINE__, s, t, delta, dc, p1, log2(p1));
		  printf("[%s:%d] %d %d |     XDP_AND_TH[%8X->%8X] = %6.5f 2^%f\n", 
					__FILE__, __LINE__, s, t, delta, dc, p2, log2(p2));
#if 1
		  uint32_t dc_exper = 0;
		  double p3 = max_xdp_rot_and_exper(delta, &dc_exper, s, t);
		  printf("[%s:%d] %d %d | MAX_XDP_AND_EX[%8X->%8X] = %6.5f 2^%f\n", 
					__FILE__, __LINE__, s, t, delta, dc_exper, p3, log2(p3));
		  assert(p1 == p3);
#endif
		  //	 uint32_t hw = hw32(delta) & MASK;
		  //	 printf("| hw %d", hw);
		  printf("\n");
		  //  printf("[%s:%d] %d %d | %8X -> %8X %f\n", __FILE__, __LINE__, s, t, delta, dc, p);
		  assert(p1 == p2);
		  assert(p1 != 0.0);
		}
#if 1
	 }
  } 
#endif  // #if 1									  // s,t
  printf("[%s:%d] OK\n", __FILE__, __LINE__);
}

void test_max_xdp_rot_and_rand()
{
  uint32_t N = (1U << 20);

  for(uint32_t i = 0; i < N; i++) {
	 for(uint32_t s = 0; s < WORD_SIZE; s++) {
		for(uint32_t t = 0; t < WORD_SIZE; t++) {
		  if(s == t)
			 continue;
		  uint32_t delta = random32() & MASK;
		  uint32_t dc = 0;

		  double p1 = max_xdp_rot_and(delta, &dc, s, t);
		  double p2 = xdp_rot_and(delta, dc, s, t); 
		  printf("[%s:%d] %d %d | MAX_XDP_AND_TH[%8X->%8X] = %6.5f 2^%f\n", 
					__FILE__, __LINE__, s, t, delta, dc, p1, log2(p1));
		  printf("[%s:%d] %d %d |     XDP_AND_TH[%8X->%8X] = %6.5f 2^%f\n", 
					__FILE__, __LINE__, s, t, delta, dc, p2, log2(p2));
#if 1
		  uint32_t dc_exper = 0;
		  double p3 = max_xdp_rot_and_exper(delta, &dc_exper, s, t);
		  printf("[%s:%d] %d %d | MAX_XDP_AND_EX[%8X->%8X] = %6.5f 2^%f\n", 
					__FILE__, __LINE__, s, t, delta, dc_exper, p3, log2(p3));
		  assert(p1 == p3);
#endif
		  printf("\n");
		  assert(p1 == p2);
		  assert(p1 != 0.0);
		}
	 }
  } 
}

void test_max_xdp_rot_and_bounds()
{
  uint32_t s = 1;
  uint32_t t = 8 % WORD_SIZE;
  uint32_t delta = random32() & MASK;
  uint32_t i_start = 0;
  uint32_t cycle_len = WORD_SIZE;
  uint32_t da = LROT(delta, s);
  uint32_t db = LROT(delta, t);
  uint32_t dc_max = 0;
  uint32_t da_idx[WORD_SIZE] = {0};
  uint32_t db_idx[WORD_SIZE] = {0};
  uint32_t start_idx = 0;

  gsl_vector* B[XDP_ROT_AND_NISTATES][WORD_SIZE];
  for(int j = 0; j < XDP_ROT_AND_NISTATES; j++){
	 for(int i = 0; i < WORD_SIZE; i++){
		B[j][i] = gsl_vector_calloc(XDP_ROT_AND_MSIZE);
	 }
  }

  for(int j = 0; j < XDP_ROT_AND_NISTATES; j++){
	 uint32_t fs[2] = {0};
	 if(j == 0) {
		fs[0] = 0;
		fs[1] = 1;
	 } 
	 if(j == 1) {
		fs[0] = 2;
		fs[1] = 3;
	 } 
	 gsl_vector_set(B[j][WORD_SIZE - 1], fs[0], 1.0); 
	 gsl_vector_set(B[j][WORD_SIZE - 1], fs[1], 1.0); 
  }

  bool b_is_marked[WORD_SIZE] = {false};
  cycle_len = xdp_rot_compute_indices(s, t, b_is_marked, i_start, start_idx, da_idx, db_idx);
  assert(cycle_len == WORD_SIZE);

  max_xdp_rot_and_bounds(B, i_start, cycle_len, da_idx, db_idx, da, db, &dc_max);

  max_xdp_rot_and_print_bounds(B);

  for(int j = 0; j < XDP_ROT_AND_NISTATES; j++){
	 for(int i = 0; i < WORD_SIZE; i++){
		gsl_vector_free(B[j][i]);
	 }
  }

}

void test_xdp_rot_and_pddt()
{
  const uint32_t s = 1;
  const uint32_t t = 8 % WORD_SIZE;
  const double p_thres = XDP_ROT_AND_P_THRES;
  const uint32_t max_cnt = XDP_ROT_AND_MAX_DIFF_CNT;
  std::set<differential_t, struct_comp_diff_dx_dy> hways_diff_set_dx_dy;
  std::multiset<differential_t, struct_comp_diff_p> hways_diff_mset_p;
  uint32_t cnt_diff = xdp_rot_and_pddt( &hways_diff_set_dx_dy, &hways_diff_mset_p, s, t, max_cnt, p_thres);
  uint32_t len_dx_dy = hways_diff_set_dx_dy.size();
  uint32_t len_p = hways_diff_mset_p.size();
#if 0
  xdp_rot_and_print_set_dx_dy(hways_diff_set_dx_dy);
#endif
#if 1
  xdp_rot_and_print_mset_p(hways_diff_mset_p);
#endif
  printf("[%s:%d] pDDT size | %d %d %d\n ", __FILE__, __LINE__, cnt_diff, len_dx_dy, len_p);
}




/**
 * Main function.
 */
int main()
{
  printf("#--- [%s:%d] Tests, WORD_SIZE  = %d, MASK = %8X\n", __FILE__, __LINE__, WORD_SIZE, MASK);
  srandom(time(NULL));

  // ---max-xdp-rot-and ---

  //  test_xdp_rot_and_pddt();
  //  test_max_xdp_rot_and_rand();
  //  test_max_xdp_rot_and_is_max_all();
  //  test_max_xdp_rot_and_is_max();
  //  test_max_xdp_rot_and_bounds();

  // --- xdp-rot-and ---

  //  test_xdp_rot_and_pddt();
  //  test_xdp_and_rot_indices();
  //  test_xdp_rot_and_rand();
  test_xdp_rot_and_all();
  //  test_xdp_rot_and();
  //  test_xdp_rot_and_print_graph();
  //  test_rot_rot_x();
  //  test_xdp_rot_and_vs_xdp_and_all();
  return 0;
}
