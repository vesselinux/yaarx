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
 * \file  xdp-rot-and.cc 
 * \author A.Roy, V.Velichkov, {arnab.roy,vesselin.velichkov}@uni.lu
 * \date 2012-2013
 * \brief The XOR differential probability of the sequence of ROT and
 * AND: \f$b = f(a) = (a~\mathrm{rot}~s) \wedge (a~\mathrm{rot}~t)\f$: 
 * \f$\mathrm{xdp}^{\mathrm{rot}\wedge}(da \rightarrow db)\f$.
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

// c = (a <<< r1) & (a <<< r2)
double xdp_rot_and_exper(uint32_t da, uint32_t dc,
								 uint32_t rot_const_1, uint32_t rot_const_2)
{
  assert(WORD_SIZE <= 20);
  uint32_t cnt = 0;

  for(uint32_t x = 0; x < ALL_WORDS; x++) {
	 uint32_t xx = x ^ da;
	 uint32_t z = LROT(x, rot_const_1) & LROT(x, rot_const_2);
	 uint32_t zz = LROT(xx, rot_const_1) & LROT(xx, rot_const_2);
	 uint32_t dz = z ^ zz;
	 if(dz == dc) {
		cnt++;
	 }
  }
  double p = (double)cnt / (double)(ALL_WORDS);
  return p;
}

void xdp_rot_and_alloc_matrices(gsl_matrix* A[WORD_SIZE])
{
  for(int i = 0; i < WORD_SIZE; i++){
	 A[i] = gsl_matrix_calloc(XDP_ROT_AND_MSIZE, XDP_ROT_AND_MSIZE);
  }
}

void xdp_rot_and_free_matrices(gsl_matrix* A[WORD_SIZE])
{
  for(int i = 0; i < WORD_SIZE; i++){
	 gsl_matrix_free(A[i]);
  }
}

void xdp_rot_and_print_graph(gsl_matrix* A[WORD_SIZE])
{
  for(int i = 0; i < WORD_SIZE; i++){
	 printf("A[%2d] \n", i);
	 for(int row = 0; row < XDP_ROT_AND_MSIZE; row++){
		for(int col = 0; col < XDP_ROT_AND_MSIZE; col++){
		  double e = gsl_matrix_get(A[i], row, col);
		  printf("%3.2f, ", e);
		}
		printf("\n");
	 }
	 printf("\n");
  }
}

void xdp_rot_and_print_matrix(gsl_matrix* A)
{
  for(int row = 0; row < XDP_ROT_AND_MSIZE; row++){
	 for(int col = 0; col < XDP_ROT_AND_MSIZE; col++){
		double e = gsl_matrix_get(A, row, col);
		printf("%3.2f, ", e);
	 }
	 printf("\n");
  }
}

void xdp_rot_and_print_vector(gsl_vector* R)
{
	 for(int col = 0; col < XDP_ROT_AND_MSIZE; col++){
		double e = gsl_vector_get(R, col);
		printf("%3.2f, ", e);
	 }
}

// xdp_and_diff_idx_to_states: g_s[idx][valid_states]
// [x]y -> 0[x], 1[x]
// [0]0 -> 0[0], 1[0] : 0 -> 0, 2
// [0]1 -> 0[0], 1[0] : 1 -> 0, 2
// [1]0 -> 0[1], 1[1] : 2 -> 1, 3
// [1]1 -> 0[1], 1[1] : 3 -> 1, 3
// 
// diff_indx=(x,y): 0=(0,0), 1=(0,1), 2=(1,0), 3=(1,1)
void xdp_rot_and_compute_subgraph(gsl_matrix* A,
											 uint32_t da_in, uint32_t db_in, uint32_t dc_in,
											 uint32_t da_out, uint32_t db_out, uint32_t dc_out)
{
  uint32_t idx_in  = (da_in << 2) | (db_in << 1) | (dc_in << 0);
  uint32_t idx_out = (da_out << 2) | (db_out << 1) | (dc_out << 0);
  uint32_t s[XDP_ROT_AND_MSIZE][XDP_ROT_AND_MSIZE] = {{0}};

  // V[da|db|dc][{(x,y)}]
  uint32_t V[8][4] = {
	 {1, 1, 1, 1},				  // 0: 0,1,2,3
	 {0, 0, 0, 0},				  // 1: -
	 {1, 1, 0, 0}, 			  // 2: 0,1
	 {0, 0, 1, 1},				  // 3: 2,3
	 {1, 0, 1, 0},				  // 4: 0,2
	 {0, 1, 0, 1},				  // 5: 1,3
	 {0, 1, 1, 0},				  // 6: 1,2
	 {1, 0, 0, 1}				  // 7: 0,3
  };

  //  uint32_t cnt = 0;
  for(uint32_t i = 0; i < XDP_ROT_AND_MSIZE; i++) {
	 for(uint32_t j = 0; j < XDP_ROT_AND_MSIZE; j++) {

		if(V[idx_in][i] && V[idx_out][j]) {
		  uint32_t upper = (i >> 1) & 1;
		  uint32_t lower = (j >> 0) & 1;
		  if(upper == lower) {
			 assert(s[i][j] == 0);
			 s[i][j] = 1;
#if 0									  // DEBUG
			 printf("Add link: %d -> %d\n", i, j);
#endif
		  }
		}

	 }
  }
  // 
  //                 col = input
  //                         |
  //                         V
  //                  [x] [x] [x] [x]  
  // row = output <-  [x] [x] [x] [x]  
  //                  [x] [x] [x] [x]  
  // 
  // row = output, col = input
  for(uint32_t row = 0; row < XDP_ROT_AND_MSIZE; row++) {
	 for(uint32_t col = 0; col < XDP_ROT_AND_MSIZE; col++) {
		double e = (double)s[col][row];
		gsl_matrix_set(A, row, col, e);
	 }
  }
} 

// i_start is the bit position at which we start; start_idx is the bit index of 
// the start bit of the cycle. We must always end on the start_idx so that we have
// a cycle. For example we may start at position i_start = 3 with
// start index 4 and we may have a cycle e.g. (4,7)->(7,5)->(5,4) 
uint32_t xdp_rot_compute_indices(uint32_t s, uint32_t t, bool b_is_marked[WORD_SIZE], 
											uint32_t i_start, uint32_t start_idx,
											uint32_t da_idx[WORD_SIZE], uint32_t db_idx[WORD_SIZE])
{
  uint32_t n = WORD_SIZE;
  uint32_t r = 0;

  assert(s != t);

  if(t > s) {
	 r = (t - s);
  } 
  if(t < s) {
	 r = n + (t - s);
  }

  uint32_t i = start_idx;
  uint32_t cycle_len = 0;
#if 0									  // DEBUG
  printf("[%s:%d] %d\n", __FILE__, __LINE__, i);
#endif
   do {
	 da_idx[i_start + cycle_len] = i;
	 b_is_marked[i] = true;
#if 0									  // DEBUG
	 printf("%d ", i);
#endif
	 i = (i + r) % n; 
	 cycle_len++;  
	} while((cycle_len != n) && (i != start_idx));
#if 0									  // DEBUG
  printf("\n");
#endif
#if 0									  // DEBUG
  printf("[%s:%d] %d\n", __FILE__, __LINE__, (i_start + cycle_len));
#endif
  assert((i_start + cycle_len) <= WORD_SIZE);
  for(i = i_start; i < (i_start + cycle_len); i++) {
	 uint32_t j = ((i - i_start) + 1) % cycle_len;
	 db_idx[i_start + j] = da_idx[i];
  }
  //  assert(cycle_len <= WORD_SIZE);
  return cycle_len;
}

// compute graph as a sequence of adjacency matrices; s,t - rotation constants
void xdp_rot_and_compute_graph(gsl_matrix* A[WORD_SIZE], uint32_t i_start, uint32_t cycle_len,
										 uint32_t da_idx[WORD_SIZE], uint32_t db_idx[WORD_SIZE],
										 const uint32_t da, const uint32_t db, const uint32_t dc)
{
  //  uint32_t dc_idx[5] = {0, 2, 4, 1, 3};
  //  for(uint32_t i = 0; i < (WORD_SIZE - 1); i++) {
#if 0									  // DEBUG
  printf("[%s:%d] %d %d\n", __FILE__, __LINE__, (i_start + (cycle_len - 1)), (WORD_SIZE - 1));
#endif
  assert((i_start + (cycle_len - 1)) <= (WORD_SIZE - 1));
  for(uint32_t i = i_start; i < (i_start + (cycle_len - 1)); i++) {
	 uint32_t da_i  = (da >> da_idx[i]) & 1;
	 uint32_t db_i  = (da >> db_idx[i]) & 1;
	 uint32_t dc_i  = (dc >> da_idx[i]) & 1;
	 uint32_t da_ii = (da >> da_idx[i+1]) & 1;
	 uint32_t db_ii = (da >> db_idx[i+1]) & 1;
	 uint32_t dc_ii = (dc >> da_idx[i+1]) & 1;
#if 0									  // DEBUG
	 printf("--- [%2d] ---\n", i);
#endif
	 xdp_rot_and_compute_subgraph(A[i], da_i, db_i, dc_i, da_ii, db_ii, dc_ii);
  }
}

// i_start: start bit postion; cycle_len - lend of cycle; multiply matrices: A[i_start] ... A[i_start + cycle_len]
double xdp_rot_and_one_cycle(gsl_matrix* A[WORD_SIZE], uint32_t i_start, uint32_t cycle_len)
{
  double p = 0.0;

  //  assert(WORD_SIZE == 5);
  gsl_vector* C[2];
  gsl_vector* L[2];
  gsl_vector* R = gsl_vector_calloc(XDP_ROT_AND_MSIZE);

  for(uint32_t i = 0; i < 2; i++) {
	 C[i] = gsl_vector_calloc(XDP_ROT_AND_MSIZE);
	 L[i] = gsl_vector_calloc(XDP_ROT_AND_MSIZE);
  }

  gsl_vector_set(C[0], 0, 1.0);
  gsl_vector_set(C[0], 2, 1.0);
  gsl_vector_set(L[0], 0, 1.0);
  gsl_vector_set(L[0], 1, 1.0);

  gsl_vector_set(C[1], 1, 1.0);
  gsl_vector_set(C[1], 3, 1.0);
  gsl_vector_set(L[1], 2, 1.0);
  gsl_vector_set(L[1], 3, 1.0);
#if 0									  // DEBUG
  double p_tmp[2][WORD_SIZE] = {{0.0}};
#endif
  double prob[2] = {0.0, 0.0};
  for(uint32_t j = 0; j < 2; j++) {

	 gsl_vector_set_all(R, 0.0);

	 assert((i_start + (cycle_len - 1)) <= (WORD_SIZE - 1));
	 for(uint32_t i = i_start; i < (i_start + (cycle_len - 1)); i++) {
#if 0									  // DEBUG
		printf("[%s:%d] %d|%2d:\n", __FILE__, __LINE__, j, i);
		printf("C%d[%d] = ", j, i);
		xdp_rot_and_print_vector(C[j]);
		//		printf("\nA[%d] = \n", i);
		//		xdp_rot_and_print_matrix(A[i]);
		printf("\n");
#endif
		gsl_blas_dgemv(CblasNoTrans, 1.0, A[i], C[j], 0.0, R);
		gsl_vector_memcpy(C[j], R);
#if 0									  // DEBUG
		double p_i = 0.0;
		gsl_blas_ddot(L[j], C[j], &p_i);
		p_i /= (double)(1ULL << cycle_len);
		p_tmp[j][i] = p_i;
#endif
	 }
	 gsl_blas_ddot(L[j], C[j], &prob[j]);
#if 1									  // DEBUG
	 uint32_t tmp = prob[j];
	 prob[j] /= (double)(1ULL << cycle_len);
#endif
#if 1									  // DEBUG
	 if(prob[j] > 1.0) {
		printf("[%s:%d] %d %f %d %f\n", __FILE__, __LINE__, tmp, prob[j], (1U << cycle_len), (double)(1U << cycle_len));
	 }
#endif
	 assert(prob[j] <= 1.0);
#if 0									  // DEBUG
	 //	 printf("C%d[%d] = \n", j, WORD_SIZE - 1);
	 printf("\nC%d[%d] = ", j, cycle_len - 1);
	 xdp_rot_and_print_vector(C[j]);
	 printf(" | p = %f\n", prob[j]);
#endif
  }
#if 0									  // DEBUG
  printf("[%s:%d] p[0] %f, p[1] %f\n", __FILE__, __LINE__, prob[0], prob[1]);
#endif
  p = prob[0] + prob[1];
#if 0									  // EDBUG
  for(uint32_t i = 0; i < WORD_SIZE ; i++) {
	 double p_i = p_tmp[0][i] + p_tmp[0][i];
	 printf("[%2d]%f ", i, p_i);
  }
  printf("\n");
  double p_prev = p_tmp[0][0] + p_tmp[1][0];
  for(uint32_t i = 1; i < WORD_SIZE ; i++) {
	 double p_i = p_tmp[0][i] + p_tmp[0][i];
	 if(p_i > p_prev) {
		printf("[%s:%d] WARNING!! %f %f\n", __FILE__, __LINE__, p_i, p_prev);
	 }
	 //	 assert(p_i <= p_prev);
	 p_prev = p_i;
  }
#endif
  for(uint32_t i = 0; i < 2; i++) {
	 gsl_vector_free(C[i]);
	 gsl_vector_free(L[i]);
  }
  gsl_vector_free(R);

  return p;
}

double xdp_rot_and(const uint32_t delta, const uint32_t dc, 
						 const uint32_t s, const uint32_t t)
{
  double p_tot = 1.0;
  uint32_t i_start = 0;
  uint32_t cycle_len = WORD_SIZE;
  uint32_t da = LROT(delta, s);
  uint32_t db = LROT(delta, t);
#if 0									  // DEBUG
  printf("[%s:%d] ======> %8X | %8X %8X %8X |\n", __FILE__, __LINE__, delta, da, db, dc);
#endif
  gsl_matrix* A[WORD_SIZE];
  xdp_rot_and_alloc_matrices(A);

  uint32_t da_idx[WORD_SIZE] = {0};
  uint32_t db_idx[WORD_SIZE] = {0};
  //  uint32_t da_idx[WORD_SIZE] = {0, 2, 4, 1, 3};
  //  uint32_t db_idx[WORD_SIZE] = {3, 0, 2, 4, 1};

  bool b_is_marked[WORD_SIZE] = {false};

  while(i_start != WORD_SIZE) {
	 uint32_t start_idx = 0;
	 uint32_t j = 0;
	 bool b_all_marked = true;
	 while((b_all_marked) && (j < WORD_SIZE)) {
		b_all_marked = b_is_marked[j];
		if(b_all_marked == false) {
		  start_idx = j;
		}
		j++;
	 }
#if 0									  // DEBUG
    printf("j = %d | ", start_idx);
	 for(uint32_t i = 0; i < WORD_SIZE; i++) {
		printf("[%d]%d ", i, b_is_marked[i]);
	 }
    printf("\n");
#endif
	 cycle_len = xdp_rot_compute_indices(s, t, b_is_marked, i_start, start_idx, da_idx, db_idx);
	 //	 assert(cycle_len == WORD_SIZE);

#if 0									  // DEBUG
	 printf("[%s:%d] cycle_len = %d\n", __FILE__, __LINE__, cycle_len);
	 printf("[%s:%d] %d %d | da_idx = ", __FILE__, __LINE__, s, t);
	 for(uint32_t i = 0; i < WORD_SIZE; i++) {
		printf("%2d ", da_idx[i]);
	 }
	 printf("\n[%s:%d] %d %d | db_idx = ", __FILE__, __LINE__, s, t);
	 for(uint32_t i = 0; i < WORD_SIZE; i++) {
		printf("%2d ", db_idx[i]);
	 }
	 printf("\n");
#endif

	 xdp_rot_and_compute_graph(A, i_start, cycle_len, da_idx, db_idx, da, db, dc);

	 double p = xdp_rot_and_one_cycle(A, i_start, cycle_len);
	 assert(p <= 1.0);
#if 0									  // DEBUG
	 printf("[%s:%d] p%d %f\n", __FILE__, __LINE__, i_start, p);
#endif

	 p_tot *= p;

	 i_start += cycle_len;
#if 0									  // DEBUG
	 printf("[%s:%d] i_start %d\n", __FILE__, __LINE__, i_start);
#endif
  }

  xdp_rot_and_free_matrices(A);

  return p_tot;
}

// see also: test_rot_rot_x()
void xdp_rot_and_index_debug(uint32_t s, uint32_t t)
{
  printf("--- [%s:%d:%s()] BEGIN DEBUG ---\n", __FILE__, __LINE__, __FUNCTION__);
  bool w[WORD_SIZE] = {false};

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
  printf("--- [%s:%d:%s()] END DEBUG ---\n", __FILE__, __LINE__, __FUNCTION__);
}

void xdp_rot_and_xcond_init(uint32_t XCOND[2][2][2][2])
{
  // A000
  XCOND[0][0][0][0] = 2;		  // x = *   (anything)
  XCOND[0][0][0][1] = 2;		  // y = *
  // A001
  XCOND[0][0][1][0] = 5;		  // x = -   (impossible)
  XCOND[0][0][1][1] = 5;		  // y = -
  // A010
  XCOND[0][1][0][0] = 0;		  // x = 0   (must be 0)
  XCOND[0][1][0][1] = 2;		  // y = *
  // A011
  XCOND[0][1][1][0] = 1;		  // x = 1   (must be 1)
  XCOND[0][1][1][1] = 2;		  // y = *
  // A100
  XCOND[1][0][0][0] = 2;		  // x = *
  XCOND[1][0][0][1] = 0;		  // y = 0
  // A101
  XCOND[1][0][1][0] = 2;		  // x = *
  XCOND[1][0][1][1] = 1;		  // y = 1
  // A110
  XCOND[1][1][0][0] = 3;		  // x != y  (must be different)
  XCOND[1][1][0][1] = 3;
  // A111
  XCOND[1][1][1][0] = 4;		  // x == y  (must be equal)
  XCOND[1][1][1][1] = 4;
}


// 
// transform a 2D arrey in which a single bit is atored in a 32-bit word
// into a matrix in which 32 bits are packed into a 32-bit word suitable
// to be manipulated iwth the solve_gf2_* routines.
// 
void xdp_and_arrey_to_matrix_gf2(uint32_t A[WORD_SIZE][WORD_SIZE + 1], 
											uint32_t** M, uint32_t M_rows, uint32_t M_cols)
{
  assert(M_rows == WORD_SIZE);
  assert(M_cols == ((WORD_SIZE + 1) / WORD_SIZE));

  // TODO:
  // ...
}

void xdp_and_print_equations(uint32_t E[WORD_SIZE][WORD_SIZE + 1])
{
  for(uint32_t row = 0; row < WORD_SIZE; row++) {
	 printf("%2d: ", row);
	 for(uint32_t col = 0; col < WORD_SIZE + 1;  col++) {
		if(col == WORD_SIZE) {
		  printf("= ");
		}
		printf("%d ", E[row][col]);
	 }
	 printf("\n");
  }
}

uint32_t xdp_and_add_equation(uint32_t i, uint32_t E[WORD_SIZE][WORD_SIZE + 1],
										uint32_t da_i, uint32_t db_i, uint32_t dc_i,
										uint32_t x_i, uint32_t y_i) 
{
  uint32_t neq = i + 1;

  uint32_t diff_idx = (da_i << 2) | (db_i << 1) | (dc_i << 0);
#if 0									  // DEBUG
  printf("[%s:%d] Add equation #%2d | %d (%d %d %d) : ", __FILE__, __LINE__, diff_idx, da_i, db_i, dc_i, i);
#endif
  assert(diff_idx != 1);		  // 001: impossible

  if(diff_idx == 2) {			  // 010: x == 0
	 E[i][x_i] = 1;
	 E[i][WORD_SIZE] = 0;
  }
  if(diff_idx == 3) {			  // 011: x == 1
	 E[i][x_i] = 1;
	 E[i][WORD_SIZE] = 1;
  }
  if(diff_idx == 4) {			  // 100: y == 0
	 E[i][y_i] = 1;
	 E[i][WORD_SIZE] = 0;
  }
  if(diff_idx == 5) {			  // 101: y == 1
	 E[i][y_i] = 1;
	 E[i][WORD_SIZE] = 1;
  }
  if(diff_idx == 6) {			  // 110: x != y
	 E[i][x_i] = 1;
	 E[i][y_i] = 1;
	 E[i][WORD_SIZE] = 1;
  }
  if(diff_idx == 7) {			  // 111: x == y
	 E[i][x_i] = 1;
	 E[i][y_i] = 1;
	 E[i][WORD_SIZE] = 0;
  }
#if 0									  // DEBUG
  printf("%d %d = %d %d = %d\n", x_i, y_i, E[i][x_i], E[i][y_i], E[i][WORD_SIZE]);
#endif

  return neq;
}

// Impose constraints on the bits of the input values x
// rot-and: c = (a <<< s) & (a <<< t)
double xdp_rot_and_constraints(const uint32_t delta, const uint32_t dc,
										 const uint32_t s_in, const uint32_t t_in)
{
  uint32_t s = s_in;
  uint32_t t = t_in;
  if(s > t) {
	 std::swap(s, t);
  }
  assert(s <= t);

  uint32_t da = LROT(delta, s);
  uint32_t db = LROT(delta, t);
  double p = 0.0;

#if 1									  // DEBUG
  printf("[%s:%d] %8X = (%8X %8X) -> %8X\n", __FILE__, __LINE__, delta, da, db, dc);
#endif

  bool b_is_possible = xdp_and_is_nonzero(da, db, dc);
  if(!b_is_possible) {
	 return 0.0;
  }

  uint32_t XCOND[2][2][2][2] = {{{{0}}}};
  xdp_rot_and_xcond_init(XCOND);

  uint32_t X[WORD_SIZE] = {0};  // vector with actual conditions
  uint32_t C[WORD_SIZE] = {0}; // vector with required conditions -- used to detect conflicts
#if 1									  // DEBUG
  for(uint32_t w = 0; w < 8; w++) {
	 uint32_t i = (w >> 2) & 1;
	 uint32_t j = (w >> 1) & 1;
	 uint32_t k = (w >> 0) & 1;
	 uint32_t x = XCOND[i][j][k][0];
	 uint32_t y = XCOND[i][j][k][1];
	 printf("A%d%d%d(%d %d)\n", i, j, k, x, y);
  }
  //	 assert(0 == 1);
#endif

#if 1									  // DEBUG
  xdp_rot_and_index_debug(s, t);
#endif

  uint32_t n = WORD_SIZE;
  uint32_t l_s = (s - t + n) % n;
  uint32_t l_t = (t - s) % n;
  uint32_t u = 0;					  // both bits are assigned
  uint32_t v = 0;					  // one bit is assigned
  uint32_t m = 0;					  // no bits are assigned

#if 1									  // DEBUG
  printf("[%s:%d] (s, t) = %2d %2d\n", __FILE__, __LINE__, s, t);
#endif

  if(l_t >= l_s) {
	 u = l_s;
	 v = l_t - l_s;
	 m = n - l_t;
  } else {
	 u = l_t;
	 v = l_s - l_t;

	 m = n - l_s;
  }

#if 1									  // DEBUG
  printf("[%s:%d] (l_s, l_t) = (%2d %2d) | (u, v, m) = (%2d %2d %2d)\n", __FILE__, __LINE__, l_s, l_t, u, v, m);
#endif
  assert((u + v + m) == n);

  const uint32_t x_start = (n - s);
  const uint32_t y_start = (n - t);

  uint32_t E[WORD_SIZE][WORD_SIZE + 1] = {{0}};
  //  uint32_t neq = 0;

  for(uint32_t i = 0; i < u; i++) {
	 uint32_t x_i = (x_start + i) % n;
	 uint32_t y_i = (y_start + i) % n;
	 uint32_t da_i = (da >> i) & 1;
	 uint32_t db_i = (db >> i) & 1;
	 uint32_t dc_i = (dc >> i) & 1;
	 X[x_i] = XCOND[da_i][db_i][dc_i][0];
	 X[y_i] = XCOND[da_i][db_i][dc_i][1];

	 C[x_i] = X[x_i];
	 C[y_i] = X[y_i];

	 xdp_and_add_equation(i, E, da_i, db_i, dc_i, x_i, y_i);

#if 1									  // DEBUG
	 printf("[%s:%d] %3d %3d | %d %d %d ", __FILE__, __LINE__, x_i, y_i, da_i, db_i, dc_i);
	 printf("| X[%2d %2d] %d %d\n", x_i, y_i, X[x_i], X[y_i]);
#endif

  }
  for(uint32_t i = u; i < (u + v); i++) {
	 uint32_t x_i = (x_start + i) % n;
	 uint32_t y_i = (y_start + i) % n;
	 uint32_t da_i = (da >> i) & 1;
	 uint32_t db_i = (db >> i) & 1;
	 uint32_t dc_i = (dc >> i) & 1;
	 X[x_i]          = XCOND[da_i][db_i][dc_i][0];
	 uint32_t y_cond = XCOND[da_i][db_i][dc_i][1];

	 C[x_i] = X[x_i];
	 C[y_i] = y_cond;

	 xdp_and_add_equation(i, E, da_i, db_i, dc_i, x_i, y_i);

#if 1									  // DEBUG
	 printf("[%s:%d] %3d %3d | %d %d %d ", __FILE__, __LINE__, x_i, y_i, da_i, db_i, dc_i);
	 printf("| X[%2d %2d] %d %d \n", x_i, y_i, X[x_i], X[y_i]);
#endif

  }
  for(uint32_t i = (u + v); i < (u + v + m); i++) {
	 uint32_t x_i = (x_start + i) % n;
	 uint32_t y_i = (y_start + i) % n;
	 uint32_t da_i = (da >> i) & 1;
	 uint32_t db_i = (db >> i) & 1;
	 uint32_t dc_i = (dc >> i) & 1;
	 uint32_t x_cond = XCOND[da_i][db_i][dc_i][0];
	 uint32_t y_cond = XCOND[da_i][db_i][dc_i][1];

	 C[x_i] = x_cond;
	 C[y_i] = y_cond;

	 xdp_and_add_equation(i, E, da_i, db_i, dc_i, x_i, y_i);

#if 1									  // DEBUG
	 printf("[%s:%d] %3d %3d | %d %d %d ", __FILE__, __LINE__, x_i, y_i, da_i, db_i, dc_i);
	 printf("| X[%2d %2d] %d %d \n", x_i, y_i, X[x_i], X[y_i]);
#endif

  }

  uint32_t cnt = 1;
  for(uint32_t i = 0; i < WORD_SIZE; i++) {
	 uint32_t x_i = X[i];
	 if(x_i == 2) {
		cnt *= 2;
	 }
	 assert((x_i >= 0) && (x_i <= 4));
  }
  p = (double)cnt / (double)ALL_WORDS;

#if 1									  // DEBUG
  printf("[%s:%d] X: ", __FILE__, __LINE__);
  for(uint32_t i = 0; i < WORD_SIZE; i++) {
	 printf("[%2d]%2d ", i, X[i]);
  }
  printf(" | %d %f\n", cnt, p);
  printf("[%s:%d] C: ", __FILE__, __LINE__);
  for(uint32_t i = 0; i < WORD_SIZE; i++) {
	 printf("[%2d]%2d ", i, C[i]);
  }
  printf("\n");
#endif

  xdp_and_print_equations(E);

  return p;
}

// {--- MAX-ADP-ROT-AND ---

void xdp_rot_and_compute_graph_i(gsl_matrix* A[WORD_SIZE], uint32_t i_start, uint32_t cycle_len,
											uint32_t da_idx[WORD_SIZE], uint32_t db_idx[WORD_SIZE],
											const uint32_t da, const uint32_t db, const uint32_t dc)
{
#if 0									  // DEBUG
  printf("[%s:%d] %d %d\n", __FILE__, __LINE__, (i_start + (cycle_len - 1)), (WORD_SIZE - 1));
#endif
  assert((i_start + (cycle_len - 1)) <= (WORD_SIZE - 1));
  for(uint32_t i = i_start; i < (i_start + (cycle_len - 1)); i++) {
	 uint32_t da_i  = (da >> da_idx[i]) & 1;
	 uint32_t db_i  = (da >> db_idx[i]) & 1;
	 uint32_t dc_i  = (dc >> da_idx[i]) & 1;
	 uint32_t da_ii = (da >> da_idx[i+1]) & 1;
	 uint32_t db_ii = (da >> db_idx[i+1]) & 1;
	 uint32_t dc_ii = (dc >> da_idx[i+1]) & 1;
#if 0									  // DEBUG
	 printf("--- [%2d] ---\n", i);
#endif
	 xdp_rot_and_compute_subgraph(A[i], da_i, db_i, dc_i, da_ii, db_ii, dc_ii);
  }
}

void xdp_rot_and_normalize_matrix(gsl_matrix* A, double f)
{
  for(uint32_t i = 0; i < XDP_ROT_AND_MSIZE; i++) {
	 for(uint32_t j = 0; j < XDP_ROT_AND_MSIZE; j++) {
		double e = gsl_matrix_get(A, i, j);
		e /= f;
		gsl_matrix_set(A, i, j, e);
	 }
  }
}

void max_xdp_rot_and_bounds_0(uint32_t k, const uint32_t k_start, const uint32_t n, double* p, uint32_t* dc,
										gsl_matrix* A, gsl_vector* B[XDP_ROT_AND_NISTATES][WORD_SIZE], gsl_vector* C[2],
										uint32_t da_idx[WORD_SIZE], uint32_t db_idx[WORD_SIZE],
										const uint32_t da, const uint32_t db, 
										uint32_t* dc_max, double* p_max)
{
  if(k == (n  - 1)) {
	 assert(*p > *p_max);		  // !!!
	 *p_max = *p;
	 *dc_max = *dc;
	 return;
  } 

#if 0									  // DEBUG
  printf("[%s:%d] %d %d %d\n", __FILE__, __LINE__, k, k_start, n);
#endif
  assert((k+1) < WORD_SIZE);

  uint32_t da_i  = (da >> da_idx[k]) & 1;
  uint32_t db_i  = (da >> db_idx[k]) & 1;
  //	 uint32_t dc_i  = (dc >> da_idx[k]) & 1;

  uint32_t da_ii = (da >> da_idx[k+1]) & 1;
  uint32_t db_ii = (da >> db_idx[k+1]) & 1;
  //	 uint32_t dc_ii = (dc >> da_idx[k+1]) & 1;

  // cycle over the possible values of the k-th and (k+1)-st bits of *dc
  for(uint32_t dc_i = 0; dc_i < 2; dc_i++) { 
#if 1
	 if(k > k_start) {
		uint32_t dc_i_prev = (*dc >> da_idx[k - 1]) & 1;
		if(dc_i != dc_i_prev)
		  continue;
	 }
#endif
	 for(uint32_t dc_ii = 0; dc_ii < 2; dc_ii++) { 

		gsl_matrix_set_all(A, 0.0);	  // init
		xdp_rot_and_compute_subgraph(A, da_i, db_i, dc_i, da_ii, db_ii, dc_ii);
		//		double f = 1.0;
		//		xdp_rot_and_normalize_matrix(A, f);

		// temp
		gsl_vector* R[XDP_ROT_AND_NISTATES];
		for(uint32_t s = 0; s < XDP_ROT_AND_NISTATES; s++) {
		  R[s] = gsl_vector_calloc(XDP_ROT_AND_MSIZE);
		}
		double new_p = 0.0;

		// L A C
		for(uint32_t s = 0; s < XDP_ROT_AND_NISTATES; s++) { // initial states
		  // L A C
		  double p_s = 0.0;
		  gsl_blas_dgemv(CblasNoTrans, 1.0, A, C[s], 0.0, R[s]);
		  gsl_blas_ddot(B[s][k + 1], R[s], &p_s);
		  new_p += p_s;
#if 0									  // DEBUG
		  printf("[%s:%d] %d[%d]: ", __FILE__, __LINE__, k, s);
		  printf("R%d x B%d[%d] = ", s, s, k+1);
		  xdp_rot_and_print_vector(R[s]);
		  printf(" X ");
		  xdp_rot_and_print_vector(B[s][k+1]);
		  printf(" | %f\n", p_s);
#endif
		}

		// continue only if the probability so far is still bigger than the best found so far
		if(new_p > *p_max) {	  // !!!
		  uint32_t new_dc = *dc | (dc_i << da_idx[k]) | (dc_ii << da_idx[k+1]);
		  max_xdp_rot_and_bounds_0(k+1, k_start, n, &new_p, &new_dc, A, B, R, da_idx, db_idx, da, db, dc_max, p_max);
		  //		 max_adp_arx_bounds_i(k+1, n, lrot_const, &new_p, &new_de, A, B, R, dc, dd, de_max, p_max);
		}

		for(uint32_t s = 0; s < XDP_ROT_AND_NISTATES; s++) {
		  gsl_vector_free(R[s]);
		}
	 }
  }
}

/**
 * Compute bounds.
 */
void max_xdp_rot_and_bounds_i(uint32_t k, const uint32_t k_start, const uint32_t n, double* p, uint32_t* dc,
										gsl_matrix* A, gsl_vector* B[WORD_SIZE], gsl_vector* C,
										uint32_t da_idx[WORD_SIZE], uint32_t db_idx[WORD_SIZE],
										const uint32_t da, const uint32_t db, 
										uint32_t* dc_max, double* p_max)
{
  if(k == (n - 1)) {
	 assert(*p > *p_max);
	 *p_max = *p;
	 *dc_max = *dc;
	 return;
  } 

#if 0									  // DEBUG
  printf("[%s:%d] %d %d %d\n", __FILE__, __LINE__, k, k_start, n);
#endif
  assert((k+1) < WORD_SIZE);

  uint32_t da_i  = (da >> da_idx[k]) & 1;
  uint32_t db_i  = (da >> db_idx[k]) & 1;
  //	 uint32_t dc_i  = (dc >> da_idx[k]) & 1;

  uint32_t da_ii = (da >> da_idx[k+1]) & 1;
  uint32_t db_ii = (da >> db_idx[k+1]) & 1;
  //	 uint32_t dc_ii = (dc >> da_idx[k+1]) & 1;

  // cycle over the possible values of the k-th and (k+1)-st bits of *dc
  for(uint32_t dc_i = 0; dc_i < 2; dc_i++) { 
#if 1
	 if(k > k_start) {
		uint32_t dc_i_prev = (*dc >> da_idx[k - 1]) & 1;
		if(dc_i != dc_i_prev)
		  continue;
	 }
#endif
	 for(uint32_t dc_ii = 0; dc_ii < 2; dc_ii++) { 

		gsl_matrix_set_all(A, 0.0);	  // init
		xdp_rot_and_compute_subgraph(A, da_i, db_i, dc_i, da_ii, db_ii, dc_ii);

		// temp
		gsl_vector* R = gsl_vector_calloc(XDP_ROT_AND_MSIZE);
		double new_p = 0.0;

		// L A C
		gsl_blas_dgemv(CblasNoTrans, 1.0, A, C, 0.0, R);
		gsl_blas_ddot(B[k + 1], R, &new_p);
		// continue only if the probability so far is still bigger than the best found so far
		if(new_p > *p_max) {
		  uint32_t new_dc = *dc | (dc_i << da_idx[k]) | (dc_ii << da_idx[k+1]);

		  max_xdp_rot_and_bounds_i(k+1, k_start, n, &new_p, &new_dc, A, B, R, da_idx, db_idx, da, db, dc_max, p_max);
		}
		gsl_vector_free(R);

	 }
  }
}

void max_xdp_rot_and_bounds(gsl_vector* B[XDP_ROT_AND_NISTATES][WORD_SIZE],
									 uint32_t i_start, uint32_t cycle_len,
									 uint32_t da_idx[WORD_SIZE], uint32_t db_idx[WORD_SIZE],
									 const uint32_t da, const uint32_t db, uint32_t* dc_max)
{
  //  assert(cycle_len == WORD_SIZE);
  gsl_matrix* A = gsl_matrix_calloc(XDP_ROT_AND_MSIZE, XDP_ROT_AND_MSIZE);

  //  for(uint32_t k = (WORD_SIZE - 2); k > 0; k--) { // bit postion
  assert((i_start + (cycle_len - 1)) <= (WORD_SIZE - 1));
  for(int k = (int)(i_start + (cycle_len - 2)); k >= (int)i_start; k--) { // bit postion
#if 0									  // DEBUG
	 printf("[%s:%d] %d %d\n", __FILE__, __LINE__, k, (int)i_start);
#endif
	 assert((k+1) < WORD_SIZE);
	 for(uint32_t s = 0; s < XDP_ROT_AND_NISTATES; s++) { // initial state

		for(uint32_t i = 0; i < XDP_ROT_AND_MSIZE; i++) { // state

		  gsl_vector* C = gsl_vector_calloc(XDP_ROT_AND_MSIZE);
		  gsl_vector_set(C, i, 1.0);

		  uint32_t n = i_start + cycle_len;
		  uint32_t k_start = k;
		  uint32_t dc_init = 0;
		  double p_init = gsl_vector_get(B[s][k], i);
		  double p_max_i = 0.0;

		  max_xdp_rot_and_bounds_i(k, k_start, n, &p_init, &dc_init, A, B[s], C, da_idx, db_idx, da, db, dc_max, &p_max_i);
		  gsl_vector_set(B[s][k], i, p_max_i);
#if 0									  // DEBUG
		  printf("[%s:%d] k %2d, s %2d, i %2d | %f\n", __FILE__, __LINE__, k, s, i, p_max_i);
#endif
		  gsl_vector_free(C);
		}
	 }
  }
  gsl_matrix_free(A);
}

void max_xdp_rot_and_print_bounds(gsl_vector* B[XDP_ROT_AND_NISTATES][WORD_SIZE])
{
  printf("[%s:%d]\n", __FILE__, __LINE__);
  for(uint32_t s = 0; s < XDP_ROT_AND_NISTATES; s++) { // initial state
	 printf("[%s:%d] --- istate [%2d] ---\n", __FILE__, __LINE__, s);
	 for(uint32_t k = WORD_SIZE - 1; k > 0; k--) { // bit postion
		printf("[%2d] ", k);
		for(uint32_t i = 0; i < XDP_ROT_AND_MSIZE; i++) { // state
		  double p_i = gsl_vector_get(B[s][k], i);
		  printf("%f ", p_i);
		} // i
		printf("\n");
	 }	// k
	 printf("\n\n");
  } // s
}

double max_xdp_rot_and_exper(uint32_t da, uint32_t* dc_max,
									  uint32_t s, uint32_t t)
{
  *dc_max = 0;
  assert(WORD_SIZE <= 20);

  double p_max = 0.0;
  for(uint32_t dc = 0; dc < ALL_WORDS; dc++) {
	 double p = xdp_rot_and(da, dc, s, t);
	 if(p > p_max) {
		p_max = p;
		*dc_max = dc;
	 }
  }
  return p_max;
}

double max_xdp_rot_and(const uint32_t delta, uint32_t* dc, 
							  const uint32_t s, const uint32_t t)
{
  //  uint32_t cycle_len = WORD_SIZE;
  double p_max = 1.0;
  uint32_t da = LROT(delta, s);
  uint32_t db = LROT(delta, t);
  uint32_t dc_max = 0;
  uint32_t da_idx[WORD_SIZE] = {0};
  uint32_t db_idx[WORD_SIZE] = {0};
  //  uint32_t start_idx = 0;

  uint32_t cycle_len = WORD_SIZE;
  uint32_t i_start = 0;
  bool b_is_marked[WORD_SIZE] = {false};
  while(i_start != WORD_SIZE) {
	 uint32_t start_idx = 0;
	 uint32_t j = 0;
	 bool b_all_marked = true;
	 while((b_all_marked) && (j < WORD_SIZE)) {
		b_all_marked = b_is_marked[j];
		if(b_all_marked == false) {
		  start_idx = j;
		}
		j++;
	 }
	 cycle_len = xdp_rot_compute_indices(s, t, b_is_marked, i_start, start_idx, da_idx, db_idx);
#if 0									  // DEBUG
	 printf("[%s:%d] cycle_len %d\n", __FILE__, __LINE__, cycle_len);
#endif
	 //	 assert(cycle_len == WORD_SIZE);

	 gsl_matrix* A = gsl_matrix_calloc(XDP_ROT_AND_MSIZE, XDP_ROT_AND_MSIZE);

	 gsl_vector* B[XDP_ROT_AND_NISTATES][WORD_SIZE];
	 for(int j = 0; j < XDP_ROT_AND_NISTATES; j++){
		for(int i = 0; i < WORD_SIZE; i++){
		  B[j][i] = gsl_vector_calloc(XDP_ROT_AND_MSIZE);
		}
	 }
	 gsl_vector* C[XDP_ROT_AND_NISTATES];

	 for(uint32_t i = 0; i < XDP_ROT_AND_NISTATES; i++) {
		C[i] = gsl_vector_calloc(XDP_ROT_AND_MSIZE);
	 }

	 for(int j = 0; j < XDP_ROT_AND_NISTATES; j++) { // start states
		uint32_t ss[2] = {0};
		if(j == 0) {
		  ss[0] = 0;
		  ss[1] = 2;
		} 
		if(j == 1) {
		  ss[0] = 1;
		  ss[1] = 3;
		} 
		gsl_vector_set(C[j], ss[0], 1.0); 
		gsl_vector_set(C[j], ss[1], 1.0); 
	 }

	 for(int j = 0; j < XDP_ROT_AND_NISTATES; j++) { // final states
		uint32_t fs[2] = {0};
		if(j == 0) {
		  fs[0] = 0;
		  fs[1] = 1;
		} 
		if(j == 1) {
		  fs[0] = 2;
		  fs[1] = 3;
		} 
		//		gsl_vector_set(B[j][WORD_SIZE - 1], fs[0], 1.0); 
		//		gsl_vector_set(B[j][WORD_SIZE - 1], fs[1], 1.0); 
		assert((i_start + cycle_len) <= WORD_SIZE);
		gsl_vector_set(B[j][i_start + cycle_len - 1], fs[0], 1.0); 
		gsl_vector_set(B[j][i_start + cycle_len - 1], fs[1], 1.0); 
	 }

	 max_xdp_rot_and_bounds(B, i_start, cycle_len, da_idx, db_idx, da, db, &dc_max);
#if 0									  // DEBUG
	 max_xdp_rot_and_print_bounds(B);
#endif
	 //	 uint32_t n = cycle_len;
	 uint32_t n = i_start + cycle_len;
	 uint32_t k = i_start;
	 uint32_t k_start = k;
	 uint32_t dc_init = 0;
	 double p_init = 0.0;
	 double p_max_cycle = 0.0;

	 max_xdp_rot_and_bounds_0(k, k_start, n, &p_init, &dc_init, A, B, C, da_idx, db_idx, da, db, &dc_max, &p_max_cycle);

	 double f = (double)(1ULL << cycle_len);
	 p_max_cycle = p_max_cycle / f;
	 *dc = dc_max;
#if 0									  // DEBUG
	 printf("[%s:%d] %8X %f\n", __FILE__, __LINE__, *dc, p_max_cycle);
#endif
	 for(uint32_t i = 0; i < XDP_ROT_AND_NISTATES; i++) {
		gsl_vector_free(C[i]);
	 }

	 for(int j = 0; j < XDP_ROT_AND_NISTATES; j++){
		for(int i = 0; i < WORD_SIZE; i++){
		  gsl_vector_free(B[j][i]);
		}
	 }

	 gsl_matrix_free(A);

	 p_max *= p_max_cycle;
	 i_start += cycle_len;

  } // cycle

  return p_max;
}

// --- XDP-ROT-AND-PDDT ---

/**
 * For a given output difference dy, check if in the
 * list of differentials set_dx_dy exists an entry (dx -> dy)
 */
bool xdp_rot_and_is_dx_in_set_dx_dy(uint32_t dy, uint32_t dx, uint32_t dx_prev, uint32_t lrot_const_u,
												std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy)
{
  // dy = gamma
  // dx_prev = dy_{i} = dx_{i-1} = alpha_{i-1}
  // dx = dx_{i} = alpha_{i}

  assert(diff_set_dx_dy.size() != 0);
  uint32_t dz = dy ^ dx_prev ^ LROT(dx, lrot_const_u); // dx_{i+1} = gamma ^ dx_{i-1} ^ (alpha <<< 2)
#if 0									  // DEBUG
  printf("[%s:%d] gamma %8X, dx_prev %8X, dx %8X, dz %8X\n", __FILE__, __LINE__, dy, dx_prev, dx, dz);
#endif
  bool b_is_inset = false;
  std::set<differential_t, struct_comp_diff_dx_dy>::iterator set_iter = diff_set_dx_dy.begin();;
  while((set_iter != diff_set_dx_dy.end()) && (!b_is_inset)) {
	 //XOR(dy, dx_prev);
	 b_is_inset = (dz == set_iter->dx);
	 set_iter++;
  }
  assert(diff_set_dx_dy.size() != 0);
  return b_is_inset;
}


void xdp_rot_and_pddt_i(uint32_t k, uint32_t n, uint32_t s, uint32_t t, 
								const uint32_t delta_in, const uint32_t dc_in,
								std::set<differential_t, struct_comp_diff_dx_dy>* hways_diff_set_dx_dy,
								std::multiset<differential_t, struct_comp_diff_p>* hways_diff_mset_p,
								uint64_t* cnt_diff, uint64_t max_cnt, double p_thres)
{
  assert(p_thres == XDP_ROT_AND_P_THRES);
  uint32_t delta = delta_in;
  uint32_t dc = dc_in;
#if 0									  // DEBUG
  printf("[%s:%d] %d / %d\n", __FILE__, __LINE__, k, n);
#endif

  if(k == n) {

	 uint32_t da = delta;
	 double p = xdp_rot_and(da, dc, s, t);

    // Definition: Highway -- a transition (da -> dc) with prob. p such that hw32(da) <= hw_thres and p <= 2^-4
	 // Add to highways if above the threshold
	 // We want only the input difference to F to have controlled weight
	 // because the output will be XOR-ed with the input diff from the prev. round
	 bool b_low_hw = (hw32(da) <= XDP_ROT_AND_MAX_HW);
	 assert(b_low_hw);
	 if((p > XDP_ROT_AND_P_THRES) && (b_low_hw) && (p != 0.0) && (da != 0) && (*cnt_diff < max_cnt)) {

		differential_t diff;
		diff.dx = da;
		diff.dy = dc;
		diff.p = p;

		hways_diff_mset_p->insert(diff);
		hways_diff_set_dx_dy->insert(diff);
		(*cnt_diff)++;
#if 1									  // DEBUG
		printf("%10lld / %10lld\r", *cnt_diff, max_cnt);
		fflush(stdout);
#endif
		assert(*cnt_diff == hways_diff_set_dx_dy->size());
	 }
	 return;
  }

  if(*cnt_diff == max_cnt)
	 return;

  for(uint32_t x = 0; x < 2; x++) {
	 for(uint32_t y = 0; y < 2; y++) {

		uint32_t new_delta = (delta | (x << k));
		uint32_t new_dc = (dc | (y << k));

#if 1
		uint32_t da = LROT(delta, s);
		uint32_t db = LROT(delta, t);
		uint32_t a = ((da >> k) & 1);
		uint32_t b = ((db >> k) & 1);
		uint32_t c = ((new_dc >> k) & 1);
		bool b_is_impossible = ((a == 0) && (b == 0) && (c == 1));
#endif

		bool b_low_hw = (hw32(new_delta) <= XDP_ROT_AND_MAX_HW);
		///		if(b_low_hw) { 
		//		if(!b_is_impossible) { 
		if((!b_is_impossible) && (b_low_hw)) { 
		  xdp_rot_and_pddt_i(k+1, n, s, t, new_delta, new_dc, hways_diff_set_dx_dy, hways_diff_mset_p, cnt_diff, max_cnt, p_thres);
		}
	 }
  }
}

/**
 * Wrapper for \ref xdp_rot_and_pddt_i
 */
uint64_t xdp_rot_and_pddt(std::set<differential_t, struct_comp_diff_dx_dy>* hways_diff_set_dx_dy,
								  std::multiset<differential_t, struct_comp_diff_p>* hways_diff_mset_p,
								  const uint32_t s, const uint32_t t, const uint64_t max_cnt, const double p_thres)
{
  uint64_t cnt_diff = 0;
  uint32_t k = 0;
  uint32_t n = WORD_SIZE;
  uint32_t delta = 0;
  uint32_t dc = 0;
  xdp_rot_and_pddt_i(k, n, s, t, delta, dc, hways_diff_set_dx_dy, hways_diff_mset_p, &cnt_diff, max_cnt, p_thres);
  return cnt_diff;
}

// full DDT as STL set/mset
void xdp_rot_and_ddt(std::set<differential_t, struct_comp_diff_dx_dy>* hways_diff_set_dx_dy,
								 std::multiset<differential_t, struct_comp_diff_p>* hways_diff_mset_p,
								 const uint32_t s, const uint32_t t, const double p_thres)
{
  assert(p_thres == 0.0);
  for(uint32_t delta = 0; delta < ALL_WORDS; delta++) {
		for(uint32_t dc = 0; dc < ALL_WORDS; dc++) {
		  double p = xdp_rot_and(delta, dc, s, t);
		  if(p > p_thres) {
			 differential_t diff;
			 diff.dx = delta;
			 diff.dy = dc;
			 diff.p = p;
			 hways_diff_mset_p->insert(diff);
			 hways_diff_set_dx_dy->insert(diff);
		  }
		}
#if 1									  // DEBUG
		printf("row %10d / %10lld\r", delta, ALL_WORDS);
		fflush(stdout);
#endif
  }
}

/**
 * For a fixed input difference \f$\alpha_r\f$ to round \f$r\f$
 * compute a list of output differences \f$\beta_r\f$ that satisfy the
 * following conditions:
 *
 * -# The probability of the differential \f$(\alpha_r \rightarrow
 * \beta_r)\f$ is bigger than a pre-defined threshold \p p_thres .  
 * -# The input difference \f$\alpha_{r+1} = \alpha_{r-1} +
 * \beta_{r}\f$ to the next round has a matching entry in the
 * pre-computed pDDT \p hways_diff_set_dx_dy.
 * 
 * \see tea_f_da_db_dc_add_pddt_i
 */
// s,t,u -- the three rotation constants: 1, 8, 2
void xdp_rot_and_dx_pddt_i(uint32_t k, uint32_t n, uint32_t s, uint32_t t, uint32_t u,
									const uint32_t delta, const uint32_t delta_prev, const uint32_t dc_in,
									std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy, // initial highways
									std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p, 
									std::set<differential_t, struct_comp_diff_dx_dy>* hways_diff_set_dx_dy, // all highways
									std::multiset<differential_t, struct_comp_diff_p>* hways_diff_mset_p, 
									std::set<differential_t, struct_comp_diff_dx_dy>* croads_diff_set_dx_dy, // countryroads
									std::multiset<differential_t, struct_comp_diff_p>* croads_diff_mset_p,
									uint64_t* cnt_diff, uint64_t max_cnt, double p_thres, bool b_backto_hway)
{
  uint32_t dc = dc_in;

  if(k == n) {

	 uint32_t da = delta;
	 double p = xdp_rot_and(da, dc, s, t);
#if 0									  // DEBUG
	 printf("[%s:%d] %d %d | %d / %d | %8X | %8X -> %8X %f 2^%f %f 2^%f\n", __FILE__, __LINE__, k, n, *cnt_diff, max_cnt, delta, da, dc, p_thres, log2(p_thres), p, log2(p));
#endif

	 differential_t diff;
	 diff.dx = da;
	 diff.dy = dc;
	 diff.p = p;

#if 0
	 //	 bool b_low_hw = ((hw32(da) <= XDP_ROT_AND_MAX_HW) && (hw32(dc) <= XDP_ROT_AND_MAX_HW));

    // Definition: Highway -- a transition (da -> dc) with prob. p such that hw32(da) <= hw_thres and p <= 2^-4
	 // Add to highways if above the threshold
	 // We want only the input difference to F to have controlled weight
	 // because the output will be XOR-ed with the input diff from the prev. round
	 bool b_low_hw = (hw32(da) <= XDP_ROT_AND_MAX_HW);
	 if((p > XDP_ROT_AND_P_THRES) && (b_low_hw) && (p != 0.0)) {

		// check if it is already in highway table
		uint32_t old_size = hways_diff_set_dx_dy->size();
		hways_diff_set_dx_dy->insert(diff);
		uint32_t new_size = hways_diff_set_dx_dy->size();

		if(old_size != new_size) {
		  hways_diff_mset_p->insert(diff);
#if 1									  // DEBUG
		  printf("\r[%s:%d] NEW Hway: %8X %8X %6.5f 2^%4.2f | HW size: Dp %10d, Dxy %10d", __FILE__, __LINE__, da, dc, p, log2(p), hways_diff_mset_p->size(), hways_diff_set_dx_dy->size());
		  fflush(stdout);
#endif
		}
	 }
#endif

	 double p_low_thres = XDP_ROT_AND_P_LOW_THRES;
	 if((p > p_thres) && (*cnt_diff < max_cnt) && (p != 0.0) && (p > p_low_thres)) {

		bool b_is_inset = true;
		if(b_backto_hway) {
		  //		  b_is_inset = xdp_rot_and_is_dx_in_set_dx_dy(diff.dy, delta, delta_prev, u, *hways_diff_set_dx_dy);
		  b_is_inset = xdp_rot_and_is_dx_in_set_dx_dy(diff.dy, delta, delta_prev, u, *diff_set_dx_dy); // !!!
		  //		  assert(0 == 1);
		}

		if(b_is_inset) {
		  uint32_t num_croads = croads_diff_set_dx_dy->size();
		  croads_diff_set_dx_dy->insert(diff);
		  if(num_croads < croads_diff_set_dx_dy->size()) { // if a new croad was added, add it also in the other list
			 croads_diff_mset_p->insert(diff);
			 (*cnt_diff)++;
#if 0									  // DEBUG
			 printf("[%10lld / %10lld] %f 2^%f\r", *cnt_diff, max_cnt, p_thres, log2(p_thres));
			 fflush(stdout);
#endif
#if 0									  // DEBUG
			 printf("\r[%s:%d] %lld / %lld : NEW Croad: %8X %8X %6.5f 2^%4.2f | CR size: Dp %10d, Dxy %10d", __FILE__, __LINE__, *cnt_diff, max_cnt, da, dc, p, log2(p), croads_diff_mset_p->size(), croads_diff_set_dx_dy->size());
			 fflush(stdout);
#endif
		  }
		  //  assert(croads_diff_mset_p->size() == croads_diff_set_dx_dy->size());
		}
	 }
	 return;
  }

  if(*cnt_diff == max_cnt)
	 return;

  for(uint32_t y = 0; y < 2; y++) {

	 //  bool b_is_possible = xdp_and_is_nonzero(da, db, dc);
	 uint32_t new_dc = (dc | (y << k));
#if 1
	 uint32_t da = LROT(delta, s);
	 uint32_t db = LROT(delta, t);
	 uint32_t a = ((da >> k) & 1);
	 uint32_t b = ((db >> k) & 1);
	 uint32_t c = ((new_dc >> k) & 1);
	 bool b_is_impossible = ((a == 0) && (b == 0) && (c == 1));
#endif
	 // we want the output diff from the F-function to be at most two times the maximum allowed
	 // so that after XORing with the difference from the previous round the result may stoll have weight 
	 // less or equal to the maximum
	 bool b_low_hw = (hw32(delta) <= XDP_ROT_AND_MAX_HW);
	 //	 bool b_low_hw = (hw32(delta) <= XDP_ROT_AND_MAX_HW) && ((hw32(new_dc) <= XDP_ROT_AND_MAX_HW));
	 //	 bool b_low_hw = (hw32(delta) <= XDP_ROT_AND_MAX_HW) && ((hw32(new_dc) <= hw32(delta)));
	 //	 assert(b_low_hw);
	 if((!b_is_impossible) && (b_low_hw)) {
	 //	 if(b_low_hw) {
		xdp_rot_and_dx_pddt_i(k+1, n, s, t, u, delta, delta_prev, new_dc, diff_set_dx_dy, diff_mset_p, hways_diff_set_dx_dy, hways_diff_mset_p, croads_diff_set_dx_dy, croads_diff_mset_p, cnt_diff, max_cnt, p_thres, b_backto_hway);
	 }
  }
}

/**
 * Wrapper for \ref xdp_rot_and_dx_pddt_i
 */
uint64_t xdp_rot_and_dx_pddt(const uint32_t delta, const uint32_t delta_prev, 
									  std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy, // initial highways
									  std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p, 
									  std::set<differential_t, struct_comp_diff_dx_dy>* hways_diff_set_dx_dy, // all highways
									  std::multiset<differential_t, struct_comp_diff_p>* hways_diff_mset_p, 
									  std::set<differential_t, struct_comp_diff_dx_dy>* croads_diff_set_dx_dy, // ocuntryroads
									  std::multiset<differential_t, struct_comp_diff_p>* croads_diff_mset_p,
									  const uint32_t s, const uint32_t t, const uint32_t u,
									  const uint64_t max_cnt, const double p_thres, bool b_backto_hway)
{
  uint32_t dc = 0;
  uint64_t cnt_diff = 0;
#if !XDP_ROT_PDDT_GEN_RANDOM 
  uint32_t k = 0;
  uint32_t n = WORD_SIZE;
  uint32_t old_len = croads_diff_set_dx_dy->size();
  xdp_rot_and_dx_pddt_i(k, n, s, t, u, delta, delta_prev, dc, diff_set_dx_dy, diff_mset_p, hways_diff_set_dx_dy, hways_diff_mset_p, croads_diff_set_dx_dy, croads_diff_mset_p, &cnt_diff, max_cnt, p_thres, b_backto_hway);
  uint32_t new_len = croads_diff_set_dx_dy->size();
  assert(cnt_diff == (new_len - old_len));
#else	 // generate random difference

  //  bool b_low_hw = (hw32(da) <= XDP_ROT_AND_MAX_HW);
  uint32_t N = (1ULL << 5);
  for(uint32_t i = 0; i < N; i++) {
	 //	 dc = random32() & MASK;
	 uint32_t da = delta;
	 dc = gen_sparse(hw32(da), WORD_SIZE);
	 double p = xdp_rot_and(da, dc, s, t);

	 bool b_low_hw = (hw32(da) <= XDP_ROT_AND_MAX_HW) && ((hw32(dc) <= XDP_ROT_AND_MAX_HW));
	 //	 printf("\r[%s:%d] %X -> %X 2^%f", __FILE__, __LINE__, da, dc, log2(p));
	 //	 fflush(stdout);
	 if((p > p_thres) && (cnt_diff < max_cnt) && (p != 0.0) && (da != 0) && (p >= XDP_ROT_AND_P_LOW_THRES ) && (b_low_hw)) {

		differential_t diff;
		diff.dx = da;
		diff.dy = dc;
		diff.p = p;

		bool b_is_inset = true;
		if(b_backto_hway) {
		  b_is_inset = xdp_rot_and_is_dx_in_set_dx_dy(diff.dy, delta, delta_prev, u, *diff_set_dx_dy); // !!!
		}

		if(b_is_inset) {
		  uint32_t num_croads = croads_diff_set_dx_dy->size();
		  croads_diff_set_dx_dy->insert(diff);
		  if(num_croads < croads_diff_set_dx_dy->size()) { // if a new croad was added, add it also in the other list
			 croads_diff_mset_p->insert(diff);
			 (cnt_diff)++;
#if 0									  // DEBUG
			 printf("\r[%s:%d] %lld / %lld : NEW Croad: %8X %8X %6.5f 2^%4.2f | CR size: Dp %10d, Dxy %10d", __FILE__, __LINE__, cnt_diff, max_cnt, da, dc, p, log2(p), croads_diff_mset_p->size(), croads_diff_set_dx_dy->size());
			 fflush(stdout);
			 //			 printf("\n[%s:%d] %lld / %lld : NEW Croad: %8X %8X %6.5f 2^%4.2f | CR size: Dp %10d, Dxy %10d\n", __FILE__, __LINE__, cnt_diff, max_cnt, da, dc, p, log2(p), croads_diff_mset_p->size(), croads_diff_set_dx_dy->size());
#endif
		  }
		}
	 } else {
		//		printf("\r[%s:%d] Bad Croad %X -> %X 2^%f", __FILE__, __LINE__, da, dc, log2(p));
		//		fflush(stdout);
	 }
  }

#endif

  return cnt_diff;
}

void xdp_rot_and_print_mset_hw(std::multiset<differential_t, struct_comp_diff_hw> hways_diff_mset_hw)
{
  uint32_t cnt = 1;
  std::set<differential_t, struct_comp_diff_p>::iterator set_iter;
  for(set_iter = hways_diff_mset_hw.begin(); set_iter != hways_diff_mset_hw.end(); set_iter++) {
	 uint32_t dx = set_iter->dx;
	 uint32_t dy = set_iter->dy;
	 double p = set_iter->p;
	 uint32_t hw = hw32(dx);// + hw32(dy);
	 printf("%10d: %8X -> %8X %f 2^%f | %2d\n", cnt, dx, dy, p, log2(p), hw);
	 cnt++;
  }
}

void xdp_rot_and_print_mset_p(std::multiset<differential_t, struct_comp_diff_p> hways_diff_mset_p)
{
  uint32_t cnt = 1;
  std::set<differential_t, struct_comp_diff_p>::iterator set_iter;
  for(set_iter = hways_diff_mset_p.begin(); set_iter != hways_diff_mset_p.end(); set_iter++) {
	 uint32_t dx = set_iter->dx;
	 uint32_t dy = set_iter->dy;
	 double p = set_iter->p;
	 uint32_t hw = hw32(dx) + hw32(dy);
	 printf("%10d: %8X -> %8X %f 2^%f | %2d\n", cnt, dx, dy, p, log2(p), hw);
	 cnt++;
  }
}

void xdp_rot_and_print_set_dx_dy(std::set<differential_t, struct_comp_diff_dx_dy> hways_diff_set_dx_dy)
{
  uint32_t cnt = 1;
  std::set<differential_t, struct_comp_diff_dx_dy>::iterator set_iter;
  for(set_iter = hways_diff_set_dx_dy.begin(); set_iter != hways_diff_set_dx_dy.end(); set_iter++) {
	 uint32_t dx = set_iter->dx;
	 uint32_t dy = set_iter->dy;
	 double p = set_iter->p;
	 uint32_t hw = hw32(dx) + hw32(dy);
	 printf("%10d: %8X -> %8X %f 2^%f | %2d\n", cnt, dx, dy, p, log2(p), hw);
	 cnt++;
  }
}
