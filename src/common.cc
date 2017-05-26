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
 * \file  common.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Common functions used accross all YAARX programs.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif

/**
 * Measure item in milliseconds
 * see: http://stackoverflow.com/questions/1861294/how-to-calculate-execution-time-of-a-code-snippet-in-c
 */
timestamp_t get_timestamp()
{
  struct timeval now;
  gettimeofday (&now, NULL);
  return  now.tv_usec + (timestamp_t)now.tv_sec * 1000000;
}

/**
 * Generate a random 32-bit value.
 */
uint32_t random32()
{
  return(random() ^ (random() << 16));
}

/**
 * Generate a random 64-bit value.
 */
uint64_t random64()
{
  return(((uint64_t)random32() << 32) | (random32()));
}

/**
 * Generate a random WORD-bit value.
 */
WORD_T xrandom()
{
  WORD_T w = 0;
#if(WORD_SIZE <= 32)
  w = random32();
#else // #if(WORD_SIZE > 32)
  w = random64();
#endif // #if(WORD_SIZE <= 32)
  return w;
}

/** 
 * Hamming weight of a byte.
 */
uint32_t hw8(const uint32_t x)
{
     int i;
     int w=0;
     for(i=0; i<8; i++) 
          w+=((x>>i) & 1);
     return w;
}

/** 
 * Hamming weight of a 32-bit word (inefficient).
 */
uint32_t hw32_slow(const uint32_t x)
{
     int i;
     int w=0;
     for(i=3; i>=0; i--) {
          w+=hw8((x >> i*8) & 0xff);
     }
     return w;
}

/** 
 * Hamming weight of a 32-bit word (efficient).
 */
uint32_t hw32(const uint32_t w)
{
  uint32_t res = w - ((w >> 1) & 0x55555555);
  res = (res & 0x33333333) + ((res >> 2) & 0x33333333);
  res = (res + (res >> 4)) & 0x0F0F0F0F;
  res = res + (res >> 8);
  return (res + (res >> 16)) & 0x000000FF;
}

/** 
 * Hamming weight of a 64-bit word (efficient).
 */
uint64_t hw64(const uint64_t w)
{
  uint32_t hw = 0;
  uint32_t w_L = w & 0xffffffff;
  uint32_t w_R = (w >> 32) & 0xffffffff;
  hw = hw32(w_L) + hw32(w_R);
#if 0 // DEBUG
  printf("[%s:%d] w w_L w_R %llX %llX %llX\n", __FILE__, __LINE__, 
			(WORD_MAX_T)w, (WORD_MAX_T)w_L, (WORD_MAX_T)w_R);
#endif // #if 1 // DEBUG
  return hw;
}

/** 
 * Hamming weight of a WORD-bit word (efficient).
 */
uint32_t hamming_weight(const WORD_T w)
{
#if 0 // DEBUG
  printf("[%s:%d] Enter %s() %llX\n", __FILE__, __LINE__, __FUNCTION__, (WORD_MAX_T)w);
#endif // #if 1 // DEBUG
  uint32_t hw = 0;
#if(WORD_SIZE <= 32)
  hw = hw32(w);
#else // #if(WORD_SIZE > 32)
  hw = hw64(w);
#endif // #if(WORD_SIZE <= 32)
#if 0 // DEBUG
  printf("[%s:%d] Exit %s() %d\n", __FILE__, __LINE__, __FUNCTION__, hw);
#endif // #if 1 // DEBUG
  return hw;
}

/**
 * Compute parity of 32-bit word with a multiply 
 * Credit: https://graphics.stanford.edu/~seander/bithacks.html
 */
uint32_t parity32(const uint32_t x)
{
  uint32_t v = x; // 32-bit word
  v ^= v >> 1;
  v ^= v >> 2;
  v = (v & 0x11111111U) * 0x11111111U;
  return (v >> 28) & 1;
}

/**
 * Compute parity of 64-bit word with a multiply 
 * Credit: https://graphics.stanford.edu/~seander/bithacks.html
 */
uint64_t parity64(const uint64_t x)
{
  uint64_t v = x; // 64-bit word
  v ^= v >> 1;
  v ^= v >> 2;
  v = (v & 0x1111111111111111UL) * 0x1111111111111111UL;
  return (v >> 60) & 1;
}

/**
 * Compute parity of the word \p x with a multiply 
 *
 * \see parity32, parity64
 */
WORD_T parity(const WORD_T x)
{
#if(WORD_SIZE <= 32)
  WORD_T par = parity32(x);
#else //#if(WORD_SIZE > 32)
  WORD_T par = parity64(x);
#endif //#if(WORD_SIZE <= 32)
  return par;
}

/**
 * Returns true if the argument is an even number.
 */
bool is_even(uint32_t i)
{
  bool b_ret = true;
  if((i%2) == 1)
	 b_ret = false;
  return b_ret;
}

/**
 * Generate a random sparse n-bit difference with Hamming weight at most hw.
 */ 
WORD_T gen_sparse(uint32_t hw, uint32_t n)
{
  //  uint32_t mask = ~(0xffffffff << n);
  WORD_T x = 0;

  // at hw random positions i_pos set the bit x[i_pos] to 1
  for(uint32_t i = 0; i < hw; i++) {
	 uint32_t i_pos = xrandom() % n;
	 uint32_t bit = xrandom() & 1;
	 x = (bit << i_pos) | x;
  }
  return x;
}

/** 
 * Print a value in binary.
 */
//void print_binary(const WORD_T n)
void print_binary(const uint64_t n)
{
  //  for(int i = 8; i >= WORD_SIZE; i--) {
  //	 printf(" ");
  //  }
  for(int i = WORD_SIZE - 1; i >= 0; i--) {
	 int msb = (n >> i) & 1;
	 printf("%d", msb); 
  }
}

/** 
 * Print a value in binary.
 */
//void print_binary(const WORD_T n, const uint32_t word_size)
void print_binary(const uint64_t n, const uint32_t word_size)
{
  for(int i = 8; i >= (int)word_size; i--) {
	 printf(" ");
  }
  for(int i = (int)(word_size - 1); i >= 0; i--) {
	 int msb = (n >> i) & 1;
	 printf("%d", msb); 
  }
}

/**
 * Compare two differentials by probability.
 */
bool operator<(differential_t x, differential_t y)
{
  if(x.p > y.p)					  // ! must be strictly >
	 return true;
  return false;
}

/**
 * Compare two differences by probability.
 */
bool operator<(difference_t x, difference_t y)
{
  if(x.p > y.p)
	 return true;
  return false;
}

/**
 * Evaluate if two differentials are identical.
 * Returns TRUE if they are.
 */
bool operator==(differential_t a, differential_t b)
{
  bool b_ret = false;
  if((a.p == b.p) && (a.dx == b.dx) && (a.dy == b.dy)) {
	 b_ret = true;
  }
  return b_ret;
}

/**
 * Print the list of 2d differentials stored represented as an STL set
 * and ordered by index idx = ((2^n dx) + dy), where n is the word size.
 */
void print_set(const std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy)
{
  uint32_t cnt_elms = 0;
  std::set<differential_t, struct_comp_diff_dx_dy>::iterator set_iter;
  for(set_iter = diff_set_dx_dy.begin(); set_iter != diff_set_dx_dy.end(); set_iter++, cnt_elms++) {
		uint32_t dx = set_iter->dx;
		uint32_t dy = set_iter->dy;
		double p = set_iter->p;
		printf("[%s:%d] %4d: %8X %8X %f (2^%f)\n", __FILE__, __LINE__, cnt_elms, dx, dy, p, log2(p));
  }
}

/**
 * Print the list of 2d differentials stored represented as an STL multiset
 * and ordered by probability.
 */
void print_mset(const std::multiset<differential_t, struct_comp_diff_p> diff_mset_p)
{
  uint32_t cnt_elms = 0;
  //std::set<differential_t, struct_comp_diff_p>::iterator set_iter;
  for(auto set_iter = diff_mset_p.begin(); set_iter != diff_mset_p.end(); set_iter++, cnt_elms++) {
		uint32_t dx = set_iter->dx;
		uint32_t dy = set_iter->dy;
		double p = set_iter->p;
		printf("[%s:%d] %4d: %8X %8X %f\n", __FILE__, __LINE__, cnt_elms, dx, dy, p);
  }
}

/**
 * Compare differential_3d_t structs for use with std::sort
 */
bool sort_comp_diff_3d_p(differential_3d_t a, differential_3d_t b)
{
  bool b_less = (a.p > b.p);	  // higher probability first
  return b_less;
}

void yaarx_alloc_matrices_2d(WORD_T*** A, uint32_t A_rows, uint32_t A_cols)
{
  *A = (WORD_T **)calloc(A_rows, sizeof(WORD_T *));
  for(uint32_t i = 0; i < A_rows; i++) {
	 (*A)[i] = (WORD_T *)calloc(A_cols, sizeof(WORD_T));
  }
}

void yaarx_free_matrices_2d(WORD_T** A, uint32_t A_rows, uint32_t A_cols)
{
  for(uint32_t i = 0; i < A_rows; i++) {
	 free(A[i]);
  }
  free(A);
}

void yaarx_alloc_matrices_4d(WORD_T***** A, uint32_t A_dim)
{
  printf("[%s:%d] Enter %s()\n", __FILE__, __LINE__, __FUNCTION__);
  *A = (WORD_T ****)calloc(A_dim, sizeof(WORD_T ***));
  for(uint32_t i = 0; i < A_dim; i++) {
	 (*A)[i] = (WORD_T ***)calloc(A_dim, sizeof(WORD_T **));
	 for(uint32_t j = 0; j < A_dim; j++) {
		(*A)[i][j] = (WORD_T **)calloc(A_dim, sizeof(WORD_T *));
		for(uint32_t k = 0; k < A_dim; k++) {
		  (*A)[i][j][k] = (WORD_T *)calloc(A_dim, sizeof(WORD_T));
		}
	 }
  }
}

void yaarx_free_matrices_4d(WORD_T**** A, uint32_t A_dim)
{
  printf("[%s:%d] Enter %s()\n", __FILE__, __LINE__, __FUNCTION__);
  for(uint32_t i = 0; i < A_dim; i++) {
	 for(uint32_t j = 0; j < A_dim; j++) {
		for(uint32_t k = 0; k < A_dim; k++) {
		  free(A[i][j][k]);
		}
		free(A[i][j]);
	 }
	 free(A[i]);
  }
  free(A);
}

void yaarx_alloc_matrices_3d(WORD_T**** A, uint32_t A_dim)
{
  *A = (WORD_T ***)calloc(A_dim, sizeof(WORD_T **));
  for(uint32_t i = 0; i < A_dim; i++) {
	 (*A)[i] = (WORD_T **)calloc(A_dim, sizeof(WORD_T *));
	 for(uint32_t j = 0; j < A_dim; j++) {
		(*A)[i][j] = (WORD_T *)calloc(A_dim, sizeof(WORD_T));
	 }
  }
}

void yaarx_free_matrices_3d(WORD_T*** A, uint32_t A_dim)
{
  for(uint32_t i = 0; i < A_dim; i++) {
	 for(uint32_t j = 0; j < A_dim; j++) {
		free(A[i][j]);
	 }
	 free(A[i]);
  }
  free(A);
}

void yaarx_alloc_matrices_3d(gsl_matrix* A[2][2][2], uint32_t A_dim)
{
  int32_t nmatrix = (1U << 3);
  for(int i = 0; i < nmatrix; i++){
	 int t = i;
	 int a = t & 1;
	 t /= 2;
	 int b = t & 1;
	 t /= 2;
	 int c = t & 1;
	 t /= 2;
	 A[a][b][c] = gsl_matrix_calloc(A_dim, A_dim);
  }
}

void yaarx_free_matrices_3d(gsl_matrix* A[2][2][2], uint32_t A_dim)
{
  int32_t nmatrix = (1U << 3);
  for(int i = 0; i < nmatrix; i++){
	 int t = i;
	 int a = t & 1;
	 t /= 2;
	 int b = t & 1;
	 t /= 2;
	 int c = t & 1;
	 t /= 2;
	 gsl_matrix_free(A[a][b][c]);
  }
}

/**
 * Basic matrix multiplication over F_2
 * See: http://www.joux.biz/algcrypt/PROGRAMS/Matmul3_1.html
 */
inline void matrix_matrix_multiply_bool(std::array<std::array<bool, WORD_SIZE>, WORD_SIZE>* res, 
													 const std::array<std::array<bool, WORD_SIZE>, WORD_SIZE> mat1, 
													 const std::array<std::array<bool, WORD_SIZE>, WORD_SIZE> mat2)
{
  for(int l = 0; l < WORD_SIZE; l++) {
    for(int c = 0; c < WORD_SIZE; c++) { 
		(*res)[l][c] = 0;
      for (int k = 0; k < WORD_SIZE; k++) {
        (*res)[l][c] ^= (mat1[l][k] & mat2[k][c]);
      }
    }
  }
}

