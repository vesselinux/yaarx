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
 * \file  linear-code-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2015
 * \brief Experiments with linear codes for SK design
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_ADD_H
#include "xdp-add.hh"
#endif
#ifndef MAX_XDP_ADD_H
#include "max-xdp-add.hh"
#endif

#if (WORD_SIZE < 4)
/*
 * Dummy define-s
 */
#define LCODE_GEN_MATRIX_NROWS 2 // K
#define LCODE_GEN_MATRIX_NCOLS 4 // N
#define LCODE_MESSAGE_LEN_K LCODE_GEN_MATRIX_NROWS
#define LCODE_CODEWORD_LEN_N LCODE_GEN_MATRIX_NCOLS
#define LCODE_MIN_DIST_D 2
WORD_T g_G[LCODE_GEN_MATRIX_NROWS][LCODE_GEN_MATRIX_NCOLS] = {
  {1,0,0,1},
  {0,1,1,1}
};
#endif // #if (WORD_SIZE == 4)

#if (WORD_SIZE == 4)
/*
[4, 2, 2] Linear Code over GF(2)
Generator matrix:
[1 0 0 1]
[0 1 1 1]
true
*/
/**
 * Dimensions of the linear code [N,K,D]:
 * 2^K codewords of size N bits each with minimum distance D 
 */
#define LCODE_GEN_MATRIX_NROWS 2 // K
#define LCODE_GEN_MATRIX_NCOLS 4 // N
#define LCODE_MESSAGE_LEN_K LCODE_GEN_MATRIX_NROWS
#define LCODE_CODEWORD_LEN_N LCODE_GEN_MATRIX_NCOLS
#define LCODE_MIN_DIST_D 2
/*
 * The "best known" [4,2,2] linear code generated with Magma:
 * http://magma.maths.usyd.edu.au/calc/
 * http://magma.maths.usyd.edu.au/magma/handbook/text/1810
 *
 * BKLC(GF(2), 4, 2) 
 * [4, 2, 2] Linear Code over GF(2)
 *
 * Generator matrix:
 * [1 0 0 1]
 * [0 1 1 1]
 */
WORD_T g_G[LCODE_GEN_MATRIX_NROWS][LCODE_GEN_MATRIX_NCOLS] = {
  {1,0,1,0},
  {0,1,0,0}
};
#endif // #if (WORD_SIZE == 4)

#if (WORD_SIZE == 6)
/*
[4, 2, 2] Linear Code over GF(2)
Generator matrix:
[1 0 0 1]
[0 1 1 1]
true
*/
/**
 * Dimensions of the linear code [N,K,D]:
 * 2^K codewords of size N bits each with minimum distance D 
 */
#define LCODE_GEN_MATRIX_NROWS 3 // K
#define LCODE_GEN_MATRIX_NCOLS 6 // N
#define LCODE_MESSAGE_LEN_K LCODE_GEN_MATRIX_NROWS
#define LCODE_CODEWORD_LEN_N LCODE_GEN_MATRIX_NCOLS
#define LCODE_MIN_DIST_D 3 // D
/*
 * The "best known" [6,3,3] linear code generated with Magma:
 * http://magma.maths.usyd.edu.au/calc/
 * http://magma.maths.usyd.edu.au/magma/handbook/text/1810
 * 
 * [6, 3, 3] Linear Code over GF(2)
 * Generator matrix:
 * [1 0 0 1 0 1]
 * [0 1 0 1 1 0]
 * [0 0 1 1 1 1]
 * true
 */
WORD_T g_G[LCODE_GEN_MATRIX_NROWS][LCODE_GEN_MATRIX_NCOLS] = {
  {1,0,0,1,0,1},
  {0,1,0,1,1,0},
  {0,0,1,1,1,1}
};
#endif // #if (WORD_SIZE == 4)


#if (WORD_SIZE == 8)
/**
 * Dimensions of the linear code [N,K,D]:
 * 2^K codewords of size N bits each with minimum distance D 
 */
#define LCODE_GEN_MATRIX_NROWS 4 // K
#define LCODE_GEN_MATRIX_NCOLS 8 // N
#define LCODE_MESSAGE_LEN_K LCODE_GEN_MATRIX_NROWS
#define LCODE_CODEWORD_LEN_N LCODE_GEN_MATRIX_NCOLS
#define LCODE_MIN_DIST_D 4
/*
 * The "best known" [8,4,4] linear code generated with Magma:
 * http://magma.maths.usyd.edu.au/calc/
 * http://magma.maths.usyd.edu.au/magma/handbook/text/1810
 *
 * BKLC(GF(2), 8, 4) 
 * [8, 4, 4] Quasicyclic of degree 2 Linear Code
 * over GF(2) (a cyclic code is a block code, where the circular
 * shifts of each codeword gives another * word that belongs to the
 * code.)  
 *
 * Generator matrix:
 */
WORD_T g_G[LCODE_GEN_MATRIX_NROWS][LCODE_GEN_MATRIX_NCOLS] = {
  {1,0,0,1,0,1,1,0},
  {0,1,0,1,0,1,0,1},
  {0,0,1,1,0,0,1,1},
  {0,0,0,0,1,1,1,1},
};
#endif // #if (WORD_SIZE == 8)

#if (WORD_SIZE == 10)
/**
 * Dimensions of the linear code [N,K,D]:
 * 2^K codewords of size N bits each with minimum distance D 
 */
#define LCODE_GEN_MATRIX_NROWS 5 // K
#define LCODE_GEN_MATRIX_NCOLS 10 // N
#define LCODE_MESSAGE_LEN_K LCODE_GEN_MATRIX_NROWS
#define LCODE_CODEWORD_LEN_N LCODE_GEN_MATRIX_NCOLS
#define LCODE_MIN_DIST_D 4
/*
 * The "best known" [10,5,4] linear code generated with Magma:
 * http://magma.maths.usyd.edu.au/calc/
 * http://magma.maths.usyd.edu.au/magma/handbook/text/1810
 *
 * BKLC(GF(2), 10, 5) 
 *
 * Generator matrix:
 */
WORD_T g_G[LCODE_GEN_MATRIX_NROWS][LCODE_GEN_MATRIX_NCOLS] = {
  {1,0,0,1,0,1,0,1,1,1},
  {0,1,0,1,0,1,0,1,0,0},
  {0,0,1,1,0,0,0,0,1,1},
  {0,0,0,0,1,1,0,0,1,1},
  {0,0,0,0,0,0,1,1,1,1},
};
#endif // #if (WORD_SIZE == 10)

#if (WORD_SIZE == 16)
/**
 * Dimensions of the linear code [N,K,D]:
 * 2^K codewords of size N bits each with minimum distance D 
 */
#define LCODE_GEN_MATRIX_NROWS 8 // K
#define LCODE_GEN_MATRIX_NCOLS 16 // N
#define LCODE_MESSAGE_LEN_K LCODE_GEN_MATRIX_NROWS
#define LCODE_CODEWORD_LEN_N LCODE_GEN_MATRIX_NCOLS
#define LCODE_MIN_DIST_D 5
/*
 * The "best known" [16,8,5] linear code generated with Magma:
 * http://magma.maths.usyd.edu.au/calc/
 * http://magma.maths.usyd.edu.au/magma/handbook/text/1810
 *
 * BKLC(GF(2), 16, 8)
 * [16, 8, 5] Linear Code over GF(2)
 * Generator matrix:
 */
WORD_T g_G[LCODE_GEN_MATRIX_NROWS][LCODE_GEN_MATRIX_NCOLS] = {
  {1,0,0,0,0,0,0,0,1,0,0,1,1,1,1,0},
  {0,1,0,0,0,0,0,0,0,1,0,0,1,1,1,1},
  {0,0,1,0,0,0,0,0,1,1,0,0,1,1,0,0},
  {0,0,0,1,0,0,0,0,0,1,1,0,0,1,1,0},
  {0,0,0,0,1,0,0,0,0,0,1,1,0,0,1,1},
  {0,0,0,0,0,1,0,0,1,1,1,1,0,0,1,0},
  {0,0,0,0,0,0,1,0,0,1,1,1,1,0,0,1},
  {0,0,0,0,0,0,0,1,1,1,0,1,0,1,1,1},
};
#endif // #if (WORD_SIZE == 16)

void lcode_matrix_print(gsl_matrix* A, uint32_t nrows, uint32_t ncols)
{
  for(uint32_t row = 0; row < nrows; row++) {
	 for(uint32_t col = 0; col < ncols; col++) {
		double x = gsl_matrix_get(A, row, col);
		//		printf("%4.2f ", x);
		printf("%1.0f", x);
	 }
	 printf("\n");
  }
}

void lcode_vector_print(gsl_vector* V, uint32_t len)
{
  for(uint32_t i = 0; i < len; i++) {
	 double x = gsl_vector_get(V, i);
	 //	 printf("%4.2f ", x);
	 printf("%1.0f,", x);
  }
  printf("\n");
}

/*
 * vec [0, 1, 2, ... len - 1] = [LSB .. MSB] => hex [MSB .. LSB]: 
 * [1, 1, 0, 1] -> binary 1011 -> hex 0xB
 */
void lcode_vec_to_hex(WORD_T* hex, gsl_vector* vec, uint32_t vec_len)
{
  *hex = 0;
  for(uint32_t i = 0; i < vec_len; i++) {
	 WORD_T bit_i = (WORD_T)gsl_vector_get(vec, i);
	 assert((bit_i == 0) || (bit_i == 1));
    (*hex) |= (bit_i << i);
	 //	 printf(" %X %d\n", *hex, bit_i);
  }
}

/*
 * hex [MSB .. LSB] => vec [0, 1, 2, ... len - 1] = [LSB .. MSB] 
 * hex 0xB -> binary 1011 -> [1, 1, 0, 1]
 */
void lcode_hex_to_vec(const WORD_T hex, gsl_vector* vec, uint32_t vec_len)
{
  gsl_vector_set_zero(vec);
  for(uint32_t i = 0; i < vec_len; i++) {
	 WORD_T bit_i = (hex >> i) & 1;
	 assert((bit_i == 0) || (bit_i == 1));
	 gsl_vector_set(vec, i, bit_i);
  }
}

/**
 * Convert matrix of double-s to matrix of Booleans: if an element x is
 * non-zero => set it to (x mod 2); else leave it to zero
 */
void lcode_matrix_double_to_boolean(gsl_matrix* A,  uint32_t nrows, uint32_t ncols)
{
  for(uint32_t row = 0; row < nrows; row++) {
	 for(uint32_t col = 0; col < ncols; col++) {
		WORD_T x = (WORD_T)gsl_matrix_get(A, row, col);
		if(x != 0) { // if non-zero, set it to 1.0
		  x %= 2;
		  gsl_matrix_set(A, row, col, (double)x);
		}
	 }
  }
}

/**
 * Convert vector of double-s to vector of Booleans: if an element x is
 * non-zero => set it to (x mod 2); else leave it to zero
 */
void lcode_vector_double_to_boolean(gsl_vector* vec,  uint32_t vec_len)
{
  for(uint32_t i = 0; i < vec_len; i++) {
	 WORD_T x = (WORD_T)gsl_vector_get(vec, i);
	 if(x != 0) { // if non-zero, set it to 1.0
		x %= 2;
		gsl_vector_set(vec, i, (double)x);
	 }
  }
}

/**
 * Encode NROWS bit message X into NCOLS bite codeword C using the NROWS x
 * NCOLS generator matrix G as:
 *
 * C[1 x NCOLS] = X[1 x NROWS] G[NROWS x NCOLS]
 */
void lcode_encode(gsl_vector* codeword, gsl_vector* message, 
					  gsl_matrix* G,  uint32_t nrows, uint32_t ncols)
{
  /*
	* M G = (M^t G^t)^t
	*/
  gsl_blas_dgemv(CblasTrans, 1.0, G, message, 0.0, codeword);
#if 0
  lcode_vector_print(codeword, LCODE_CODEWORD_LEN_N);
#endif // #if 0
  /*
	* Transform codeword to Boolean
	*/
  lcode_vector_double_to_boolean(codeword, ncols);
}

void lcode_matrix_init(WORD_T GM[LCODE_GEN_MATRIX_NROWS][LCODE_GEN_MATRIX_NCOLS], gsl_matrix* A, uint32_t nrows, uint32_t ncols)
{
  for(uint32_t row = 0; row < nrows; row++) {
	 for(uint32_t col = 0; col < ncols; col++) {
		gsl_matrix_set(A, row, col, GM[row][col]);
	 }
  }
}

/*
 * Store all the codewords of a linear code
 */
void lcode_codewords(std::vector<WORD_T>* C, gsl_matrix* G, uint32_t message_len)
{
  uint32_t all_words = (1UL << message_len);
  gsl_vector* message_vec = gsl_vector_calloc(LCODE_MESSAGE_LEN_K);
  gsl_vector* codeword_vec = gsl_vector_calloc(LCODE_CODEWORD_LEN_N);
  WORD_T message_hex = 0;
  WORD_T codeword_hex = 0;
 
  for(WORD_T x = 0; x < all_words; x++) {
	 // re-init
	 message_hex = x;
	 codeword_hex = 0;
	 gsl_vector_set_zero(message_vec);
	 gsl_vector_set_zero(codeword_vec);

	 lcode_hex_to_vec(message_hex, message_vec, LCODE_MESSAGE_LEN_K);

	 lcode_encode(codeword_vec, message_vec, G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);

	 lcode_vec_to_hex(&codeword_hex, codeword_vec, LCODE_CODEWORD_LEN_N);

	 C->push_back(codeword_hex);

#if 0
	 printf("%X %X ", message_hex, codeword_hex);
	 print_binary(message_hex, message_len);
	 printf(" ");
	 print_binary(codeword_hex);
	 printf("\n");
#endif
  }

  gsl_vector_free(codeword_vec);
  gsl_vector_free(message_vec);
}

/*
 * Store all differences between the codewords of a linear code
 */
void lcode_codewords_diffs(std::vector<WORD_T> C)
{
  uint32_t cnt = 0;
  for(uint32_t i = 1; i < C.size(); i++) {
	 for(uint32_t j = i; j < C.size(); j++) {
		cnt++;
		WORD_T diff = C[i] ^ C[j];
		printf("%3d %4X ",  cnt, diff);
		print_binary(diff);
		printf("\n");
		uint32_t hw = hamming_weight(diff);
		assert((hw >= LCODE_MIN_DIST_D) || (diff == 0));
	 }
  }
}

/*
 * The DP of the component G(x_L) + G(x_R) = y:
 * (da -> db) = (da_L || da_R) -> db
 */
double lcode_add_dp_exper(WORD_T da, WORD_T db)
{
  //  printf("[%s:%d] Enter %s()\n", __FILE__, __LINE__, __FUNCTION__);
  //  assert((WORD_SIZE == 16) || (WORD_SIZE == 10) || (WORD_SIZE == 8));
  double p_ret = 0.0;
  uint32_t cnt = 0;

  gsl_matrix* G = gsl_matrix_calloc(LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);

  // first pair
  gsl_vector* message_vec_L = gsl_vector_calloc(LCODE_MESSAGE_LEN_K);
  gsl_vector* message_vec_R = gsl_vector_calloc(LCODE_MESSAGE_LEN_K);
  gsl_vector* codeword_vec_L = gsl_vector_calloc(LCODE_CODEWORD_LEN_N);
  gsl_vector* codeword_vec_R = gsl_vector_calloc(LCODE_CODEWORD_LEN_N);
  // second pair
  gsl_vector* message_vec_LL = gsl_vector_calloc(LCODE_MESSAGE_LEN_K);
  gsl_vector* message_vec_RR = gsl_vector_calloc(LCODE_MESSAGE_LEN_K);
  gsl_vector* codeword_vec_LL = gsl_vector_calloc(LCODE_CODEWORD_LEN_N);
  gsl_vector* codeword_vec_RR = gsl_vector_calloc(LCODE_CODEWORD_LEN_N);

  WORD_T half_mask = (MASK >> (WORD_SIZE / 2));

  WORD_T da_L = (da >> (WORD_SIZE / 2)) & half_mask;
  WORD_T da_R = da & half_mask;

  uint32_t nskipped = 0;
  //  printf("[%s:%d] half_mask %X da da_L da_R %X %X %X\n", __FILE__, __LINE__, half_mask, da, da_L, da_R);

  lcode_matrix_init(g_G, G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);

  for(WORD_T i = 0; i < ALL_WORDS; i++) {

	 // first pair
	 WORD_T x_L = (i >> (WORD_SIZE / 2)) & half_mask;
	 WORD_T x_R = i & half_mask;
	 WORD_T code_x_L = 0;
	 WORD_T code_x_R = 0;
#if 0
	 if(x_L == x_R) {
		nskipped++;
		//		printf("[%s:%d] Skipped#%2d i x_L x_R %X %X %X\n", __FILE__, __LINE__, nskipped, i, x_L, x_R);
		continue;
	 }
#endif
	 lcode_hex_to_vec(x_L, message_vec_L, LCODE_MESSAGE_LEN_K);
	 lcode_hex_to_vec(x_R, message_vec_R, LCODE_MESSAGE_LEN_K);

	 lcode_encode(codeword_vec_L, message_vec_L, G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);
	 lcode_encode(codeword_vec_R, message_vec_R, G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);
	 //	 lcode_encode(codeword_vec_R, message_vec_R, G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);

	 lcode_vec_to_hex(&code_x_L, codeword_vec_L, LCODE_CODEWORD_LEN_N);
	 lcode_vec_to_hex(&code_x_R, codeword_vec_R, LCODE_CODEWORD_LEN_N);

	 // second pair
	 WORD_T xx_L = (x_L ^ da_L);
	 WORD_T xx_R = (x_R ^ da_R);
	 WORD_T code_xx_L = 0;
	 WORD_T code_xx_R = 0;
#if 0
	 if(xx_L == xx_R) {
		nskipped++;
		//		printf("[%s:%d] Skipped#%2d i x_L x_R %X %X %X\n", __FILE__, __LINE__, nskipped, i, x_L, x_R);
		continue;
	 }
#endif
	 lcode_hex_to_vec(xx_L, message_vec_LL, LCODE_MESSAGE_LEN_K);
	 lcode_hex_to_vec(xx_R, message_vec_RR, LCODE_MESSAGE_LEN_K);

	 lcode_encode(codeword_vec_LL, message_vec_LL, G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);
	 lcode_encode(codeword_vec_RR, message_vec_RR, G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);
	 //	 lcode_encode(codeword_vec_RR, message_vec_RR, G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);

	 lcode_vec_to_hex(&code_xx_L, codeword_vec_LL, LCODE_CODEWORD_LEN_N);
	 lcode_vec_to_hex(&code_xx_R, codeword_vec_RR, LCODE_CODEWORD_LEN_N);

	 WORD_T y = ADD(code_x_L, code_x_R);
	 WORD_T yy = ADD(code_xx_L, code_xx_R);
	 WORD_T odiff = (y ^ yy);

	 //	 printf("[%s:%d] y yy dy odiff %X %X %X %X\n", __FILE__, __LINE__, y, yy, odiff, db);

#if 0
	 uint32_t dist_x = hamming_weight(code_x_L ^ code_x_R);
	 uint32_t dist_xx = hamming_weight(code_xx_L ^ code_xx_R);
	 //	 uint32_t dist_dx = hamming_weight((code_x_L ^ code_x_R) ^ (code_xx_L ^ code_xx_R));

	 if(!(dist_x >= LCODE_MIN_DIST_D)) {
		printf("[%s:%d] i x_L x_R dx %X %X %X %X | dist_x %d\n", __FILE__, __LINE__, i, code_x_L, code_x_R, (code_x_L ^ code_x_R), dist_x);
	 }
	 if((x_L != 0) && (x_R != 0) && (xx_L != 0) && (xx_R != 0)) {
		assert(dist_x >= LCODE_MIN_DIST_D);
	 }
	 if(!(dist_xx >= LCODE_MIN_DIST_D)) {
		printf("[%s:%d] i xx_L xx_R dx %X %X %X %X | dist_xx %d\n", __FILE__, __LINE__, i, code_xx_L, code_xx_R, (code_xx_L ^ code_xx_R), dist_xx);
	 }
	 if((xx_L != 0) && (xx_R != 0) && (xx_L != 0) && (xx_R != 0)) {
		assert(dist_xx >= LCODE_MIN_DIST_D);
	 }
#endif

	 printf("[%s:%d]  %4d  x_L  x_R (%X %X) (%X %X)\n", __FILE__, __LINE__, i, code_x_L, code_x_R, code_xx_L, code_xx_R);
	 if(odiff == db) {
		cnt++;
		printf("[%s:%d]  %4d  x_L  x_R (%X %X) (%X %X) <- %d\n", __FILE__, __LINE__, cnt, code_x_L, code_x_R, code_xx_L, code_xx_R, cnt);
		//		printf("[%s:%d]  %4d  x_L  x_R (%X %X) (%X %X)\n", __FILE__, __LINE__, cnt, x_L, x_R, xx_L, xx_R);
		//		printf("[%s:%d]  %4d xx_L xx_R %X %X\n", __FILE__, __LINE__, cnt, xx_L, xx_R);
	 }
  }

  p_ret = (double)cnt / (double)(ALL_WORDS - nskipped);
  //  printf("[%s:%d] cnt %d (%f) nskipped %d\n", __FILE__, __LINE__, cnt, p_ret, nskipped);
  //  assert(nskipped == 16);

  gsl_vector_free(codeword_vec_LL);
  gsl_vector_free(codeword_vec_RR);
  gsl_vector_free(message_vec_LL);
  gsl_vector_free(message_vec_RR);

  gsl_vector_free(codeword_vec_L);
  gsl_vector_free(codeword_vec_R);
  gsl_vector_free(message_vec_L);
  gsl_vector_free(message_vec_R);

  gsl_matrix_free(G);

  return p_ret;
}

/*
 * Number of differing bit positions between words a and b
 */
uint32_t lcode_ndiff_bits(WORD_T a, WORD_T b)
{
  WORD_T diff = (~((a & b) | (~a & ~b))) & MASK;
  uint32_t ndiff_bits = hamming_weight(diff);
  return ndiff_bits;
}

/*
 * Number of differing bit positions between words a and b, exclusing the MSB
 */
uint32_t lcode_ndiff_bits_no_msb(WORD_T a, WORD_T b)
{
  WORD_T diff = (~((a & b) | (~a & ~b))) & MASK;
  uint32_t ndiff_bits_no_msb = hamming_weight(diff & ~(1UL << (WORD_SIZE - 1))); // don't count the MSB
  return ndiff_bits_no_msb;
}

WORD_T speck_sigma_left(const WORD_T x, const WORD_T rot_const)
{
  WORD_T y = LROT(x, rot_const);
  return y;
}

WORD_T speck_sigma_right(const WORD_T x, const WORD_T y, const WORD_T rot_const)
{
  WORD_T z = x ^ LROT(y, rot_const);
  return z;
}

WORD_T speck_negation(const WORD_T x)
{
  WORD_T y = (~x) & MASK;
  return y;
}

double speck_round_dp_max(const WORD_T r, const WORD_T s, // rot const
								const WORD_T da_in, const WORD_T db_in,
								WORD_T* da_out, WORD_T* db_out)
{

  WORD_T da = speck_sigma_left(da_in, r);
  WORD_T db = speck_sigma_right(da_in, db_in, s);
  WORD_T dc_max = 0;
  double p_max = max_xdp_add_lm(da, db, &dc_max);

  *da_out = dc_max;
  *db_out = db;
  return p_max;
}


void speck_diff_seq()
{
  WORD_T r = 1;
  WORD_T s = 2;
  //  for(r = 0; r < WORD_SIZE; r++) {
  //	 for(s = 0; s < WORD_SIZE; s++) {
  uint32_t hist[WORD_SIZE + WORD_SIZE] = {0};
  printf("[%s:%d] ==== %d %d ====\n", __FILE__, __LINE__, r, s);
  for(WORD_T x = 0; x < ALL_WORDS; x++) {
	 for(WORD_T y = 0; y < ALL_WORDS; y++) {
		if((x == 0) && (y == 0))
		  continue;
		WORD_T t1 = x ^ y;
		WORD_T d1 = hamming_weight(t1);
		WORD_T t2 = (LROT(x, r) ^ x ^ LROT(y, s)) & MASK;
		WORD_T d2 = hamming_weight(t2);
		WORD_T branch_num = d1 + d2;
		assert(branch_num <= WORD_SIZE + WORD_SIZE);
		hist[branch_num]++;
		//		printf("%d %d | %2d\n", d1, d2, sum);
	 }
  }
  for(uint32_t i = 0; i < (WORD_SIZE + WORD_SIZE); i++) {
	 printf("%2d ", i);
	 printf("%10d ", hist[i]);
	 double frac = ((double)hist[i] / (double)(ALL_WORDS * ALL_WORDS)) * 100;
	 printf("%4.2f %% ", frac);
	 uint32_t L = (uint32_t)log2(hist[i]);
	 for(uint32_t j = 0; j < L; j++) {
		printf("-");
	 }
	 printf("\n");
  }
  //	 }
  //  }
}

void speck_negation_approximation()
{
  uint32_t cnt_max = 0;
  WORD_T r_max = 0;
  WORD_T s_max = 0;
  for(WORD_T r = 0; r < WORD_SIZE; r++) {
	 for(WORD_T s = 0; s < WORD_SIZE; s++) {
		//		printf("[%s:%d] -------- %d %d --------\n", __FILE__, __LINE__, r, s);
		uint32_t cnt = 0;
		for(WORD_T x = 0; x < ALL_WORDS; x++) {
		  for(WORD_T y = 0; y < ALL_WORDS; y++) {

			 //			 WORD_T a = XOR(speck_sigma_left(x, r), speck_sigma_right(x, y, s));
			 WORD_T a = (LROT(x, r) ^ y) & MASK;
			 WORD_T b = XOR(speck_negation(x), y);
			 WORD_T b_tmp = speck_negation(XOR(x, y));
			 assert(b == b_tmp);

#if 1
			 uint32_t ndiff = lcode_ndiff_bits(a, b);
			 assert(ndiff <= WORD_SIZE);
			 cnt += (WORD_SIZE - ndiff); // add number of equal bits
#endif
#if 0 // DEBUG
			 printf("%d %d\n", (WORD_SIZE - ndiff), cnt);
			 print_binary(a, WORD_SIZE);
			 printf("\n");
			 print_binary(b, WORD_SIZE);
			 printf("\n\n");
#endif // #if 1 // DEBUG
#if 0
			 if(a == b) {
				cnt++;
			 }
#endif
		  }
		}
		if(cnt > cnt_max) {
		  cnt_max = cnt;
		  r_max = r;
		  s_max = s;
		  //		  printf("[%s:%d] Update max: %d %d %d\n", __FILE__, __LINE__, r_max, s_max, cnt_max);
#if 1
		  double ratio = (double)cnt / (double)(ALL_WORDS * ALL_WORDS * WORD_SIZE);
		  printf("[%s:%d] Update max: %d %d cnt (%5d / %5d) = %f\n", __FILE__, __LINE__, 
					r_max, s_max, cnt, (uint32_t)(ALL_WORDS * ALL_WORDS * WORD_SIZE), ratio);
#endif
#if 0
		  double ratio = (double)cnt / (double)(ALL_WORDS * ALL_WORDS);
		  printf("[%s:%d] Update max: %d %d cnt (%5d / %5d) = %f\n", __FILE__, __LINE__, 
					r_max, s_max, cnt, (uint32_t)(ALL_WORDS * ALL_WORDS), ratio);
#endif
		}
	 }
  }

}

/*
 * Experiment with the differential probability of one round of Speck
 */
void speck_round_dp()
{
  uint32_t N = 10;
  uint32_t nrounds = N;

  for(nrounds = 1; nrounds <= N; nrounds++) {

	 printf("[%s:%d] ---- R %2d ----\n", __FILE__, __LINE__, nrounds);

	 double p_max_glob = 1.0;
	 WORD_T r_max_glob = 0;
	 WORD_T s_max_glob = 0;


	 //	 for(WORD_T r = 0; r < WORD_SIZE; r++) 
	 WORD_T r = 1;
{
			 //		for(WORD_T s = 0; s < WORD_SIZE; s++) 
	 WORD_T s = 2;
{
		  double p_max = 0.0;
		  WORD_T r_max = 0;
		  WORD_T s_max = 0;
		  for(WORD_T i = 0; i < ALL_WORDS; i++) {
			 for(WORD_T j = 0; j < ALL_WORDS; j++) {

				if((i == 0) && (j == 0))
				  continue;

				double p = 1.0;
				WORD_T da_in = i;
				WORD_T db_in = j;
				for(uint32_t n = 0; n < nrounds; n++) {

				  WORD_T da_out = 0;
				  WORD_T db_out = 0;
				  double p_max = speck_round_dp_max(r, s, da_in, db_in, &da_out, &db_out);
				  p *= p_max;

				  da_in = da_out;
				  db_in = db_out;
				}

				if(p > p_max) {
				  p_max = p;
				  r_max = r;
				  s_max = s;
				  //				printf("[%s:%d] Update max: %d %d (%X %X -> %X) (%X %X -> %X) %f\n", __FILE__, __LINE__, 
				  //						 r_max, s_max, i, j, dc, da, db, dc2, p_max);
				}
			 }
		  }
		  if(p_max < p_max_glob) {
			 //			 printf("[%s:%d] -------- R %2d rs = [%d %d] --------\n", __FILE__, __LINE__, nrounds, r, s);
			 p_max_glob = p_max;
			 r_max_glob = r_max;
			 s_max_glob = s_max;
			 printf("[%s:%d] Update global max: %d %d %f\n", __FILE__, __LINE__, r_max_glob, s_max_glob, log2(p_max_glob));
		  }
		}
	 }
  }
}

// --- TESTS ---

#if 1 // AUX code
#include "linear-code-tests-aux.cc"
#endif // AUX code

/**
 * Compare differential_3d_t structs for use with std::sort
 */
bool sort_comp_diff_3d_hw_custom(differential_3d_t a, differential_3d_t b)
{
  uint32_t rconst = 2;//8 % WORD_SIZE;
  uint32_t lconst = 3 % WORD_SIZE;
  uint32_t hw1 = hamming_weight(RROT(a.dz, rconst) ^ a.dz ^ LROT(a.dy, lconst));
  uint32_t hw2 = hamming_weight(RROT(b.dz, rconst) ^ b.dz ^ LROT(b.dy, lconst));
  bool b_less = (hw1 < hw2);	  // lower Hamming weight first first
  return b_less;
}


void test_speck_xdp_add_vec()
{
  printf("[%s:%d] %s()\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t rconst = 2;//8 % WORD_SIZE;
  uint32_t lconst = 3 % WORD_SIZE;
  printf("[%s:%d] r l const %d %d\n", __FILE__, __LINE__, rconst, lconst);
  std::vector<differential_3d_t> diff_vec;
  for(WORD_T da = 0; da < ALL_WORDS; da++) {
	 for(WORD_T db = 0; db < ALL_WORDS; db++) {
		for(WORD_T dc = 0; dc < ALL_WORDS; dc++) {
		  double p = xdp_add_lm(da, db, dc);
		  differential_3d_t diff;
		  diff.dx = da;
		  diff.dy = db;
		  diff.dz = dc;
		  diff.p = p;
		  diff_vec.push_back(diff);
		}
	 }
  }
  std::sort(diff_vec.begin(), diff_vec.end(), sort_comp_diff_3d_p);
  //  std::sort(diff_vec.begin(), diff_vec.end(), sort_comp_diff_3d_hw_custom);

  double p_prev = 1.0;
  uint32_t cnt = 0;
  for(std::vector<differential_3d_t>::iterator vec_iter = diff_vec.begin(); vec_iter != diff_vec.end(); vec_iter++) {
	 differential_3d_t diff = *vec_iter;
	 WORD_T da = diff.dx;
	 WORD_T db = diff.dy;
	 WORD_T dc = diff.dz;
	 double p = diff.p;
	 if(p != p_prev) {
		printf("ndiffs = %d 2^%4.2f\n", cnt, log2(cnt));
		printf("----------------------------------------------------------------\n");
		p_prev = p;
		cnt = 0;
	 }
	 cnt++;
	 if(p != 0.0) {
		uint32_t hwa = hamming_weight(da);
		uint32_t hwb = hamming_weight(db);
		uint32_t hwc = hamming_weight(dc);
		printf("HW %2d %2d %2d ", hwa, hwb, hwc);
		print_binary(da); printf(" ");
		print_binary(db); printf(" ");
		print_binary(dc); printf(" ");
		printf(" %X %X %X | %2.0f\n", da, db, dc, log2(p));
	 }
  }
  printf("impossible diffs = %d 2^%4.2f\n", cnt, log2(cnt));
  printf("----------------------------------------------------------------\n");
  printf("[%s:%d] vec size: %d 2^%4.2f\n", __FILE__, __LINE__, (uint32_t)diff_vec.size(), log2(diff_vec.size()));
}

void test_speck_xdp_add()
{
  printf("[%s:%d] %s()\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t rconst = 8 % WORD_SIZE;
  uint32_t lconst = 3 % WORD_SIZE;
  printf("[%s:%d] r l const %d %d\n", __FILE__, __LINE__, rconst, lconst);
  gsl_matrix* A = gsl_matrix_calloc(WORD_SIZE + 1, WORD_SIZE + 1);
  for(WORD_T da = 0; da < ALL_WORDS; da++) {
	 for(WORD_T db = 0; db < ALL_WORDS; db++) {
		for(WORD_T dc = 0; dc < ALL_WORDS; dc++) {
		  if((da == 0) && (db == 0) && (dc == 0))
			 continue;
		  double p = xdp_add_lm(da, db, dc);
		  if(p == 0)
			 continue;
		  WORD_T da_in = da;
		  WORD_T db_in = db;
		  WORD_T da_out = RROT(dc, rconst);
		  WORD_T db_out = dc ^ LROT(db, lconst);
		  WORD_T delta_in = (da_in ^ db_in);
		  WORD_T delta_out = (da_out ^ db_out);
		  uint32_t col = hamming_weight(delta_in);
		  uint32_t row = hamming_weight(delta_out);
		  //		  if(col != 1)
		  //			 continue;
#if 1 // DEBUG
		  uint32_t hw_no_msb = hamming_weight(delta_in & ~(1UL << (WORD_SIZE - 1))); // don't count the MSB
		  double p_max_log2 = -1.0 * hw_no_msb;
		  double p_log2 = log2(p);
		  if(p_log2 > p_max_log2) {
			 printf("%X %X -> %X %f %f\n", da, db, dc, p_log2, p_max_log2);
		  }
		  assert(p_log2 <= p_max_log2);
		  if(p == 1.0) {
			 if(hw_no_msb != 0) {
				printf("%X %X %X\n", da, db, delta_in);
			 }
			 assert(hw_no_msb == 0);
		  }
#endif
		  assert(col <= WORD_SIZE);
		  assert(row <= WORD_SIZE);
		  //		  print_binary(da); printf(" ");
		  //		  print_binary(db); printf(" ");
		  //		  print_binary(dc); printf(" ");
		  //		  printf("(%X %X) -> %X -> (%X %X) | %2.0f\n", da_in, db_in, dc, da_out, db_out, log2(p));
		  double x = 1.0 + gsl_matrix_get(A, row, col);
		  gsl_matrix_set(A, row, col, x);
		}
	 }
  }
  for(int row = 0; row <= WORD_SIZE; row++){
	 for(int col = 0; col <= WORD_SIZE; col++){
		double e = gsl_matrix_get(A, row, col);
		printf("%7.0f, ", e);
	 }
	 printf("\n");
  }
  printf("\n");
  gsl_matrix_free(A);
}

void test_speck_xdp_add_two_round()
{
  printf("[%s:%d] %s()\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t rconst = 8 % WORD_SIZE;
  uint32_t lconst = 3 % WORD_SIZE;
  printf("[%s:%d] r l const %d %d\n", __FILE__, __LINE__, rconst, lconst);
  gsl_matrix* A = gsl_matrix_calloc(WORD_SIZE + 1, WORD_SIZE + 1);
  for(WORD_T da = 0; da < ALL_WORDS; da++) {
	 for(WORD_T db = 0; db < ALL_WORDS; db++) {
		for(WORD_T dc = 0; dc < ALL_WORDS; dc++) {
		  if((da == 0) && (db == 0) && (dc == 0))
			 continue;
		  double p = xdp_add_lm(da, db, dc);
		  if(p == 0)
			 continue;

		  // 1st round
		  WORD_T da_in = da;
		  WORD_T db_in = db;
		  WORD_T da_out = RROT(dc, rconst);
		  WORD_T db_out = dc ^ LROT(db, lconst);
		  WORD_T delta_in = (da_in ^ db_in);

		  // 2nd round
		  da_in = da_out;
		  db_in = db_out;
		  for(WORD_T dc_two = 0; dc_two < ALL_WORDS; dc_two++) {
			 double p_two = xdp_add_lm(da_in, db_in, dc_two);
			 if(p_two == 0)
				continue;

			 da_out = RROT(dc_two, rconst);
			 db_out = dc_two ^ LROT(db, lconst);
			 WORD_T delta_out = (da_out ^ db_out);

			 uint32_t col = hamming_weight(delta_in);
			 uint32_t row = hamming_weight(delta_out);
			 assert(col <= WORD_SIZE);
			 assert(row <= WORD_SIZE);
			 //			 printf("(%X %X) -> %X -> (%X %X) | %2.0f\n", da, db, dc_two, da_out, db_out, log2(p));
			 double x = 1.0 + gsl_matrix_get(A, row, col);
			 gsl_matrix_set(A, row, col, x);
		  }
		}
	 }
  }
  for(int row = 0; row <= WORD_SIZE; row++){
	 for(int col = 0; col <= WORD_SIZE; col++){
		double e = gsl_matrix_get(A, row, col);
		printf("%2.0f, ", e);
	 }
	 printf("\n");
  }
  printf("\n");
  gsl_matrix_free(A);
}


int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %8lX\n", __FILE__, __LINE__, WORD_SIZE, MASK);
  srandom(time(NULL));
  //  assert(WORD_SIZE == 4);
  //  assert(WORD_SIZE == 8);
  //  assert(WORD_SIZE == 10);
  //  assert(WORD_SIZE == 16);
  //  test_lcode();
  //  test_1();
  //  test_lcode_add_dp();
  //  test_lcode_add_dp_all();
  //  test_lcode_add_dp_all_matrices();
  //  test_lcode_codewords();
  //  test_lcode_add_dp_rand();
  //  test_max_xdp_add_lin_transform();
  //  test_max_prob();
  //  test_max_xdp_add();
  //  test_max_xdp_rot_add_two_block();
  //  test_max_xdp_add_single();
  //  speck_round_dp();
  //  speck_negation_approximation();
  //  speck_diff_seq();
  //  test_speck_xdp_add_vec();
  test_speck_xdp_add();
  //  test_speck_xdp_add_two_round();
  return 0;
}
