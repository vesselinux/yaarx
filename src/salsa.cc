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
 * \file  salsa.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \brief Analysis of block cipher Salsa20.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_ADD_DIFF_SET_H
#include "xdp-add-diff-set.hh"
#endif
#ifndef SALSA_H
#include "salsa.hh"
#endif

/**
 * The constants c for 256-bit (32 Bytes) key.
 */
const char sigma[17]  = "expand 32-byte k";

/**
 * The array \p e encodes the operations of the Salsa
 * column round by providing the indexes of the words on which
 * operations are performed. The information for i-th entry of e
 * is interpreted as follow (see the column round operation of Salsa20):
 * 
 * e[i][0] = XOR( e[i][1], LROT( ADD(e[i][2],e[i][3]), e[i][4]) )
 *         = e[i][1] ^ ((e[i][2] + e[i][3]) <<< e[i][4])
 */
uint32_t E[SALSA_STATE + SALSA_STATE][5] = { // elements of the state before column round
  /* Column round */
  /* column# 0 [0,4,8,12] */
  { 4,  4,  0, 12,  7},
  { 8,  8,  4,  0,  9},
  {12, 12,  8,  4, 13},
  { 0,  0, 12,  8, 18},
  /* column# 1 [1,5,9,13 */
  { 9,  9,  5,  1,  7},
  {13, 13,  9,  5,  9},
  { 1,  1, 13,  9, 13},
  { 5,  5,  1, 13, 18},
  /* column# 2 [2,6,10,14 */
  {14, 14, 10,  6,  7},
  { 2,  2, 14, 10,  9},
  { 6,  6,  2, 14, 13},
  {10, 10,  6,  2, 18},
  /* column# 3 [3,7,11,15 */
  { 3,  3, 15, 11,  7},
  { 7,  7,  3, 15,  9},
  {11, 11,  7,  3, 13},
  {15, 15, 11,  7, 18},
  /* Row round */
  /* row# 0 [0,1,2,3] */
  {1,   1,  0,  3,  7},
  {2,   2,  1,  0,  9},
  {3,   3,  2,  1, 13},
  {0,   0,  3,  2, 18},
  /* row# 1 [4,5,6,7] */
  {6,   6,  5,  4,  7},
  {7,   7,  6,  5,  9},
  {4,   4,  7,  6, 13},
  {5,   5,  4,  7, 18},
  /* row# 2 [8,9,10,11] */
  {11, 11, 10,  9,  7},
  {8,   8, 11, 10,  9},
  {9,   9,  8, 11, 13},
  {10, 10,  9,  8, 18},
  /* row# 3 [12,13,14,15] */
  {12, 12, 15, 14,  7},  
  {13, 13, 12, 15,  9},  
  {14, 14, 13, 12, 13},  
  {15, 15, 14, 13, 18}
};

double xdp_add_dset_salsa_arx(gsl_matrix* A[3][3][3], 
										diff_set_t dx, 
										diff_set_t dy, 
										diff_set_t dz, 
										diff_set_t* dt,
										uint32_t k, 
										bool b_single_diff)
{
  diff_set_t ds = {0, 0};
  double p = rmax_xdp_add_dset(A, dx, dy, &ds, b_single_diff);
  ds = lrot_dset(ds, k);
  *dt = xor_dset(ds, dz);
  return p;
}

double xdp_add_dset_salsa20(const uint32_t e[SALSA_STATE + SALSA_STATE][5], 
									 const uint32_t r_start, const uint32_t r_end, gsl_matrix* A[3][3][3],
									 const diff_set_t DX_in[SALSA_STATE], diff_set_t DY_in[SALSA_STATE],
									 diff_set_t DT[MAX_NROUNDS][SALSA_STATE], 
									 double P[MAX_NROUNDS][SALSA_STATE])
//									 double PW[SALSA_STATE]) // word_probabilities
{
  assert(r_start <= r_end);
  assert((r_end + 1) < MAX_NROUNDS);

  double p_diff = 1.0;			  // prob. of differential
  diff_set_t DX[SALSA_STATE] = {{0, 0}};

  for(uint32_t i = 0; i < SALSA_STATE; i++) {
	 DX[i] = DX_in[i];
  }

  for(uint32_t r = r_start; r < r_end; r++) {
#if 0									  // DEBUG
	 printf("[%s:%d] round# %d / %d\n", __FILE__, __LINE__, r, (r_end - 1));
#endif
	 for(uint32_t i = 0; i < SALSA_STATE; i++) {
#if 0									  // DEBUG
		printf("[%s:%d] round# [%d / %d], word# [%2d / %2d]\n", __FILE__, __LINE__, r, (r_end - 1), i, (SALSA_STATE - 1));
#endif
		uint32_t j = i;					  // even rounds
		bool is_odd = (r % 2);
		if(is_odd) {
		  j = i + SALSA_STATE;	  // odd rounds
		}
		uint32_t f[5] = {e[j][0], e[j][1], e[j][2], e[j][3], e[j][4]};
		diff_set_t dx = DX[f[2]];
		diff_set_t dy = DX[f[3]];
		diff_set_t dz = DX[f[1]];
		uint32_t k = f[4];
		diff_set_t dt = {0, 0};
		bool b_single_diff = false;
		//		if(r == (r_end - 1)) { // last round
		//		  b_single_diff = true;
		//		}
		double p = xdp_add_dset_salsa_arx(A, dx, dy, dz, &dt, k, b_single_diff);
		uint32_t w = f[0];
#if 0									  // DEBUG
		printf("[%s:%d] %2d: w[%2d]: (k = %d) ", __FILE__, __LINE__, r, i, k);
		xdp_add_dset_print_set(dx);
		printf(" (%2X,%2X) | ", dx.diff, dx.fixed);
		xdp_add_dset_print_set(dy);
		printf(" (%2X,%2X) | ", dy.diff, dy.fixed);
		xdp_add_dset_print_set(dz);
		printf(" (%2X,%2X) | ", dz.diff, dz.fixed);
		xdp_add_dset_print_set(dt);
		printf(" (%2X,%2X) | ", dt.diff, dt.fixed);
		printf("%f 2^%f\n", p, log2(p));
		printf("----------------\n");
#endif
		//		DT[r + 1][w] = dt;
		DX[w] = dt;
		P[r + 1][w] = p;
		p_diff *= p;
	 }
	 for(uint32_t i = 0; i < SALSA_STATE; i++) { // store trail
		DT[r + 1][i] = DX[i];
	 }
	 if(r == (r_end - 1)) { // last round
		for(uint32_t i = 0; i < SALSA_STATE; i++) {
		  DY_in[i] = DT[r + 1][i];		  // copy final output
		  assert(DX[i].diff == DT[r + 1][i].diff);
		  assert(DX[i].fixed == DT[r + 1][i].fixed);
		}
	 }
  }
  return p_diff;
}

/*
  std::vector<uint32_t> dc_set_all;
  xdp_add_dset_gen_diff_all(dc_set, &dc_set_all);
  std::vector<uint32_t>::iterator dc_iter = dc_set_all.begin();

  for(da_iter = da_set_all.begin(); da_iter != da_set_all.end(); da_iter++) {
*/

// 
// A fixed input difference goes to an output set.
// 
double xdp_add_dset_salsa20_exper(const uint32_t e[SALSA_STATE + SALSA_STATE][5], 
											 const uint32_t r_start, const uint32_t r_end, uint32_t npairs,
											 const diff_set_t DX_set[SALSA_STATE], diff_set_t DY_set[SALSA_STATE],
											 double PW[SALSA_STATE]) // probs of words
{
  assert((r_end + 1) < MAX_NROUNDS);

  uint32_t DX[SALSA_STATE] = {0};
  uint32_t cnt = 0;
  uint32_t CW[SALSA_STATE] = {0}; // count words
  for(uint32_t i = 0; i < SALSA_STATE; i++) {
	 DX[i] = DX_set[i].diff;
	 //	 assert(DX_set[i].fixed == 0);
  }
  for(uint32_t i = 0; i < npairs; i++) {
	 uint32_t X1[SALSA_STATE] = {0};
	 uint32_t X2[SALSA_STATE] = {0};
	 uint32_t Y1[SALSA_STATE] = {0};
	 uint32_t Y2[SALSA_STATE] = {0};
	 for(uint32_t j = 0; j < SALSA_STATE; j++) {
		X1[j] = random32() & MASK;
		X2[j] = XOR(X1[j], DX[j]);
	 }
	 salsa20(E, r_start, r_end, X1, Y1);
	 salsa20(E, r_start, r_end, X2, Y2);
	 uint32_t DY[SALSA_STATE] = {0};
	 for(uint32_t j = 0; j < SALSA_STATE; j++) {
		DY[j] = XOR(Y1[j], Y2[j]);
		//		printf("[%d] %8X %8X\n", j, DY[j], DYY[j]);
	 }
	 //	 printf("\n");
	 bool b_is_equal = true;
	 uint32_t w = 0;
	 while((b_is_equal) && (w < SALSA_STATE)) {
		b_is_equal = is_inset(DY[w], DY_set[w]);
		w++;
	 }
	 if(b_is_equal) {
		cnt++;
	 }
	 for(w = 0; w < SALSA_STATE; w++) {
		if(is_inset(DY[w], DY_set[w])) {
		  CW[w]++;
		}
	 }
  }
  double p = (double)cnt / (double)npairs;
  for(uint32_t w = 0; w < SALSA_STATE; w++) {
	 PW[w] = (double)CW[w] / (double)npairs;
  }
  return p;
}

/**
 * The ARX primitive of Salsa20:
 * t = z ^ ((x + y) <<< k);
 */
uint32_t salsa_arx(uint32_t x, uint32_t y, uint32_t z, uint32_t k)
{
  //  uint32_t t = XOR(z, LROT(ADD(x, y), k));
  uint32_t s = ADD(x, y);
  uint32_t r = LROT(s, k);
  uint32_t t = XOR(z, r);
  return t;
}

void salsa20(const uint32_t e[SALSA_STATE + SALSA_STATE][5], 
				 const uint32_t r_start, const uint32_t r_end, 
				 const uint32_t X_in[SALSA_STATE], uint32_t Y_in[SALSA_STATE])

{
  assert(r_start <= r_end);

  uint32_t X[SALSA_STATE] = {0};

  for(int i = 0;i < SALSA_STATE;++i) {
	 X[i] = X_in[i];
  }

  for(uint32_t r = r_start; r < r_end; r++) {
	 for(uint32_t i = 0; i < SALSA_STATE; i++) {
		uint32_t j = i;					  // even rounds
		bool is_odd = (r % 2);
		if(is_odd) {
		  j = i + SALSA_STATE;	  // odd rounds
		}
		uint32_t f[5] = {e[j][0], e[j][1], e[j][2], e[j][3], e[j][4]};
		//		X[f[0]] = XOR(X[f[1]], LROT(ADD(X[f[2]],X[f[3]]), f[4]));
		// t = z ^ ((x + y) <<< k);
		uint32_t x = X[f[2]];
		uint32_t y = X[f[3]];
		uint32_t z = X[f[1]];
		uint32_t k = f[4];
		//		uint32_t t = XOR(z, LROT(ADD(x, y), k));
		uint32_t t = salsa_arx(x, y, z, k);
		X[f[0]] = t;
	 }
  }
 
#if SALSA_FEED_FORWARD // feed-forward
  for (int i = 0;i < SALSA_STATE;++i) 
	 Y_in[i] = ADD(X[i],X_in[i]);
#else // no feed-forward
  for (int i = 0;i < SALSA_STATE;++i) {
	 Y_in[i] = X[i];
  }
#endif
}

/**
 * Convert the 16 Byte constant sigma of Salsa20
 * into an array of 4 32-bit words.
 */
void salsa_sigma_to_uint32(uint32_t X[4], const char c[17])
{
  for(uint32_t i = 0; i < 4; i++) {
	 uint32_t j = (4*i);
	 X[i] = (c[j] << 24) | (c[j+1] << 16) | (c[j+2] << 8) | c[j+3];
#if 0
	 printf("[%s:%d] %8X = %X %X %X %X\n", __FILE__, __LINE__, X[i], c[j], c[j+1], c[j+2], c[j+3]);
#endif
  }
}

/**
 * Generate a random input state.
 */
void salsa_gen_rand_input_state(uint32_t X[SALSA_STATE])
{
	  uint32_t C[4] = {0};
	  salsa_sigma_to_uint32(C, sigma);

	  /* input key at positions [1,2,3,4] */
	  X[ 1] = random32() & MASK;
	  X[ 2] = random32() & MASK;
	  X[ 3] = random32() & MASK;
	  X[ 4] = random32() & MASK;
	  /* input key at positions [11,12,13,14] */
	  X[11] = random32() & MASK;
	  X[12] = random32() & MASK;
	  X[13] = random32() & MASK;
	  X[14] = random32() & MASK;
	  /* input constants on the main diagonal: positions [0,5,10,15] */
	  X[ 0] = C[0] & MASK;
	  X[ 5] = C[1] & MASK;
	  X[10] = C[2] & MASK;
	  X[15] = C[3] & MASK;
	  /* set the iv - positions [6,7] */
	  X[ 6] = random32() & MASK;
	  X[ 7] = random32() & MASK;
	  /* set the counter - positions [8,9] */
	  X[ 8] = random32() & MASK;
	  X[ 9] = random32() & MASK;

	  // compare constants to Salsa reference implementation:
	  // http://cr.yp.to/snuffle/salsa20/ref/salsa20.c
#if 0									  // DEBUG
	  uint32_t tmp[4] = {0};
#define SWAP32(v)											\
	  ((LROT(v,  8) & 0x00FF00FF) |					\
		(LROT(v, 24) & 0xFF00FF00))
#define U32TO32_LITTLE(v) SWAP32(v)
#define U8TO32_LITTLE(p) U32TO32_LITTLE(((uint32_t*)(p))[0])
	  tmp[0] = U8TO32_LITTLE(sigma + 0);
	  tmp[1] = U8TO32_LITTLE(sigma + 4);
	  tmp[2] = U8TO32_LITTLE(sigma + 8);
	  tmp[3] = U8TO32_LITTLE(sigma + 12);
	  for(uint32_t i= 0; i < 4; i++) {
		 assert(tmp[i] == C[i]);
	  }
	  printf("[%s:%d] %s\n", __FILE__, __LINE__, sigma);
	  for(uint32_t i = 0; i < 16; i++) {
		 printf("%X", sigma[i]);
		 if(((i+1) % 4) == 0) {
			printf("\n");
		 }
	  }
	  for(uint32_t i = 0; i < 4; i++) {
		 printf("X[%2d] %8X %8X\n", 5*i, X[5*i], C[i]);
	  }
#endif
}

/**
 * Print state in 32-bit words.
 */
void salsa_print_state_uint32(const uint32_t X[SALSA_STATE])
{
  printf("[%s:%d]\n", __FILE__, __LINE__);
  for(uint32_t i = 0; i < SALSA_STATE; i++) {
	 printf("%8X ", X[i]);
	 if(((i+1) % 4) == 0) {
		printf("\n");
	 }
  }
}

/**
 * Print state in 8-bit words.
 */
void salsa_print_state_uint8(const uint8_t X[4 * SALSA_STATE])
{
  printf("[%s:%d]\n", __FILE__, __LINE__);
  for(uint32_t i = 0; i < (4 * SALSA_STATE); i++) {
	 printf("%3d ", X[i]);
	 if(((i+1) % 16) == 0) {
		printf("\n");
	 }
  }
}

void salsa_uint8_to_uint32(const uint8_t X[4], uint32_t* Y)
{
  *Y = 0;
  *Y = (X[3] << 24) | (X[2] << 16) | (X[1] << 8) | X[0];
}

void salsa_uint32_to_uint8(uint8_t X[4], const uint32_t Y)
{
  uint32_t mask = 0xff;
  X[0] = (Y >>  0) & mask;
  X[1] = (Y >>  8) & mask;
  X[2] = (Y >> 16) & mask;
  X[3] = (Y >> 24) & mask;
}

void salsa_state_uint8_to_uint32(const uint8_t X[4 * SALSA_STATE], uint32_t Y[SALSA_STATE])
{
  for(uint32_t i = 0; i < SALSA_STATE; i++) {
	 uint32_t j = (4*i);
	 const uint8_t x8[4] = {X[j], X[j+1], X[j+2], X[j+3]};
	 salsa_uint8_to_uint32(x8, &Y[i]);
  }
}

void salsa_state_uint32_to_uint8(uint8_t X[4 * SALSA_STATE], const uint32_t Y[SALSA_STATE])
{
  for(uint32_t i = 0; i < SALSA_STATE; i++) {
	 uint8_t x8[4] = {0, 0, 0, 0};
	 const uint32_t y32 = Y[i];
	 salsa_uint32_to_uint8(x8, y32);
	 uint32_t j = (4*i);
	 X[j] = x8[0];
	 X[j+1] = x8[1];
	 X[j+2] = x8[2];
	 X[j+3] = x8[3];
  }
}

void salsa_print_trail(uint32_t nrounds, diff_set_t DT[MAX_NROUNDS][SALSA_STATE], double P[MAX_NROUNDS][SALSA_STATE])
{
  assert((nrounds + 1) < MAX_NROUNDS);
  for(int i = 0; i < (int)(nrounds + 1); i++) {
	 printf("R[%2d]\n", i - 1);
	 for(uint32_t j = 0; j < SALSA_STATE; j++) {
		printf(" [%2d] %8X ", j, DT[i][j].diff);
		xdp_add_dset_print_set(DT[i][j]);
		printf(" | %f (2^%f) | ", P[i][j], log2(P[i][j]));
		printf("\n");
		//		if(((j + 1) % 4) == 0) {
		//		  printf("\n");
		//		}
	 }
	 printf("\n");
  }
}

/**
 * Compute the random case for the probability.
 */
void salsa_compute_prob_rand(const diff_set_t Y[SALSA_STATE], double P[SALSA_STATE])
{
  for(uint32_t i = 0; i < SALSA_STATE; i++) {
	 uint64_t s = 1UL << (WORD_SIZE - (hw32(Y[i].fixed) & MASK));
	 P[i] = 1.0 / (double)s;
  }
}

void salsa_print_prob(double P[SALSA_STATE])
{
  for(uint32_t i = 0; i < SALSA_STATE; i++) {
	 printf("[%2d] %f (2^%6.3f) ", i, P[i], log2(P[i]));
	 //	 printf("[%2d] 2^%6.3f ", i, log2(P[i]));
	 if(((i + 1) % 4) == 0) {
		printf("\n");
	 }
  }
}

void salsa_print_prob_vs_rand(double P[SALSA_STATE], double P_rand[SALSA_STATE])
{
  for(uint32_t i = 0; i < SALSA_STATE; i++) {
	 //	 printf("[%2d] 2^%6.3f (2^%6.3f) ", i, log2(P[i]), log2(P_rand[i]));
#if 1
	 //	 if(P[i] > P_rand[i]) {
	 if((P[i] / 2.0) > P_rand[i]) {
		printf("[%2d] 2^%6.3f (2^%6.3f) ", i, log2(P[i]), log2(P_rand[i]));
		assert(0 == 1);
	 } else {
		printf("[%2d]       X (2^%6.3f) ", i, log2(P_rand[i]));
	 }
#endif
	 if(((i + 1) % 4) == 0) {
		printf("\n");
	 }
  }
}

/**
 * Generate random shift constants. Used when the word size
 * is less than 32.
 */
void salsa_gen_rand_shift_const(uint32_t E[SALSA_STATE + SALSA_STATE][5])
{
  // Constants for a 16-bit version of Salsa20
  // (cf. paper by Sylvain Pelissier, EPFL)
#if(WORD_SIZE == 16)
  printf("[%s:%d] Generate shift constants for 16-bit version: ", __FILE__, __LINE__);
  uint32_t S[4] = {4, 5, 7, 9};
  printf("%d %d %d %d\n", S[0], S[1], S[2], S[3]);
  for(uint32_t i = 0; i < (SALSA_STATE + SALSA_STATE); i++) {
	 E[i][4] = S[i % 4];
	 //	 printf("[%s:%d] Set const %d\n", __FILE__, __LINE__, E[i][4]);
  }
#elif(WORD_SIZE == 8)
  printf("[%s:%d] Generate shift constants for 8-bit version:\n", __FILE__, __LINE__);
  uint32_t S[4] = {2, 3, 4, 5};
  printf("%d %d %d %d\n", S[0], S[1], S[2], S[3]);
  for(uint32_t i = 0; i < (SALSA_STATE + SALSA_STATE); i++) {
	 E[i][4] = S[i % 4];
	 //	 printf("[%s:%d] Set const %d\n", __FILE__, __LINE__, E[i][4]);
  }
#elif(WORD_SIZE < 8)
  printf("[%s:%d] Generate shift constants for %d-bit version:\n", __FILE__, __LINE__, WORD_SIZE);
  uint32_t S[4] = {1, 2, 3, 4};
  printf("%d %d %d %d\n", S[0], S[1], S[2], S[3]);
  for(uint32_t i = 0; i < (SALSA_STATE + SALSA_STATE); i++) {
	 E[i][4] = S[i % 4];
	 //	 printf("[%s:%d] Set const %d\n", __FILE__, __LINE__, E[i][4]);
  }
#else
  printf("[%s:%d] Generate random shift constants...\n", __FILE__, __LINE__);
  for(uint32_t i = 0; i < (SALSA_STATE + SALSA_STATE); i++) {
	 E[i][4] = random32() % WORD_SIZE;
  }
#endif
}

/**
 *  Generate an array of dependencies of each of the SALSA_STATE
 *  number of output words after ROUNDS number of rounds upon some of
 *  the modular additions in rounds 0,1,2,...,ROUNDS-2. dep[i][j] are
 *  32-bit words of which only the 16 lsb bits are used. each of these
 *  16 bits corresponds to one modular addition in the given round.
 *
 *  Example: Let ROUNDS = 3. Then each of the 16 words after round 3
 *  depends on some modular additions from rounds 1,2 and 3. Let's say
 *  that word 4 depends on additions 1 and 8 after round 1 (if we
 *  start counting from zero this is a 16-bit word with bits #1 and #8
 *  set to 1: 0x0102), on additions 2 and 7 after round 2 (0x0044) and
 *  on additions 15 and 3 after round 3 (0x8010). Then the
 *  corresponding entry of dep for word 4 will be:
 *
 *  dep[4] = {0x0082, 0x0044, 0x8010}
 *
 *  The modular additions in a given round are enumerated with the
 *  same index as the index of the word which is computed by using
 *  this modular addition.
 *
 *  Example: The modular addition (word[0] + word[12]) described with
 *  the pair (word[0], word[12]) and used to compute word 4 has index
 *  4:
 *
 *  word[4] = XOR(word[4],ROTATE(PLUS(word[0],word[12]), 7);
 *
 *  So the addition PLUS(word[0],word[12]) has index 4 in the dep
 *  array.
 */
void salsa_gen_word_deps(const uint32_t nrounds, 
								 const uint32_t e[SALSA_STATE + SALSA_STATE][5], 
								 uint32_t D[MAX_NROUNDS][SALSA_STATE])
{  
  assert(nrounds < MAX_NROUNDS);
  // initialize the D array to 0
  for(uint32_t r = 0; r < nrounds; r++) {
	 for(uint32_t i = 0; i < SALSA_STATE; i++) {
		D[r][i] = 0;
	 }
  }
  
  for(uint32_t r = 0; r < nrounds; r++) {
	 for(uint32_t i = 0; i < SALSA_STATE; i++) {
		//		const uint32_t* const f = e[(r & 1) ? (i + SALSA_STATE) : i];		  
		uint32_t j = i;					  // even rounds
		bool is_odd = (r % 2);
		if(is_odd) {
		  j = i + SALSA_STATE;	  // odd rounds
		}
		uint32_t f[5] = {e[j][0], e[j][1], e[j][2], e[j][3], e[j][4]};
		for(uint32_t s = 0; s <= r ; s++) {
		  D[s][f[0]] = D[s][f[1]] | D[s][f[2]] | D[s][f[3]];
		}
		// word f[0] Dends also on the addition which
		// participates in the calculation of f[0]
		D[r][f[0]] |= 1 << f[0];
	 }
  }  
}

/**
 * Given the probabilities for each of the words of the state after
 * every round \p PT computed with \ref xdp_add_dset_salsa20 , and the
 * array of word dependencies \p D computed with \ref salsa_gen_word_deps ,
 * compute the individual probabilities for each of the words of the
 * state after \p nrounds .
 *
 * \attention \p P[0] is the initial input and therefore P[i] is the
 * output from round \f$i - 1\f$.
 */
void salsa_word_probs(const uint32_t nrounds,
							 const uint32_t e[SALSA_STATE + SALSA_STATE][5], 
							 double PT[MAX_NROUNDS][SALSA_STATE],
							 uint32_t D[MAX_NROUNDS][SALSA_STATE],
							 double P[SALSA_STATE])
{
  assert((nrounds + 1) < MAX_NROUNDS);
  for(uint32_t i = 0; i < SALSA_STATE; i++) {
	 P[i] = 1.0;
  }
  for(uint32_t i = 0; i < SALSA_STATE; i++) {
	 //printf("\nword %d after round %d depends on:\n", i, ROUNDS - 1);
	 // counts over dependencies
	 for(uint32_t s = 0; s < nrounds; s++)
		//printf("dep[%d][%d]=0x%08x\n", i, s, dep[i][s]);
		// counts over bits within one dependency word
		// (we use only the 16 lsb bits of each dep word)
		for(uint32_t j = 0; j < SALSA_STATE; j++) {
		  if ((D[s][i] >> j) & 1) {
			 P[i] *= PT[s + 1][j]; 
			 //printf("[%d][%d]=0x%08x (%4.2f) ",s,j,state[s][j],log2(P[s][j]));
			 //printf("  addition %d of round %d %f\n", j, s, final_prob[i]);
		  }
		}
	 //printf("word[%i] final_prob=%8.2f\n", i, final_prob[i]);
  }
}

void salsa_word_probs_v2(const uint32_t r_start, const uint32_t r_end, 
								 const uint32_t e[SALSA_STATE + SALSA_STATE][5], 
								 double PT[MAX_NROUNDS][SALSA_STATE],
								 double P[SALSA_STATE])
{
  assert(r_start <= r_end);
  assert((r_end + 1) < MAX_NROUNDS);

  for(uint32_t i = 0; i < SALSA_STATE; i++) {
	 P[i] = 1.0;
  }

  for(uint32_t r = r_start; r < r_end; r++) {
	 for(uint32_t i = 0; i < SALSA_STATE; i++) {
		uint32_t j = i;					  // even rounds
		bool is_odd = (r % 2);
		if(is_odd) {
		  j = i + SALSA_STATE;	  // odd rounds
		}
		uint32_t f[5] = {e[j][0], e[j][1], e[j][2], e[j][3], e[j][4]};
		uint32_t i_dx = f[2];
		uint32_t i_dy = f[3];
		uint32_t i_dz = f[1];

		P[i] *= PT[r+1][i_dx] * PT[r+1][i_dy] * PT[r+1][i_dz];
	 }
  }
}
