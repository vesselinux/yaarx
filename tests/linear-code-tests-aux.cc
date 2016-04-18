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
 * \file  linear-code-tests-aux.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2015
 * \brief Auxiliary file containing less commonly used code for file linear-code-tests.cc 
 */ 

#if 1 // Primitive 1: L + ADD

WORD_T ltransform_add(gsl_matrix* L, WORD_T L_nrows, WORD_T L_ncols, WORD_T x, WORD_T y)
{
  assert(L_nrows == (2 * WORD_SIZE));
  assert(L_ncols == WORD_SIZE);

  gsl_vector* xy_vec = gsl_vector_calloc(L_nrows);
  gsl_vector* l_vec = gsl_vector_calloc(L_ncols);

  WORD_T xy_hex = (y << (L_nrows / 2)) | y;
  WORD_T l_hex = 0;

  lcode_hex_to_vec(xy_hex, xy_vec, L_nrows);
  lcode_encode(l_vec, xy_vec, L, L_nrows, L_ncols);
  lcode_vec_to_hex(&l_hex, l_vec, L_ncols);

  WORD_T z = ADD(l_hex, y);

  gsl_vector_free(xy_vec);
  gsl_vector_free(l_vec);
  return z;
}

double xdp_ltransform_add_exper(gsl_matrix* L, WORD_T L_nrows, WORD_T L_ncols,
										  WORD_T dx, WORD_T dy, WORD_T dz)
{
  uint32_t cnt = 0;
  for(WORD_T x = 0; x < ALL_WORDS; x++) {
	 for(WORD_T y = 0; y < ALL_WORDS; y++) {
		WORD_T xx = XOR(x, dx);
		WORD_T yy = XOR(y, dy);
		WORD_T z = ltransform_add(L, L_nrows, L_ncols, x, y);
		WORD_T zz = ltransform_add(L, L_nrows, L_ncols, xx, yy);
		WORD_T diff = XOR(z, zz);
		if(diff == dz) {
		  cnt++;
		}
	 }
  }
  double p = (double)cnt / (double)(ALL_WORDS * ALL_WORDS);
  return p;
}

double max_xdp_ltransform_add_exper(gsl_matrix* L, WORD_T L_nrows, WORD_T L_ncols,
												WORD_T dx, WORD_T dy, WORD_T* dz)
{
  double p_max = 0.0;
  WORD_T dz_max = 0;
  for(WORD_T i = 0; i < ALL_WORDS; i++) {
	 double p = xdp_ltransform_add_exper(L, L_nrows, L_ncols, dx, dy, i);
	 if(p > p_max) {
		p_max = p;
		dz_max = i;
	 }
  }
  *dz = dz_max;
  return p_max;
}

void test_max_xdp_add_lin_transform()
{
  uint32_t L_nrows = (2 * WORD_SIZE);
  uint32_t L_ncols = WORD_SIZE;
  gsl_matrix* L = gsl_matrix_calloc(L_nrows, L_ncols);
  gsl_vector* V_in = gsl_vector_calloc(L_nrows);
  gsl_vector* V_out = gsl_vector_calloc(L_ncols);
  uint64_t N = (1ULL << (L_nrows * L_ncols));
  printf("[%s:%d] N = %d X %d N = 2^%4.2f\n", __FILE__, __LINE__, L_nrows, L_ncols, log2(N));

  double log_sum_min = 0.0;
  uint32_t e_min = 0;

  for(uint32_t e = 0; e < N; e++) {
	 gsl_matrix_set_zero(L);
	 printf("\n========= [%s:%d] Matrix L for e %X ========\n", __FILE__, __LINE__, e);
	 uint32_t cnt = 0;
	 for(uint32_t row = 0; row < L_nrows; row++) {
		for(uint32_t col = 0; col < L_ncols; col++) {
		  uint32_t bit = (e >> cnt) & 1;
		  //		  printf("%3d-%d", cnt, bit);
		  gsl_matrix_set(L, row, col, bit);
		  cnt++;
		}
	 }
	 lcode_matrix_print(L, L_nrows, L_ncols);

	 double log_sum = 0.0;
	 for(WORD_T da = 0; da < ALL_WORDS; da++) {
		for(WORD_T db = 0; db < ALL_WORDS; db++) {
		  WORD_T dc = 0;
		  double p_min = max_xdp_add_lm(da, db, &dc);
		  //		  double p_min_inv = max_xdp_and_add_exper(da, db, &dc);//max_xdp_add_lm(da ^ db, db, &dc);
		  //		  double p_min_inv = max_xdp_add_lm(da ^ db, db, &dc);
		  double p_min_inv = max_xdp_ltransform_add_exper(L, L_nrows, L_ncols, da, db, &dc);

		  double p_prod = p_min * p_min_inv;

		  log_sum += log2(p_prod);

		  //		  printf("[%s:%d] max (%X,%X)->%X = 2^%f 2^%f | 2^%f\n", __FILE__, __LINE__, da, db, dc, 
		  //					log2(p_min), log2(p_min_inv), log2(p_prod));
		}
	 }
	 if(log_sum < log_sum_min) {
		log_sum_min = log_sum;
		e_min = e;
		printf("[%s:%d] log_sum_min 2^%f e %X\n", __FILE__, __LINE__, log_sum_min, e_min);
	 }
	 printf("[%s:%d] log_sum 2^%f | min 2^%f e %X\n", __FILE__, __LINE__, log_sum, log_sum_min, e_min);

  }
  gsl_vector_free(V_out);
  gsl_vector_free(V_in);
  gsl_matrix_free(L);
}

#endif // #if 1 // Primitive 1: L + ADD


#if 1 // Primitive 3: ADD + ROT + ADD
/*
 * x = (x_L | x_R) -> y = (x_L + x_R) | ((x_L <<< rot_L) + (x_R <<< rot_R))
 *
 * WARNING! x and y are of size (2 * WORD_SIZE)
 */
WORD_T rot_add_two_block(WORD_T x, WORD_T rot_L, WORD_T rot_R)
{
  WORD_T x_L = (x >> WORD_SIZE) & MASK;
  WORD_T x_R = x & MASK;
  WORD_T y_L = ADD(x_L, x_R);

  WORD_T x_rot_L = LROT(x_L, rot_L);
  WORD_T x_rot_R = LROT(x_R, rot_R);
  //  WORD_T x_rot_L = x_L ^ rot_L;
  //  WORD_T x_rot_R = x_R ^ rot_R; 
  WORD_T y_R = ADD(x_rot_L, x_rot_R);

  WORD_T y = (y_L << WORD_SIZE) | y_R;

#if 1 // DEBUG
  assert(x_L <= MASK);
  assert(x_R <= MASK);
  assert(y_L <= MASK);
  assert(y_R <= MASK);
  assert(x_rot_L <= MASK);
  assert(x_rot_R <= MASK);

  WORD_T double_mask = (0xffffffffUL >> (32 - (2*WORD_SIZE)));
  if(!(y <= double_mask)) {
	 printf("[%s:%d] y > MASK %X > %llX\n", __FILE__, __LINE__, y, (WORD_MAX_T)double_mask);
  }
  assert(y <= double_mask);
#endif // #if 1 // DEBUG
  return y;
}

double xdp_rot_add_two_block_exper(WORD_T dx, WORD_T dy, WORD_T rot_L, WORD_T rot_R)
{
  WORD_T double_mask = (0xffffffffUL >> (32 - (2*WORD_SIZE)));
  uint32_t cnt = 0;
  for(WORD_T x = 0; x < (ALL_WORDS * ALL_WORDS); x++) { // x is of size (2 * WORD_SIZE)
	 WORD_T xx = (x ^ dx) & double_mask;
	 WORD_T y = rot_add_two_block(x, rot_L, rot_R);
	 WORD_T yy = rot_add_two_block(xx, rot_L, rot_R);
	 WORD_T diff = (y ^ yy) & double_mask;
	 if(diff == dy) {
		cnt++;
	 }
  }
  double p = (double)cnt / (double)(ALL_WORDS * ALL_WORDS);
  return p;
}

double max_xdp_rot_add_two_block_exper(WORD_T dx, WORD_T* dy_max, WORD_T rot_L, WORD_T rot_R)
{
  double p_max = 0.0;
  for(WORD_T dy = 0; dy < (ALL_WORDS * ALL_WORDS); dy++) { // dy is of size (2 * WORD_SIZE)
	 double p = xdp_rot_add_two_block_exper(dx, dy, rot_L, rot_R);
	 if(p > p_max) {
		p_max = p;
		*dy_max = dy;
	 }
  }
  return p_max;
}

void test_max_xdp_rot_add_two_block()
{
  //  WORD_T double_mask = (0xffffffffUL >> (32 - (2*WORD_SIZE)));
  WORD_T rot_L = 0;//1;//2 % WORD_SIZE;
  WORD_T rot_R = 3;// % WORD_SIZE;
  //  double p_log2_sum_max = 0.0;
  for(WORD_T da = 0; da < (ALL_WORDS * ALL_WORDS); da++) {
	 WORD_T db = 0;
	 double p_max = max_xdp_rot_add_two_block_exper(da, &db, rot_L, rot_R);
	 if((p_max >= 0.5) || (db == 0)) {
		printf("[%s:%d] max %X->%X = 2^%f\n", __FILE__, __LINE__, da, db, log2(p_max));
	 }
#if 0 // Estimate the probability
	 WORD_T da_L = (da >> (WORD_SIZE / 2)) & half_mask;
	 WORD_T da_R = x & half_mask;
	 double p_max_L = max_xdp_add_lm(da_L, da_R, &dc);
	 double p_max_R = max_xdp_rot_add_exper(da_L, da_R, &dc);
	 double p_max_est = p_max_L * p_max_R;
	 printf("[%s:%d] max %X->%X = 2^%f 2^%f\n", __FILE__, __LINE__, da, db, log2(p_max), log2(p_max_est));
#endif // #if 1
  }
}

#endif

#if 1 // Primitive 2: ROT + ADD
WORD_T rot_add(WORD_T x, WORD_T y)
{
#if 0
  WORD_T r = 1 % WORD_SIZE;
  WORD_T s = 3 % WORD_SIZE;
  WORD_T x_xor = LROT(x, r);
  WORD_T y_xor = LROT(y, s);
#endif
  WORD_T x_xor = x;// & (~0U & MASK);
  WORD_T y_xor = y;
  WORD_T z = ADD(x_xor, y_xor);
  return z;
}

double xdp_rot_add_exper(WORD_T dx, WORD_T dy, WORD_T dz)
{
  uint32_t cnt = 0;
  for(WORD_T x = 0; x < ALL_WORDS; x++) {
	 for(WORD_T y = 0; y < ALL_WORDS; y++) {
		WORD_T xx = XOR(x, dx);
		WORD_T yy = XOR(y, dy);
		WORD_T z = rot_add(x, y);
		WORD_T zz = rot_add(xx, yy);
		WORD_T diff = XOR(z, zz);
		if(diff == dz) {
		  cnt++;
		}
	 }
  }
  double p = (double)cnt / (double)(ALL_WORDS * ALL_WORDS);
  return p;
}

double max_xdp_rot_add_exper(WORD_T dx, WORD_T dy, WORD_T* dz)
{
  double p_max = 0.0;
  WORD_T dz_max = 0;
  for(WORD_T i = 0; i < ALL_WORDS; i++) {
	 double p = xdp_rot_add_exper(dx, dy, i);
	 if(p > p_max) {
		p_max = p;
		dz_max = i;
	 }
  }
  *dz = dz_max;
  return p_max;
}

void test_max_xdp_add()
{
  double log_sum = 0.0;
  for(WORD_T da = 0; da < ALL_WORDS; da++) {
	 for(WORD_T db = 0; db < ALL_WORDS; db++) {
		uint32_t dc = 0;
		//		double p_max = max_xdp_add_lm(da, db, &dc);
		double p_max = max_xdp_rot_add_exper(da, db, &dc);

		//		double p_prod = p_max * p_max_rot_add;

		log_sum += log2(p_max);

		printf("[%s:%d] max (%X,%X)->%X = 2^%f\n", __FILE__, __LINE__, da, db, dc, log2(p_max));
	 }
  }
  printf("[%s:%d] log_sum 2^%f\n", __FILE__, __LINE__, log_sum);
}

#endif // #if 1 // Primitive 2: ROT + ADD

#if 1 // Primitive 4: single input
WORD_T add_single(WORD_T x, WORD_T r)
{
  WORD_T x_xor = LROT(x, r);
  WORD_T y = ADD(x_xor, x);
  //  printf("[%s:%d] %X \n", __FILE__, __LINE__, y);
  return y;
}

double xdp_add_single_exper(WORD_T dx, WORD_T dy, WORD_T r)
{
  uint32_t cnt = 0;
  for(WORD_T x = 0; x < ALL_WORDS; x++) {
	 WORD_T xx = XOR(x, dx);
	 WORD_T y = add_single(x, r);
	 WORD_T yy = add_single(xx, r);
	 WORD_T diff = XOR(y, yy);
	 if(diff == dy) {
		cnt++;
	 }
  }
  double p = (double)cnt / (double)(ALL_WORDS);
  return p;
}

double max_xdp_add_single_exper(WORD_T dx, WORD_T *dy, WORD_T r)
{
  double p_max = 0.0;
  WORD_T dy_max = 0;
  for(WORD_T i = 0; i < ALL_WORDS; i++) {
	 double p = xdp_add_single_exper(dx, i, r);
	 if(p > p_max) {
		p_max = p;
		dy_max = i;
	 }
  }
  *dy = dy_max;
  return p_max;
}

void test_max_xdp_add_single()
{
  WORD_T r = xrandom() % WORD_SIZE;
  for(WORD_T i = 0; i < 1; i++) {
	 uint32_t nzero = 0;
	 double p_max_glob = 0.0;
	 //	 r = i;
	 //	 printf("[%s:%d] ======== r %2d =======\n", __FILE__, __LINE__, r);
	 for(WORD_T da = 1; da < ALL_WORDS; da++) {
		uint32_t db = 0;
		double p_max = max_xdp_add_single_exper(da, &db, r);
		printf("[%s:%d] r %X max %X->%X = 2^%f\n", __FILE__, __LINE__, r, da, db, log2(p_max));
		if(db == 0) {
		  nzero++;
		}
		if(p_max > p_max_glob) {
		  p_max_glob = p_max;
		}
	 }
	 printf("[%s:%d] r %d | nzero %d p_max 2^%f\n", __FILE__, __LINE__, r, nzero, log2(p_max_glob));
  }
}

#endif // #if 1 // Primitive 4: single input


// --- TESTS ---

void test_lcode_codewords()
{
  uint32_t message_len = (WORD_SIZE / 2);
  gsl_matrix* G = gsl_matrix_calloc(LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);
  std::vector<WORD_T> C_L;
  std::vector<WORD_T> C_R;

  lcode_matrix_init(g_G, G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);

  printf("[%s:%d] Code L\n", __FILE__, __LINE__);
  lcode_matrix_print(G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);
  lcode_codewords(&C_L, G, message_len);

  printf("[%s:%d] Code R\n", __FILE__, __LINE__);
  lcode_matrix_print(G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);
  lcode_codewords(&C_R, G, message_len);

  assert(C_L.size() == C_R.size());

  for(uint32_t i = 0; i < C_L.size(); i++) {
	 WORD_T message_hex = i;
	 WORD_T codeword_hex_L = C_L[i];
	 WORD_T codeword_hex_R = C_R[i];
	 printf("%4X %4X ", message_hex, codeword_hex_L);
	 print_binary(message_hex, message_len);
	 printf(" ");
	 print_binary(codeword_hex_L);
	 printf(" ");
	 print_binary(codeword_hex_R);
	 printf("\n");
  }
#if 0
  lcode_codewords_diffs(C_L);
#endif
#if 0 // print combinations of codewords from the two codes
  uint32_t cnt = 0;
  for(uint32_t i = 0; i < C_L.size(); i++) {
	 for(uint32_t j = 0; j < C_R.size(); j++) {

		WORD_T da = C_L[i];
		WORD_T db = C_L[j];
		WORD_T dc = 0;

		//		if(da == db)
		//		  continue;

		cnt++;

		double p_max = max_xdp_add_lm(da, db, &dc);

		/*
		 * Indicates positions where the two words differ
		 */
		WORD_T diff = (~((C_L[i] & C_R[j]) | (~C_L[i] & ~C_R[j]))) & MASK;
		uint32_t hw = hamming_weight(diff);
		printf("%3d %4X ",  cnt, diff);
		print_binary(C_L[i]);
		printf(" ");
		print_binary(C_R[j]);
		printf(" ");
		print_binary(diff);
		printf(" %3d | max 2^%f\n", hw, log2(p_max));
		assert((hw >= LCODE_MIN_DIST_D) || (diff == 0));
	 }
  }
#endif
  gsl_matrix_free(G);
}

void test_lcode_add_dp_all()
{
#if 1 // collapse
  gsl_matrix* G = gsl_matrix_calloc(LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);

  lcode_matrix_init(g_G, G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);

  lcode_matrix_print(G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);

  double p_max = 0.0;
  double p_ind_max = 0.0;
  for(WORD_T i = 0; i < ALL_WORDS; i++) {
	 if(i == 0) // skip the zero difference
		continue;
	 WORD_T half_mask = (MASK >> (WORD_SIZE / 2));
	 WORD_T x_L = (i >> (WORD_SIZE / 2)) & half_mask;
	 WORD_T x_R = i & half_mask;
	 if(x_L == x_R) { // skip inputs diffs with same halves
		continue;
	 }
	 for(WORD_T j = 0; j < ALL_WORDS; j++) {
		WORD_T da = i;
		WORD_T db = j;
		double p = lcode_add_dp_exper(da, db);
#if 1 // compute probability as independent inputs
		gsl_vector* message_vec_L = gsl_vector_calloc(LCODE_MESSAGE_LEN_K);
		gsl_vector* message_vec_R = gsl_vector_calloc(LCODE_MESSAGE_LEN_K);
		gsl_vector* codeword_vec_L = gsl_vector_calloc(LCODE_CODEWORD_LEN_N);
		gsl_vector* codeword_vec_R = gsl_vector_calloc(LCODE_CODEWORD_LEN_N);
		WORD_T da_L = (da >> (WORD_SIZE / 2)) & half_mask;
		WORD_T da_R = da & half_mask;

		WORD_T code_da_L = 0;
		WORD_T code_da_R = 0;

		lcode_hex_to_vec(da_L, message_vec_L, LCODE_MESSAGE_LEN_K);
		lcode_hex_to_vec(da_R, message_vec_R, LCODE_MESSAGE_LEN_K);

		lcode_encode(codeword_vec_L, message_vec_L, G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);
		lcode_encode(codeword_vec_R, message_vec_R, G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);

		//	 lcode_vector_print(codeword_vec_L, LCODE_MESSAGE_LEN_K);
		lcode_vec_to_hex(&code_da_L, codeword_vec_L, LCODE_CODEWORD_LEN_N);
		lcode_vec_to_hex(&code_da_R, codeword_vec_R, LCODE_CODEWORD_LEN_N);

		/*
		 * Number of differing bit positions
		 */
		//		WORD_T diff = (~((code_da_L & code_da_R) | (~code_da_L & ~code_da_R))) & MASK;
		//		uint32_t ndiff_bits = hamming_weight(diff);

		double p_ind = xdp_add_lm(code_da_L, code_da_R, db);
		if(p > p_max) {
		  p_max = p;
		  //		  printf("[%s:%d] %X -> %X 2^%f (%f) | p_ind 2^%f p_ind_max 2^%f <- update p_max\n", __FILE__, __LINE__, 
		  //					da, db, log2(p_max), p_max, log2(p_ind), log2(p_ind_max));
		}
		if(p_ind > p_ind_max) {
		  p_ind_max = p_ind;
		  //		  printf("[%s:%d] %X -> %X 2^%f (%f) | p_ind 2^%f p_ind_max 2^%f <- update p_ind_max\n", __FILE__, __LINE__, 
		  //					da, db, log2(p_max), p_max, log2(p_ind), log2(p_ind_max));
		}
		if(p != p_ind) {
		  //		  printf("[%s:%d] %X %X -> %X 2^%f != 2^%f \n", __FILE__, __LINE__, 
		  //					code_da_L, code_da_R, db, log2(p), log2(p_ind));
		}
		printf("[%s:%d] %X -> %X | (%X %X -> %X) %f %f \n", __FILE__, __LINE__, 
				 da, db, code_da_L, code_da_R, db, log2(p), log2(p_ind));
		//		assert(ndiff_bits >= LCODE_MIN_DIST_D);
		gsl_vector_free(codeword_vec_L);
		gsl_vector_free(codeword_vec_R);
		gsl_vector_free(message_vec_L);
		gsl_vector_free(message_vec_R);
#endif 
	 }
  }
  printf("[%s:%d] p_max 2^%f p_ind_max 2^%f\n", __FILE__, __LINE__, log2(p_max), log2(p_ind_max));
  gsl_matrix_free(G);
#endif // #if 1 // collapse
}

void test_lcode_add_dp_all_matrices()
{
#if 1 // collapse
  double p_min = 1.0;
  uint32_t e_min = 0;

  uint32_t N = (1UL << (LCODE_GEN_MATRIX_NROWS * (LCODE_GEN_MATRIX_NCOLS / 2)));
  for(uint32_t t = 0; t < N; t++) {
	 uint32_t e = t;
#if 1
	 printf("[%s:%d] Matrix G for e %X\n", __FILE__, __LINE__, e);
	 uint32_t cnt = 0;
	 for(uint32_t row = 0; row < LCODE_GEN_MATRIX_NROWS; row++) {
		for(uint32_t col = (LCODE_GEN_MATRIX_NCOLS / 2); col < LCODE_GEN_MATRIX_NCOLS; col++) {
		  g_G[row][col] = (e >> cnt) & 1;
		  cnt++;
		}
	 }
	 //	 assert(cnt == 18);
#endif // #if 0
	 for(uint32_t row = 0; row < LCODE_GEN_MATRIX_NROWS; row++) {
		for(uint32_t col = 0; col < LCODE_GEN_MATRIX_NCOLS; col++) {
		  printf("%d,", g_G[row][col]);
		}
		printf("\n");
	 }

	 double p_max = 0.0;
	 for(WORD_T i = 0; i < ALL_WORDS; i++) {
		if(i == 0) // skip the zero difference
		  continue;
		WORD_T half_mask = (MASK >> (WORD_SIZE / 2));
		WORD_T x_L = (i >> (WORD_SIZE / 2)) & half_mask;
		WORD_T x_R = i & half_mask;
		if(x_L == x_R) { // skip inputs diffs with same halves
		  continue;
		}
		for(WORD_T j = 0; j < ALL_WORDS; j++) {
		  WORD_T da = i;
		  WORD_T db = j;
		  double p = lcode_add_dp_exper(da, db);
		  if(p > p_max) {
			 p_max = p;
			 printf("[%s:%d] %X -> %X 2^%f (%f) | Global min 2^%f for e_min %X\n", __FILE__, __LINE__, da, db, log2(p_max), p_max, log2(p_min), e_min);
		  }
		}
	 }

#if 1 // random matrix G
	 if(p_max < p_min) {
		p_min = p_max;
		e_min = e;
	 }
#endif // #if 0 // random matrix G

#if 0 // random matrix G
	 printf("[%s:%d] Random matrix G\n", __FILE__, __LINE__);
	 for(uint32_t row = 0; row < LCODE_GEN_MATRIX_NROWS; row++) {
		for(uint32_t col = 0; col < LCODE_GEN_MATRIX_NCOLS; col++) {
		  printf("%d,", g_G[row][col]);
		}
		printf("\n");
	 }
#endif
  }
#endif // #if 1 // collapse
}

void test_lcode_add_dp_rand()
{
#if 1 // collapse
  uint32_t N = (1UL << 20);
  double p_max = 0.0;

  gsl_matrix* G = gsl_matrix_calloc(LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);

  lcode_matrix_init(g_G, G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);

  lcode_matrix_print(G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);

  for(uint32_t t = 0; t < N; t++) {


	 gsl_vector* message_vec_L = gsl_vector_calloc(LCODE_MESSAGE_LEN_K);
	 gsl_vector* message_vec_R = gsl_vector_calloc(LCODE_MESSAGE_LEN_K);
	 gsl_vector* codeword_vec_L = gsl_vector_calloc(LCODE_CODEWORD_LEN_N);
	 gsl_vector* codeword_vec_R = gsl_vector_calloc(LCODE_CODEWORD_LEN_N);

	 //	 WORD_T i = xrandom() & MASK;
	 //	 WORD_T j = xrandom() & MASK;
	 uint32_t hw_lim = 8;
	 WORD_T i = gen_sparse(hw_lim, WORD_SIZE) & MASK;
	 WORD_T j = gen_sparse(hw_lim, WORD_SIZE) & MASK;

	 if(i == 0) // skip the zero difference
		continue;
	 WORD_T half_mask = (MASK >> (WORD_SIZE / 2));
	 WORD_T x_L = (i >> (WORD_SIZE / 2)) & half_mask;
	 WORD_T x_R = i & half_mask;
	 if(x_L == x_R) { // skip inputs diffs with same halves
		continue;
	 }
	 WORD_T da = i;
	 WORD_T db = j;
	 double p = lcode_add_dp_exper(da, db);
	 if(p > p_max) {
		p_max = p;
		printf("[%s:%d] %X -> %X 2^%f (%f)\n", __FILE__, __LINE__, da, db, log2(p_max), p_max);
	 }

#if 1 // compute probability as independent inputs
	 WORD_T da_L = (da >> (WORD_SIZE / 2)) & half_mask;
	 WORD_T da_R = da & half_mask;

	 WORD_T code_da_L = 0;
	 WORD_T code_da_R = 0;
	 WORD_T dc = 0;

	 lcode_hex_to_vec(da_L, message_vec_L, LCODE_MESSAGE_LEN_K);
	 lcode_hex_to_vec(da_R, message_vec_R, LCODE_MESSAGE_LEN_K);

	 lcode_encode(codeword_vec_L, message_vec_L, G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);
	 lcode_encode(codeword_vec_R, message_vec_R, G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);

	 //	 lcode_vector_print(codeword_vec_L, LCODE_MESSAGE_LEN_K);
	 lcode_vec_to_hex(&code_da_L, codeword_vec_L, LCODE_CODEWORD_LEN_N);
	 lcode_vec_to_hex(&code_da_R, codeword_vec_R, LCODE_CODEWORD_LEN_N);

	 /*
	  * Number of differing bit positions
	  */
	 WORD_T diff = (~((code_da_L & code_da_R) | (~code_da_L & ~code_da_R))) & MASK;
	 uint32_t ndiff_bits = hamming_weight(diff);
	 uint32_t ndiff_bits_no_msb = hamming_weight(diff & ~(1UL << (WORD_SIZE - 1))); // don't count the MSB
	 //	 uint32_t ndiff_bits_no_msb = hamming_weight(diff); // don't count the MSB

	 double p_ind_max_expected_log2 = -(double)(ndiff_bits_no_msb);
	 double p_ind_max = max_xdp_add_lm(code_da_L, code_da_R, &dc);
	 if(p_ind_max_expected_log2 < log2(p_ind_max)) {
		//		printf("[%s:%d] %X %X %X %X\n", __FILE__, __LINE__, da_L, da_R, code_da_L, code_da_R);
		printf("[%s:%d] %f %f\n", __FILE__, __LINE__, p_ind_max_expected_log2, log2(p_ind_max));
	 }
    assert(p_ind_max_expected_log2 >= log2(p_ind_max)); // the expected probability is a bound!
    if(ndiff_bits < LCODE_MIN_DIST_D) {
		printf("[%s:%d] min dist %d %d\n", __FILE__, __LINE__, ndiff_bits, LCODE_MIN_DIST_D);
    }
	 assert(ndiff_bits >= LCODE_MIN_DIST_D);
#endif 

	 gsl_vector_free(codeword_vec_L);
	 gsl_vector_free(codeword_vec_R);
	 gsl_vector_free(message_vec_L);
	 gsl_vector_free(message_vec_R);

  }

  gsl_matrix_free(G);
#endif // #if 1 // collapse
}

void test_lcode_add_dp()
{
#if 1 // collapse
  gsl_matrix* G = gsl_matrix_calloc(LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);
  gsl_vector* message_vec_L = gsl_vector_calloc(LCODE_MESSAGE_LEN_K);
  gsl_vector* message_vec_R = gsl_vector_calloc(LCODE_MESSAGE_LEN_K);
  gsl_vector* codeword_vec_L = gsl_vector_calloc(LCODE_CODEWORD_LEN_N);
  gsl_vector* codeword_vec_R = gsl_vector_calloc(LCODE_CODEWORD_LEN_N);

  lcode_matrix_init(g_G, G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);

  lcode_matrix_print(G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);

  //  WORD_T da = xrandom() & MASK; 
  //  WORD_T db = xrandom() & MASK;
  WORD_T da = 1;
  WORD_T db = 5;//3; //5;
  double p = lcode_add_dp_exper(da, db);

#if 1 // compute probability as independent inputs
  WORD_T half_mask = (MASK >> (WORD_SIZE / 2));
  WORD_T da_L = (da >> (WORD_SIZE / 2)) & half_mask;
  WORD_T da_R = da & half_mask;

  WORD_T code_da_L = 0;
  WORD_T code_da_R = 0;

  lcode_hex_to_vec(da_L, message_vec_L, LCODE_MESSAGE_LEN_K);
  lcode_hex_to_vec(da_R, message_vec_R, LCODE_MESSAGE_LEN_K);

  lcode_encode(codeword_vec_L, message_vec_L, G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);
  lcode_encode(codeword_vec_R, message_vec_R, G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);

  lcode_vec_to_hex(&code_da_L, codeword_vec_L, LCODE_CODEWORD_LEN_N);
  lcode_vec_to_hex(&code_da_R, codeword_vec_R, LCODE_CODEWORD_LEN_N);

  double p_ind = xdp_add_lm(code_da_L, code_da_R, db);
  printf("[%s:%d] %X -> %X | (%X %X -> %X) %f %f \n", __FILE__, __LINE__, 
			da, db, code_da_L, code_da_R, db, log2(p), log2(p_ind));
#endif 

  printf("[%s:%d] %X -> %X 2^%f 2^%f\n", __FILE__, __LINE__, da, db, log2(p), log2(p_ind));

  gsl_vector_free(codeword_vec_L);
  gsl_vector_free(codeword_vec_R);
  gsl_vector_free(message_vec_L);
  gsl_vector_free(message_vec_R);
  gsl_matrix_free(G);
#endif // #if 1 // collapse
}


/*
[./tests/linear-code-tests.cc:276] i x_L x_R 42 2 2
[./tests/linear-code-tests.cc:324] y yy dy odiff 154 3AD 2F9 0
[./tests/linear-code-tests.cc:327] i x_L x_R dx 42 AA AA 0
linear-code-tests: ./tests/linear-code-tests.cc:331: double lcode_add_dp_exper(uint32_t, uint32_t): Assertion `dist_x >= 4' failed.
Aborted (core dumped)
*/
void test_lcode()
{
#if 1 // collapse
  gsl_matrix* G = gsl_matrix_calloc(LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);
  gsl_vector* message_vec = gsl_vector_calloc(LCODE_MESSAGE_LEN_K);
  gsl_vector* codeword_vec = gsl_vector_calloc(LCODE_CODEWORD_LEN_N);

  WORD_T message_hex = 1;//0x2;//xrandom() & 0xFF;
  WORD_T codeword_hex = 0;

  lcode_matrix_init(g_G, G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);

  lcode_matrix_print(G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);

  lcode_hex_to_vec(message_hex, message_vec, LCODE_MESSAGE_LEN_K);

  lcode_encode(codeword_vec, message_vec, G, LCODE_GEN_MATRIX_NROWS, LCODE_GEN_MATRIX_NCOLS);

  lcode_vec_to_hex(&codeword_hex, codeword_vec, LCODE_CODEWORD_LEN_N);

  printf("[%s:%d] Message_Hex: %X ", __FILE__, __LINE__, message_hex);
  print_binary(message_hex, (WORD_SIZE / 2));
  printf("\n");
  printf("[%s:%d] Message_Vec: ", __FILE__, __LINE__);
  lcode_vector_print(message_vec, LCODE_MESSAGE_LEN_K);

  printf("[%s:%d] Codeword_Hex: %X ", __FILE__, __LINE__, codeword_hex);
  print_binary(codeword_hex);
  printf("\n");
  printf("[%s:%d] Codeword_Vec: ", __FILE__, __LINE__);
  lcode_vector_print(codeword_vec, LCODE_CODEWORD_LEN_N);

  gsl_vector_free(codeword_vec);
  gsl_vector_free(message_vec);
  gsl_matrix_free(G);
#endif // #if 1 // collapse
}

void test_max_prob()
{
#if 1 // collapse
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);
  for(WORD_T da = 0; da < ALL_WORDS; da++) {
	 for(WORD_T db = 0; db < ALL_WORDS; db++) {
		WORD_T dc = 0;
		WORD_T dc1 = 0;
		double p_max = max_xdp_add_lm(da, db, &dc);
		double p_max_inv = max_xdp_rot_add_exper(da, db, &dc1);
		//		double p_max_inv_1 = max_xdp_xor_add_exper(A, da, db, &dc1);
		//		double p_max = max_xdp_add(A, da, db, &dc);
		//		double p_max_inv_2 = max_xdp_add_exper(A, da, db, &dc2);
		if(p_max != p_max_inv) {
		  printf("[%s:%d] %f %f\n", __FILE__, __LINE__, p_max, p_max_inv);
		}
		//		assert(p_max == p_max_inv);
	 }
  }
  xdp_add_free_matrices(A);
#endif // #if 1 // collapse
}

