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
 * \file  adp-rsh-xor.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief The ADD differential probability of right shift followed by XOR: \f$\mathrm{adp}^{\gg\oplus}\f$.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR_H
#include "adp-xor.hh"
#endif
#ifndef ADP_SHIFT_H
#include "adp-shift.hh"
#endif
#ifndef ADP_RSH_XOR_H
#include "adp-rsh-xor.hh"
#endif

/**
 * The sequence of operations right shift (RSH) followed by an XOR (RSH-XOR).
 * 
 * \param a input to XOR.
 * \param x input to RSH.
 * \param r shift constant.
 * \returns \f$ b = a \oplus (x \gg r) \f$.
 */
uint32_t rsh_xor(uint32_t a, uint32_t x, int r)
{
  uint32_t b = a ^ RSH(x, r);
  return b;
}

/** 
 * The ADD differential probability of RSH-XOR computed
 * experimentally over all inputs. Complexity: \f$O(2^{2n})\f$.
 *
 * \param da input difference.
 * \param dx input difference.
 * \param db output difference.
 * \param r shift constant.
 * \returns \f$\mathrm{adp}^{\gg\oplus}(r | da, dx \rightarrow db)\f$.
 * \see adp_rsh_xor
 */ 
double adp_rsh_xor_exper(const uint32_t da, const uint32_t dx, const uint32_t db, const int r)
{
  uint32_t N = ALL_WORDS * ALL_WORDS;
  uint32_t cnt = 0;

  for(uint32_t a1 = 0; a1 < ALL_WORDS; a1++) {
	 for(uint32_t x1 = 0; x1 < ALL_WORDS; x1++) {
		uint32_t a2 = ADD(a1, da);
		uint32_t x2 = ADD(x1, dx);

		uint32_t b1 = rsh_xor(a1, x1, r);
		uint32_t b2 = rsh_xor(a2, x2, r);

		uint32_t b_sub = SUB(b2, b1);
		if(b_sub == db) {
		  cnt++;
		}
	 }
  }
  double p = (double)cnt / (double)N;
  return p;
}

/**
 * Allocate memory for the transition probability matrices for \f$\mathrm{adp}^{\gg\oplus}\f$.
 * \param A transition probability matrices for \f$\mathrm{adp}^{\gg\oplus}\f$.
 * \see adp_rsh_xor_free_matrices
 */
void adp_rsh_xor_alloc_matrices(gsl_matrix* A[3][2][2][2])
{
  for(uint32_t pos = 0; pos < ADP_RSH_XOR_NPOS; pos++) {
	 for(int i = 0; i < (1 << (ADP_RSH_XOR_NINPUTS + ADP_RSH_XOR_NOUTPUTS)); i++){
		int a = (i >> 0) & 1;
		int x = (i >> 1) & 1;
		int b = (i >> 2) & 1;
		A[pos][a][x][b] = gsl_matrix_calloc(ADP_RSH_XOR_MSIZE, ADP_RSH_XOR_MSIZE);
	 }
  }
}


/**
 * Free memory reserved for the transition probability matrices for \f$\mathrm{adp}^{\gg\oplus}\f$.
 * \param A transition probability matrices for \f$\mathrm{adp}^{\gg\oplus}\f$.
 * \see adp_rsh_xor_alloc_matrices
 */
void adp_rsh_xor_free_matrices(gsl_matrix* A[3][2][2][2])
{
	 for(uint32_t pos = 0; pos < ADP_RSH_XOR_NPOS; pos++) {
		for(int i = 0; i < (1 << (ADP_RSH_XOR_NINPUTS + ADP_RSH_XOR_NOUTPUTS)); i++){
		  int a = (i >> 0) & 1;
		  int x = (i >> 1) & 1;
		  int b = (i >> 2) & 1;
		  gsl_matrix_free(A[pos][a][x][b]);
		}
	 }
}

/**
 * Transform the elements of A into probabilities.
 * \param A transition probability matrices for \f$\mathrm{adp}^{\gg\oplus}\f$.
 */
void adp_rsh_xor_normalize_matrices(gsl_matrix* A[3][2][2][2])
{
  for(uint32_t bit_pos = 0; bit_pos < ADP_RSH_XOR_NPOS; bit_pos++) {
	 for(int i = 0; i < (1 << (ADP_RSH_XOR_NINPUTS + ADP_RSH_XOR_NOUTPUTS)); i++){
		int a = (i >> 0) & 1;
		int b = (i >> 1) & 1;
		int c = (i >> 2) & 1;

		for(int row = 0; row < ADP_RSH_XOR_MSIZE; row++){
		  for(int col = 0; col < ADP_RSH_XOR_MSIZE; col++){
			 double e = gsl_matrix_get(A[bit_pos][a][b][c], row, col);
			 gsl_matrix_set(A[bit_pos][a][b][c], row, col, ADP_RSH_XOR_NORM * e);
		  }
		}
		// check
#if 1
		for(int col = 0; col < ADP_RSH_XOR_MSIZE; col++){
		  uint32_t col_sum = 0;
		  for(int row = 0; row < ADP_RSH_XOR_MSIZE; row++){
			 uint32_t e = gsl_matrix_get(A[bit_pos][a][b][c], row, col);
			 col_sum += e;
		  }
		  assert((col_sum == 0.0) || (col_sum == 1.0));
		}
#endif
	 }
  }
}

/**
 * Print the elements of A.
 * \param A transition probability matrices for \f$\mathrm{adp}^{\gg\oplus}\f$.
 */
void adp_rsh_xor_print_matrices(gsl_matrix* A[3][2][2][2])
{
  for(uint32_t bit_pos = 0; bit_pos < ADP_RSH_XOR_NPOS; bit_pos++) {
	 for(int i = 0; i < (1 << (ADP_RSH_XOR_NINPUTS + ADP_RSH_XOR_NOUTPUTS)); i++){
		int a = (i >> 0) & 1;
		int b = (i >> 1) & 1;
		int c = (i >> 2) & 1;
		printf("A%d%d%d%d \n", bit_pos, c, b, a);
		for(int row = 0; row < ADP_RSH_XOR_MSIZE; row++){
		  for(int col = 0; col < ADP_RSH_XOR_MSIZE; col++){
			 double e = gsl_matrix_get(A[bit_pos][a][b][c], row, col);
			 printf("%4.3f, ", e);
		  }
		  printf("\n");
		}
		printf("\n");
		// check
#if 0
		for(int col = 0; col < ADP_RSH_XOR_MSIZE; col++){
		  uint32_t col_sum = 0;
		  for(int row = 0; row < ADP_RSH_XOR_MSIZE; row++){
			 uint32_t e = gsl_matrix_get(A[bit_pos][a][b][c], row, col);
			 col_sum += e;
		  }
		  printf("col_sum = %2d\n", col_sum);
		}
#endif
	 }
  }
}

/** 
 * S-function for the operation \f$({\gg\oplus})\f$ (RSH-XOR).
 * 
 * \param A zero-initialized set of matrices.
 * \returns Transition probability matrices A for \f$\mathrm{adp}^{\gg\oplus}\f$.
 *
 * \f$A[3][2][2][2] = A[j][da[i]][dx[i+r]][db[i]]\f$, where \f$da[i]\f$
 * denotes the i-th bit of \f$da\f$, \f$n\f$ is the word size, \f$r\f$
 * is the shift constant, \f$i\f$ is the bit position and \f$j\f$ is a
 * special bit position with three possible values:
 * 
 *   - \f$ j = 0 : 0 \le i < n - r\f$.
 *   - \f$ j = 1 : n - r < i < n\f$.
 *   - \f$ j = 2 : i = n - r\f$.
 */
void adp_rsh_xor_sf(gsl_matrix* A[3][2][2][2])
{
  uint32_t N = (1L << ADP_RSH_XOR_NINPUTS);

  for(uint32_t bit_pos = 0; bit_pos < ADP_RSH_XOR_NPOS; bit_pos++) { // 0,1,2

	 for(uint32_t i = 0; i < N; i++) {
		uint32_t da = (i >> 0) & 1;
		uint32_t dx = (i >> 1) & 1;
#if 0									  // DEBUG
		printf("%d%d%d\n", db, dx, da);
#endif
		for(int32_t u = 0; u < ADP_RSH_XOR_MSIZE; u++) {
		  int32_t t = u;
		  int32_t s1_in = t & 1;
		  t /= 2;
		  int32_t s2_in = t & 1;
		  t /= 2;
		  int32_t s3_in = (t & 1) - 1;
		  t /= 2;
#if 0									  // DEBUG
		  printf("[%2d] %2d%2d%2d \n", u, s3_in, s2_in, s1_in);
#endif

		  if(bit_pos == 2) {	  // i + r = n = 0 (mod n)
			 s2_in = 0;
		  }

		  for(uint32_t j = 0; j < N; j++) {
			 uint32_t a1 = (j >> 0) & 1;
			 uint32_t x1 = (j >> 1) & 1;

			 uint32_t a2 = a1 ^ da ^ s1_in;
			 uint32_t x2 = x1 ^ dx ^ s2_in;

			 uint32_t s1_out = (a1 + da + s1_in) >> 1;
			 uint32_t s2_out = (x1 + dx + s2_in) >> 1;

			 if(bit_pos == 0) {	  // normal
				;
			 }

			 if((bit_pos == 1) || (bit_pos == 2)) {	  // n - r <= i < n
				x1 = 0;
				x2 = 0;
			 }

			 uint32_t b1 = a1 ^ x1;
			 uint32_t b2 = a2 ^ x2;

			 uint32_t db = (b2 - b1 + s3_in) & 1;
			 int32_t s3_out = (int32_t)(b2 - b1 + s3_in) >> 1; // signed shift i.e. -1 >> 1 == -1
#if 1																			// DEBUG
			 assert((db == 0) || (db == 1));
			 assert((b2 - b1 + s3_in) == ((s3_out * 2) + db));
#endif

			 // checks
#if 1																			// DEBUG
			 assert((s1_out == 0) || (s1_out == 1));
			 assert((s2_out == 0) || (s2_out == 1));
			 assert((s3_out == 0) || (s3_out == -1));
#endif

			 uint32_t v = 0;

			 // compose the output state
			 v = s3_out + 1;
			 v *= 2;
			 v += s2_out;
			 v *= 2;
			 v += s1_out;

			 uint32_t col = u;
			 uint32_t row = v;
			 uint32_t e = gsl_matrix_get(A[bit_pos][da][dx][db], row, col);
			 e = e + 1;
			 gsl_matrix_set(A[bit_pos][da][dx][db], row, col, e);

		  }
		}
	 }
  }
}

/** 
 * The ADD differential probability of \f$({\gg\oplus})\f$ (RSH-XOR) computed
 * experimentally over all inputs. Complexity: \f$O(n)\f$.
 *
 * \param A transition probability matrices for \f$\mathrm{adp}^{\gg\oplus}\f$.
 * \param da input difference.
 * \param dx input difference.
 * \param db output difference.
 * \param r shift constant.
 * \returns \f$\mathrm{adp}^{\gg\oplus}(r | da, dx \rightarrow db)\f$.
 * \see adp_rsh_xor_exper
 */ 
double adp_rsh_xor(gsl_matrix* A[3][2][2][2], uint32_t da, uint32_t dx, uint32_t db, int r)
{
  gsl_vector* R;
  gsl_vector* L;
  gsl_vector* C;
  double p_tot = 0.0;

  uint32_t istate[2] = {4, 6};
  uint32_t fstate[2][4] = {
	 {0, 1, 4, 5},
	 {2, 3, 6, 7}
  };

  L = gsl_vector_calloc(ADP_RSH_XOR_MSIZE);
  C = gsl_vector_calloc(ADP_RSH_XOR_MSIZE);
  R = gsl_vector_calloc(ADP_RSH_XOR_MSIZE);

  for(int s2_guess = 0; s2_guess < 2; s2_guess++) {

	 gsl_vector_set_zero(L);
	 gsl_vector_set_zero(C);
	 gsl_vector_set_zero(R);

	 int istate_idx = istate[s2_guess];
	 gsl_vector_set(C, istate_idx, 1.0);

	 for(int i = 0; i < 4; i++) {
		int fstate_idx = fstate[s2_guess][i];
		gsl_vector_set(L, fstate_idx, 1.0);
	 }

	 for(uint32_t pos = 0; pos < WORD_SIZE; pos++) {
		int special_pos = 0;	  // (i+r < n)
		if((pos + r) < WORD_SIZE) { // (i+r < n)
		  special_pos = 0;			 // normal
		}
		if((pos + r) > WORD_SIZE) { // (i + r > n)
		  special_pos = 1;
		}
		if((pos + r) == WORD_SIZE) { // (i + r == n)
		  special_pos = 2;
		}
		uint32_t x_pos = (pos + r) % WORD_SIZE;
		assert((x_pos < WORD_SIZE) && (x_pos >= 0));
		//		uint32_t dx = (da >> r);

		int i = (da >> pos) & 1;
		//		int j = (da >> x_pos) & 1;
		int j = (dx >> x_pos) & 1;
		int k = (db >> pos) & 1;

		gsl_blas_dgemv(CblasNoTrans, 1.0, A[special_pos][i][j][k], C, 0.0, R);
		gsl_vector_memcpy(C, R);
	 }
	 double p = 0.0;
	 gsl_blas_ddot(L, C, &p);
	 p_tot += p;

  }

  gsl_vector_free(R);
  gsl_vector_free(C);
  gsl_vector_free(L);

  return p_tot;
}

/**
 * Approximation of \f$\mathrm{adp}^{\gg\oplus}\f$ obtained  as the multiplication of 
 * the differential probabilities \f$\mathrm{adp}^{\gg}\f$ and \f$\mathrm{adp}^{\oplus}\f$.
 *
 * \param da input difference.
 * \param dx input difference.
 * \param db output difference.
 * \param r shift constant.
 * \returns \f$\mathrm{adp}^{\gg\oplus}(r | da, dx \rightarrow db) \approx \mathrm{adp}^{\gg} \cdot \mathrm{adp}^{\oplus} \f$.
 * \see adp_xor, adp_rsh
 *
 */ 
double adp_rsh_xor_approx(uint32_t da, uint32_t dx, uint32_t db, int r)
{
  gsl_matrix* A[2][2][2];
  double p_tot = 0.0;

  // allocate memory
  adp_xor_alloc_matrices(A);
  adp_xor_sf(A);
  adp_xor_normalize_matrices(A);

  // compute dy = (dx >> r)
  uint32_t dy[4] = {0, 0, 0, 0};

  adp_rsh_odiffs(dy, dx, r);

  for(int i = 0; i < 4; i++) {

	 double p1 = adp_rsh(dx, dy[i], r);
	 double p2 = adp_xor(A, da, dy[i], db);
#if DEBUG_ADP_RSH_XOR
	 printf("[%s:%d] ADP_RSH[(%d -%d-> %d)] = %6.5f\n", 
			  __FILE__, __LINE__, da, r, dx[i], p1);
	 printf("[%s:%d] ADP_XOR[(%d, %d -> %d)] = %6.5f\n", 
			  __FILE__, __LINE__, da, dx[i], db, p2);
#endif
	 p_tot += (p1 * p2);
  }
  //  printf("p_tot = %f\n", p_tot);

  // free memory
  adp_xor_free_matrices(A);

  return p_tot;
}
