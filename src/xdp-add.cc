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
 * \file  xdp-add.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief The XOR differential probability of ADD \f$\mathrm{xdp}^{+}(da,db \rightarrow db)\f$.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_ADD_H
#include "xdp-add.hh"
#endif

/**
 * Allocate memory for the transition probability matrices for \f$\mathrm{xdp}^{+}\f$.
 * \param A transition probability matrices for \f$\mathrm{xdp}^{+}\f$.
 * \see xdp_add_free_matrices
 */
void xdp_add_alloc_matrices(gsl_matrix* A[2][2][2])
{
  for(int i = 0; i < XDP_ADD_NMATRIX; i++){
	 int t = i;
	 int a = t & 1;
	 t /= 2;
	 int b = t & 1;
	 t /= 2;
	 int c = t & 1;
	 t /= 2;
	 //			 printf("%d%d%d \n", c, b, a);
	 A[a][b][c] = gsl_matrix_calloc(XDP_ADD_MSIZE, XDP_ADD_MSIZE);
  }
}

/**
 * Free memory reserved by a previous call to \ref xdp_add_alloc_matrices.
 * \param A transition probability matrices for \f$\mathrm{xdp}^{+}\f$.
 */
void xdp_add_free_matrices(gsl_matrix* A[2][2][2])
{
  for(int i = 0; i < XDP_ADD_NMATRIX; i++){
	 int t = i;
	 int a = t & 1;
	 t /= 2;
	 int b = t & 1;
	 t /= 2;
	 int c = t & 1;
	 t /= 2;
	 //			 printf("%d%d%d \n", c, b, a);
	 //			 if(A[a][b][c] != NULL)
	 gsl_matrix_free(A[a][b][c]);
  }
}

/**
 * Transform the elements of A into probabilities.
 * \param A transition probability matrices for \f$\mathrm{xdp}^{+}\f$.
 */
void xdp_add_normalize_matrices(gsl_matrix* A[2][2][2])
{
  for(int i = 0; i < XDP_ADD_NMATRIX; i++){
	 int a = (i >> 0) & 1;
	 int b = (i >> 1) & 1;
	 int c = (i >> 2) & 1;

	 for(int row = 0; row < XDP_ADD_MSIZE; row++){
		for(int col = 0; col < XDP_ADD_MSIZE; col++){
		  double e = gsl_matrix_get(A[a][b][c], row, col);
		  gsl_matrix_set(A[a][b][c], row, col, XDP_ADD_NORM * e);
		}
	 }
	 // check col sum
#if 1
	 for(int col = 0; col < XDP_ADD_MSIZE; col++){
		double col_sum = 0;
		for(int row = 0; row < XDP_ADD_MSIZE; row++){
		  double e = gsl_matrix_get(A[a][b][c], row, col);
		  col_sum += e;
		}
		assert((col_sum == 0.0) || (col_sum == 1.0));
	 }
#endif
  }
}

/**
 * Print the matrices for \f$\mathrm{xdp}^{+}\f$.
 * \param A transition probability matrices for \f$\mathrm{xdp}^{+}\f$.
 */
void xdp_add_print_matrices(gsl_matrix* A[2][2][2])
{
  for(int i = 0; i < XDP_ADD_NMATRIX; i++){
	 int a = (i >> 0) & 1;
	 int b = (i >> 1) & 1;
	 int c = (i >> 2) & 1;
	 printf("A%d%d%d \n", c, b, a);
	 for(int row = 0; row < XDP_ADD_MSIZE; row++){
		for(int col = 0; col < XDP_ADD_MSIZE; col++){
		  double e = gsl_matrix_get(A[a][b][c], row, col);
		  printf("%3.2f, ", e);
		}
		printf("\n");
	 }
	 printf("\n");

	 // check
#if 0
	 for(int col = 0; col < XDP_ADD_MSIZE; col++){
		uint32_t col_sum = 0;
		for(int row = 0; row < XDP_ADD_MSIZE; row++){
		  uint32_t e = gsl_matrix_get(A[a][b][c], row, col);
		  col_sum += e;
		}
		//					printf("%2d ", col_sum);
		assert((col_sum == 0) || (col_sum == XDP_ADD_COLSUM));
	 }
#endif
  }
}

/**
 * Print the matrices for \f$\mathrm{xdp}^{+}\f$ in a format
 * readable by the computer algebra system Sage (http://www.sagemath.org/).
 *
 * \param A transition probability matrices for \f$\mathrm{xdp}^{+}\f$.
 */
void xdp_add_print_matrices_sage(gsl_matrix* A[2][2][2])
{
  printf("# [%s:%d] Matrices for XDP-ADD generated with %s() \n", __FILE__, __LINE__, __FUNCTION__);

  printf("#--- Normalization factor --- \n");
  printf("f = %f\n", XDP_ADD_NORM);

  // print L
  gsl_vector* L = gsl_vector_calloc(XDP_ADD_MSIZE);
  gsl_vector_set_all(L, 1.0);
  printf("#--- Vector L --- \n");
  printf("L = vector(QQ,[ ");
  for(int col = 0; col < XDP_ADD_MSIZE; col++){
	 double e = gsl_vector_get(L, col);
	 printf("%4.3f", e);
	 if(col == XDP_ADD_MSIZE - 1) {
		printf(" ");
	 } else {
		printf(", ");
	 }
  }
  printf("])\n\n");

  // print C
  gsl_vector* C = gsl_vector_calloc(XDP_ADD_MSIZE);
  gsl_vector_set_zero(C);
  gsl_vector_set(C, XDP_ADD_ISTATE, 1.0);
  printf("#--- Vector C --- \n");
  printf("C = vector(QQ,[ ");
  for(int col = 0; col < XDP_ADD_MSIZE; col++){
	 double e = gsl_vector_get(C, col);
	 printf("%4.3f", e);
	 if(col == XDP_ADD_MSIZE - 1) {
		printf(" ");
	 } else {
		printf(", ");
	 }
  }
  printf("])\n\n");

  // print A
  for(int i = 0; i < XDP_ADD_NMATRIX; i++){
	 int a = (i >> 0) & 1;
	 int b = (i >> 1) & 1;
	 int c = (i >> 2) & 1;
	 printf("#---AA%d%d%d--- \n", c, b, a);
	 printf("AA%d%d%d = matrix(QQ,%d,%d,[\n", c, b, a, XDP_ADD_MSIZE, XDP_ADD_MSIZE);
	 for(int row = 0; row < XDP_ADD_MSIZE; row++){
		for(int col = 0; col < XDP_ADD_MSIZE; col++){
		  double e = gsl_matrix_get(A[a][b][c], row, col);
		  printf("%3.2f", e);
		  if((row == XDP_ADD_MSIZE - 1) && (col == XDP_ADD_MSIZE - 1)) {
			 printf(" ");
		  } else {
			 printf(", ");
		  }
		}
		printf("\n");
	 }
	 printf("])\n\n");
	 //	 printf("\n");
  }
  for(int i = 0; i < XDP_ADD_NMATRIX; i++){
	 int a = (i >> 0) & 1;
	 int b = (i >> 1) & 1;
	 int c = (i >> 2) & 1;
	 printf("A%d%d%d = f * AA%d%d%d\n", c, b, a, c, b, a);
  }
  printf("\n");
  printf("A = [A000, A001, A010, A011, A100, A101, A110, A111]\n");
  printf("\n");
  printf("AA = [AA000, AA001, AA010, AA011, AA100, AA101, AA110, AA111]\n");
}

/** 
 * S-function for \f$\mathrm{xdp}^{+}\f$:
 * \f$\mathrm{xdp}^{+}(da,db \rightarrow db)\f$.
 *
 * \param A zero-initialized set of matrices.
 * \returns Transition probability matrices A for \f$\mathrm{xdp}^{+}(da,db \rightarrow db)\f$.
 *
 * \f$A[2][2][2] = A[da[i]][db[i]][dc[i]]\f$, where 
 * 
 *   - \f$da[i]\f$ : the i-th bit of the first input difference.
 *   - \f$db[i]\f$ : the i-th bit of the second input difference.
 *   - \f$dc[i]\f$ : the i-th bit of the output difference.
 * \see adp_xor_sf
 */
void xdp_add_sf(gsl_matrix* A[2][2][2])
{
  // for all 4 possible differences: (b_diff, a_diff)
  for(int d = 0; d < 4; d++) {
	 //for(int dd; dd < 4; dd++) {

	 //int d = dd;
	 const int a_diff = (d >> 0) & 1;
	 const int b_diff = (d >> 1) & 1;

	 // for all 4 possible states (nodes) (c2_carry, c1_carry) 
	 for(int s = 0; s < 4; s++) {

		int u = s;

		const int c1_carry_in = (u % 2); // 0,1
		u /= 2;
		const int c2_carry_in = (u % 2); // 0,1
		u /= 2;

		u = s; 

#if 0									  // DEBUG
		printf("u = (c1_carry_in, c2_cary_in) : %d = (%d,%d)\n", u, c1_carry_in, c2_carry_in);
#endif
		// for all 4 possible half-pairs b1, a1
		for(int i = 0; i < 4; i++) {

		  // extract a1,b1
		  const int a1 = (i >> 0) & 1;
		  const int b1 = (i >> 1) & 1;

		  // compute a2,b2
		  const int a2 = a1 ^ a_diff;
		  const int b2 = b1 ^ b_diff;

		  // pass the pairs (a1,b1) and (a2,b2) through the add
		  const int c1 = a1 + b1 + c1_carry_in; // 0,1,2,3
		  const int c2 = a2 + b2 + c2_carry_in; // 0,1,2,3

		  // compute the difference of c
		  const int c_diff = ((c1 ^ c2) & 1);

		  const int c1_carry_out = c1 >> 1;
		  const int c2_carry_out = c2 >> 1;

		  int v = 0;

		  // pack the infromation (c2_carry_out, c1_carry_out)
		  // in an output node v. the corresponding input nodes is u
		  v = (v * 2) + c2_carry_out;
		  v = (v * 2) + c1_carry_out;

#if 0									  // DEBUG
		  printf("v = (c1_carry_out, c2_cary_out) : %d = (%d,%d)\n", v, c1_carry_out, c2_carry_out);
#endif
		  // add a path between states u and v in the trellis
		  // the transition which makes this path possible is:
		  // (a_diff,b_diff)->c_diff
		  // columns are inputs, rows are outputs in the final matrix
		  // 
		  //                   input u
		  //                     |
		  //                     V
		  //              [x] [x] [x] [x]  
		  // output v <-  [x] [x] [x] [x]  
		  //              [x] [x] [x] [x]  
		  // 
		  uint32_t col = u;
		  uint32_t row = v;
		  uint32_t e = gsl_matrix_get(A[a_diff][b_diff][c_diff], row, col);
		  e = e + 1;
		  gsl_matrix_set(A[a_diff][b_diff][c_diff], row, col, e);
		}
	 }
  }
}

/**
 * The XOR differential probability of ADD  
 * (\f$\mathrm{xdp}^{+}\f$). \b Complexity: \f$O(n)\f$.
 * 
 * \param A transition probability matrices for \f$\mathrm{xdp}^{+}\f$
 *        computed with \ref xdp_add_sf.
 * \param da first input difference.
 * \param db second input difference.
 * \param dc output difference.
 * \return \f$p = \mathrm{xdp}^{+}(da, db \rightarrow dc)\f$
 * \see adp_xor
 */
double xdp_add(gsl_matrix* A[2][2][2], WORD_T da, WORD_T db, WORD_T dc)
{
  double p = 1.0;
  gsl_vector* R;
  gsl_vector* L;
  gsl_vector* C;

  L = gsl_vector_calloc(XDP_ADD_MSIZE);
  C = gsl_vector_calloc(XDP_ADD_MSIZE);

  // init C
  gsl_vector_set(C, XDP_ADD_ISTATE, 1.0);
  // init L
  for(int i = 0; i < XDP_ADD_MSIZE; i++)
	 gsl_vector_set(L, i, 1.0);

  R = gsl_vector_calloc(XDP_ADD_MSIZE);

  for(int pos = 0; pos < WORD_SIZE; pos++) {
	 int i = (da >> pos) & 1;
	 int j = (db >> pos) & 1;
	 int k = (dc >> pos) & 1;

	 gsl_blas_dgemv(CblasNoTrans, 1.0, A[i][j][k], C, 0.0, R);
	 gsl_vector_memcpy(C, R);

#if 1									  // DEBUG
	 double tmp_p = 0.0;
	 gsl_blas_ddot(L, R, &tmp_p);
	 if(tmp_p > p) {
		printf("[%s:%d] WARNING! %16.15f > %16.15f\n", __FILE__, __LINE__, p, tmp_p);
		//		assert(float_equals(*p, *p_max));
	 } 
#if 0
	 assert(tmp_p <= p);
#endif
	 p = tmp_p;
#endif
#if 0									  // DEBUG
	 printf("[%s:%d] k = %d: a %d | b %d | c %d | %f\n", __FILE__, __LINE__, pos, i, j, k, p);
#endif
  }
#if 0							  // DEBUG
  printf("R  ");
  for(int i = 0; i < XDP_ADD_MSIZE; i++) {
	 double e = gsl_vector_get(C, i);
	 printf("%f ", e);
  }
  printf("\n");
  printf("L  ");
  for(int i = 0; i < XDP_ADD_MSIZE; i++) {
	 double e = gsl_vector_get(L, i);
	 printf("%f ", e);
  }
  printf("\n");
#endif
  gsl_blas_ddot(L, C, &p);

  gsl_vector_free(R);
  gsl_vector_free(C);
  gsl_vector_free(L);

#if 0									  // DEBUG
  printf("%llX %llX -> %llX : %f 2^%4.2f\n", (WORD_MAX_T)da, (WORD_MAX_T)db, (WORD_MAX_T)dc, p, log2(p));
#endif

  return p;
}

/**
 * The XOR differential probability of ADD (\f$\mathrm{xdp}^{+}\f$)
 * computed experimentally over all inputs. \b Complexity: \f$O(2^{2n})\f$.
 * 
 * \param da first input difference.
 * \param db second input difference.
 * \param dc output difference.
 * \return \f$p = \mathrm{xdp}^{+}(da, db \rightarrow dc)\f$
 * \see xdp_add
 */
double xdp_add_exper(const WORD_T da, const WORD_T db, const WORD_T dc)
{
  double p = 0.0;
#if(WORD_SIZE <= 16)
  uint64_t N = (1ULL << WORD_SIZE);
  uint32_t cnt = 0;

  uint32_t all = N * N;				  // all input pairs

  for(uint32_t a1 = 0; a1 < N; a1++) {
	 uint32_t a2 = (a1 ^ da) & MASK;
	 for(uint32_t b1 = 0; b1 < N; b1++) {
		uint32_t b2 = (b1 ^ db) & MASK;
		//						  printf("%2d %2d %2d\n", a1, b1);
		uint32_t c1 = ADD(a1, b1);
		uint32_t c2 = ADD(a2, b2);
		uint32_t dx = (c1 ^ c2) & MASK;
		assert((dx >= 0) && (dx < MOD));
		if(dx == dc)
		  cnt++;
	 }
  }
  p = (double)cnt / (double)all;
#endif // #if(WORD_SIZE <= 16)
  return p;
}

/**
 * The all-one parity function (AOP) [Algorithm 1, Lipmaa, Moriai, FSE 2001]
 *
 * y = aop(x): y[i] = 1 iff x[i..j] = 11..1 has odd length .
 *
 */
WORD_T aop(WORD_T x, WORD_T n_in)
{
  //  assert(0 == 1);
  WORD_T n = n_in;

  // set n to the closest power of 2 from above
#if 1 // TEST
  bool b_is_pow2 = ((n == 2) || (n == 4) || (n == 8) || (n == 16) || (n == 32) || (n == 64));
  if(!b_is_pow2) {
	 if(n < 2) n = 2;
	 if((n > 2) && (n < 4)) n = 4;
	 if((n > 4) && (n < 8)) n = 8;
	 if((n > 8) && (n < 16)) n = 16;
	 if((n > 16) && (n < 32)) n = 32;
	 if((n > 32) && (n < 64)) n = 64;
	 if((n > 64) && (n < 128)) n = 128;
  }
#endif  // #if // TEST

  // n must be power of 2
  assert((n == 2) || (n == 4) || (n == 8) || (n == 16) || (n == 32) || (n == 64));

  WORD_T L = (WORD_T)log2(n);

#if 0 // DEBUG
  printf("log2(%d) = %d\n", n, L);
  printf("x = ");
  print_binary(x);
  printf("\n");
#endif // #if 0 // DEBUG

  WORD_T a[WORD_SIZE] = {0};  // x[]
  WORD_T b[WORD_SIZE] = {0};  // y[]

  a[1] = x & (x >> 1);

#if 0 // DEBUG
  printf("a[%2d] = ", 1);
  printf("a[%2d] & ", 1 - 1);
  printf("(a[%2d] >> %d) = ", 1 - 1, 1);
  print_binary(x);
  printf(" & ");
  print_binary((x >> 1));
  printf(" = ");
  print_binary(a[1]);
  printf("| %d\n", 1);
#endif // #if 0 // DEBUG

  for(WORD_T i = 2; i < L; i++) {
	 //	 WORD_T r = (1U << (i - 1));
	 WORD_T r = ((WORD_T)1 << (i - 1));
	 a[i] = a[i-1] & (a[i-1] >> r);

#if 0 // DEBUG
	 printf("a[%2d] = ", i);
	 printf("a[%2d] & ", i - 1);
	 printf("(a[%2d] >> %d) = ", i - 1, r);
	 print_binary(a[i - 1]);
	 printf(" & ");
	 print_binary((a[i-1] >> r));
	 printf(" = ");
	 print_binary(a[i]);
	 printf("| %d\n", r);
#endif // #if 0 // DEBUG

  }

  b[1] = x & (~a[1]);

#if 0 // DEBUG
  printf("\n");
  printf(" b[%2d] = ", 1);
  printf(" x & (~a[ 1]) = ");
  print_binary(x);
  printf(" & ");
  print_binary(~a[1]);
  printf(" = ");
  print_binary(b[1]);
  printf("\n");
#endif // #if 0 // DEBUG

  for(WORD_T i = 2; i <= L; i++) {
	 //	 WORD_T r = (1U << (i - 1));
	 WORD_T r = ((WORD_T)1 << (i - 1));
	 b[i] = b[i-1] | ((b[i-1] >> r) & a[i-1]);

#if 0 // DEBUG
	 printf(" b[%2d] = ", i);
	 printf("b[%2d] | (", i - 1);
	 printf("(b[%2d] >> %d) & ", i - 1, r);
	 printf("a[%2d]) = ", i - 1);
	 print_binary(b[i-1]);
	 printf(" | (");
	 print_binary((b[i-1] >> r));
	 printf(" & ");
	 print_binary(a[i-1]);
	 printf(") = ");
	 print_binary(b[i]);
	 printf("\n");
#endif // #if 0 // DEBUG

  }
  WORD_T y = b[L];

#if 0 // DEBUG
  printf("y = ");
  print_binary(y);
  printf("\n");
#endif // #if 0 // DEBUG
  return y;
}

/**
 * The common alternation parity function (CAP) (cf. [Lipmaa, Moriai, FSE 2001]).
 *
 * \param x first input word
 * \param y second input word.
 * \returns \f$C = \mathrm{cap}(x, y)\f$.
 *
 * \f$C = \mathrm{cap}(x, y)\f$: 
 * 
 *   - \f$C[i] = 1\f$ if \f$L[i]\f$ is even and non-zero, \f$0 \le i < n\f$.
 *   - \f$C[i] = 0\f$ if \f$L[i]\f$ is odd.
 *   - \f$C[i] = ?\f$ if \f$L[i] = 0\f$ (\f$C\f$ is unspecified).
 *
 * where \f$L[i]\f$ is the length of the longest common alternating  chain:
 * \f$(x[i] = y[i]) \neq (x[i+1] = y[i+1]) \neq ... \neq (x[i + L[i]] = y[i + L[i]])\f$.
 * 
 * \attention Counting starts from 1. For example if \f$(x[i] = y[i])
 * \wedge (x[i+1] \neq y[i+1])\f$ then \f$L[i] = 1\f$ and \f$C[i] = 0\f$.
 * 
 * \see aop .
 */
WORD_T cap(WORD_T x, WORD_T y)
{
  WORD_T n = WORD_SIZE;
  WORD_T a = ~(x ^ y);

  a &= MASK;

  // Set the MSB of a = ~(x ^ y) to be 0 as if x[n-1] != y [n-1] 
  // so that the MSB is not counted in the AOP function 
  if(((a >> (n - 1)) & 1)) {
	 a &= ~(1 << (n - 1));		  // !!!
  }

  WORD_T b = a & (a >> 1) & (x ^ (x >> 1));
  WORD_T c = aop(b, n);

#if 0 // DEBUG
  printf("[%s:%d] x = ", __FILE__, __LINE__);
  print_binary(x);
  printf("\n");
  printf("[%s:%d] y = ", __FILE__, __LINE__);
  print_binary(y);
  printf("\n");
  printf("[%s:%d] c = ", __FILE__, __LINE__);
  print_binary(c);
  printf("\n");
  printf("[%s:%d]~x^y ", __FILE__, __LINE__);
  print_binary(a);
  printf("\n");
#endif  // #if 1 // DEBUG
  return c;
}

/**
 * Check if three integers are equal.
 *
 * \param x first input word
 * \param y second input word.
 * \param z third input word.
 * \return \p TRUE if \f$x  = y = z\f$; \p FALSE otherwise.
 */
bool is_eq(WORD_T x, WORD_T y, WORD_T z) 
{
  return ((x == y) && (x == z));
}

/**
 * For three \f$n\f$-bit input words \f$x,y,z\f$
 * compute an \f$n\f$-bit output word \f$e\f$ such that 
 * \f$e[i] = 1 \iff x[i] = y[i] = z[i]\f$ and
 * \f$e[i] = 0\f$ otherwise; \f$0 \le i < n\f$.
 *
 * \param x first input word
 * \param y second input word.
 * \param z third input word.
 * \return \f$e : e[i] = 1 \iff x[i] = y[i] = z[i],~ 0 \le i < n\f$.
 *
 * \note credits: Yann Le Core
 */
WORD_T eq(const WORD_T x, const WORD_T y, const WORD_T z)
{
  //  printf("[%s:%d] Enter %s()\n", __FILE__, __LINE__, __FUNCTION__);
  //  WORD_T e = ~((x ^ y) | (x ^ z)) & MASK; // yann
  WORD_T e = ((x & y & z) | (~x & ~y & ~z)) & MASK;
  //  printf("[%s:%d] return e %X\n", __FILE__, __LINE__, e);
  //  printf("[%s:%d] Exit %s()\n", __FILE__, __LINE__, __FUNCTION__);
  return e;
}

WORD_T eq_unoptimized(const WORD_T x, const WORD_T y, const WORD_T z) 
{
#if 0	// DEBUG
  printf("[%s:%d] %s() %llX %llX %llX\n", __FILE__, __LINE__, __FUNCTION__, 
			(WORD_MAX_T)x, (WORD_MAX_T)y, (WORD_MAX_T)z);
#endif // #if 1	// DEBUG

  WORD_T e = 0;

  for(uint32_t i = 0; i < WORD_SIZE; i++) {
	 uint32_t x_i = (x >> i) & 1;
	 uint32_t y_i = (y >> i) & 1;
	 uint32_t z_i = (z >> i) & 1;

	 if(is_eq(x_i, y_i, z_i)) {
		e |= (1ULL << i);		
	 }
#if 0	// DEBUG
	 printf("[%s:%d] %d: %d %d %d %llX\n", __FILE__, __LINE__, i, x_i, y_i, z_i, e);
#endif // #if 1	// DEBUG
  }
#if 0	// DEBUG
  printf("\nx = ");
  print_binary(x);
  printf("\ny = ");
  print_binary(y);
  printf("\nz = ");
  print_binary(z);
  printf("\ne = ");
  print_binary(e);
  printf("\n");
  printf("\nn = ");
  print_binary(~e);
  printf("\n");
#endif // #if 0	// DEBUG
  return e;
}

/**
 * Checks of the differential (da, db -> dc) is possible.
 */
bool xdp_add_is_nonzero(WORD_T da, WORD_T db, WORD_T dc)
{
  bool b_is_possible = ((eq((da << 1), (db << 1), (dc << 1)) & (da ^ db ^ dc ^ (da << 1))) == 0);
  return b_is_possible;
}


/**
 * Same as \ref eq but taking the word size as in input parameter
 *
 * \note credits: Yann Le Core
 */
#if 0 // not used
WORD_T eq(const WORD_T x, const WORD_T y, const WORD_T z, const uint32_t word_size)
{
#if (WORD_SIZE <= 32)
  WORD_T mask = ~(0xffffffffUL << word_size);
#else // #if (WORD_SIZE > 32)
  WORD_T mask = ~(0xffffffffffffffffUL << word_size);
#endif // #if (WORD_SIZE <= 32)
  //  WORD_T e = ~((x ^ y) | (x ^ z)) & mask; // yann
  WORD_T e = ((x & y & z) | (~x & ~y & ~z)) & mask;

  return e;
}
#endif

WORD_T eq_unoptimized(const WORD_T x, const WORD_T y, const WORD_T z, const uint32_t word_size) 
{
#if 0 // DEBUG
  printf("[%s:%d] %s() %llX %llX %llX %d\n", __FILE__, __LINE__, __FUNCTION__, 
			(WORD_MAX_T)da, (WORD_MAX_T)db, (WORD_MAX_T)dc, wprd_size);
#endif// #if 0 // DEBUG

  WORD_T e = 0;

  for(uint32_t i = 0; i < word_size; i++) {
	 uint32_t x_i = (x >> i) & 1;
	 uint32_t y_i = (y >> i) & 1;
	 uint32_t z_i = (z >> i) & 1;

	 if(is_eq(x_i, y_i, z_i)) {
		e |= (1ULL << i);		
	 }
#if 0	// DEBUG
	 printf("[%s:%d] %d: %d %d %d %llX\n", __FILE__, __LINE__, i, x_i, y_i, z_i, e);
#endif // #if 1	// DEBUG
  }
#if 0	// DEBUG
  printf("\nx = ");
  print_binary(x);
  printf("\ny = ");
  print_binary(y);
  printf("\nz = ");
  print_binary(z);
  printf("\ne = ");
  print_binary(e);
  printf("\n");
  printf("\nn = ");
  print_binary(~e);
  printf("\n");
#endif // #if 0	// DEBUG
  return e;
}

