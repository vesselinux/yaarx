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
 * \file  adp-arx.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief The ADD differential probability of the sequence of operations: 
 *        \ref ADD, \ref LROT, \ref XOR (\ref ARX): 
 *        \f$\mathrm{adp}^{\mathrm{ARX}}(da,db,dd \rightarrow de)\f$.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_ARX_H
#include "adp-arx.hh"
#endif

/**
 * Array of initial states for the S-function of 
 * \f$\mathrm{adp}^{\mathrm{ARX}}\f$: \ref adp_arx_sf.
 */
uint32_t ADP_ARX_ISTATES[ADP_ARX_NISTATES] = {0,2,4,6};

/**
 * Array of final states for the S-function of 
 * \f$\mathrm{adp}^{\mathrm{ARX}}\f$: \ref adp_arx_sf.
 * Every set of final states corresponds to a
 * unique initial state (\ref ADP_ARX_ISTATES).
 */
uint32_t ADP_ARX_FSTATES[ADP_ARX_NISTATES][ADP_ARX_NFSTATES] = {{0,1}, {2,3}, {4,5}, {6,7}};

/**
 * Allocate memory for the transition probability matrices for \f$\mathrm{adp}^{\mathrm{ARX}}\f$.
 * \param A transition probability matrices for \f$\mathrm{adp}^{\mathrm{ARX}}\f$.
 * \see adp_arx_free_matrices
 */
void adp_arx_alloc_matrices(gsl_matrix* A[2][2][2][2])
{
  for(int j = 0; j < ADP_ARX_NSPOS; j++) { // special bit postions
	 for(int i = 0; i < ADP_ARX_NMATRIX; i++) {
		int t = i;
		int a = t & 1;
		t /= 2;
		int b = t & 1;
		t /= 2;
		int c = t & 1;
		t /= 2;
		//			 printf("%d%d%d%d \n", c, b, a, j);
		A[j][a][b][c] = gsl_matrix_calloc(ADP_ARX_MSIZE, ADP_ARX_MSIZE);
	 }
  }
}

/**
 * Free memory reserved by a previous call to \ref adp_arx_alloc_matrices.
 * \param A transition probability matrices for \f$\mathrm{adp}^{\mathrm{ARX}}\f$.
 */
void adp_arx_free_matrices(gsl_matrix* A[2][2][2][2])
{
  for(int j = 0; j < ADP_ARX_NSPOS; j++) { // special bit postions
	 for(int i = 0; i < ADP_ARX_NMATRIX; i++) {
		int t = i;
		int a = t & 1;
		t /= 2;
		int b = t & 1;
		t /= 2;
		int c = t & 1;
		t /= 2;
		//			 printf("%d%d%d%d \n", c, b, a, j);
		gsl_matrix_free(A[j][a][b][c]);
	 }
  }
}

/**
 * Transform the elements of A into probabilities.
 * \param A transition probability matrices for \f$\mathrm{adp}^{\mathrm{ARX}}\f$.
 */
void adp_arx_normalize_matrices(gsl_matrix* A[2][2][2][2])
{
  for(int j = 0; j < ADP_ARX_NSPOS; j++) { // special bit postions
	 for(int i = 0; i < ADP_ARX_NMATRIX; i++){
		int a = (i >> 0) & 1;
		int b = (i >> 1) & 1;
		int c = (i >> 2) & 1;

		for(int row = 0; row < ADP_ARX_MSIZE; row++){
		  for(int col = 0; col < ADP_ARX_MSIZE; col++){
			 double e = gsl_matrix_get(A[j][a][b][c], row, col);
			 gsl_matrix_set(A[j][a][b][c], row, col, ADP_ARX_NORM * e);
		  }
		}
		// check col sum
#if 1
		for(int col = 0; col < ADP_ARX_MSIZE; col++){
		  double col_sum = 0;
		  for(int row = 0; row < ADP_ARX_MSIZE; row++){
			 double e = gsl_matrix_get(A[j][a][b][c], row, col);
			 col_sum += e;
		  }
		  assert((col_sum == 0.0) || (col_sum == 1.0));
		}
#endif
	 }
  } // special position
}

/**
 * Print the matrices for \f$\mathrm{adp}^{\mathrm{ARX}}\f$.
 * \param A transition probability matrices for \f$\mathrm{adp}^{\mathrm{ARX}}\f$.
 */
void adp_arx_print_matrices(gsl_matrix* A[2][2][2][2])
{
  for(int j = 0; j < ADP_ARX_NSPOS; j++) { // special bit postions
	 printf("--- [%s:%d] Special position j = %d ---\n", __FILE__, __LINE__, j);
	 for(int i = 0; i < ADP_ARX_NMATRIX; i++){
		int a = (i >> 0) & 1;
		int b = (i >> 1) & 1;
		int c = (i >> 2) & 1;
		printf("A%d|%d%d%d \n", j, c, b, a);
		for(int row = 0; row < ADP_ARX_MSIZE; row++){
		  for(int col = 0; col < ADP_ARX_MSIZE; col++){
			 double e = gsl_matrix_get(A[j][a][b][c], row, col);
			 printf("%3.2f, ", e);
		  }
		  printf("\n");
		}
		printf("\n");

		// check
#if 0
		for(int col = 0; col < ADP_ARX_MSIZE; col++){
		  uint32_t col_sum = 0;
		  for(int row = 0; row < ADP_ARX_MSIZE; row++){
			 uint32_t e = gsl_matrix_get(A[j][a][b][c], row, col);
			 col_sum += e;
		  }
		  //					printf("%2d ", col_sum);
		  assert((col_sum == 0) || (col_sum == ADP_ARX_COLSUM));
		}
#endif
	 }
  } // special position j
}

// Compute adp-arx: the differential probability of the sequence of operations
// modular addition, bit rotation and xor with respect to additive differences
// 
// Let a,b,d,e are fixed input additive differences such that:
// a = a2 - a1
// b = b2 - b1
// d = d2 - d1
// e is a fixed output difference; k is a rotation constant; <<< is left bit rotation; ^ designates xor
// 
// Then the following
// 
// P = adp-arx((a,b,d)->e)
// 
// is the probability that
// 
// e = [((a2 + b2) <<< k) ^ d2] - [((a1 + b1) <<< k) ^ d1]
// 

//
// Constructing an S-function for the ARX operation using
// additive differences. Computation of ADP^{ARX}: The differential 
// probability (DP) of ARX with respect to additive differences
// 
// The ARX operation:
// 
// ADD  : Delta^+a[i]      Delta^+b[i]      Delta^+d[i+k]
//        {0,1}            {0,1}            {0,1}
//        |                |                |
//        ------>[+]<-------                |
//                |                         |
//             Delta^+c[i]                  |
//             {0,1}                        |
//                |                         |
// PAIR : (c1[i],c2[i])=                    (d1[i+k],d2[i+k])
//        ({0,1},{0,1})                     d_carry[i+k]={0,1}
//        c_carry[i]={0,1}                  |
//                |                         |
//                |                         | 
//                |          [<<< k]        V
//                ------->(c1[i],c2[i])--->(x)
//                                          |
//                                          V
// PAIR:                   (e1[i+k],e2[i+k])=
//                              ({0,1},{0,1})
//                    (e1[i+k]=c1[i]^d1[i+k],
//                     e2[i+k]=c2[i]^d2[i+k])
//                                          |
// ADD:                         Delta^+e[i+k]
//                             e_carry[i+k]={-1,0}
//                                      
// 
// The states of the S-function at time i will are composed of:
// 
// [c_carry[i]={0,1}, d_carry[i+k]={0,1}, e_carry[i+k]={-1,0}]
// 
// At one time we shall have 2*2*2=8 states.
// 
// In fact we approximate only the rotation and the xor -
// additive differences pass through modular addition
// with probability 1.
// 

// 
// S-function for an ARX construction which uses additive differences
// the first dimension of the matrix (the first [2])
// shows wheather this is a general matrix (ie. for all bit except bit0)
// or a special matrix (ie. a matrix for bit 0)
// b_is_bit0==true when the rotated bits d and e are at position 0.
// then arx_matrix generates special kind of matrices
// for which d_carry and e_carry are set to 0
// old name: arx_add_matrix
// matrix[is_bit0][c][d][e][8][8]

/** 
 * S-function for \f$\mathrm{adp}^{\mathrm{ARX}}\f$:
 * \f$\mathrm{adp}^{\mathrm{ARX}}(da,db,dd \rightarrow de)\f$.
 *
 * \param A zero-initialized set of matrices.
 * \returns Transition probability matrices A for
 *          \f$\mathrm{adp}^{\mathrm{ARX}}(da,db,dd \rightarrow de)\f$.
 *
 * \f$A[2][2][2][2] = A[j][dc[i]][dd[i+r]][de[i+r]]\f$, where 
 * 
 *   - \f$r\f$ : rotation constant.
 *   - \f$dc[i]\f$ : the \f$i\f$-th bit of the first input difference.
 *   - \f$dd[i+r]\f$ : the \f$(i+r)\f$-th bit of the second input difference.
 *   - \f$dd[i+r]\f$ : the \f$(i+r)\f$-th bit of the output difference.
 *   - \f$j\f$ : special bit postion:
 *      -# \f$ j = 0 \Rightarrow (i+r) = 0\f$.
 *      -# \f$ j = 1 \Rightarrow (i+r) \neq 0\f$.
 *
 * \note At bit position \f$i: (i+r) = 0\f$, a special set of matrices 
 *       is generated for which the carries generated at position
 *       \f$(i+r)\f$ in the differences \f$dd,de\f$ are set to 0.
 */
//void adp_arx_sfunction(uint32_t trellis[2][2][2][2][8][8])
void adp_arx_sf(gsl_matrix* A[2][2][2][2])
{
  // number of possible input differences
  uint32_t ndiffs = (1UL << ADP_ARX_NINPUTS);
  assert(ndiffs == 4);
  uint32_t nstates = ADP_ARX_MSIZE;
  uint32_t nvals = ndiffs;

  // b_is_pos_zero==true when the rotated bits d and e are at position 0.
  for(uint32_t j_spos = 0; j_spos < ADP_ARX_NSPOS; j_spos++) { // special bit position

	 bool b_is_pos_zero = j_spos;

	 for(uint32_t i = 0; i < ndiffs; i++) {
		uint32_t dc = (i >> 0) & 1; // input to ROT
		uint32_t dd = (i >> 1) & 1; // input to XOR
		//			 printf("%d%d\n", db, da);

		for(int32_t u = 0; u < (int)nstates; u++) {
		  int32_t t = u;
		  int32_t in_s1 = t & 1;  // dc = (da + db)
		  t /= 2;
		  int32_t in_s2 = t & 1;  // dd
		  t /= 2;
		  int32_t in_s3 = (t & 1) - 1; // de
		  t /= 2;
		  //					printf("[%2d] %2d%2d%2d \n", u, in_s3, in_s2, in_s1);

		  // if the rotated bits d,e is at position 0, set their carries to 0
		  if(b_is_pos_zero == true)	{ // b_bit_bit0
			 in_s2 = 0;
			 in_s3 = 0;
		  }

		  for(uint32_t j = 0; j < nvals; j++) {
			 uint32_t a1 = (j >> 0) & 1;
			 uint32_t b1 = (j >> 1) & 1;
			 //						  printf("%d%d\n", b1, a1);

			 // compute sf
			 uint32_t a2 = a1 ^ dc ^ in_s1;
			 uint32_t b2 = b1 ^ dd ^ in_s2;

			 int32_t out_s1 = (a1 + dc + in_s1) >> 1;
			 int32_t out_s2 = (b1 + dd + in_s2) >> 1;

			 // xor with three inputs
			 uint32_t c1 = a1 ^ b1;
			 uint32_t c2 = a2 ^ b2;
			 uint32_t de = (c2 - c1 + in_s3) & 1;
			 assert((de == 0) || (de == 1));

			 int32_t out_s3 = (int32_t)(c2 - c1 + in_s3) >> 1; // signed shift i.e. -1 >> 1 == -1
			 assert((c2 - c1 + in_s3) == ((out_s3 * 2) + de));

			 // checks
			 assert((out_s1 == 0) || (out_s1 == 1));
			 assert((out_s2 == 0) || (out_s2 == 1));
			 assert((out_s3 == 0) || (out_s3 == -1));

			 uint32_t v = 0;

			 // compose the output state
			 v = out_s3 + 1;
			 v *= 2;
			 v += out_s2;
			 v *= 2;
			 v += out_s1;

			 // add a link between U and V in the adjacency matrix
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
			 uint32_t e = gsl_matrix_get(A[j_spos][dc][dd][de], row, col);
			 e = e + 1;
			 gsl_matrix_set(A[j_spos][dc][dd][de], row, col, e);

		  } // vals
		}		  // states
	 }			  // diffs
  }			  // is_bit0
}

/**
 * The additive differential probability of \ref ARX
 * \f$\mathrm{adp}^{\mathrm{ARX}}\f$. \b Complexity: \f$O(n)\f$.
 * 
 * \param A transition probability matrices for \f$\mathrm{adp}^{\mathrm{ARX}}\f$
 *        computed with \ref adp_arx_sf.
 * \param rot_const rotation constant.
 * \param da first input difference (input to \ref ADD).
 * \param db second input difference (input to \ref ADD).
 * \param dd third input difference (input to \ref XOR).
 * \param de output difference (output from \ref ARX).
 * \returns \f$\mathrm{adp}^{\mathrm{ARX}}(da,db,dd \rightarrow de)\f$.
 *
 * \note If \f$a,b,d\f$ and \f$e\f$ are values that satisfy the differences
 *       \f$da,db,dd\f$ and \f$de\f$ respectively, then the ARX operation is 
 *       defined as: \f$e = (((a + b) \ll< r) \oplus d)\f$.
 */
double adp_arx(gsl_matrix* A[2][2][2][2], uint32_t rot_const, 
					uint32_t da, uint32_t db, uint32_t dd, uint32_t de)
{

  uint32_t dc = ADD(da, db);	  // input to ROT

  double p_tot = 0.0;
  gsl_vector* R;
  gsl_vector* L;
  gsl_vector* C;

  L = gsl_vector_calloc(ADP_ARX_MSIZE);
  C = gsl_vector_calloc(ADP_ARX_MSIZE);
  R = gsl_vector_calloc(ADP_ARX_MSIZE);

  // init L
  gsl_vector_set_all(L, 1.0);

  for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) {

	 uint32_t istate = ADP_ARX_ISTATES[is];

	 gsl_vector_set_all(R, 0.0);	  // clear the temporary vector R
	 gsl_vector_set_all(C, 0.0);	  // clear the initial vector C
	 gsl_vector_set_all(L, 0.0);	  // clear the initial vector L

	 gsl_vector_set(C, istate, 1.0); // init C
	 for(uint32_t fs = 0; fs < ADP_ARX_NFSTATES; fs++) {
		uint32_t fstate = ADP_ARX_FSTATES[is][fs];
		gsl_vector_set(L, fstate, 1.0); // init L
	 }

	 for(int pos = 0; pos < WORD_SIZE; pos++) {
		uint32_t spos = 0;			  // special position;
		uint32_t rot_pos = ((pos + rot_const) % WORD_SIZE); // (i+r) mod n
		if(rot_pos == 0) {
		  spos = 1;
		}

		uint32_t i = (dc >> pos) & 1;
		uint32_t j = (dd >> rot_pos) & 1;
		uint32_t k = (de >> rot_pos) & 1;

		assert((i == 0) || (i == 1));
		assert((j == 0) || (j == 1));
		assert((k == 0) || (k == 1));

		gsl_blas_dgemv(CblasNoTrans, 1.0, A[spos][i][j][k], C, 0.0, R);
		gsl_vector_memcpy(C, R);

	 }

	 double p = 1.0;
	 gsl_blas_ddot(L, C, &p);
	 p_tot += p;
#if 0									  // DEBUG
	 printf("[%s:%d] %f %f\n", __FILE__, __LINE__, p, p_tot);
#endif

  } // for(uint32_t istate...

  gsl_vector_free(R);
  gsl_vector_free(C);
  gsl_vector_free(L);

#if 0									  // DEBUG
  printf("%8X %8X %8X -> %8X : %f\n", da, db, dd, de, p_tot);
#endif

  return p_tot;
}

//#define ARX(x,y,z,r) XOR(z,ROT(ADD(x,y),r)) 

/**
 * The additive differential probability of ARX (\f$\mathrm{adp}^{\mathrm{ARX}}\f$)
 * computed experimentally over all inputs. \b Complexity: \f$O(2^{4n})\f$.
 * 
 * \param r rotation constant.
 * \param da first input difference (input to \ref ADD).
 * \param db second input difference (input to \ref ADD).
 * \param dd third input difference (input to \ref XOR).
 * \param de output difference (output from \ref ARX).
 * \returns \f$\mathrm{adp}^{\mathrm{ARX}}(da,db,dd \rightarrow de)\f$.
 * \see adp_arx
 */
double adp_arx_exper(uint32_t r, uint32_t da, uint32_t db, uint32_t dd, uint32_t de)
{
  assert(WORD_SIZE <= 10);
  uint64_t N = (1ULL << WORD_SIZE);
  uint32_t cnt = 0;

  uint32_t all = N * N * N;				  // all input pairs

  for(uint32_t a1 = 0; a1 < N; a1++) {
	 uint32_t a2 = ADD(a1, da); //(a1 + da) % MOD;

	 for(uint32_t b1 = 0; b1 < N; b1++) {
		uint32_t b2 = ADD(b1, db); //(b1 + db) % MOD;

		for(uint32_t d1 = 0; d1 < N; d1++) {
		  uint32_t d2 = ADD(d1, dd); //(d1 + dd) % MOD;

		  uint32_t e1 = ARX(r,a1,b1,d1);
		  uint32_t e2 = ARX(r,a2,b2,d2);

#if 0									  // DEBUG
		  uint32_t c1 = ADD(a1,b1);
		  uint32_t c2 = ADD(a2,b2);
		  uint32_t ee1 = (((c1 << r) | (c1 >> (WORD_SIZE - r))) ^ d1) & MASK;
		  uint32_t ee2 = (((c2 << r) | (c2 >> (WORD_SIZE - r))) ^ d2) & MASK;
		  assert(e1 == ee1);
		  assert(e2 == ee2);
#endif  // DEBUG

		  uint32_t dx = SUB(e2,e1);//(e2 - e1 + MOD) % MOD;

		  assert((dx >= 0) && (dx < MOD));

		  if(dx == de) {
			 cnt++;
		  }
		}
	 }
  }
  double p = (double)cnt / (double)all;
  return p;
}
