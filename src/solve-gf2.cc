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
 * \file  solve-gf2.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Solving linear systems of Boolean equations using Gaussain elimination.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif

// C = (12*32) x (16*32) = 384 x 512; T = (16*32) x (12*32) = 512 x 384 
void solve_gf2_matrix_transpose(const uint32_t** C, int M, int N, uint32_t** T, int P, int Q)
{
  int c_row,c_col,c_bit;
  uint32_t bit;

  assert((M == (Q * WORD_SIZE)));
  assert(((N * WORD_SIZE) == P));

  for(c_row=0; c_row<M; c_row++) { // row of C
	 for(c_col=0; c_col<N; c_col++) {
		for(c_bit=0; c_bit < WORD_SIZE; c_bit++) { // 31,30,29,...,0
		  bit = (C[c_row][c_col] >> (WORD_SIZE - c_bit - 1)) & 1;  // one bit of C
		  T[c_col*WORD_SIZE + c_bit][c_row / WORD_SIZE] |= (bit << (WORD_SIZE - (c_row % WORD_SIZE) - 1));
		}
	 }
  }
}

// concatenate the identity matrix I[m][m] to the left of the matrix a[m][n]
// ap[m][m+n] is the output matrix ap = [ I[m][m] | a[m][n] ]
// ap[P][Q], a[M][N]
void solve_gf2_identity_matrix_left_concat(uint32_t** ap, int P, int Q, uint32_t** a, int M, int N)
{
  assert(P == M);
  assert(Q == (M/WORD_SIZE + N));

  // make identity matrix
  for(int row = 0, bit = 0; row < M; row++ , bit++) {		// rows
	 ap[row][bit/WORD_SIZE] = (1UL << (WORD_SIZE - 1 - (bit % WORD_SIZE)));
  }

  for(int i = 0; i < M; ++i) {
	 // copy the rest of the contents of the original matrix a to ap
	 for (int j = 0; j < N; ++j) {
		ap[i][M/WORD_SIZE + j] = a[i][j];
	 }
  }
}

// find the first non-zero element in an 1D array; return its index
// if no such element exists, returns -1. 
// a[m][n]
int solve_gf2_find_first_nonzero(const uint32_t** a, int m, int n, const int r, const int s)
{
  // cycle through columns
  for(int i=s; i<n; ++i) {
	 if(a[r][i]!=0) {
		return i;
	 }
  }
  return -1;
}

// swap rows r and s of the matrix a[m][n] i.e. row s becomes row r
// a[m][n]
void solve_gf2_swap_rows(uint32_t** a, const int m, const int n, const int r, const int s)
{
  uint32_t temp_row[n];

  assert(r < m);
  assert(s < m);

  for(int i=0; i < n; i++) {
	 temp_row[i] = a[r][i];
	 a[r][i] = a[s][i];
	 a[s][i] = temp_row[i];
  }
}

// m - rows; s columns from the identity matrix (s = m / WORD_SIZE); n - total number of columns
// a[m][n] where a[m][s] == I (identity matrix), s < n, s = m / WORD_SIZE
int solve_gf2_gaussian_elimination(uint32_t** a, int m, int s, int n)
{
  int d = 0;

  // cycle through rows
  for (int i = 0; i < m; ++i) {
	 // find the first non-zero word in row i of the original matrix
	 // ie. starting from s because from 0 to s-1 is the
	 // identity matrix
	 const int p = solve_gf2_find_first_nonzero((const uint32_t**) a, m, n, i, s);

	 // if row i contains all zeros then move it to the top
	 // ie. swap it with row d=0...; in this way we shall have
	 // all zero rows at the top of the matrix
	 if (p == -1) {
		solve_gf2_swap_rows(a, m, n, i, d);
		++d;
	 } else {
		for (int j = i + 1; j < m; ++j) {
		  if ((a[j][p] ^ a[i][p]) < a[j][p]) {
			 for (int k = 0; k < n; ++k) {
				a[j][k] ^= a[i][k];
			 }
		  }
		}
	 }
  }
  return d; 
}

// solve a system of linear Boolean equations using Gaussain elimination
// G[M][N] - original matrix
// Gt[S][T] - transposed matrix of G; S = N*WORD_SIZE, T = M/WORD_SIZE
// Gt_ext[P][Q] - extended matrix with the identity matrix: Gt_ext = [I | Gt]; S == P, Q = P/WORD_SIZE + T 
void solve_gf2_system(const uint32_t** G, int M, int N,
							 uint32_t** Gt, int S, int T,
							 uint32_t** Gt_ext, int P, int Q,
							 int* nsol)
{	
  assert(S == (N*WORD_SIZE));
  assert(T == (M/WORD_SIZE));
  assert(P == S);
  assert(Q == ((P/WORD_SIZE) + T));
  assert((P%WORD_SIZE) == 0);

  solve_gf2_matrix_transpose(G,M,N,Gt,S,T);
  solve_gf2_identity_matrix_left_concat(Gt_ext, P, Q, Gt, S, T); // ! Q = P/WORD_SIZE + T
  *nsol = solve_gf2_gaussian_elimination(Gt_ext, P, P/WORD_SIZE, Q);
}
