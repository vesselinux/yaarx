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
 * \file  morus-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2015
 * \brief Analysis of the authenticated cipher MORUS
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_AND_H
#include "xdp-and.hh"
#endif
#ifndef ADP_XOR_H
#include "adp-xor.hh"
#endif

/*
 * Morus reference code: http://www3.ntu.edu.sg/home/wuhj/research/caesar/code/morus.zip
 */

#define n1 (5 % WORD_SIZE)
#define n2 (31 % WORD_SIZE)
#define n3 (7 % WORD_SIZE)
#define n4 (22 % WORD_SIZE)
#define n5 (13 % WORD_SIZE)

//#define LROT(x,n)   (((x) << (n)) | ((x) >> (32-n)))  

/*
 * Rotate each WORD_T-bit words to the right by y positions. In the
 * original specification WORD_T = 32.
 */
void morus_rotr_xxx_yy(const WORD_T x[4], const uint32_t r, WORD_T y[4])
{
  assert(x[0] < ALL_WORDS);
  assert(x[1] < ALL_WORDS);
  assert(x[2] < ALL_WORDS);
  assert(x[3] < ALL_WORDS);
  y[0] = RROT(x[0],r);
  y[1] = RROT(x[1],r);
  y[2] = RROT(x[2],r);
  y[3] = RROT(x[3],r);
  assert(y[0] < ALL_WORDS);
  assert(y[1] < ALL_WORDS);
  assert(y[2] < ALL_WORDS);
  assert(y[3] < ALL_WORDS);
}

/*
 * Rotate the postions of 4 words by 32:
 * x[] <<< 32: x(3,2,1,0) -> y(2,1,0,3)
 */
void morus_word_rotr_32(const WORD_T x[4], WORD_T y[4])
{
  y[3] = x[2];  
  y[2] = x[1];  
  y[1] = x[0];  
  y[0] = x[3]; 
}

/*
 * Rotate the postions of 4 words by 64:
 * x <<< 64: x(3,2,1,0) -> y(1,0,3,2)
 */
void morus_word_rotr_64(const WORD_T x[4], WORD_T y[4])
{
  y[3] = x[1];  
  y[2] = x[0];  
  y[1] = x[3];     
  y[0] = x[2];     
}

void morus_word_print(const WORD_T x[4])
{
  printf("[%s:%d] ", __FILE__, __LINE__);
  for(uint32_t i = 0; i < 4; i++) {
	 printf("%X ", x[i]);
  }
  printf("\n");
}

void morus_state_print(const WORD_T x[5][4])
{
  //  printf("[%s:%d] ", __FILE__, __LINE__);
  for(uint32_t i = 0; i < 5; i++) {
	 for(uint32_t j = 0; j < 4; j++) {
		printf("%X ", x[i][j]);
	 }
	 printf("\n");
  }
}

/*
 * XOR two states
 */
void morus_word_xor(const WORD_T x[4], const WORD_T y[4], WORD_T z[4])
{
  z[0] = (x[0] ^ y[0]);
  z[1] = (x[1] ^ y[1]);
  z[2] = (x[2] ^ y[2]);
  z[3] = (x[3] ^ y[3]);
}

/*
 * AND two states
 */
void morus_word_and(const WORD_T x[4], const WORD_T y[4], WORD_T z[4])
{
  z[0] = (x[0] & y[0]);
  z[1] = (x[1] & y[1]);
  z[2] = (x[2] & y[2]);
  z[3] = (x[3] & y[3]);
}

bool morus_states_are_equal(const WORD_T x[4], const WORD_T y[4])
{
  bool b_equal = 
	 ((x[0] == y[0]) &&
	  (x[1] == y[1]) &&
	  (x[2] == y[2]) &&
	  (x[3] == y[3]));
  return b_equal;
}

void morus_find_solution_rand()
{
  //  uint32_t cnt = 0;
  WORD_T b1 = 31 % WORD_SIZE;
  WORD_T b2 = 7 % WORD_SIZE;
  WORD_T b3 = 22 % WORD_SIZE;
  WORD_T b4 = 13 % WORD_SIZE;

  printf("[%s:%d] b1234 %2d %2d %2d %2d\n", __FILE__, __LINE__,
			b1, b2, b3, b4);

  const WORD_T zero_state[4] = {0, 0, 0, 0};

  bool b_found = false;
  while(!b_found) {
	 b_found = true;
	 WORD_T B[4] = {0, 0, 0, 0};
	 WORD_T p0[4] = {0, 0, 0, 0};
	 WORD_T p1[4] = {0, 0, 0, 0};
	 for(uint32_t i = 0; i < 4; i++) {
		B[i] = xrandom() & MASK;
		p0[i] = xrandom() & MASK;
		p1[i] = xrandom() & MASK;
	 }
	 WORD_T B_rot64[4] = {0, 0, 0, 0};
#if 1 // DEBUG
	 printf("[%s:%d] BEFORE rotr64\n", __FILE__, __LINE__);
	 morus_word_print(B);
#endif // #if 1 // DEBUG
	 morus_word_rotr_64(B, B_rot64);
#if 1 // DEBUG
	 printf("[%s:%d] AFTER rotr64\n", __FILE__, __LINE__);
	 morus_word_print(B_rot64);
#endif // #if 1 // DEBUG

	 WORD_T B_rot32[4] = {0, 0, 0, 0};
#if 1 // DEBUG
	 printf("[%s:%d] BEFORE rotr32\n", __FILE__, __LINE__);
	 morus_word_print(B);
#endif // #if 1 // DEBUG
	 morus_word_rotr_32(B, B_rot32);
#if 1 // DEBUG
	 printf("[%s:%d] AFTER rotr32\n", __FILE__, __LINE__);
	 morus_word_print(B_rot32);
#endif // #if 1 // DEBUG

	 //  WORD_T A = morus_rotr_xxx_yy(B);

	 // EQ1 and EQ2

	 WORD_T E1_left[4] = {0, 0, 0, 0};
#if 1 // DEBUG
	 printf("[%s:%d] BEFORE morus_rotr_xxx_yy %d\n", __FILE__, __LINE__, b1);
	 morus_word_print(B_rot64);
#endif // #if 1 // DEBUG
	 morus_rotr_xxx_yy(B_rot64, b1, E1_left);
#if 1 // DEBUG
	 printf("[%s:%d] AFTER morus_rotr_xxx_yy %d\n", __FILE__, __LINE__, b1);
	 morus_word_print(E1_left);
#endif // #if 1 // DEBUG

	 WORD_T E1_right[4] = {0, 0, 0, 0};
#if 1 // DEBUG
	 printf("[%s:%d] BEFORE morus_rotr_xxx_yy %d\n", __FILE__, __LINE__, b2);
	 morus_word_print(B_rot32);
#endif // #if 1 // DEBUG
	 morus_rotr_xxx_yy(B_rot32, b2, E1_right);
#if 1 // DEBUG
	 printf("[%s:%d] AFTER morus_rotr_xxx_yy %d\n", __FILE__, __LINE__, b2);
	 morus_word_print(E1_right);
#endif // #if 1 // DEBUG
 
	 if(!morus_states_are_equal(E1_left, E1_right))
		continue;

	 if(morus_states_are_equal(E1_left, zero_state))
		continue;

	 printf("[%s:%d] CHECKPOINT 1\n", __FILE__, __LINE__);

	 // EQ3
	 WORD_T E2_left[4] = {0, 0, 0, 0};
#if 1 // DEBUG
	 printf("[%s:%d] BEFORE morus_rotr_xxx_yy %d\n", __FILE__, __LINE__, b3);
	 morus_word_print(B);
#endif // #if 1 // DEBUG
	 morus_rotr_xxx_yy(B, b3, E2_left);
#if 1 // DEBUG
	 printf("[%s:%d] AFTER morus_rotr_xxx_yy %d\n", __FILE__, __LINE__, b3);
	 morus_word_print(E2_left);
#endif // #if 1 // DEBUG

	 WORD_T E2_right[4] = {0, 0, 0, 0};
#if 1 // DEBUG
	 printf("[%s:%d] BEFORE morus_word_xor\n", __FILE__, __LINE__);
	 morus_word_print(B_rot64);
	 morus_word_print(E1_left);
#endif // #if 1 // DEBUG
	 morus_word_xor(B_rot64, E1_left, E2_right);
#if 1 // DEBUG
	 printf("[%s:%d] AFTER morus_word_xor\n", __FILE__, __LINE__);
	 morus_word_print(E2_right);
#endif // #if 1 // DEBUG

	 if(!morus_states_are_equal(E2_left, E2_right))
		continue;

	 if(morus_states_are_equal(E2_left, zero_state))
		continue;

#if 1  // DEBUG
	 printf("[%s:%d] CHECKPOINT 2\n", __FILE__, __LINE__);
	 morus_word_print(E1_left);
	 morus_word_print(E1_right);
	 morus_word_print(E2_left);
	 morus_word_print(E2_right);
#endif // DEBUG

	 // EQ4
	 WORD_T E3_left[4] = {0, 0, 0, 0};
	 morus_rotr_xxx_yy(B, b4, E3_left);

	 WORD_T tmp_1[4] = {0, 0, 0, 0};
	 morus_word_and(p0, p1, tmp_1);

	 WORD_T tmp_2[4] = {0, 0, 0, 0};
	 morus_word_xor(p1, B, tmp_2);
	 morus_word_and(p0, tmp_2, tmp_2);

	 WORD_T E3_right[4] = {0, 0, 0, 0};
	 morus_word_xor(E3_right, tmp_1, E3_right);
	 morus_word_xor(E3_right, tmp_2, E3_right);
	 morus_word_xor(E3_right, B_rot64, E3_right);
	 morus_word_xor(E3_right, E1_left, E3_right);

	 if(morus_states_are_equal(E3_left, zero_state))
		continue;

	 if(morus_states_are_equal(E3_left, E3_right)) {
		b_found = true;
		printf("[%s:%d] Found solution: \n", __FILE__, __LINE__);
		morus_word_print(E1_left);
		morus_word_print(E1_right);
		morus_word_print(E2_left);
		morus_word_print(E2_right);
		morus_word_print(E3_left);
		morus_word_print(E3_right);
	 }
  }
}

void morus_find_solution_all()
{
  assert(WORD_SIZE < 10);
  //  uint32_t cnt = 0;
  WORD_T b1 = 31 % WORD_SIZE;
  WORD_T b2 = 7 % WORD_SIZE;
  WORD_T b3 = 22 % WORD_SIZE;
  WORD_T b4 = 13 % WORD_SIZE;

  printf("[%s:%d] b1234 %2d %2d %2d %2d\n", __FILE__, __LINE__,
			b1, b2, b3, b4);

  uint64_t cnt = 0;

  const WORD_T zero_state[4] = {0, 0, 0, 0};

  for(WORD_T i1 = 0; i1 < ALL_WORDS; i1++) {
	 for(WORD_T i2 = 0; i2 < ALL_WORDS; i2++) {
		for(WORD_T i3 = 0; i3 < ALL_WORDS; i3++) {
		  for(WORD_T i4 = 0; i4 < ALL_WORDS; i4++) {
 
	       cnt++;

			 WORD_T B[4] = {i1, i2, i3, i4};

			 WORD_T B_rot64[4] = {0, 0, 0, 0};
			 morus_word_rotr_64(B, B_rot64);

			 WORD_T B_rot32[4] = {0, 0, 0, 0};
			 morus_word_rotr_32(B, B_rot32);

			 // EQ1 and EQ2
			 WORD_T E1_left[4] = {0, 0, 0, 0};
			 morus_rotr_xxx_yy(B_rot64, b1, E1_left);

			 WORD_T E1_right[4] = {0, 0, 0, 0};
			 morus_rotr_xxx_yy(B_rot32, b2, E1_right);
 
			 if(!morus_states_are_equal(E1_left, E1_right))
				continue;

			 if(morus_states_are_equal(E1_left, zero_state))
				continue;

			 // EQ3
			 WORD_T E2_left[4] = {0, 0, 0, 0};
			 morus_rotr_xxx_yy(B, b3, E2_left);

			 WORD_T E2_right[4] = {0, 0, 0, 0};
			 morus_word_xor(B_rot64, E1_left, E2_right);

			 if(!morus_states_are_equal(E2_left, E2_right))
				continue;

			 if(morus_states_are_equal(E2_left, zero_state))
				continue;

#if 1  // DEBUG
			 printf("[%s:%d] Found solution: \n", __FILE__, __LINE__);
			 morus_word_print(E1_left);
			 morus_word_print(E1_right);
			 morus_word_print(E2_left);
			 morus_word_print(E2_right);
#endif // DEBUG
		  }
		}
	 }
  }
  printf("[%s:%d] cnt = 2^%4.2f\n", __FILE__, __LINE__, log2(cnt));
}

//void morus_stateupdate(unsigned int msgblk[], unsigned int state[][4])    
void morus_stateupdate(WORD_T msgblk[], WORD_T state[][4])    
{   
  //  unsigned int temp;  
  WORD_T temp;  

  // --- ROUND 1 ---

  // s0 ^ s3
  state[0][0] ^= state[3][0]; 
  state[0][1] ^= state[3][1]; 
  state[0][2] ^= state[3][2]; 
  state[0][3] ^= state[3][3]; 

  // s0 ^ (s1 & s2)
  state[0][0] ^= state[1][0] & state[2][0]; 
  state[0][1] ^= state[1][1] & state[2][1]; 
  state[0][2] ^= state[1][2] & state[2][2]; 
  state[0][3] ^= state[1][3] & state[2][3];     

  // LROT_128_32(s0, n1)
  state[0][0] = LROT(state[0][0],n1);  
  state[0][1] = LROT(state[0][1],n1);       
  state[0][2] = LROT(state[0][2],n1);       
  state[0][3] = LROT(state[0][3],n1);  

  // s3 <<< 32: (3,2,1,0) -> (2,1,0,3)
  temp = state[3][3];    
  state[3][3] = state[3][2];  
  state[3][2] = state[3][1];  
  state[3][1] = state[3][0];  
  state[3][0] = temp;  

  // --- ROUND 2 ---

  // s1 ^ M
  state[1][0] ^= msgblk[0];   
  state[1][1] ^= msgblk[1];   
  state[1][2] ^= msgblk[2];   
  state[1][3] ^= msgblk[3];

  // s1 ^ s4
  state[1][0] ^= state[4][0]; 
  state[1][1] ^= state[4][1]; 
  state[1][2] ^= state[4][2]; 
  state[1][3] ^= state[4][3]; 

  // s1 ^ (s2 ^ s3)
  state[1][0] ^= (state[2][0] & state[3][0]); 
  state[1][1] ^= (state[2][1] & state[3][1]); 
  state[1][2] ^= (state[2][2] & state[3][2]); 
  state[1][3] ^= (state[2][3] & state[3][3]);     

  // LROT_128_32(s1, n2)
  state[1][0] = LROT(state[1][0],n2);  
  state[1][1] = LROT(state[1][1],n2);       
  state[1][2] = LROT(state[1][2],n2);       
  state[1][3] = LROT(state[1][3],n2); 

  // s4 <<< 64: (3,2,1,0) -> (1,0,3,2)
  temp = state[4][3];    
  state[4][3] = state[4][1];  
  state[4][1] = temp;     
  temp = state[4][2];    
  state[4][2] = state[4][0];  
  state[4][0] = temp;     

  // --- ROUND 3 ---

  // s2 ^ M
  state[2][0] ^= msgblk[0];   
  state[2][1] ^= msgblk[1];   
  state[2][2] ^= msgblk[2];   
  state[2][3] ^= msgblk[3];

  // s2 ^ s0
  state[2][0] ^= state[0][0]; 
  state[2][1] ^= state[0][1]; 
  state[2][2] ^= state[0][2]; 
  state[2][3] ^= state[0][3]; 

  // s2 ^ (s3 & s4)
  state[2][0] ^= state[3][0] & state[4][0]; 
  state[2][1] ^= state[3][1] & state[4][1]; 
  state[2][2] ^= state[3][2] & state[4][2]; 
  state[2][3] ^= state[3][3] & state[4][3];     

  // LROT_128_32(s2, n3)
  state[2][0] = LROT(state[2][0],n3);  
  state[2][1] = LROT(state[2][1],n3);       
  state[2][2] = LROT(state[2][2],n3);       
  state[2][3] = LROT(state[2][3],n3);  

  // s0 <<< 96: (3,2,1,0) -> (0,3,2,1)
  temp = state[0][0];    
  state[0][0] = state[0][1];  
  state[0][1] = state[0][2];  
  state[0][2] = state[0][3];  
  state[0][3] = temp;  

  // --- ROUND 4 ---

  // s3 ^ M
  state[3][0] ^= msgblk[0];   
  state[3][1] ^= msgblk[1];   
  state[3][2] ^= msgblk[2];   
  state[3][3] ^= msgblk[3];

  // s3 ^ s1
  state[3][0] ^= state[1][0]; 
  state[3][1] ^= state[1][1]; 
  state[3][2] ^= state[1][2]; 
  state[3][3] ^= state[1][3]; 

  // s3 ^ (s0 & s4)
  state[3][0] ^= state[4][0] & state[0][0]; 
  state[3][1] ^= state[4][1] & state[0][1]; 
  state[3][2] ^= state[4][2] & state[0][2]; 
  state[3][3] ^= state[4][3] & state[0][3];     

  // LROT_128_32(s3, n4)
  state[3][0] = LROT(state[3][0],n4);  
  state[3][1] = LROT(state[3][1],n4); 
  state[3][2] = LROT(state[3][2],n4); 
  state[3][3] = LROT(state[3][3],n4);  

  // s3 <<< 64: (3,2,1,0) -> (1,0,3,2)
  temp = state[1][3]; 
  state[1][3] = state[1][1];
  state[1][1] = temp;     
  temp = state[1][2];
  state[1][2] = state[1][0];
  state[1][0] = temp;     

  // --- ROUND 5 ---

  // s4 ^ M
  state[4][0] ^= msgblk[0];
  state[4][1] ^= msgblk[1];
  state[4][2] ^= msgblk[2];
  state[4][3] ^= msgblk[3];

  // s4 ^ s2
  state[4][0] ^= state[2][0];
  state[4][1] ^= state[2][1];
  state[4][2] ^= state[2][2];
  state[4][3] ^= state[2][3]; 

  // s4 ^ (s0 & s1)
  state[4][0] ^= state[0][0] & state[1][0];
  state[4][1] ^= state[0][1] & state[1][1];
  state[4][2] ^= state[0][2] & state[1][2];
  state[4][3] ^= state[0][3] & state[1][3];     

  // LROT_128_32(s4, n5)
  state[4][0] = LROT(state[4][0],n5);
  state[4][1] = LROT(state[4][1],n5);
  state[4][2] = LROT(state[4][2],n5);
  state[4][3] = LROT(state[4][3],n5);  

  // s2 <<< 32: (3,2,1,0) -> (2,1,0,3)
  temp = state[2][3];
  state[2][3] = state[2][2];
  state[2][2] = state[2][1];
  state[2][1] = state[2][0];
  state[2][0] = temp;  
}

/* The input to the initialization is the 128-bit (16-byte) key; 128-bit (16-byte) IV; */
void morus_initialization(const uint32_t nrounds, WORD_T state[][4])
{
  uint32_t i;
  unsigned int temp[4]  = {0,0,0,0}; 
  //  unsigned char key[16] = {0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd}; 
#if 0
  unsigned char con0[16] = {0x0,0x1,0x01,0x02,0x03,0x05,0x08,0x0d,0x15,0x22,0x37,0x59,0x90,0xe9,0x79,0x62}; 
  unsigned char con1[16] = {0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd}; 
  memcpy(state[0], iv,   16);
  memcpy(state[1], key,  16);  
  memset(state[2], 0xff, 16);   
  memcpy(state[3], con0, 16);  
  memcpy(state[4], con1, 16);  
#endif

  for (i = 0; i < 4;  i++) {
	 temp[i] = 0;
  }

  for (i = 0; i < nrounds; i++) { //  for (i = 0; i < 16; i++) {
	 morus_stateupdate(temp, state);
  }

#if 0
  for (i = 0; i < 4;  i++) {
	 state[1][i] ^= ((unsigned int*)key)[i];
  }
#endif
}

struct morus_diff_state_t
{
  WORD_T diff_state_in[5][4]; // input difference state
  /*
	* diff_state_out[5][4][i] contains the number of times that
	* difference i was encountered
	*/
  WORD_T diff_state_out[5][4][ALL_WORDS]; // all output differences
};

#define XOR_DIFF 1

//X = (\texttt{B3},\texttt{45},\texttt{1C},\texttt{96},\texttt{88},\texttt{EA},\texttt{2D},\texttt{41},\texttt{D9},\texttt{DC},\texttt{8B},\texttt{A0},\texttt{23},\texttt{4B},\texttt{76},\texttt{40},\texttt{D4},\texttt{A4},\texttt{5B},\texttt{23})\enspace,
WORD_T g_init_state[5][4] = {
  {0xB3, 0x45, 0x1C, 0x96},
  {0x88, 0xEA, 0x2D, 0x41},
  {0xD9, 0xDC, 0x8B, 0xA0},
  {0x23, 0x4B, 0x76, 0x40},
  {0xD4, 0xA4, 0x5B, 0x23}
};

/*
 * The DP of the MORUS state update function
 */
void morus_stateupdate_dp(std::vector<morus_diff_state_t>* diff_state_vec)
{
  uint32_t nrounds = 16;//NROUNDS;
  unsigned int state_init[5][4] = {{0}};

  for(uint32_t i = 0; i < 5; i++) {
	 for(uint32_t j = 0; j < 4; j++) {
#if 1 // random state
		state_init[i][j] = xrandom() & MASK;
#else // fixed state
		state_init[i][j] = g_init_state[i][j] & MASK;
#endif // #if 0 // random state
	 }
  }

#if 0 // DEBUG
  for(uint32_t j = 0; j < 4; j++) {
	 state_first[2][j] = state_second[2][j] = ~(0UL) & MASK;
  }
#endif

  printf("[%s:%d] Initial state values:\n", __FILE__, __LINE__);
  morus_state_print(state_init);
  printf("\n");

  // for all differences [0][0] in the IV do
  for(WORD_T diff = 0; diff < ALL_WORDS; diff++) {
  //  uint32_t diff = 0x1D;
  //{

	 // initialize new state
	 morus_diff_state_t new_state;
#if 1
	 for(uint32_t i = 0; i < 5; i++) {
		for(uint32_t j = 0; j < 4; j++) {
		  new_state.diff_state_in[i][j] = 0;
		  for(uint32_t k = 0; k < ALL_WORDS; k++) {
			 new_state.diff_state_out[i][j][k] = 0;
		  }
		}
	 }
#endif

	 // add difference
	 new_state.diff_state_in[0][0] = diff;

	 // for all words [0][0] in the IV do
	 for(uint32_t i = 0; i < ALL_WORDS; i++) {

		// Init state
		unsigned int state_first[5][4] = {{0}};
		unsigned int state_second[5][4] = {{0}};
		for(uint32_t i = 0; i < 5; i++) {
		  for(uint32_t j = 0; j < 4; j++) {
			 state_first[i][j] = state_second[i][j] = state_init[i][j] & MASK;
		  }
		}

		state_first[0][0] = i;

#if XOR_DIFF
		state_second[0][0] = XOR(state_first[0][0], diff);
#else
		state_second[0][0] = SUB(state_first[0][0], diff);
#endif // #if XOR_DIFF

#if 0 // DEBUG
			printf("[%s:%d] BEFORE\n", __FILE__, __LINE__);
			morus_state_print(state_first);
			printf("\n");
			morus_state_print(state_second);
			printf("-------------------\n");
#endif // #if 0 // DEBUG

#if 1
		morus_initialization(nrounds, state_first);
		morus_initialization(nrounds, state_second);
#else
		WORD_T temp[4] = { 0, 0, 0, 0 }; //used as empty messsage block
		for (uint32_t i = 0; i < nrounds; i++) morus_stateupdate(temp, state_first);
		for (uint32_t i = 0; i < nrounds; i++) morus_stateupdate(temp, state_second);
#endif

#if 0 // DEBUG
			printf("[%s:%d] AFTER\n", __FILE__, __LINE__);
			morus_state_print(state_first);
			printf("\n");
			morus_state_print(state_second);
			printf("-------------------\n");
#endif // #if 0 // DEBUG

		for(uint32_t i = 0; i < 5; i++) {
		  for(uint32_t j = 0; j < 4; j++) {
#if XOR_DIFF
			 WORD_T dx = XOR(state_second[i][j], state_first[i][j]);
#else 
			 WORD_T dx = SUB(state_second[i][j], state_first[i][j]);
#endif // #if XOR_DIFF
			 new_state.diff_state_out[i][j][dx]++;
		  }
		}
	 }


#if 0 // DEBUG
	 for (uint32_t i = 0; i < 5; i++)
		{
		  for (uint32_t j = 0; j < 4; j++)
			 {
				for (uint32_t k = 0; k < 256; k++) // 256 possible output difference
				  {
					 if(new_state.diff_state_out[i][j][k] <= 8)
						continue;
					 //				  diffprob = ctr_diff[i][j][k];
				    printf("output row = %2d, column = %2d; ", i, j);
					 printf("output diff. = 0x%2x, prob. = %d; \n", k,  new_state.diff_state_out[i][j][k]);
					 //if (fabs(diffprob + 8) > 0.1) fprintf(fout, "warning=============================== \n");
				  }
				printf("\n\n");
			 }
		}
#endif

	 diff_state_vec->push_back(new_state);

  } // new diff
}

void test_morus_stateupdate_dp()
{
  printf("[%s:%d] XOR_DIFF %d\n", __FILE__, __LINE__, XOR_DIFF);
  std::vector<morus_diff_state_t> diff_state_vec;

  morus_stateupdate_dp(&diff_state_vec);

  std::vector<morus_diff_state_t>::iterator vec_iter = 
	 diff_state_vec.begin();

  uint32_t vec_len  = (uint32_t)diff_state_vec.size();

  printf("[%s:%d] vec_len %d\n", __FILE__, __LINE__, vec_len);

#if 1
  uint32_t cnt = 0;
  while(vec_iter != diff_state_vec.end()) {
	 morus_diff_state_t x = *vec_iter;
	 vec_iter++;
	 cnt++;
	 for(uint32_t i = 0; i < 5; i++) {
		for(uint32_t j = 0; j < 4; j++) {
		  for(uint32_t k = 0; k < ALL_WORDS; k++) {
			 if(x.diff_state_out[i][j][k] <= 12)
			 //			 if(x.diff_state_out[i][j][k] <= 15)
				continue;

			 double prob = (double)x.diff_state_out[i][j][k] / (double)ALL_WORDS;
			 if(prob == 1.0)
				continue;

			 printf("\n\nIN:\n");
			 morus_state_print(x.diff_state_in);
			 printf("\nOUT:\n");
			 printf("[%d][%d] %X (%lld %4.2f)", i, j, k, (WORD_MAX_T)x.diff_state_out[i][j][k], log2(prob));
		  }
		}
	 }
  }
  printf("[%s:%d] XOR_DIFF %d\n", __FILE__, __LINE__, XOR_DIFF);
#endif
}

double adp_and_exper(const uint32_t da, const uint32_t db, const uint32_t dc)
{
  assert(WORD_SIZE <= 10);
  uint64_t N = (1ULL << WORD_SIZE);
  uint32_t cnt = 0;

  uint32_t all = N * N;				  // all input pairs

  for(uint32_t a1 = 0; a1 < N; a1++) {
	 uint32_t a2 = (a1 + da) % MOD;
	 for(uint32_t b1 = 0; b1 < N; b1++) {
		uint32_t b2 = (b1 + db) % MOD;
		uint32_t c1 = (a1 & b1);
		uint32_t c2 = (a2 & b2);
		uint32_t dx = SUB(c2, c1);//(c2 - c1 + MOD) % MOD;
		assert((dx >= 0) && (dx < MOD));
		if(dx == dc) {
		  cnt++;
		}
	 }
  }
  double p = (double)cnt / (double)all;
  return p;
}


void test_adp_and_all()
{
  assert(WORD_SIZE <= 5);

  // adp-and
  uint32_t A[2][2][2] = {{{0}}};
  xdp_and_bf(A);

  // adp-xor
  gsl_matrix* B[2][2][2];
  adp_xor_alloc_matrices(B);
  adp_xor_sf(B);
  adp_xor_normalize_matrices(B);


  uint64_t N = (1ULL << WORD_SIZE);
  for(WORD_T da = 0; da < N; da++) {
	 for(WORD_T db = 0; db < N; db++) {
		for(WORD_T dc = 0; dc < N; dc++) {
		  double p1 = xdp_and(A, da, db, dc);
		  double p2 = adp_and_exper(da, db, dc);
		  double p3 = adp_xor(B, da, db, 0);

		  if((p2 <= p1) || (p1 == 0.0))
			 continue;

		  printf("[%s:%X] XDP_AND[(%X,%X)->%X] = %6.5f 2^%f\n", 
					__FILE__, __LINE__, da, db, dc, p1, log2(p1));
		  printf("[%s:%X] ADP_AND[(%X,%X)->%X] = %6.5f 2^%f\n", 
					__FILE__, __LINE__, da, db, dc, p2, log2(p2));
		  printf("[%s:%X] ADP_XOR[(%X,%X)->%X] = %6.5f 2^%f\n", 
					__FILE__, __LINE__, da, db, 0, p3, log2(p3));
		  printf("\n");
		}
	 }
  }

  adp_xor_free_matrices(B);
}

void test_adp_and()
{
  assert(WORD_SIZE <= 5);

  // adp-and
  uint32_t A[2][2][2] = {{{0}}};
  xdp_and_bf(A);

  // adp-xor
  gsl_matrix* B[2][2][2];
  adp_xor_alloc_matrices(B);
  adp_xor_sf(B);
  adp_xor_normalize_matrices(B);

  WORD_T da2 = 0;
  WORD_T db2 = 0;
  WORD_T dc2 = 0;

  WORD_T da3 = (~0U) & MASK;
  WORD_T db3 = 0;
  WORD_T dc3 = da3;

  double p2 = adp_and_exper(da2, db2, dc2);
  double p3 = adp_xor(B, da3, db3, dc3);

  printf("[%s:%X] ADP_AND[(%X,%X)->%X] = %6.5f 2^%f\n", 
			__FILE__, __LINE__, da2, db2, dc2, p2, log2(p2));
  printf("[%s:%X] ADP_XOR[(%X,%X)->%X] = %6.5f 2^%f\n", 
			__FILE__, __LINE__, da3, db3, dc3, p3, log2(p3));
  printf("\n");

  adp_xor_free_matrices(B);
}

// {--- MIXED DIFFERENCES TESTS ---

double xor_add(WORD_T d, WORD_T D)
{
  printf("[%s:%d] CHECKPOINT!\n", __FILE__, __LINE__);
  double p = 1.0;
  for(WORD_T i = 0; i < (WORD_SIZE - 1); i++) {
	 WORD_T d_i = (d >> i) & 1; 
	 WORD_T D_i = (D >> i) & 1; 
	 WORD_T d_ii = (d >> (i+1)) & 1; 
	 WORD_T D_ii = (D >> (i+1)) & 1; 
	 if(i == 0) {
		if(d_i != D_i) {
		  return 0.0;
		}
	 } else {
		if(D_i == 0) {
		  printf("[%s:%d] CHECKPOINT!\n", __FILE__, __LINE__);
		  if((d_ii ^ D_ii) != d_i) {
			 return 0.0;
		  }
		}
		if(D_i == 1) {
  printf("[%s:%d] CHECKPOINT!\n", __FILE__, __LINE__);
		  bool b_one = ((d_ii ^ D_ii) == (d_i ^ (d_i & 1)));
		  bool b_two = ((d_ii ^ D_ii) == (1 & (d_i ^ (d_i & 1))));
		  if(b_one && b_two)
			 continue;
		  if((b_one && !b_two) || (!b_one && b_two)) {
			 p /= 0.5;
		  } else {
			 if(!b_one && !b_two) {
				return 0.0;
			 }
		  }
		}
	 }
  }
  return p;
}

void test_xor_add()
{
  //  for(WORD_T d = 0; d < ALL_WORDS; d++) { // add diff
  //	 for(WORD_T D = 0; D < ALL_WORDS; D++) { // xor diff
  WORD_T d = 1;
  WORD_T D = 1;
  {
	 {
		uint32_t cnt = 0;
		for(WORD_T x = 0; x < ALL_WORDS; x++) { // value x
		  WORD_T y1 = ADD(x, d);
		  WORD_T y2 = XOR(x, D);
		  if(y1 == y2) {
			 cnt++;
		  }
		}
		if(cnt) {
		  double p2 = xor_add(d, D);
		  double prob = (double)cnt / (double)ALL_WORDS;
		  printf("d D %X %X | %d %4.2f %4.2f\n", d, D, cnt, prob, p2);
		}
	 }
  }
}

// --- MIXED DIFFERENCES TESTS ---}


int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %8lX\n", __FILE__, __LINE__, WORD_SIZE, MASK);
  srandom(time(NULL));
  test_morus_stateupdate_dp();
  //  test_xor_add();
  //  morus_find_solution_all();
  //  morus_find_solution_rand();
  //  test_adp_and_all();
  //  test_adp_and();
  return 0;
}
