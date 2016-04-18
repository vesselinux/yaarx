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
 * \file  tweetcipher-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for tweetcipher-ref.cc .
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif

#define LOOP(n) for(i=0;i<n;++i)
#define W(v,n) ((uint64_t*)v)[n]
#define R(v,n)(((v)<<(64-n))|((v)>>n))
#define AXR(a,b,c,r) x[a]+=x[b];x[c]=R(x[c]^x[a],r);
#define G(a,b,c,d) {AXR(a,b,d,32) AXR(c,d,b,25) AXR(a,b,d,16) AXR(c,d,b,11)}
#define ROUNDS {for(r=6;r--;){LOOP(4) G(i,i+4,i+8,i+12) \
                              LOOP(4) G(i,(i+1)%4+4,(i+2)%4+8,(i+3)%4+12)}}

/*
Test vector

$ echo smashup | ./bin/tweetcipher-ref  e kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk vvvvvvvvvvvvvvvv | ./bin/tweetcipher-ref d  kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk vvvvvvvvvvvvvvvv 

*v[1] = e
*v[2] = kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk = W[0:3] :  W[0]kkkkkkkk W[1]kkkkkkkk W[2]kkkkkkkk W[3]kkkkkkkk
*v[3] = vvvvvvvvvvvvvvvv

v[1] = 65 e

v[2][0] 6B6B6B6B6B6B6B6B kkk...
v[2][1] 6B6B6B6B6B6B6B6B
v[2][2] 6B6B6B6B6B6B6B6B
v[2][3] 6B6B6B6B6B6B6B6B

v[3][4] 7676767676767676 vvv...
v[3][5] 7676767676767676

*/
//int main(int _,char**v)
//int main(int _,char**v)
#define TWEET_PTLEN 64			  // plaintext length
#define TWEET_CONST 0x7477697468617369ULL

int main()
{
  srandom(time(NULL));

  uint64_t x[16];					  // state
  uint64_t i;
  uint64_t c;
  uint64_t r;
  uint64_t f=1;//'e'==*v[1];		  // encrypt or decrypt

  uint64_t key[4] = {0};
  uint64_t iv[2]  = {0};

  for(uint32_t i = 0; i < 4; i++) {
	 key[i] = random64();
	 printf("%llX ", key[i]);
  }
  printf("\n");
  for(uint32_t i = 0; i < 2; i++) {
	 iv[i] = random64();
	 printf("%llX ", iv[i]);
  }
  printf("\n");

  // --- Encryption ---

  // initialize input state
  for(i = 0; i < 16; ++i) {
    x[i] = (i * TWEET_CONST);
  }
  // add key
  for(i = 0; i < 4; ++i) {		  // LOOP(4) x[i]=W(v[2],i);
	 //	 x[i] = ((uint64_t*)v[2])[i];
	 x[i] = key[i];
  }
  // add tweak
  for(i = 0; i < 2; ++i) {		  // LOOP(2) x[i+4]=W(v[3],i);
	 //	 x[i+4] = ((uint64_t*)v[3])[i];
	 x[i+4] = iv[i];
  }
  ROUNDS;
  uint8_t pt_in[TWEET_PTLEN] = {0};
  uint8_t ct[TWEET_PTLEN] = {0};//{0x61, 0x61, 0x61, 0x61, 0x61, 0xA};
  for(uint32_t i = 0; i < TWEET_PTLEN; i++) {
	 ct[i] = random32() & 0xFF;
	 pt_in[i] = ct[i];
  }
  ct[TWEET_PTLEN - 1] = 0xA;			  // EOF
  pt_in[TWEET_PTLEN - 1] = ct[TWEET_PTLEN - 1];
  printf(" plaintext: ");
  for(uint32_t i = 0; i < TWEET_PTLEN; i++) {
	 printf("%2X ", ct[i]);
  }
  printf("\n");
  for(uint32_t j = 0; j < TWEET_PTLEN; j++) {
	 c = ct[j];//getchar();

	 ct[j] = (uint8_t)(0xFF & (x[0]^c));
	 if(f == 1) {					  // encrypt
		x[0] = c ^ x[0];
	 } else {						  // decrypt
		x[0] = c ^ (x[0] & (~255ULL)); // ~255ULL = FFFFFFFFFFFFFF00
	 }
    ROUNDS;
  }
  x[0]^=1;
  ROUNDS;
  printf("\n");
#if 0
  LOOP(8) printf("%2llX ", 255 & ((x[4]^x[5])>>8*i));
  printf("\n");
  LOOP(8) printf("%2llX ", 255 & ((x[6]^x[7])>>8*i));
  printf("\n");
#endif

  // --- Decryption ---
  //  printf("\n --- Decryption --- \n");
  f = 0;
  printf("ciphertext: ");
  for(uint32_t i = 0; i < TWEET_PTLEN; i++) {
	 printf("%2X ", ct[i]);
  }
  printf("\n");

  // initialize input state
  for(i = 0; i < 16; ++i) {
    x[i] = (i * TWEET_CONST);
  }
  // add key
  for(i = 0; i < 4; ++i) {		  // LOOP(4) x[i]=W(v[2],i);
	 x[i] = key[i];
  }
  // add tweak
  for(i = 0; i < 2; ++i) {		  // LOOP(2) x[i+4]=W(v[3],i);
	 x[i+4] = iv[i];
  }
  ROUNDS;
  uint8_t pt[TWEET_PTLEN] = {0};
  for(uint32_t j = 0; j < TWEET_PTLEN; j++) {
	 c = ct[j];//0x61;//getchar();
    if( j == (TWEET_PTLEN - 1) ) { // decrypt
		pt[j] = 0xA;
		break;
	 }
	 pt[j] = (uint8_t)(0xFF & (x[0]^c));
	 if(f == 1) {					  // encrypt
		x[0] = c ^ x[0];
	 } else {						  // decrypt
		x[0] = c ^ (x[0] & (~255ULL)); // ~255ULL = FFFFFFFFFFFFFF00
	 }
    ROUNDS;
  }
  x[0]^=1;
  ROUNDS;
  printf("\n");
  printf(" decrypted: ");
  for(uint32_t i = 0; i < TWEET_PTLEN; i++) {
	 printf("%2X ", pt[i]);
	 assert(pt_in[i] == pt[i]);
  }
  printf("\n");

  return 0;
}


/**
 * Main function of the tests.
 */
#if 0
int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %8X\n", __FILE__, __LINE__, WORD_SIZE, MASK);
  srandom(time(NULL));

  return 0;
}
#endif
