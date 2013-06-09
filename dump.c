

/* --- */
#if 0									  // DEBUG
			 if(da == 0xF) {
				printf("\n[%s:%d] CNT %d: Dxy add %8X -> %8X  | %f = 2^%4.2f | %15d\n", __FILE__, __LINE__, *cnt_new, diff.dx, diff.dy, diff.p, log2(diff.p), diff_set_dx_dy->size());
				if(diff.dy == 0) {
				  printf("p_min = 2^%f\n", log2(p_thres));
				  //				  assert(0 == 1);
				}
			 }
#endif
#if 0									  // DEBUG
			 double p_min = hways_diff_mset_p->rbegin()->p;
			 if(p_f >= p_min) {
				hways_diff_mset_p->insert(diff);
			 }
			 //#else
#endif


/* --- */

void test_temp()
{
  uint32_t N = MOD;
  for(uint32_t x = 0; x < N; x++) {
	 uint32_t y1 = idea_mul(0, x);
	 uint32_t y2 = SUB(1, x);
	 printf("[%s:%d] %d | %d %d\n", __FILE__, __LINE__, x, y1, y2);
	 assert(y1 == y2);
  }
}


/* --- */

/* 
20130604

- Differential trail for Raiden

B[ 0] = 2^0.000000
B[ 1] = 2^-0.997976
B[ 2] = 2^-2.003092
B[ 3] = 2^-4.650513
B[ 4] = 2^-6.904208
B[ 5] = 2^-9.169075
B[ 6] = 2^-9.157518 <-
B[ 7] = 2^-12.040834
B[ 8] = 2^-14.024897
B[ 9] = 2^-14.292030
B[10] = 2^-16.278184
B[11] = 2^-18.262943
B[12] = 2^-18.331495
B[13] = 2^-20.341391
B[14] = 2^-22.351996
B[15] = 2^-22.253144 <-
B[16] = 2^-24.251735
B[17] = 2^-26.279474
B[18] = 2^-26.258336 <-
B[19] = 2^-28.253063
B[20] = 2^-30.272388
B[21] = 2^-30.280357
B[22] = 2^-32.306301
B[23] = 2^-34.318149
B[24] = 2^-34.273955 <-
B[25] = 2^-36.302411
B[26] = 2^-38.273297
B[27] = 2^-38.225304 <-
B[28] = 2^-40.215825
B[29] = 2^-42.211429
B[30] = 2^-42.388128
B[31] = 2^-44.395013
pDDT sizes: Dp 200, Dxy 336
 0:        0 <-        0 1.000000 (2^0.000000)
 1: 7FFFFF00 <- 7FFFFF00 0.161896 (2^-2.626863)
 2: 80000100 <- 7FFFFF00 0.245026 (2^-2.028995)
 3:        0 <-        0 1.000000 (2^0.000000)
 4: 7FFFFF00 <- 7FFFFF00 0.211670 (2^-2.240112)
 5: 80000100 <- 7FFFFF00 0.207306 (2^-2.270167)
 6:        0 <-        0 1.000000 (2^0.000000)
 7: 7FFFFF00 <- 7FFFFF00 0.113983 (2^-3.133107)
 8: 80000100 <- 7FFFFF00 0.248840 (2^-2.006708)
 9:        0 <-        0 1.000000 (2^0.000000)
10: 7FFFFF00 <- 7FFFFF00 0.248138 (2^-2.010783)
11: 80000100 <- 7FFFFF00 0.250977 (2^-1.994375)
12:        0 <-        0 1.000000 (2^0.000000)
13: 7FFFFF00 <- 7FFFFF00 0.250061 (2^-1.999648)
14: 80000100 <- 7FFFFF00 0.250763 (2^-1.995604)
15:        0 <-        0 1.000000 (2^0.000000)
16: 7FFFFF00 <- 7FFFFF00 0.249146 (2^-2.004940)
17: 80000100 <- 7FFFFF00 0.246033 (2^-2.023078)
18:        0 <-        0 1.000000 (2^0.000000)
19: 7FFFFF00 <- 7FFFFF00 0.248596 (2^-2.008124)
20: 80000100 <- 7FFFFF00 0.247284 (2^-2.015760)
21:        0 <-        0 1.000000 (2^0.000000)
22: 7FFFFF00 <- 7FFFFF00 0.245056 (2^-2.028816)
23: 80000100 <- 7FFFFF00 0.251495 (2^-1.991396)
24:        0 <-        0 1.000000 (2^0.000000)
25: 7FFFFF00 <- 7FFFFF00 0.247375 (2^-2.015226)
26: 80000100 <- 7FFFFF00 0.253876 (2^-1.977806)
27:        0 <-        0 1.000000 (2^0.000000)
28: 7FFFFF00 <- 7FFFFF00 0.249481 (2^-2.002997)
29: 80000100 <- 7FFFFF00 0.247650 (2^-2.013625)
30:        0 <-        0 1.000000 (2^0.000000)
31: 7FFFFF00 <- 7FFFFF00 0.248810 (2^-2.006885)
p_tot = 0.000000000000043 = 2^-44.395013, Bn = 0.000000 = 2^-44.395013
[./src/tea-add-threshold-search.cc:1007] nrounds = 32

Iterative for 3 rounds. 

 */

/* ---- */

void test_idea_lin()
{
  assert(WORD_SIZE == 16);

  long **K;
  // fix key to random
  ushort key[8] = {0xFD01, 0x3631, 0xFF19, 0x6C15, 0x8F26, 0x96BE, 0xCAE8, 0x15FE};

  // generate random key
#if 0
  for(uint32_t j = 0; j < 8; j++) {
	 key[j] = random32() & 0xFFFF;
	 printf("0x%4X, ", key[j]);
  }
  printf("\n");
#endif

  // alloc K
  K = (long **)calloc(9, sizeof(long *));
  for(uint32_t i = 0; i < 9; i++) {
    K[i] = (long *)calloc(6, sizeof(long));
    for(uint32_t j = 0; j < 6; j++) {
		K[i][j] = 0;
	 }
  }
  IDEA_encryption_key_schedule(key, K);

  for(uint32_t q = 0; q < 1; q++) { // index of active difference

	 ushort DX[4] = {0, 0, 0, 0};
	 for(uint32_t j = 0; j < 4; j++) {
		DX[j] = 0;
	 }
	 DX[q] = 1;						  // D[0] = alpha

	 printf("[%s:%d] DX = (%8X %8X %8X %8X)\n", __FILE__, __LINE__, DX[0], DX[1], DX[2], DX[3]);

	 uint32_t N = (1U << WORD_SIZE);
	 for(uint32_t i = 0; i < N; i++) {

		ushort DY[4] = {0, 0, 0, 0};
		ushort DY_lin[4] = {0, 0, 0, 0};
		ushort X1[4] = {0, 0, 0, 0};
		ushort X2[4] = {0, 0, 0, 0};
		ushort Y1[4] = {0, 0, 0, 0};
		ushort Y2[4] = {0, 0, 0, 0};

		for(uint32_t j = 0; j < 4; j++) {
		  X1[j] = random32() & 0xFFFF;
		  X2[j] = ADD(DX[j], X1[j]);
		}
		X1[0] = i;
		X2[0] = ADD(DX[0], X1[0]);

		IDEA_LIN_encryption(X1, Y1, K);
		IDEA_LIN_encryption(X2, Y2, K);

		for(uint32_t j = 0; j < 4; j++) {
		  DY_lin[j] = SUB(Y2[j], Y1[j]);
		}

		for(uint32_t j = 0; j < 4; j++) {
		  Y1[j] = 0;
		  Y2[j] = 0;
		}

		IDEA_encryption(X1, Y1, K);
		IDEA_encryption(X2, Y2, K);

		for(uint32_t j = 0; j < 4; j++) {
		  DY[j] = SUB(Y2[j], Y1[j]);
		}

		printf("[%s:%d] ", __FILE__, __LINE__);
		for(uint32_t j = 0; j < 4; j++) {
		  printf("%8X ", DY_lin[j]);
		}
		printf(" | ");
		for(uint32_t j = 0; j < 4; j++) {
		  printf("%8X ", DY[j]);
		}
#if 0
		printf(" | ");
		for(uint32_t j = 0; j < 4; j++) {
		  printf("%8X ", X1[j]);
		}
		printf(" | ");
		for(uint32_t j = 0; j < 4; j++) {
		  printf("%8X ", X2[j]);
		}
#endif
		printf("\n");
	 }
  }

  // free K
  for(uint32_t i = 0; i < 9; i++) {
    free(K[i]);
  }
  free(K);
}

/* --- */

/*
 * Multiplication, modulo (2**16)+1
 * Original GPG implementation
 */
#define low16(x) ((x) & 0xFFFF)

uint16_t idea_mul_orig(uint16_t a, uint16_t b)
{
  uint32_t p;

  p = (uint32_t) (a * b);
  if (p) {
	 b = low16(p);
	 a = p >> 16;
	 return (b - a) + (b < a);
  } else if (a) {
	 return 1 - b;
  } else {
	 return 1 - a;
  }
}

/* --- */
/*
 * Multiplication, modulo (2**16)+1
 * Note that this code is structured on the assumption that
 * untaken branches are cheaper than taken branches, and the
 * compiler doesn't schedule branches.
 */
#ifdef SMALL_CACHE
CONST static uint16 mul(register uint16 a, register uint16 b)
{
	  register word32 p;

	  p = (word32) a *b;
	  if (p) {
			 b = low16(p);
			 a = p >> 16;
			 return (b - a) + (b < a);
	  } else if (a) {
			 return 1 - b;
	  } else {
			 return 1 - a;
	  }
}				/* mul */
#endif				/* SMALL_CACHE */



/* --- */

double adp_mul(const uint32_t da, const uint32_t db, const uint32_t dc)
{
  // (db x) + (da y) = dc - (da db)
  double p = 0.0;
  uint32_t d = gcd(da, db);
#if 1									  // GMP Test
  // Compute GCD with the GNU MP library
  mpz_t z_da, z_db, z_g;
  mpz_init_set_ui(z_da, da);
  mpz_init_set_ui(z_db, db);
  mpz_init(z_g);
  mpz_gcd(z_g, z_da, z_db);
  uint32_t g = mpz_get_ui(z_g);

  int32_t A = da / (int32_t)g;
  int32_t B = db / (int32_t)g;
  int32_t c = (dc - (da * db));
  int32_t C = c / (int32_t)g;

  printf("[%s:%d] g = gcd(%d, %d) %d\n", __FILE__, __LINE__, da, db, g);
  printf("[%s:%d] A (%d/%d) %d, B (%d/%d) %d, C (%d/%d) %d\n", __FILE__, __LINE__, da, g, A, db, g, B, c, g, C);

  mpz_clear(z_da);
  mpz_clear(z_db);
  mpz_clear(z_g);
#endif
  printf("[%s:%d] gcd(%d,%d) = %d %d\n", __FILE__, __LINE__, da, db, d, g);
  assert(d == g);
  if(d == 0) {
	 return 0.0;
  }
  int32_t e = dc - (da * db);  // gamma - (alpha * beta)
  int32_t r = (e % d);			  // remainder from e / d
  printf("[%s:%d] gcd(%d,%d) = %d, e = %d, r = %d\n", __FILE__, __LINE__, da, db, d, e, r);
  if(r != 0) {						  // d does not divide e
	 return 0.0;
  }
  uint32_t n = (1UL << WORD_SIZE);
  p = 1.0 / (double)n; // 2^-n
  int32_t e_mod = e % MOD;		  // (gamma - (alpha * beta)) mod 2^n
  if(e != e_mod) {
	 p *= 2;
  }
  return p;
}

/* --- */

/* 
	[./src/tea.cc:201] R 1 key F691432E 777F2DD4 delta 9E3779B9
 1: 0.080665 (2^-3.631920)        F <- FFFFFFFF | 2^-3.631920
------------------------------------
[./src/tea.cc:201] R 2 key D059DD11 3E61E99B delta 9E3779B9
2: 1.000000 (2^0.000000)        0 <-        0 | 2^-3.631920
------------------------------------
[./src/tea.cc:201] R 3 key F691432E 777F2DD4 delta 3C6EF372
3: 0.140709 (2^-2.829214)        F <- FFFFFFFF | 2^-6.461134
------------------------------------
[./src/tea.cc:201] R 4 key D059DD11 3E61E99B delta 3C6EF372
4: 0.003910 (2^-7.998592)        0 <-        F | 2^-14.459726
------------------------------------
[./src/tea.cc:201] R 5 key F691432E 777F2DD4 delta DAA66D2B
5: 0.080753 (2^-3.630343) FFFFFFF1 <- FFFFFFFF | 2^-18.090069
------------------------------------
[./src/tea.cc:201] R 6 key D059DD11 3E61E99B delta DAA66D2B
6: 1.000000 (2^0.000000)        0 <-        0 | 2^-18.090069
------------------------------------
[./src/tea.cc:201] R 7 key F691432E 777F2DD4 delta 78DDE6E4
7: 0.136083 (2^-2.877440) FFFFFFF1 <- FFFFFFFF | 2^-20.967509
------------------------------------
[./src/tea.cc:201] R 8 key D059DD11 3E61E99B delta 78DDE6E4
8: 0.000125 (2^-12.961081)        2 <- FFFFFFF1 | 2^-33.928590
------------------------------------
[./src/tea.cc:201] R 9 key F691432E 777F2DD4 delta 1715609D
9: 0.080970 (2^-3.626472)        F <-        1 | 2^-37.555062
------------------------------------
[./src/tea.cc:201] R10 key D059DD11 3E61E99B delta 1715609D
10: 1.000000 (2^0.000000)        0 <-        0 | 2^-37.555062
------------------------------------
[./src/tea.cc:201] R11 key F691432E 777F2DD4 delta B54CDA56
11: 0.139676 (2^-2.839843) FFFFFFF1 <-        1 | 2^-40.394905
------------------------------------
[./src/tea.cc:201] R12 key D059DD11 3E61E99B delta B54CDA56
12: 0.000000 (2^-inf) FFFFFFFE <- FFFFFFF1 | 2^-inf
------------------------------------
[./src/tea.cc:201] R13 key F691432E 777F2DD4 delta 5384540F
13: 0.080468 (2^-3.635446)        F <- FFFFFFFF | 2^-inf
------------------------------------
[./src/tea.cc:201] R14 key D059DD11 3E61E99B delta 5384540F
14: 1.000000 (2^0.000000)        0 <-        0 | 2^-inf
------------------------------------
[./src/tea.cc:201] R15 key F691432E 777F2DD4 delta F1BBCDC8
15: 0.135598 (2^-2.882590)       11 <- FFFFFFFF | 2^-inf
------------------------------------
[./src/tea.cc:201] R16 key D059DD11 3E61E99B delta F1BBCDC8
16: 0.001965 (2^-8.991221)        0 <-       11 | 2^-inf
------------------------------------
[./src/tea.cc:201] R17 key F691432E 777F2DD4 delta 8FF34781
17: 0.079695 (2^-3.649363) FFFFFFEF <- FFFFFFFF | 2^-inf
------------------------------------
[./src/tea.cc:201] R18 key D059DD11 3E61E99B delta 8FF34781
18: 1.000000 (2^0.000000)        0 <-        0 | 2^-inf
------------------------------------
[./tests/tea-add-threshold-search-tests.cc:304] Total: 2^-inf
[./tests/tea-add-threshold-search-tests.cc:305] key
key[0] = 0xF691432E;
key[1] = 0x777F2DD4;
key[2] = 0xD059DD11;
key[3] = 0x3E61E99B;
cnt_good = [ 0 /  1]
OK

real    0m1.009s
user    0m1.000s
sys     0m0.004s

 */

/* --- */
/* 
	[./tests/tea-add-threshold-search-tests.cc:150] Final full trail:
 0:        0 <-        0 1.000000 (2^0.000000)
 1: FFFFFFF1 <-        1 0.126862 (2^-2.978673)
 2: FFFFFFFF <- FFFFFFF1 0.005249 (2^-7.573735)
 3:        0 <-        0 1.000000 (2^0.000000)
 4: FFFFFFFF <- FFFFFFF1 0.005493 (2^-7.508147)
 5:        F <- FFFFFFFF 0.132599 (2^-2.914860)
 6:        0 <-        0 1.000000 (2^0.000000)
 7:        F <- FFFFFFFF 0.081238 (2^-3.621705)
 8:        2 <-        F 0.004303 (2^-7.860449)
 9: FFFFFFF1 <-        1 0.127808 (2^-2.967954)
10:        0 <-        0 1.000000 (2^0.000000)
11:       11 <-        1 0.079956 (2^-3.644649)
12:        0 <-       11 0.002228 (2^-8.810175)
13: FFFFFFEF <-        1 0.134216 (2^-2.897368)
14:        0 <-        0 1.000000 (2^0.000000)
15:        F <-        1 0.084229 (2^-3.569547)
16: FFFFFFFF <-        F 0.001709 (2^-9.192645)
17:        0 <-        0 1.000000 (2^0.000000)
p_tot = 0.000000000000000 = 2^-63.539908
[./tests/tea-add-threshold-search-tests.cc:164] key
key[0] = 0x72AB3584;
key[1] = 0xBC1123CF;
key[2] = 0x1487D2B6;
key[3] = 0x70F2DE4;
[./tests/tea-add-threshold-search-tests.cc:168] Print in LaTeX:

real    13m15.865s
user    13m13.482s
sys     0m0.128s

 */
/* --- */

/*

add-threshold-search.cc:1134] tea_add_trail_search_full()
B[ 0] = 2^0.000000
B[ 1] = 2^-1.018968
B[ 2] = 2^-2.957259
B[ 3] = 2^-6.069958
B[ 4] = 2^-11.801666
B[ 5] = 2^-17.265197
B[ 6] = 2^-20.945037
B[ 7] = 2^-24.207170
B[ 8] = 2^-28.035174
B[ 9] = 2^-32.487802
B[10] = 2^-35.770491
B[11] = 2^-39.306786
B[12] = 2^-42.749709
B[13] = 2^-46.157456
B[14] = 2^-49.921512
B[15] = 2^-53.963286
B[16] = 2^-57.424109
B[17] = 2^-60.899134
B[18] = 2^-64.618808
pDDT sizes: Dp 65, Dxy 65 | hway 356511, croad 345961
 0:        F <-        1 0.136597 (2^-2.872006)
 1:        0 <-        0 1.000000 (2^0.000000)
 2:        F <-        1 0.131805 (2^-2.923518)
 3:        0 <-        F 0.002106 (2^-8.891476)
 4: FFFFFFF1 <-        1 0.135040 (2^-2.888538)
 5:        0 <-        0 1.000000 (2^0.000000)
 6:        F <-        1 0.136627 (2^-2.871683)
 7: FFFFFFFF <-        F 0.003967 (2^-7.977632)
 8:        0 <-        0 1.000000 (2^0.000000)
 9: FFFFFFFF <-        F 0.004028 (2^-7.955606)
 10: FFFFFFF1 <- FFFFFFFF 0.134735 (2^-2.891802)
 11:        0 <-        0 1.000000 (2^0.000000)
 12: FFFFFFF1 <- FFFFFFFF 0.134674 (2^-2.892456)
 13:        1 <- FFFFFFF1 0.004150 (2^-7.912537)
 14:        0 <-        0 1.000000 (2^0.000000)
 15:        1 <- FFFFFFF1 0.004028 (2^-7.955606)
 16:        F <-        1 0.134186 (2^-2.897696)
 17:        0 <-        0 1.000000 (2^0.000000)
 18: FFFFFFF1 <-        1 0.077576 (2^-3.688252)
 p_tot = 0.000000000000000 = 2^-64.618808, Bn = 0.000000 = 2^-64.618808
 [./src/tea-add-threshold-search.cc:1208] nrounds = 19
 [./tests/tea-add-threshold-search-tests.cc:137]
----- End search -----
 [./tests/tea-add-threshold-search-tests.cc:140] Final trail:
 0: FFFFFFF1 <-        1 0.135956 (2^-2.878790)
 1:        0 <-        0 1.000000 (2^0.000000)
 2:        F <-        1 0.134949 (2^-2.889517)
 3:        0 <-        F 0.001892 (2^-9.045804)
 4: FFFFFFF1 <-        1 0.133392 (2^-2.906252)
 5:        0 <-        0 1.000000 (2^0.000000)
 6:        F <-        1 0.135376 (2^-2.884956)
 7:        0 <-        F 0.002014 (2^-8.955606)
 8: FFFFFFF1 <-        1 0.132843 (2^-2.912206)
 9:        0 <-        0 1.000000 (2^0.000000)
 10:       11 <-        1 0.135498 (2^-2.883656)
 11:        0 <-       11 0.002136 (2^-8.870717)
 12: FFFFFFEF <-        1 0.134552 (2^-2.893764)
 13:        0 <-        0 1.000000 (2^0.000000)
 14:       11 <-        1 0.133301 (2^-2.907243)
 15:        0 <-       11 0.002380 (2^-8.714598)
 16: FFFFFFEF <-        1 0.131958 (2^-2.921849)
 17:        0 <-        0 1.000000 (2^0.000000)
 18: FFFFFFF1 <-        1 0.135559 (2^-2.883006)
 p_tot = 0.000000000000000 = 2^-64.547964, Bn = 0.000000 = 2^-64.547964
 [./tests/tea-add-threshold-search-tests.cc:150] Final full trail:
 0:        F <-        1 0.136597 (2^-2.872006)
 1:        0 <-        0 1.000000 (2^0.000000)
 2:        F <-        1 0.131805 (2^-2.923518)
 3:        0 <-        F 0.002106 (2^-8.891476)
 4: FFFFFFF1 <-        1 0.135040 (2^-2.888538)
 5:        0 <-        0 1.000000 (2^0.000000)
 6:        F <-        1 0.136627 (2^-2.871683)
 7: FFFFFFFF <-        F 0.003967 (2^-7.977632)
 8:        0 <-        0 1.000000 (2^0.000000)
 9: FFFFFFFF <-        F 0.004028 (2^-7.955606)
 10: FFFFFFF1 <- FFFFFFFF 0.134735 (2^-2.891802)
 11:        0 <-        0 1.000000 (2^0.000000)
 12: FFFFFFF1 <- FFFFFFFF 0.134674 (2^-2.892456)
 13:        1 <- FFFFFFF1 0.004150 (2^-7.912537)
 14:        0 <-        0 1.000000 (2^0.000000)
 15:        1 <- FFFFFFF1 0.004028 (2^-7.955606)
 16:        F <-        1 0.134186 (2^-2.897696)
 17:        0 <-        0 1.000000 (2^0.000000)
 18: FFFFFFF1 <-        1 0.077576 (2^-3.688252)
p_tot = 0.000000000000000 = 2^-64.618808
 [./tests/tea-add-threshold-search-tests.cc:164] key
 key[0] = 0xE028DF9A;
key[1] = 0x8819B4C3;
key[2] = 0x3AB116AF;
key[3] = 0x3C50723;
[./tests/tea-add-threshold-search-tests.cc:168] Print in LaTeX:

real    37m11.116s
user    35m43.542s
sys     0m1.232s
vpv@igor:~/skcrypto/trunk/work/src/yaarx$
vpv@igor:~/skcrypto/trunk/work/src/yaarx$
vpv@igor:~/skcrypto/trunk/work/src/yaarx$
vpv@igor:~/skcrypto/trunk/work/src/yaarx$
vpv@igor:~/skcrypto/trunk/work/src/yaarx$
*/

/* --- */
/* 

%------------------------
\texttt{key} & \texttt{1B2F30BF} & & \texttt{A8922EEA} & \texttt{DB39318C} & \texttt{FF5F3C72} \\
\toprule
$r$ & $\Delta y$ & & $\Delta x$ & $p$ & $\mathrm{log}_2 p$\\
\midrule
$ 0$ & \texttt{       F} & $\leftarrow$ & \texttt{FFFFFFFF} & $0.130249$ & $2^{-2.94}$ \\
$ 1$ & \texttt{       0} & $\leftarrow$ & \texttt{       0} & $1.000000$ & $2^{0.00}$ \\
$ 2$ & \texttt{FFFFFFEF} & $\leftarrow$ & \texttt{FFFFFFFF} & $0.079865$ & $2^{-3.65}$ \\
$ 3$ & \texttt{       0} & $\leftarrow$ & \texttt{FFFFFFEF} & $0.001068$ & $2^{-9.87}$ \\
$ 4$ & \texttt{      11} & $\leftarrow$ & \texttt{FFFFFFFF} & $0.135529$ & $2^{-2.88}$ \\
$ 5$ & \texttt{       0} & $\leftarrow$ & \texttt{       0} & $1.000000$ & $2^{0.00}$ \\
$ 6$ & \texttt{FFFFFFEF} & $\leftarrow$ & \texttt{FFFFFFFF} & $0.082092$ & $2^{-3.61}$ \\
$ 7$ & \texttt{       2} & $\leftarrow$ & \texttt{FFFFFFEF} & $0.001953$ & $2^{-9.00}$ \\
$ 8$ & \texttt{      11} & $\leftarrow$ & \texttt{       1} & $0.130005$ & $2^{-2.94}$ \\
$ 9$ & \texttt{       0} & $\leftarrow$ & \texttt{       0} & $1.000000$ & $2^{0.00}$ \\
$10$ & \texttt{      11} & $\leftarrow$ & \texttt{       1} & $0.080048$ & $2^{-3.64}$ \\
$11$ & \texttt{FFFFFFFE} & $\leftarrow$ & \texttt{      11} & $0.000793$ & $2^{-10.30}$ \\
$12$ & \texttt{FFFFFFEF} & $\leftarrow$ & \texttt{FFFFFFFF} & $0.136047$ & $2^{-2.88}$ \\
$13$ & \texttt{       0} & $\leftarrow$ & \texttt{       0} & $1.000000$ & $2^{0.00}$ \\
$14$ & \texttt{       F} & $\leftarrow$ & \texttt{FFFFFFFF} & $0.080658$ & $2^{-3.63}$ \\
$15$ & \texttt{FFFFFF01} & $\leftarrow$ & \texttt{       F} & $0.005402$ & $2^{-7.53}$ \\
$16$ & \texttt{FFFFF0F8} & $\leftarrow$ & \texttt{FFFFFF00} & $0.046509$ & $2^{-4.43}$ \\
\midrule
 $\prod_{r}$ & & & & & $2^{-67.30}$ \\
\bottomrule
% TEA_ADD_P_THRES = 0.050000, TEA_ADD_MAX_PDDT_SIZE = 2^25.000000, NROUNDS = 20
% Time: 12.4 min.
 */

/* --- */

/* 
%------------------------
\texttt{key} & \texttt{E028DF9A} & & \texttt{8819B4C3} & \texttt{3AB116AF} & \texttt{ 3C50723} \\
\toprule
$r$ & $\Delta y$ & & $\Delta x$ & $p$ & $\mathrm{log}_2 p$\\
\midrule
$ 0$ & \texttt{       0} & $\leftarrow$ & \texttt{       0} & $1.000000$ & $2^{0.00}$ \\
$ 1$ & \texttt{FFFFFFEF} & $\leftarrow$ & \texttt{FFFFFFFF} & $0.078400$ & $2^{-3.67}$ \\
$ 2$ & \texttt{       0} & $\leftarrow$ & \texttt{FFFFFFEF} & $0.000214$ & $2^{-12.19}$ \\
$ 3$ & \texttt{      11} & $\leftarrow$ & \texttt{FFFFFFFF} & $0.142639$ & $2^{-2.81}$ \\
$ 4$ & \texttt{       0} & $\leftarrow$ & \texttt{       0} & $1.000000$ & $2^{0.00}$ \\
$ 5$ & \texttt{       F} & $\leftarrow$ & \texttt{FFFFFFFF} & $0.079102$ & $2^{-3.66}$ \\
$ 6$ & \texttt{       2} & $\leftarrow$ & \texttt{       F} & $0.001984$ & $2^{-8.98}$ \\
$ 7$ & \texttt{FFFFFFF1} & $\leftarrow$ & \texttt{       1} & $0.134491$ & $2^{-2.89}$ \\
$ 8$ & \texttt{       0} & $\leftarrow$ & \texttt{       0} & $1.000000$ & $2^{0.00}$ \\
$ 9$ & \texttt{       F} & $\leftarrow$ & \texttt{       1} & $0.082306$ & $2^{-3.60}$ \\
$10$ & \texttt{FFFFFFFF} & $\leftarrow$ & \texttt{       F} & $0.004089$ & $2^{-7.93}$ \\
$11$ & \texttt{       0} & $\leftarrow$ & \texttt{       0} & $1.000000$ & $2^{0.00}$ \\
$12$ & \texttt{FFFFFFFF} & $\leftarrow$ & \texttt{       F} & $0.006287$ & $2^{-7.31}$ \\
$13$ & \texttt{FFFFFFF1} & $\leftarrow$ & \texttt{FFFFFFFF} & $0.078949$ & $2^{-3.66}$ \\
$14$ & \texttt{       0} & $\leftarrow$ & \texttt{       0} & $1.000000$ & $2^{0.00}$ \\
$15$ & \texttt{FFFFFFF1} & $\leftarrow$ & \texttt{FFFFFFFF} & $0.136536$ & $2^{-2.87}$ \\
$16$ & \texttt{FFFFFF01} & $\leftarrow$ & \texttt{FFFFFFF1} & $0.047241$ & $2^{-4.40}$ \\
\midrule
 $\prod_{r}$ & & & & & $2^{-64.00}$ \\
\bottomrule
% TEA_ADD_P_THRES = 0.050000, TEA_ADD_MAX_PDDT_SIZE = 2^25.000000, NROUNDS = 20

real    8m31.372s
user    8m30.260s
sys     0m0.124s

 */

/* ---- */

/* 

--- 20130504 ---

B[ 0] = 2^0.000000
B[ 1] = 2^-1.015582
B[ 2] = 2^-2.968580
B[ 3] = 2^-5.347015
B[ 4] = 2^-11.040928
B[ 5] = 2^-16.269840
B[ 6] = 2^-22.465169
B[ 7] = 2^-26.007645
B[ 8] = 2^-29.952421
B[ 9] = 2^-37.059350
B[10] = 2^-41.835323
B[11] = 2^-45.627288
B[12] = 2^-50.860549
B[13] = 2^-54.583891
B[14] = 2^-57.284255
B[15] = 2^-60.032646
B[16] = 2^-64.456162
pDDT sizes: Dp 59, Dxy 59 | Cp 0, Cxy 0
 0:        0 <-        0 1.000000 (2^0.000000)
 1: FFFFFFF1 <-        1 0.083160 (2^-3.587959)
 2:        0 <- FFFFFFF1 0.000305 (2^-11.678072)
 3:        F <-        1 0.141174 (2^-2.824450)
 4:        0 <-        0 1.000000 (2^0.000000)
 5: FFFFFFF1 <-        1 0.080292 (2^-3.638604)
 6: FFFFFFFE <- FFFFFFF1 0.001709 (2^-9.192645)
 7:        F <- FFFFFFFF 0.132507 (2^-2.915856)
 8:        0 <-        0 1.000000 (2^0.000000)
 9: FFFFFFF1 <- FFFFFFFF 0.081970 (2^-3.608756)
10:        1 <- FFFFFFF1 0.003906 (2^-8.000000)
11:        0 <-        0 1.000000 (2^0.000000)
12:        1 <- FFFFFFF1 0.006317 (2^-7.306513)
13:        F <-        1 0.081543 (2^-3.616296)
14:        0 <-        0 1.000000 (2^0.000000)
15: FFFFFFF1 <-        1 0.078918 (2^-3.663493)
16: FFFFFF01 <- FFFFFFF1 0.046600 (2^-4.423516)
p_tot = 0.000000000000000 = 2^-64.456162, Bn = 0.000000 = 2^-64.456162
[./src/tea-add-threshold-search.cc:1202] nrounds = 17
[./tests/tea-add-threshold-search-tests.cc:128]
----- End search -----
[./tests/tea-add-threshold-search-tests.cc:131] Final trail:
0:        0 <-        0 1.000000 (2^0.000000)
1:       11 <-        1 0.080658 (2^-3.632039)
2:        0 <-       11 0.000244 (2^-12.000000)
3: FFFFFFEF <-        1 0.143524 (2^-2.800634)
4:        0 <-        0 1.000000 (2^0.000000)
5:       11 <-        1 0.079285 (2^-3.656814)
6:        0 <-       11 0.000061 (2^-14.000000)
7: FFFFFFEF <-        1 0.138153 (2^-2.855660)
8:        0 <-        0 1.000000 (2^0.000000)
9:       11 <-        1 0.080872 (2^-3.628223)
10:        0 <-       11 0.000244 (2^-12.000000)
11: FFFFFFEF <-        1 0.141815 (2^-2.817916)
12:        0 <-        0 1.000000 (2^0.000000)
13: FFFFFFF1 <-        1 0.080353 (2^-3.637508)
14: FFFFFF01 <- FFFFFFF1 0.011353 (2^-6.460841)
p_tot = 0.000000000000000 = 2^-67.489637, Bn = 0.000000 = 2^-67.489637
[./tests/tea-add-threshold-search-tests.cc:141] Final full trail:
0:        0 <-        0 1.000000 (2^0.000000)
1: FFFFFFF1 <-        1 0.083160 (2^-3.587959)
2:        0 <- FFFFFFF1 0.000305 (2^-11.678072)
3:        F <-        1 0.141174 (2^-2.824450)
4:        0 <-        0 1.000000 (2^0.000000)
5: FFFFFFF1 <-        1 0.080292 (2^-3.638604)
6: FFFFFFFE <- FFFFFFF1 0.001709 (2^-9.192645)
7:        F <- FFFFFFFF 0.132507 (2^-2.915856)
8:        0 <-        0 1.000000 (2^0.000000)
9: FFFFFFF1 <- FFFFFFFF 0.081970 (2^-3.608756)
10:        1 <- FFFFFFF1 0.003906 (2^-8.000000)
11:        0 <-        0 1.000000 (2^0.000000)
12:        1 <- FFFFFFF1 0.006317 (2^-7.306513)
13:        F <-        1 0.081543 (2^-3.616296)
14:        0 <-        0 1.000000 (2^0.000000)
15: FFFFFFF1 <-        1 0.078918 (2^-3.663493)
16: FFFFFF01 <- FFFFFFF1 0.046600 (2^-4.423516)
p_tot = 0.000000000000000 = 2^-64.456162
[./tests/tea-add-threshold-search-tests.cc:155] key
key[0] = 0xE028DF9A;
key[1] = 0x8819B4C3;
key[2] = 0x3AB116AF;
key[3] = 0x3C50723;

real    12m5.335s
user    12m3.229s
sys     0m0.092s

 */

/* --- */

  //  std::multiset<differential_t, struct_comp_diff_p>::iterator find_iter = croads_init_mset_p.begin();
#if 0
  std::set<differential_t, struct_comp_diff_dx_dy>::iterator find_iter = croads_init_set_dx_dy.begin();
  while(find_iter != croads_init_set_dx_dy.end()) {
	 assert(0 == 1);
	 printf("[%s:%d] New entry: %8X %8X 2^%f\n", __FILE__, __LINE__, find_iter->dx, find_iter->dy, log2(find_iter->p));
	 diff_mset_p.insert(*find_iter);
	 diff_set_dx_dy.insert(*find_iter);
	 find_iter++;
  }
#endif

  // init croads with hways
#if 0
  std::set<differential_t, struct_comp_diff_dx_dy>::iterator hway_dx_dy = diff_set_dx_dy.begin();
  while(hway_dx_dy != diff_set_dx_dy.end()) {
	 croads_diff_set_dx_dy.insert(*hway_dx_dy);
	 hway_dx_dy++;
  }
  std::set<differential_t, struct_comp_diff_dx_dy>::iterator hway_p = diff_mset_p.begin();
  while(hway_p != diff_mset_p.end()) {
	 croads_diff_mset_p.insert(*hway_p);
	 hway_p++;
  }
#endif

#if 0									  // TEST
  //  3:        0 <-        F 0.003937 (2^-7.988773)
  //  differential_t tmp_diff = {0xFFFFFFF1, 0xFFFFFFFF, 0, 0.00381};
  differential_t tmp_diff = {0xF, 0x0, 0, 0.003973};
  croads_diff_set_dx_dy.insert(tmp_diff);
  croads_diff_mset_p.insert(tmp_diff);
#endif

  printf("AFTER Initial set sizes: Dp %d, Dxy %d\n", diff_mset_p.size(), diff_set_dx_dy.size());
  //  assert(diff_set_dx_dy.size() == diff_mset_p.size());


/* --- */

#if 0
	 if(nrounds == 7) {
		//	 if(nrounds == (NROUNDS - 1)) {
	 //		printf("[%s:%d] Dp:\n", __FILE__, __LINE__);
	 //		print_mset(diff_mset_p);
		printf("[%s:%d] Dxy:\n", __FILE__, __LINE__);
		print_set(diff_set_dx_dy);
		printf("\n");
	 }
#endif


/* --- */

  //  for(uint32_t nrounds = 1; nrounds <= NROUNDS; nrounds++ ) {
  //  bool b_start = false;
	 //	 for(uint32_t i = 0; i < 2; i++) { // first two rounds
	 //		if(trail[i].p < TEA_ADD_P_THRES) {
	 //		  croads_init_set_dx_dy->insert(trail[i]);
	 //		}
	 //	 }


/* --- */

/* 
B[ 1] = 2^-1.452382
B[ 2] = 2^-2.904283
B[ 3] = 2^-6.655170
B[ 4] = 2^-10.950524
B[ 5] = 2^-16.377181
B[ 6] = 2^-25.154256
B[ 7] = 2^-28.753910
B[ 8] = 2^-35.549339
B[ 9] = 2^-38.775611
B[10] = 2^-41.594769
B[11] = 2^-47.266094
B[12] = 2^-53.137958
B[13] = 2^-53.137958
B[14] = 2^-56.009320
B[15] = 2^-62.198748
B[16] = 2^-63.905545
pDDT sizes: Dp 66, Dxy 66 | Cp 0, Cxy 0
 0: FFFFFFF1 <- FFFFFFFF 0.082031 (2^-3.607683)
 1:        0 <-        0 1.000000 (2^0.000000)
 2: FFFFFFF1 <- FFFFFFFF 0.143433 (2^-2.801555)
 3:        1 <- FFFFFFF1 0.001312 (2^-9.573735)
 4:        0 <-        0 1.000000 (2^0.000000)
 5:        1 <- FFFFFFF1 0.005005 (2^-7.642448)
 6:        F <-        1 0.134827 (2^-2.890822)
 7:        0 <-        0 1.000000 (2^0.000000)
 8: FFFFFFEF <-        1 0.077148 (2^-3.696219)
 9: FFFFFFFE <- FFFFFFEF 0.001984 (2^-8.977632)
10:       11 <- FFFFFFFF 0.141052 (2^-2.825698)
11:        0 <-        0 1.000000 (2^0.000000)
12: FFFFFFF1 <- FFFFFFFF 0.079926 (2^-3.645200)
13:        2 <- FFFFFFF1 0.000305 (2^-11.678072)
14:        F <-        1 0.136169 (2^-2.876525)
15:        0 <-        0 1.000000 (2^0.000000)
16: FFFFFFF1 <-        1 0.077484 (2^-3.689955)
p_tot = 0.000000000000000 = 2^-63.905545, Bn = 0.000000 = 2^-63.905545
[./src/tea-add-threshold-search.cc:1257] nrounds = 17
[./tests/tea-add-threshold-search-tests.cc:120]
----- End search -----
[./tests/tea-add-threshold-search-tests.cc:123] Final trail:
0: FFFFFF01 <- FFFFFFF1 0.008209 (2^-6.928538)
1:        F <-        1 0.140564 (2^-2.830701)
2:        0 <-        0 1.000000 (2^0.000000)
3:        F <-        1 0.079834 (2^-3.646853)
4:        0 <-        F 0.002136 (2^-8.870717)
5: FFFFFFF1 <-        1 0.127441 (2^-2.972094)
6:        0 <-        0 1.000000 (2^0.000000)
7:        F <-        1 0.083679 (2^-3.578987)
8:        0 <-        F 0.004242 (2^-7.881059)
9: FFFFFFF1 <-        1 0.134552 (2^-2.893764)
10:        0 <-        0 1.000000 (2^0.000000)
11:       11 <-        1 0.081360 (2^-3.619539)
12:        0 <-       11 0.000092 (2^-13.415037)
13: FFFFFFEF <-        1 0.124725 (2^-3.003173)
14:        0 <-        0 1.000000 (2^0.000000)
15: FFFFFFF1 <-        1 0.084503 (2^-3.564851)
16: FFFFFF01 <- FFFFFFF1 0.017334 (2^-5.850253)
p_tot = 0.000000000000000 = 2^-69.055567, Bn = 0.000000 = 2^-69.055567
[./tests/tea-add-threshold-search-tests.cc:133] Final full trail:
0: FFFFFFF1 <- FFFFFFFF 0.082031 (2^-3.607683)
1:        0 <-        0 1.000000 (2^0.000000)
2: FFFFFFF1 <- FFFFFFFF 0.143433 (2^-2.801555)
3:        1 <- FFFFFFF1 0.001312 (2^-9.573735)
4:        0 <-        0 1.000000 (2^0.000000)
5:        1 <- FFFFFFF1 0.005005 (2^-7.642448)
6:        F <-        1 0.134827 (2^-2.890822)
7:        0 <-        0 1.000000 (2^0.000000)
8: FFFFFFEF <-        1 0.077148 (2^-3.696219)
9: FFFFFFFE <- FFFFFFEF 0.001984 (2^-8.977632)
10:       11 <- FFFFFFFF 0.141052 (2^-2.825698)
11:        0 <-        0 1.000000 (2^0.000000)
12: FFFFFFF1 <- FFFFFFFF 0.079926 (2^-3.645200)
13:        2 <- FFFFFFF1 0.000305 (2^-11.678072)
14:        F <-        1 0.136169 (2^-2.876525)
15:        0 <-        0 1.000000 (2^0.000000)
16: FFFFFFF1 <-        1 0.077484 (2^-3.689955)
p_tot = 0.000000000000000 = 2^-63.905545
[./tests/tea-add-threshold-search-tests.cc:147] key
key[0] = 0xD7A62B66;
key[1] = 0x6E8BE71C;
key[2] = 0x80ABE91A;
key[3] = 0x90CF01B8;

real    25m56.346s
user    25m51.521s
sys     0m0.260s

 */


/* --- */

/* 
--- 20130502 ---

----- End search -----


B[ 0] = 2^0.000000
B[ 1] = 2^-1.025675
B[ 2] = 2^-2.047143
B[ 3] = 2^-5.374837
B[ 4] = 2^-11.139214
B[ 5] = 2^-16.349632
B[ 6] = 2^-24.744992
B[ 7] = 2^-34.341126
B[ 8] = 2^-37.832785
B[ 9] = 2^-41.460464
B[10] = 2^-47.746218
B[11] = 2^-53.235311
B[12] = 2^-58.940618
B[13] = 2^-62.552062
B[14] = 2^-69.068246
pDDT sizes: Dp 70, Dxy 970
 0:        0 <-        0 1.000000 (2^0.000000)
 1:       11 <-        1 0.081573 (2^-3.615756)
 2:        0 <-       11 0.000366 (2^-11.415037)
 3: FFFFFFEF <-        1 0.137573 (2^-2.861728)
 4:        0 <-        0 1.000000 (2^0.000000)
 5:       11 <-        1 0.080048 (2^-3.642998)
 6:        0 <-       11 0.000031 (2^-15.000000)
 7: FFFFFFEF <-        1 0.136169 (2^-2.876525)
 8:        0 <-        0 1.000000 (2^0.000000)
 9:       11 <-        1 0.078735 (2^-3.666845)
10:        0 <-       11 0.000122 (2^-13.000000)
11: FFFFFFEF <-        1 0.137573 (2^-2.861728)
12:        0 <-        0 1.000000 (2^0.000000)
13: FFFFFFF1 <-        1 0.081818 (2^-3.611444)
14: FFFFFF01 <- FFFFFFF1 0.010925 (2^-6.516184)
p_tot = 0.000000000000000 = 2^-69.068246, Bn = 0.000000 = 2^-69.068246
[./src/tea-add-threshold-search.cc:1007] nrounds = 15

B[ 1] = 2^-1.025675
B[ 2] = 2^-2.947447
B[ 3] = 2^-5.358153
B[ 4] = 2^-11.073147
B[ 5] = 2^-16.258083
B[ 6] = 2^-22.527780
B[ 7] = 2^-26.176521
B[ 8] = 2^-29.813514
B[ 9] = 2^-36.823907
B[10] = 2^-41.821149
B[11] = 2^-44.885821
B[12] = 2^-51.655097
B[13] = 2^-54.023713
B[14] = 2^-58.803057
B[15] = 2^-62.489731
B[16] = 2^-67.229988
pDDT sizes: Dp 58, Dxy 58 | Cp 0, Cxy 0
 0:        0 <-        0 1.000000 (2^0.000000)
 1:        F <-        1 0.079376 (2^-3.655149)
 2:        0 <-        F 0.000305 (2^-11.678072)
 3: FFFFFFF1 <-        1 0.141052 (2^-2.825698)
 4:        0 <-        0 1.000000 (2^0.000000)
 5: FFFFFFF1 <-        1 0.079895 (2^-3.645751)
 6: FFFFFFFE <- FFFFFFF1 0.002106 (2^-8.891476)
 7:        F <- FFFFFFFF 0.132599 (2^-2.914860)
 8:        0 <-        0 1.000000 (2^0.000000)
 9: FFFFFFF1 <- FFFFFFFF 0.083618 (2^-3.580040)
10:        2 <- FFFFFFF1 0.000763 (2^-10.356144)
11:        F <-        1 0.141510 (2^-2.821024)
12:        0 <-        0 1.000000 (2^0.000000)
13:        F <-        1 0.080811 (2^-3.629313)
14: FFFFFFFF <-        F 0.002777 (2^-8.492205)
15:        0 <-        0 1.000000 (2^0.000000)
16: FFFFFF01 <-        F 0.037415 (2^-4.740257)
p_tot = 0.000000000000000 = 2^-67.229988, Bn = 0.000000 = 2^-67.229988
[./src/tea-add-threshold-search.cc:1257] nrounds = 17

key[0] = 0xE028DF9A;
key[1] = 0x8819B4C3;
key[2] = 0x3AB116AF;
key[3] = 0x3C50723;

real    10m25.708s
user    10m23.783s
sys     0m0.120s


 */

/* --- */

#if 0									  // DEBUG
  if(n >= 5) {
	 double p_tot = 1.0;
	 printf("[%s:%d] diff[%2d]:\n", __FILE__, __LINE__, n);
	 for(int i = 0; i < n; i++) {
		printf("%2d: %8X <- %8X %f (2^%f)\n", i, diff[i].dy, diff[i].dx, diff[i].p, log2(diff[i].p));
		p_tot *= diff[i].p;
	 }
	 printf("p_tot = %16.15f = 2^%f, Bn = %f = 2^%f\n", p_tot, log2(p_tot), *Bn, log2(*Bn));
  }
#endif  // #if 0									  // DEBUG


/* --- */

#if 0									  // OLD
	 if(b_found_in_hways) {
		//		while(hway_iter->dx == dx) {
		while((hway_iter->dx == dx) && (hway_iter->p >= p_min)) {
		  found_mset_p.insert(*hway_iter);
		  hway_iter++;
		}
#if 1
		assert(cnt_lp <= max_lp);
		if((b_found_in_croads) && (cnt_lp <= max_lp)) {
		  //		  while(croad_iter->dx == dx) {
		  while((croad_iter->dx == dx) && (croad_iter->p >= p_min)) {

			 uint32_t dy = croad_iter->dy;
			 uint32_t dx_prev = diff[n - 1].dx;
			 bool b_is_hway = is_dx_in_set_dx_dy(dy, dx_prev, *diff_set_dx_dy);
			 if(b_is_hway) {
				found_mset_p.insert(*croad_iter);
			 }
			 croad_iter++;
		  }
		}
#endif
	 } else {
		if(b_found_in_croads) {
		  //		  while(croad_iter->dx == dx) {
		  while((croad_iter->dx == dx) && (croad_iter->p >= p_min)) {

			 uint32_t dy = croad_iter->dy;
			 uint32_t dx_prev = diff[n - 1].dx;
			 bool b_is_hway = is_dx_in_set_dx_dy(dy, dx_prev, *diff_set_dx_dy);
			 //			 assert(b_is_hway);
			 if(b_is_hway) {
				found_mset_p.insert(*croad_iter);
			 }
			 croad_iter++;
		  }
		}
	 }
#endif  // OLD



/* --- */

#if 0
	 if(b_found_in_croads) {
		std::set<differential_t, struct_comp_diff_dx_dy>::iterator tmp_iter = croad_iter;
		double p_tmp_min = 1.0;
		while(tmp_iter->dx == dx) {
		  if(tmp_iter->p < p_tmp_min) {
			 p_tmp_min = tmp_iter->p;
		  }
		  tmp_iter++;
		}
		if(p_tmp_min > p_min) {
		  b_found_in_croads = false;
		}
	 }
	 if(b_found_in_hways) {
		std::set<differential_t, struct_comp_diff_dx_dy>::iterator tmp_iter = hway_iter;
		double p_tmp_min = 1.0;
		while(tmp_iter->dx == dx) {
		  if(tmp_iter->p < p_tmp_min) {
			 p_tmp_min = tmp_iter->p;
		  }
		  tmp_iter++;
		}
		if(p_tmp_min > p_min) {
		  b_found_in_hways = false;
		}
	 }
#endif



/* --- */

/* 
	[./src/tea-add-threshold-search.cc:663] [ 2 / 20]: Added 1 new country roads: p_min = 0.001154 (2^-9.758922). New sizes: Dxy 30011, Dp 30014 (cnt_lp 0 / 2).B[ 0] = 2^0.000000
B[ 1] = 2^-1.157159
B[ 2] = 2^-2.323873
B[ 3] = 2^-6.085142
B[ 4] = 2^-9.979185
B[ 5] = 2^-14.746161
B[ 6] = 2^-22.618143
B[ 7] = 2^-30.641573
B[ 8] = 2^-34.309724
B[ 9] = 2^-38.402913
B[10] = 2^-45.613117
B[11] = 2^-48.407404
B[12] = 2^-50.295533
B[13] = 2^-53.175619
B[14] = 2^-59.553567
B[15] = 2^-67.373658
pDDT sizes: Dp 69, Dxy 254 | Cp 30014, Cxy 30011
 0:        0 <-        0 1.000000 (2^0.000000)
 1: FFFFFFF1 <- FFFFFFFF 0.126526 (2^-2.982496)
 2:        1 <- FFFFFFF1 0.004120 (2^-7.923184)
 3:        0 <-        0 1.000000 (2^0.000000)
 4:        0 <- FFFFFFF1 0.000092 (2^-13.415037)
 5:        0 <-        0 1.000000 (2^0.000000)
 6:        1 <- FFFFFFF1 0.003876 (2^-8.011315)
 7:        F <-        1 0.083649 (2^-3.579513)
 8:        0 <-        0 1.000000 (2^0.000000)
 9: FFFFFFF1 <-        1 0.129517 (2^-2.948791)
10:        0 <- FFFFFFF1 0.004517 (2^-7.790547)
11:        F <-        1 0.079956 (2^-3.644649)
12:        0 <-        0 1.000000 (2^0.000000)
13: FFFFFFF1 <-        1 0.135834 (2^-2.880086)
14: FFFFFF01 <- FFFFFFF1 0.012024 (2^-6.377948)
15: FFFFF0E6 <- FFFFFF02 0.004425 (2^-7.820091)
p_tot = 0.000000000000000 = 2^-67.373658, Bn = 0.000000 = 2^-67.373658
[./src/tea-add-threshold-search.cc:1313] nrounds = 16
[./tests/tea-add-threshold-search-tests.cc:120]
----- End search -----
[./tests/tea-add-threshold-search-tests.cc:123] Final trail:
0:        0 <-        0 1.000000 (2^0.000000)
1: FFFFFFF1 <- FFFFFFFF 0.127716 (2^-2.968988)
2:        1 <- FFFFFFF1 0.004883 (2^-7.678072)
3:        0 <-        0 1.000000 (2^0.000000)
4:        1 <- FFFFFFF1 0.000061 (2^-14.000000)
5:        F <-        1 0.135651 (2^-2.882032)
6:        0 <-        0 1.000000 (2^0.000000)
7: FFFFFFF1 <-        1 0.083832 (2^-3.576359)
8:        1 <- FFFFFFF1 0.000930 (2^-10.071235)
9: FFFFFFE2 <-        2 0.080872 (2^-3.628223)
10: FFFFFD04 <- FFFFFFD3 0.001434 (2^-9.445411)
11:     2C82 <- FFFFFD06 0.000946 (2^-10.045804)
p_tot = 0.000000000000000 = 2^-64.296124, Bn = 0.000000 = 2^-64.296124
[./tests/tea-add-threshold-search-tests.cc:133] Final full trail:
0:        0 <-        0 1.000000 (2^0.000000)
1: FFFFFFF1 <- FFFFFFFF 0.126526 (2^-2.982496)
2:        1 <- FFFFFFF1 0.004120 (2^-7.923184)
3:        0 <-        0 1.000000 (2^0.000000)
4:        0 <- FFFFFFF1 0.000092 (2^-13.415037)
5:        0 <-        0 1.000000 (2^0.000000)
6:        1 <- FFFFFFF1 0.003876 (2^-8.011315)
7:        F <-        1 0.083649 (2^-3.579513)
8:        0 <-        0 1.000000 (2^0.000000)
9: FFFFFFF1 <-        1 0.129517 (2^-2.948791)
10:        0 <- FFFFFFF1 0.004517 (2^-7.790547)
11:        F <-        1 0.079956 (2^-3.644649)
12:        0 <-        0 1.000000 (2^0.000000)
13: FFFFFFF1 <-        1 0.135834 (2^-2.880086)
14: FFFFFF01 <- FFFFFFF1 0.012024 (2^-6.377948)
15: FFFFF0E6 <- FFFFFF02 0.004425 (2^-7.820091)
p_tot = 0.000000000000000 = 2^-67.373658
[./tests/tea-add-threshold-search-tests.cc:147] key
key[0] = 0xEBFC4336;
key[1] = 0xD0D3E14E;
key[2] = 0xE11CB47B;
key[3] = 0x2FFCBD53;

real    100m3.717s
user    99m52.683s
sys     0m0.076s

 */

/* ---- */

/* 
B[ 1] = 2^-1.780831
B[ 2] = 2^-3.568639
B[ 3] = 2^-6.662124
B[ 4] = 2^-10.401919
B[ 5] = 2^-16.199817
B[ 6] = 2^-20.882737
B[ 7] = 2^-26.076804
B[ 8] = 2^-29.293863
B[ 9] = 2^-33.559550
B[10] = 2^-39.028401
B[11] = 2^-44.447186
B[12] = 2^-50.559373
B[13] = 2^-53.949501
B[14] = 2^-57.907229
B[15] = 2^-62.249923
B[16] = 2^-67.311782
pDDT sizes: Dp 61, Dxy 61 | Cp 1157, Cxy 1157
 0:        F <- FFFFFFFF 0.128540 (2^-2.959710)
 1:        0 <-        0 1.000000 (2^0.000000)
 2:        F <- FFFFFFFF 0.081024 (2^-3.625504)
 3:        0 <-        F 0.003723 (2^-8.069263)
 4: FFFFFFF1 <- FFFFFFFF 0.132751 (2^-2.913200)
 5:        0 <-        0 1.000000 (2^0.000000)
 6: FFFFFFEF <- FFFFFFFF 0.080933 (2^-3.627135)
 7:        0 <- FFFFFFEF 0.000153 (2^-12.678072)
 8:       11 <- FFFFFFFF 0.125732 (2^-2.991571)
 9:        0 <-        0 1.000000 (2^0.000000)
10: FFFFFFF1 <- FFFFFFFF 0.081848 (2^-3.610906)
11:        1 <- FFFFFFF1 0.000275 (2^-11.830075)
12:        0 <-        0 1.000000 (2^0.000000)
13:        1 <- FFFFFFF1 0.004486 (2^-7.800328)
14:        F <-        1 0.086456 (2^-3.531885)
15:        0 <-        0 1.000000 (2^0.000000)
16: FFFFFFF1 <-        1 0.078339 (2^-3.674132)
p_tot = 0.000000000000000 = 2^-67.311782, Bn = 0.000000 = 2^-67.311782
[./src/tea-add-threshold-search.cc:1289] nrounds = 17
[./tests/tea-add-threshold-search-tests.cc:108]
----- End search -----
[./tests/tea-add-threshold-search-tests.cc:110] Final trail:
0: FFFFFFF1 <-        1 0.129089 (2^-2.953558)
1:        0 <-        0 1.000000 (2^0.000000)
2:        F <-        1 0.080170 (2^-3.640800)
3:        0 <-        F 0.004059 (2^-7.944718)
4: FFFFFFF1 <-        1 0.132782 (2^-2.912869)
5:        0 <-        0 1.000000 (2^0.000000)
6:       11 <-        1 0.083099 (2^-3.589019)
7:        0 <-       11 0.000122 (2^-13.000000)
8: FFFFFFEF <-        1 0.125000 (2^-3.000000)
9:        0 <-        0 1.000000 (2^0.000000)
10:       11 <-        1 0.079346 (2^-3.655704)
11:        0 <-       11 0.000153 (2^-12.678072)
12: FFFFFFEF <-        1 0.135986 (2^-2.878466)
13:        0 <-        0 1.000000 (2^0.000000)
14: FFFFFFF1 <-        1 0.084381 (2^-3.566936)
15: FFFFFF01 <- FFFFFFF1 0.005829 (2^-7.422571)
p_tot = 0.000000000000000 = 2^-67.242712, Bn = 0.000000 = 2^-67.242712
[./tests/tea-add-threshold-search-tests.cc:120] Final full trail:
0:        F <- FFFFFFFF 0.128540 (2^-2.959710)
1:        0 <-        0 1.000000 (2^0.000000)
2:        F <- FFFFFFFF 0.081024 (2^-3.625504)
3:        0 <-        F 0.003723 (2^-8.069263)
4: FFFFFFF1 <- FFFFFFFF 0.132751 (2^-2.913200)
5:        0 <-        0 1.000000 (2^0.000000)
6: FFFFFFEF <- FFFFFFFF 0.080933 (2^-3.627135)
7:        0 <- FFFFFFEF 0.000153 (2^-12.678072)
8:       11 <- FFFFFFFF 0.125732 (2^-2.991571)
9:        0 <-        0 1.000000 (2^0.000000)
10: FFFFFFF1 <- FFFFFFFF 0.081848 (2^-3.610906)
11:        1 <- FFFFFFF1 0.000275 (2^-11.830075)
12:        0 <-        0 1.000000 (2^0.000000)
13:        1 <- FFFFFFF1 0.004486 (2^-7.800328)
14:        F <-        1 0.086456 (2^-3.531885)
15:        0 <-        0 1.000000 (2^0.000000)
16: FFFFFFF1 <-        1 0.078339 (2^-3.674132)
p_tot = 0.000000000000000 = 2^-67.311782
[./tests/tea-add-threshold-search-tests.cc:134] key
key[0] = 0xD0C6E176;
key[1] = 0x35C21E2;
key[2] = 0xA52FFD16;
key[3] = 0x22075F;

real    22m15.883s
user    22m13.675s
sys     0m0.004s

 */

/* --- */

#if 0
	 if(dx == 0xF) {
		printf("[%s:%d] dx = %8X, b_found_in_hways = %d, b_found_in_croads = %d\n", __FILE__, __LINE__, dx, b_found_in_hways, b_found_in_croads);
		if(b_found_in_hways) {
		  std::set<differential_t, struct_comp_diff_dx_dy>::iterator tmp_iter = hway_iter;
		  while(tmp_iter->dx == dx) {
			 printf("Hway: %8X %8X 2^%f\n", tmp_iter->dx, tmp_iter->dy, log2(tmp_iter->p));
			 tmp_iter++;
		  }
		  assert(1 == 0);
		}
		if(b_found_in_croads) {
		  std::set<differential_t, struct_comp_diff_dx_dy>::iterator tmp_iter = croad_iter;
		  while(tmp_iter->dx == dx) {
			 printf("Croad: %8X %8X 2^%f\n", tmp_iter->dx, tmp_iter->dy, log2(tmp_iter->p));
			 tmp_iter++;
		  }
		  assert(1 == 0);
		}
	 }
#endif



/* --- */

#if 0
		  double p_min = diff_mset_p->rbegin()->p;
		  if(diff_max_dy.p >= p_min) {
			 diff_mset_p->insert(diff_max_dy);
		  }

		  diff_set_dx_dy->insert(diff_max_dy);
		  find_iter = diff_set_dx_dy->lower_bound(diff_max_dy);
#endif

/* --- */

/* 
B[ 0] = 2^0.000000
B[ 1] = 2^-1.774943
B[ 2] = 2^-3.567166
B[ 3] = 2^-6.612243
B[ 4] = 2^-10.358473
B[ 5] = 2^-16.049647
pDDT sizes: Dp 61, Dxy 792
 0: 40200000 <- 84000000 0.053040 (2^-4.236788)
 1: 7C000000 <- 80000000 0.492554 (2^-1.021647)
 2:        0 <-        0 1.000000 (2^0.000000)
 3: 84000000 <- 80000000 0.493835 (2^-1.017898)
 4: 40200000 <- 84000000 0.064117 (2^-3.963140)
 5: 3FE10000 <- C0200000 0.017822 (2^-5.810175)
p_tot = 0.000014742621785 = 2^-16.049647, Bn = 0.000015 = 2^-16.049647
[./src/tea-add-threshold-search.cc:922] nrounds = 7, Bn_init = 2^-25.692095 : key D0C6E176  35C21E2 A52FFD16   22075F
[./src/tea-add-threshold-search.cc:415] 6 | Update best found Bn: 2^-25.692095 -> 2^-25.493739
[./src/tea-add-threshold-search.cc:415] 6 | Update best found Bn: 2^-25.493739 -> 2^-21.316415
[./src/tea-add-threshold-search.cc:415] 6 | Update best found Bn: 2^-21.316415 -> 2^-21.188798
[./src/tea-add-threshold-search.cc:415] 6 | Update best found Bn: 2^-21.188798 -> 2^-21.145673
[./src/tea-add-threshold-search.cc:415] 6 | Update best found Bn: 2^-21.145673 -> 2^-21.084973
B[ 0] = 2^0.000000
B[ 1] = 2^-1.774943
B[ 2] = 2^-3.567166
B[ 3] = 2^-6.612243
B[ 4] = 2^-10.358473
B[ 5] = 2^-16.049647
B[ 6] = 2^-21.084973
pDDT sizes: Dp 62, Dxy 833
0:       11 <-        1 0.129028 (2^-2.954240)
1:        0 <-        0 1.000000 (2^0.000000)
2:        F <-        1 0.078583 (2^-3.669643)
3:        0 <-        F 0.004150 (2^-7.912537)
4: FFFFFFF1 <-        1 0.135681 (2^-2.881708)
5:        0 <-        0 1.000000 (2^0.000000)
6: FFFFFFF1 <-        1 0.078735 (2^-3.666845)
p_tot = 0.000000449563051 = 2^-21.084973, Bn = 0.000000 = 2^-21.084973
[
 */

/* --- */

/* 
	[./src/tea-add-threshold-search.cc:1154] nrounds = 17, Bn_init = 2^-63.963444 (B[16] = 2^-63.963444) : key E028DF9A 8819B4C3 3AB116AF  3C50723
B[ 0] = 2^0.000000
B[ 1] = 2^-1.025765
B[ 2] = 2^-2.054760
B[ 3] = 2^-5.340930
B[ 4] = 2^-11.095515
B[ 5] = 2^-16.449275
B[ 6] = 2^-22.433299
B[ 7] = 2^-26.481824
B[ 8] = 2^-30.985529
B[ 9] = 2^-35.000608
B[10] = 2^-42.426625
B[11] = 2^-45.555558
B[12] = 2^-50.359177
B[13] = 2^-54.416056
B[14] = 2^-56.691743
B[15] = 2^-59.593711
B[16] = 2^-63.963444
pDDT sizes: Dp 57, Dxy 123 | Cp 892, Cxy 892
 0:        0 <-        0 1.000000 (2^0.000000)
 1:        F <-        1 0.080200 (2^-3.640250)
 2:        0 <-        F 0.000214 (2^-12.192645)
 3: FFFFFFF1 <-        1 0.142303 (2^-2.812957)
 4:        0 <-        0 1.000000 (2^0.000000)
 5: FFFFFFF1 <-        1 0.082031 (2^-3.607683)
 6: FFFFFFFE <- FFFFFFF1 0.002258 (2^-8.790547)
 7:        F <- FFFFFFFF 0.139465 (2^-2.842022)
 8:        0 <-        0 1.000000 (2^0.000000)
 9: FFFFFFF1 <- FFFFFFFF 0.077820 (2^-3.683718)
10:        1 <- FFFFFFF1 0.004272 (2^-7.870717)
11:        0 <-        0 1.000000 (2^0.000000)
12:        1 <- FFFFFFF1 0.005005 (2^-7.642448)
13:        F <-        1 0.081970 (2^-3.608756)
14:        0 <-        0 1.000000 (2^0.000000)
15: FFFFFFF1 <-        1 0.133789 (2^-2.901968)
16: FFFFFF01 <- FFFFFFF1 0.048370 (2^-4.369733)
p_tot = 0.000000000000000 = 2^-63.963444, Bn = 0.000000 = 2^-63.963444
[./src/tea-add-threshold-search.cc:1238] nrounds = 17
[./tests/tea-add-threshold-search-tests.cc:101]
----- End search -----
[./tests/tea-add-threshold-search-tests.cc:103] Final trail:
0:        0 <-        0 1.000000 (2^0.000000)
1:        F <-        1 0.079254 (2^-3.657370)
2:        0 <-        F 0.000183 (2^-12.415037)
3: FFFFFFF1 <-        1 0.139069 (2^-2.846131)
4:        0 <-        0 1.000000 (2^0.000000)
5:       11 <-        1 0.079773 (2^-3.647957)
6:        0 <-       11 0.000031 (2^-15.000000)
7: FFFFFFEF <-        1 0.134125 (2^-2.898353)
8:        0 <-        0 1.000000 (2^0.000000)
9:       11 <-        1 0.080170 (2^-3.640800)
10:        0 <-       11 0.000153 (2^-12.678072)
11: FFFFFFEF <-        1 0.142181 (2^-2.814195)
12:        0 <-        0 1.000000 (2^0.000000)
13: FFFFFFF1 <-        1 0.082947 (2^-3.591670)
p_tot = 0.000000000000000 = 2^-63.189585, Bn = 0.000000 = 2^-63.189585
[./tests/tea-add-threshold-search-tests.cc:113] Final full trail:
0:        0 <-        0 1.000000 (2^0.000000)
1:        F <-        1 0.080200 (2^-3.640250)
2:        0 <-        F 0.000214 (2^-12.192645)
3: FFFFFFF1 <-        1 0.142303 (2^-2.812957)
4:        0 <-        0 1.000000 (2^0.000000)
5: FFFFFFF1 <-        1 0.082031 (2^-3.607683)
6: FFFFFFFE <- FFFFFFF1 0.002258 (2^-8.790547)
7:        F <- FFFFFFFF 0.139465 (2^-2.842022)
8:        0 <-        0 1.000000 (2^0.000000)
9: FFFFFFF1 <- FFFFFFFF 0.077820 (2^-3.683718)
10:        1 <- FFFFFFF1 0.004272 (2^-7.870717)
11:        0 <-        0 1.000000 (2^0.000000)
12:        1 <- FFFFFFF1 0.005005 (2^-7.642448)
13:        F <-        1 0.081970 (2^-3.608756)
14:        0 <-        0 1.000000 (2^0.000000)
15: FFFFFFF1 <-        1 0.133789 (2^-2.901968)
16: FFFFFF01 <- FFFFFFF1 0.048370 (2^-4.369733)
p_tot = 0.000000000000000 = 2^-63.963444
[./tests/tea-add-threshold-search-tests.cc:127] key
key[0] = 0xE028DF9A;
key[1] = 0x8819B4C3;
key[2] = 0x3AB116AF;
key[3] = 0x3C50723;

real    3m3.881s
user    3m3.555s
sys     0m0.012s

 */


/* --- */

#if 0									  // DEBUG
		if(cnt_new == 0)
		  assert(b_found_in_croads == false);
		else
		  assert(b_found_in_croads == true);
#endif

/* --- */

#if 0
	 if(b_found_in_croads) {
		std::set<differential_t, struct_comp_diff_dx_dy>::iterator tmp_iter = croad_iter;
		double p_tmp_min = 1.0;
		while(tmp_iter->dx == dx) {
		  if(tmp_iter->p < p_tmp_min) {
			 p_tmp_min = tmp_iter->p;
		  }
		  tmp_iter++;
		}
		if(p_tmp_min < p_min) {
		  b_found_in_croads = false;
		}
	 }
#endif


/* --- */

#if 1									  // TEST
  //  differential_t tmp_diff = {0xFFFFFFF1, 0xFFFFFFFF, 0, 0.00381};
  differential_t tmp_diff = {0xF, 0x1, 0, 0.003973};
  //  croads_diff_set_dx_dy.insert(tmp_diff);
  //  croads_diff_mset_p.insert(tmp_diff);
#endif


/* ---- */
	 std::set<differential_t, struct_comp_diff_dx_dy>::iterator croad_dx_dy = croads_diff_set_dx_dy.find(tmp_diff);
	 std::set<differential_t, struct_comp_diff_dx_dy>::iterator hway_dx_dy = diff_set_dx_dy.find(tmp_diff);

	 bool b_croad_found = (croads_diff_set_dx_dy.find(tmp_diff) != croads_diff_set_dx_dy.end());
	 bool b_hway_found = (diff_set_dx_dy.find(tmp_diff) != diff_set_dx_dy.end());

	 if(b_croad_found) {
		printf("\n[%s:%d] R%2d %8X %8X 2^%f | ", __FILE__, __LINE__, nrounds, croad_dx_dy->dx, croad_dx_dy->dy, log2(croad_dx_dy->p));
		printf("%8X %8X 2^%f\n", tmp_diff.dx, tmp_diff.dy, log2(tmp_diff.p));
		assert(1 == 0);
	 }
	 if(b_hway_found) {
		printf("\n[%s:%d] R%2d %8X %8X 2^%f | ", __FILE__, __LINE__, nrounds, hway_dx_dy->dx, hway_dx_dy->dy, log2(hway_dx_dy->p));
		printf("%8X %8X 2^%f\n", tmp_diff.dx, tmp_diff.dy, log2(tmp_diff.p));
		assert(1 == 0);
	 }

	 //	 if(nrounds == (NROUNDS - 1)) {
	 //		printf("[%s:%d] Dp:\n", __FILE__, __LINE__);
	 //		print_mset(diff_mset_p);
	 //		printf("[%s:%d] Dxy:\n", __FILE__, __LINE__);
	 //		print_set(diff_set_dx_dy);
	 //		printf("\n");
	 //	 }



/* --- */

/*

----- End search -----
[./tests/tea-add-threshold-search-tests.cc:103] Final trail:
0:       11 <-        1 0.080353 (2^-3.637508)
1:        0 <-        0 1.000000 (2^0.000000)
2:        F <-        1 0.138214 (2^-2.855023)
3:        0 <-        F 0.000031 (2^-15.000000)
4: FFFFFFF1 <-        1 0.081268 (2^-3.621163)
5:        0 <-        0 1.000000 (2^0.000000)
6: FFFFFFF1 <-        1 0.136566 (2^-2.872328)
7:        1 <- FFFFFFF1 0.000930 (2^-10.071235)
8: FFFFFFE2 <-        2 0.099609 (2^-3.327575)
9: FFFFFD04 <- FFFFFFD3 0.000549 (2^-10.830075)
10:     2C82 <- FFFFFD06 0.000854 (2^-10.192645)
11:        0 <-     2C55 0.000000 (2^-inf)
p_tot = 0.000000000000000 = 2^-inf, Bn = 0.000000 = 2^-inf
	  [./tests/tea-add-threshold-search-tests.cc:113] Final full trail:
	  0: FFFFFFF1 <-        1 0.082092 (2^-3.606610)
	  1:        0 <-        0 1.000000 (2^0.000000)
	  2:        F <-        1 0.139954 (2^-2.836979)
	  3:        0 <-        F 0.000092 (2^-13.415037)
	  4: FFFFFFF1 <-        1 0.084351 (2^-3.567458)
	  5:        0 <-        0 1.000000 (2^0.000000)
	  6: FFFFFFF1 <-        1 0.129852 (2^-2.945057)
	  7: FFFFFFFE <- FFFFFFF1 0.003601 (2^-8.117357)
	  8:        F <- FFFFFFFF 0.083252 (2^-3.586372)
	  9:        0 <-        0 1.000000 (2^0.000000)
	  10:        F <- FFFFFFFF 0.146271 (2^-2.773287)
	  11:        1 <-        F 0.003967 (2^-7.977632)
	  12:        0 <-        0 1.000000 (2^0.000000)
	  13:        1 <-        F 0.004730 (2^-7.723876)
	  14: FFFFFFF1 <-        1 0.134918 (2^-2.889843)
	  15:        0 <-        0 1.000000 (2^0.000000)
	  16: FFFFFFF1 <-        1 0.078949 (2^-3.662936)
p_tot = 0.000000000000000 = 2^-63.102443
	  [./tests/tea-add-threshold-search-tests.cc:127] key
	  key[0] = 0xD3DCBA64;
key[1] = 0xF1ACBEA;
key[2] = 0x5D98E5A4;
key[3] = 0xBA65798A;

real    10m21.061s
user    10m2.354s
sys     0m0.156s
vpv@mazirat:~/skcrypto/trunk/work/src/yaarx$

*/

/* --- */

/* 
----- End search -----
[./tests/tea-add-threshold-search-tests.cc:103] Final trail:
0: C0200000 <- 7C000000 0.053436 (2^-4.226037)
1: 84000000 <- 80000000 0.488068 (2^-1.034847)
2:        0 <-        0 1.000000 (2^0.000000)
3: 84000000 <- 80000000 0.490662 (2^-1.027200)
4: 40200000 <- 84000000 0.060303 (2^-4.051633)
5: 3FE10000 <- C0200000 0.015961 (2^-5.969333)
6:  3EFF800 <- C3E10000 0.001617 (2^-9.272080)
7: 7EF007C0 <- C40FF800 0.000275 (2^-11.830075)
8: 6DD6FBFE <- 42D107C0 0.000061 (2^-14.000000)
9:        2 <- 31E6F3FE 0.000000 (2^-35.590418)
p_tot = 0.000000000000000 = 2^-87.001622, Bn = 0.000000 = 2^-87.001622
[./tests/tea-add-threshold-search-tests.cc:113] Final full trail:
0: FFFFFFDE <- FFFFFFFE 0.078857 (2^-3.664610)
1: FFFFFFE2 <-        2 0.133301 (2^-2.907243)
2: FFFFFE1F <- FFFFFFE0 0.028198 (2^-5.148251)
3:       40 <- FFFFFE21 0.000061 (2^-14.000000)
4:      1E1 <-       20 0.028351 (2^-5.140465)
5: FFFFFFE2 <-        2 0.077148 (2^-3.696219)
6: FFFFFFDE <-        2 0.105469 (2^-3.245112)
7: FFFFFE1F <- FFFFFFE0 0.045441 (2^-4.459872)
8:       40 <- FFFFFE21 0.000641 (2^-10.607683)
9:      1E1 <-       20 0.050079 (2^-4.319640)
10: FFFFFFE2 <-        2 0.103577 (2^-3.271229)
11: FFFFFFE2 <-        2 0.077515 (2^-3.689387)
p_tot = 0.000000000000000 = 2^-64.149712
[./tests/tea-add-threshold-search-tests.cc:127] key
key[0] = 0xD0C6E176;
key[1] = 0x35C21E2;
key[2] = 0xA52FFD16;
key[3] = 0x22075F;

real    12m38.923s
user    12m36.491s
sys     0m0.216s

 */

/* --- */

/* 
----- End search -----
[./tests/tea-add-threshold-search-tests.cc:103] Final trail:
0:        0 <-        0 1.000000 (2^0.000000)
1:        F <-        1 0.079620 (2^-3.650719)
2:        0 <-        F 0.000214 (2^-12.192645)
3: FFFFFFF1 <-        1 0.137634 (2^-2.861088)
4:        0 <-        0 1.000000 (2^0.000000)
5:       11 <-        1 0.081055 (2^-3.624961)
6:        0 <-       11 0.000031 (2^-15.000000)
7: FFFFFFEF <-        1 0.136505 (2^-2.872973)
8:        0 <-        0 1.000000 (2^0.000000)
9:       11 <-        1 0.077850 (2^-3.683153)
10:        0 <-       11 0.000275 (2^-11.830075)
11: FFFFFFEF <-        1 0.139771 (2^-2.838868)
12:        0 <-        0 1.000000 (2^0.000000)
13: FFFFFFF1 <-        1 0.081818 (2^-3.611444)
14: FFFFFF01 <- FFFFFFF1 0.011566 (2^-6.433946)
p_tot = 0.000000000000000 = 2^-68.599872, Bn = 0.000000 = 2^-68.599872

B[ 0] = 2^0.000000
B[ 1] = 2^-1.021379
B[ 2] = 2^-2.074929
B[ 3] = 2^-5.340905
B[ 4] = 2^-11.133891
B[ 5] = 2^-16.452602
B[ 6] = 2^-22.584944
B[ 7] = 2^-26.316624
B[ 8] = 2^-30.841128
B[ 9] = 2^-35.299585
B[10] = 2^-39.350357
B[11] = 2^-42.164186
B[12] = 2^-47.611362
B[13] = 2^-52.917016
B[14] = 2^-53.310186
B[15] = 2^-56.655188
B[16] = 2^-61.075872
pDDT sizes: Dp 172, Dxy 171 | Cp 1455, Cxy 1455
[./tests/tea-add-threshold-search-tests.cc:113] Final full trail:
0: FFFFFF01 <- FFFFFFF1 0.042664 (2^-4.550851)
1:        F <- FFFFFFFF 0.079102 (2^-3.660150)
2:        0 <-        0 1.000000 (2^0.000000)
3:        F <- FFFFFFFF 0.140930 (2^-2.826948)
4:        1 <-        F 0.005219 (2^-7.582147)
5:        0 <-        0 1.000000 (2^0.000000)
6:        1 <-        F 0.001862 (2^-9.069263)
7: FFFFFFF1 <-        1 0.133026 (2^-2.910219)
8:        0 <-        0 1.000000 (2^0.000000)
9:        F <-        1 0.081909 (2^-3.609831)
10: FFFFFFFF <-        F 0.003723 (2^-8.069263)
11:        0 <-        0 1.000000 (2^0.000000)
12: FFFFFFFF <-        F 0.005463 (2^-7.516184)
13: FFFFFFF1 <- FFFFFFFF 0.083862 (2^-3.575834)
14:        0 <-        0 1.000000 (2^0.000000)
15: FFFFFFF1 <- FFFFFFFF 0.134003 (2^-2.899666)
16: FFFFFF01 <- FFFFFFF1 0.049194 (2^-4.345364)
17: FFFFF0F8 <- FFFFFF00 0.025635 (2^-5.285754)
p_tot = 0.000000000000000 = 2^-65.901474

[./tests/tea-add-threshold-search-tests.cc:127] key
key[0] = 0xE028DF9A;
key[1] = 0x8819B4C3;
key[2] = 0x3AB116AF;
key[3] = 0x3C50723;

real    11m32.323s
user    11m31.111s
sys     0m0.016s

 */



/* --- */

/* 
pDDT sizes: Dp 137, Dxy 139 | Cp 236, Cxy 236
 
	[./tests/tea-add-threshold-search-tests.cc:101] Final trail:
 0:       11 <-        1 0.130646 (2^-2.936268)
 1:        0 <-        0 1.000000 (2^0.000000)
 2:        F <-        1 0.082886 (2^-3.592732)
 3:        0 <-        F 0.004028 (2^-7.955606)
 4: FFFFFFF1 <-        1 0.132355 (2^-2.917518)
 5:        0 <-        0 1.000000 (2^0.000000)
 6:       11 <-        1 0.079895 (2^-3.645751)
 7:        0 <-       11 0.000122 (2^-13.000000)
 8: FFFFFFEF <-        1 0.127167 (2^-2.975207)
 9:        0 <-        0 1.000000 (2^0.000000)
10:       11 <-        1 0.080322 (2^-3.638056)
11:        0 <-       11 0.000122 (2^-13.000000)
12: FFFFFFEF <-        1 0.134613 (2^-2.893110)
13:        0 <-        0 1.000000 (2^0.000000)
14: FFFFFFF1 <-        1 0.085724 (2^-3.544159)
15: FFFFFF01 <- FFFFFFF1 0.004974 (2^-7.651272)
p_tot = 0.000000000000000 = 2^-67.749679, Bn = 0.000000 = 2^-67.749679
[./tests/tea-add-threshold-search-tests.cc:111] Final full trail:
0:        F <- FFFFFFFF 0.125854 (2^-2.990171)
1:        0 <-        0 1.000000 (2^0.000000)
2:        F <- FFFFFFFF 0.081512 (2^-3.616836)
3:        0 <-        F 0.004486 (2^-7.800328)
4: FFFFFFF1 <- FFFFFFFF 0.132568 (2^-2.915192)
5:        0 <-        0 1.000000 (2^0.000000)
6:       11 <- FFFFFFFF 0.081238 (2^-3.621705)
7:        0 <-       11 0.000183 (2^-12.415037)
8: FFFFFFEF <- FFFFFFFF 0.126373 (2^-2.984237)
9:        0 <-        0 1.000000 (2^0.000000)
10: FFFFFFF1 <- FFFFFFFF 0.081573 (2^-3.615756)
11:        1 <- FFFFFFF1 0.000275 (2^-11.830075)
12:        0 <-        0 1.000000 (2^0.000000)
13:        1 <- FFFFFFF1 0.004150 (2^-7.912537)
14:        F <-        1 0.080475 (2^-3.635318)
15:        0 <-        0 1.000000 (2^0.000000)
p_tot = 0.000000000000000 = 2^-63.337192
[./tests/tea-add-threshold-search-tests.cc:125] key
key[0] = 0xD0C6E176;
key[1] = 0x35C21E2;
key[2] = 0xA52FFD16;
key[3] = 0x22075F;

real    6m6.487s
user    6m5.851s
sys     0m0.004s

 */

/* --- */

/* 
pDDT sizes: Dp 57, Dxy 160 | Cp 1080, Cxy 1080
 
	[./tests/tea-add-threshold-search-tests.cc:93]
----- End search -----
[./tests/tea-add-threshold-search-tests.cc:95] Final trail:
0:       22 <- FFFFFFFE 0.137299 (2^-2.864611)
1:       11 <-        1 0.076904 (2^-3.700792)
2:        0 <-        F 0.000244 (2^-12.000000)
3: FFFFFFF1 <-        1 0.139587 (2^-2.840759)
4:        0 <-        0 1.000000 (2^0.000000)
5:       11 <-        1 0.081055 (2^-3.624961)
6:        0 <-       11 0.000092 (2^-13.415037)
7: FFFFFFEF <-        1 0.136902 (2^-2.868786)
8:        0 <-        0 1.000000 (2^0.000000)
9:       11 <-        1 0.080627 (2^-3.632585)
10:        0 <-       11 0.000122 (2^-13.000000)
11: FFFFFFEF <-        1 0.139343 (2^-2.843285)
12:        0 <-        0 1.000000 (2^0.000000)
13: FFFFFFF1 <-        1 0.080048 (2^-3.642998)
p_tot = 0.000000000000000 = 2^-64.433815, Bn = 0.000000 = 2^-64.433815

[./tests/tea-add-threshold-search-tests.cc:105] Final full trail:
0: FFFFFFDE <- FFFFFFFE 0.134216 (2^-2.897368)
1:        1 <- FFFFFFF1 0.004028 (2^-7.955606)
2:        F <- FFFFFFFF 0.082092 (2^-3.606610)
3:        0 <-        0 1.000000 (2^0.000000)
4: FFFFFFF1 <- FFFFFFFF 0.126434 (2^-2.983540)
5:        1 <- FFFFFFF1 0.004578 (2^-7.771181)
6:        0 <-        0 1.000000 (2^0.000000)
7:        1 <- FFFFFFF1 0.000458 (2^-11.093109)
8: FFFFFFF1 <-        1 0.133972 (2^-2.899995)
9:        1 <- FFFFFFE2 0.001862 (2^-9.069263)
10:       1E <-        2 0.099915 (2^-3.323161)
11:        0 <-        0 1.000000 (2^0.000000)
12:       22 <-        2 0.079895 (2^-3.645751)
13:      1FF <-       22 0.018707 (2^-5.740257)
14: FFFFE201 <-      201 0.015686 (2^-5.994375)
p_tot = 0.000000000000000 = 2^-66.980216
[./tests/tea-add-threshold-search-tests.cc:119] key
key[0] = 0xE028DF9A;
key[1] = 0x8819B4C3;
key[2] = 0x3AB116AF;
key[3] = 0x3C50723;

real    6m31.264s
user    6m30.460s
sys     0m0.040s
vpv@igor:~/skcrypto/trunk/work/src/yaarx$

*/

/* --- */

/*

0: FFFFFFF1 <-        1 0.081024 (2^-3.625504)
1:        0 <-        0 1.000000 (2^0.000000)
2:       11 <-        1 0.141785 (2^-2.818227)
3:        0 <-       11 0.000031 (2^-15.000000)
4: FFFFFFEF <-        1 0.077271 (2^-3.693938)
5:        0 <-        0 1.000000 (2^0.000000)
6:        F <-        1 0.135376 (2^-2.884956)
7:        0 <-        F 0.001953 (2^-9.000000)
8: FFFFFFF1 <-        1 0.079315 (2^-3.656259)
9:        0 <-        0 1.000000 (2^0.000000)
10:        F <-        1 0.140167 (2^-2.834779)
11:        0 <-        F 0.003510 (2^-8.154510)
12: FFFFFFF1 <-        1 0.079834 (2^-3.646853)
13:        0 <-        0 1.000000 (2^0.000000)
14: FFFFFFF1 <-        1 0.076324 (2^-3.711711)
15: FFFFFF01 <- FFFFFFF1 0.013336 (2^-6.228511)
p_tot = 0.000000000000000 = 2^-65.255247, Bn = 0.000000 = 2^-65.255247

*/

/* --- */

	 //	 if()

	 //	 if(!b_found_in_hways) {				  // if not a Highway, search in the Country roads table
	 //		croad_iter = croads_diff_set_dx_dy->lower_bound(diff_dy);
	 //		b_found_in_croads = (croad_iter != croads_diff_set_dx_dy->end()) && (croad_iter->dx == dx);
		//	 }


/* --- */

/* 
----- End search -----
[./tests/tea-add-threshold-search-tests.cc:83] Final trail:
0:        0 <-        0 1.000000 (2^0.000000)
1:        F <-        1 0.081299 (2^-3.620622)
2:        0 <-        F 0.000214 (2^-12.192645)
3: FFFFFFF1 <-        1 0.135620 (2^-2.882357)
4:        0 <-        0 1.000000 (2^0.000000)
5:        F <-        1 0.081299 (2^-3.620622)
6:        0 <-        F 0.002258 (2^-8.790547)
7:        F <-        1 0.138367 (2^-2.853431)
8:        1 <-       1E 0.002991 (2^-8.385290)
9: FFFFFFE2 <-        2 0.103882 (2^-3.266985)
10:        0 <-        0 1.000000 (2^0.000000)
11: FFFFFFE2 <-        2 0.128754 (2^-2.957315)
12: FFFFFE01 <- FFFFFFE2 0.015930 (2^-5.972094)
13: FFFFE1C3 <- FFFFFE03 0.001923 (2^-9.022720)
p_tot = 0.000000000000000 = 2^-63.564627, Bn = 0.000000 = 2^-63.564627
[./tests/tea-add-threshold-search-tests.cc:93] Final full trail:
0: FFFFFFF1 <-        1 0.080414 (2^-3.636413)
1:        0 <-        0 1.000000 (2^0.000000)
2:        F <-        1 0.140656 (2^-2.829762)
3: FFFFFFFF <-        F 0.004608 (2^-7.761595)
4:        0 <-        0 1.000000 (2^0.000000)
5: FFFFFFFF <-        F 0.001801 (2^-9.117357)
6: FFFFFFF1 <- FFFFFFFF 0.137665 (2^-2.860768)
7:        0 <-        0 1.000000 (2^0.000000)
8: FFFFFFF1 <- FFFFFFFF 0.078369 (2^-3.673571)
9:        0 <- FFFFFFF1 0.000946 (2^-10.045804)
10:        F <- FFFFFFFF 0.143158 (2^-2.804320)
11:        0 <-        0 1.000000 (2^0.000000)
12:        F <- FFFFFFFF 0.083984 (2^-3.573735)
13:        1 <-        F 0.005554 (2^-7.492205)
14:        0 <-        0 1.000000 (2^0.000000)
15:        0 <-        F 0.004120 (2^-7.923184)
16:        0 <-        0 1.000000 (2^0.000000)
17: FFFFFF01 <-        F 0.027954 (2^-5.160796)
p_tot = 0.000000000000000 = 2^-66.879511
[./tests/tea-add-threshold-search-tests.cc:107] key
key[0] = 0x2CDFA327;
key[1] = 0xBF180421;
key[2] = 0x278E5FEC;
key[3] = 0x120C8854;

real    3m41.065s
user    3m40.682s
sys     0m0.008s


 */



/* --- */
0: FFFFFF01 <- FFFFFFF1 0.008698 (2^-6.845182)
4:        0 <-        F 0.002075 (2^-8.912537) 

/* --- */

  differential_t diff_tmp;
  diff_tmp.dx = 0xFFFFFFF1;  
  diff_tmp.dy = 0xFFFFFF01;
  diff_tmp.p = 0.008698;
  printf("BEFORE Initial set sizes: Dp %d, Dxy %d\n", diff_mset_p.size(), diff_set_dx_dy.size());
  assert(diff_set_dx_dy.size() == diff_mset_p.size());
  diff_mset_p.insert(diff_tmp);
  diff_set_dx_dy.insert(diff_tmp);


/* --- */
/* 

 0: FFFFFF01 <- FFFFFFF1 0.008881 (2^-6.815125)
 1:        F <-        1 0.134735 (2^-2.891802)
 2:        0 <-        0 1.000000 (2^0.000000)
 3:       11 <-        1 0.079346 (2^-3.655704)
 4:        0 <-       11 0.002136 (2^-8.870717)
 5: FFFFFFEF <-        1 0.131226 (2^-2.929879)
 6:        0 <-        0 1.000000 (2^0.000000)
 7: FFFFFFF1 <-        1 0.079834 (2^-3.646853)
p_tot = 0.000000002124720 = 2^-28.810080, Bn = 0.000000 = 2^-28.810080

 */


/* --- */
/* 
  key[0] = 0xAAAEDCB2;
  key[1] = 0x46E15B91;
  key[2] = 0x17889304;
  key[3] = 0xDCCC9FBB;

----- End search -----
[./tests/tea-add-threshold-search-tests.cc:82] Final trail:
0:        0 <-        0 1.000000 (2^0.000000)
1:        1 <-       2D 0.000031 (2^-15.000000)
2: FFFFFFF1 <-        1 0.080170 (2^-3.640800)
3:        1 <-       1E 0.001740 (2^-9.167110)
4: FFFFFFE2 <-        2 0.135071 (2^-2.888212)
5:        0 <-        0 1.000000 (2^0.000000)
6:       22 <-        2 0.107269 (2^-3.220691)
7:        0 <-       22 0.000977 (2^-10.000000)
8: FFFFFFDE <-        2 0.075348 (2^-3.730289)
9:        0 <-        0 1.000000 (2^0.000000)
10: FFFFFFE2 <-        2 0.096222 (2^-3.377491)
11: FFFFFE01 <- FFFFFFE2 0.016449 (2^-5.925859)
12: FFFFE1C3 <- FFFFFE03 0.001892 (2^-9.045804)
p_tot = 0.000000000000000 = 2^-65.996254, Bn = 0.000000 = 2^-65.996254
[./tests/tea-add-threshold-search-tests.cc:92] Final full trail:
0: FFFFFFF1 <-        1 0.126282 (2^-2.985282)
1:        0 <-        0 1.000000 (2^0.000000)
2: FFFFFFF1 <-        1 0.079254 (2^-3.657370)
3: FFFFFFFF <- FFFFFFF1 0.003967 (2^-7.977632)
4:        0 <-        0 1.000000 (2^0.000000)
5: FFFFFFFF <- FFFFFFF1 0.003143 (2^-8.313499)
6:        F <- FFFFFFFF 0.085571 (2^-3.546729)
7:        0 <-        0 1.000000 (2^0.000000)
8: FFFFFFF1 <- FFFFFFFF 0.126587 (2^-2.981800)
9:        1 <- FFFFFFF1 0.003601 (2^-8.117357)
10:        0 <-        0 1.000000 (2^0.000000)
11:        1 <- FFFFFFF1 0.005066 (2^-7.624961)
12:        F <-        1 0.134827 (2^-2.890822)
13:        0 <-        0 1.000000 (2^0.000000)
14: FFFFFFEF <-        1 0.084930 (2^-3.557575)
15: FFFFFFFE <- FFFFFFEF 0.001221 (2^-9.678072)
16:       11 <- FFFFFFFF 0.128113 (2^-2.964514)
17:        0 <-        0 1.000000 (2^0.000000)
p_tot = 0.000000000000000 = 2^-64.295613

real    5m5.624s
user    5m5.083s
sys     0m0.008s
vpv@igor:~/skcrypto/trunk/work/src/yaarx$


 */


/* --- */

/* 

B[ 0] = 2^0.000000
B[ 1] = 2^-1.019236
B[ 2] = 2^-2.053181
B[ 3] = 2^-5.332826
B[ 4] = 2^-11.128117
B[ 5] = 2^-16.346259
B[ 6] = 2^-22.695802
B[ 7] = 2^-26.421499
B[ 8] = 2^-31.240675
B[ 9] = 2^-35.271060
B[10] = 2^-43.644738
B[11] = 2^-49.339029
B[12] = 2^-56.219195
B[13] = 2^-60.963055
B[14] = 2^-62.960625
B[15] = 2^-65.703011
pDDT sizes: Dp 58, Dxy 162 | Cp 3704, Cxy 3704
 0:        0 <-        0 1.000000 (2^0.000000)
 1: FFFFFFF1 <- FFFFFFFF 0.080841 (2^-3.628768)
 2: FFFFFFFF <- FFFFFFF1 0.003845 (2^-8.022720)
 3: FFFFFFE2 <- FFFFFFFE 0.124390 (2^-3.007062)
 4:        4 <- FFFFFFD3 0.001404 (2^-9.476438)
 5:       1E <-        2 0.100342 (2^-3.317005)
 6: FFFFFFFF <- FFFFFFF1 0.001953 (2^-9.000000)
 7:        F <-        1 0.133392 (2^-2.906252)
 8:        0 <-        0 1.000000 (2^0.000000)
 9:        F <-        1 0.080688 (2^-3.631494)
10: FFFFFFFF <-        F 0.003632 (2^-8.105182)
11:        0 <-        0 1.000000 (2^0.000000)
12: FFFFFFFF <-        F 0.006287 (2^-7.313499)
13: FFFFFFF1 <- FFFFFFFF 0.082367 (2^-3.601791)
14:        0 <-        0 1.000000 (2^0.000000)
15:        F <- FFFFFFFF 0.077332 (2^-3.692799)
p_tot = 0.000000000000000 = 2^-65.703011, Bn = 0.000000 = 2^-65.703011
[./src/tea-add-threshold-search.cc:1182] nrounds = 16
[./tests/tea-add-threshold-search-tests.cc:69]
----- End search -----
[./tests/tea-add-threshold-search-tests.cc:71] Final trail:
0:       22 <- FFFFFFFE 0.133911 (2^-2.900652)
1:       11 <-        1 0.080933 (2^-3.627135)
2:        0 <-        F 0.000458 (2^-11.093109)
3: FFFFFFF1 <-        1 0.143463 (2^-2.801248)
4:        0 <-        0 1.000000 (2^0.000000)
5:       11 <-        1 0.079010 (2^-3.661821)
6:        0 <-       11 0.000031 (2^-15.000000)
7: FFFFFFEF <-        1 0.135742 (2^-2.881059)
8:        0 <-        0 1.000000 (2^0.000000)
9:       11 <-        1 0.081696 (2^-3.613599)
10:        0 <-       11 0.000214 (2^-12.192645)
11: FFFFFFEF <-        1 0.140320 (2^-2.833209)
12:        0 <-        0 1.000000 (2^0.000000)
13: FFFFFFF1 <-        1 0.077271 (2^-3.693938)
p_tot = 0.000000000000000 = 2^-64.298415, Bn = 0.000000 = 2^-64.298415
[./tests/tea-add-threshold-search-tests.cc:81] Final full trail:
0:        0 <-        0 1.000000 (2^0.000000)
1: FFFFFFF1 <- FFFFFFFF 0.080841 (2^-3.628768)
2: FFFFFFFF <- FFFFFFF1 0.003845 (2^-8.022720)
3: FFFFFFE2 <- FFFFFFFE 0.124390 (2^-3.007062)
4:        4 <- FFFFFFD3 0.001404 (2^-9.476438)
5:       1E <-        2 0.100342 (2^-3.317005)
6: FFFFFFFF <- FFFFFFF1 0.001953 (2^-9.000000)
7:        F <-        1 0.133392 (2^-2.906252)
8:        0 <-        0 1.000000 (2^0.000000)
9:        F <-        1 0.080688 (2^-3.631494)
10: FFFFFFFF <-        F 0.003632 (2^-8.105182)
11:        0 <-        0 1.000000 (2^0.000000)
12: FFFFFFFF <-        F 0.006287 (2^-7.313499)
13: FFFFFFF1 <- FFFFFFFF 0.082367 (2^-3.601791)
14:        0 <-        0 1.000000 (2^0.000000)
15:        F <- FFFFFFFF 0.077332 (2^-3.692799)
p_tot = 0.000000000000000 = 2^-65.703011

real    5m36.633s
user    5m35.697s
sys     0m0.000s
v
 */

 /*


----- End search -----
[./tests/tea-add-threshold-search-tests.cc:71] Final trail:
 0:        0 <-        0 1.000000 (2^0.000000)
 1:        F <-        1 0.082855 (2^-3.593264)
 2:        0 <-        F 0.000183 (2^-12.415037)
 3: FFFFFFF1 <-        1 0.139984 (2^-2.836665)
 4:        0 <-        0 1.000000 (2^0.000000)
 5:       11 <-        1 0.080383 (2^-3.636960)
 6:        0 <-       11 0.000031 (2^-15.000000)
 7: FFFFFFEF <-        1 0.134766 (2^-2.891476)
 8:        0 <-        0 1.000000 (2^0.000000)
 9:       11 <-        1 0.079834 (2^-3.646853)
10:        0 <-       11 0.000183 (2^-12.415037)
11: FFFFFFEF <-        1 0.140839 (2^-2.827885)
12:        0 <-        0 1.000000 (2^0.000000)
13: FFFFFFF1 <-        1 0.079163 (2^-3.659037)
14: FFFFFF01 <- FFFFFFF1 0.012695 (2^-6.299560)
p_tot = 0.000000000000000 = 2^-69.221775, Bn = 0.000000 = 2^-69.221775
[./tests/tea-add-threshold-search-tests.cc:81] Final full trail:
 0:       1E <- FFFFFFFE 0.132050 (2^-2.920849)
 1:        0 <-        0 1.000000 (2^0.000000)
 2: FFFFFFE2 <- FFFFFFFE 0.102386 (2^-3.287903)
 3:        1 <- FFFFFFE2 0.002319 (2^-8.752072)
 4:        F <- FFFFFFFF 0.128265 (2^-2.962796)
 5:        1 <- FFFFFFF1 0.004333 (2^-7.850253)
 6:        0 <-        0 1.000000 (2^0.000000)
 7:        1 <- FFFFFFF1 0.000427 (2^-11.192645)
 8: FFFFFFF1 <-        1 0.136627 (2^-2.871683)
 9:        1 <- FFFFFFE2 0.002808 (2^-8.476438)
10:       1E <-        2 0.098785 (2^-3.339558)
11:        0 <-        0 1.000000 (2^0.000000)
12:       22 <-        2 0.079681 (2^-3.649613)
13:      1FF <-       22 0.019165 (2^-5.705379)
14: FFFFE201 <-      201 0.009033 (2^-6.790547)
p_tot = 0.000000000000000 = 2^-67.799737

real    5m47.511s
user    5m46.542s
sys     0m0.004s
vpv@mazirat:~/skcrypto/trunk/work/src/yaarx$

---

B[ 0] = 2^0.000000
B[ 1] = 2^-1.018790
B[ 2] = 2^-2.960642
B[ 3] = 2^-5.373575
B[ 4] = 2^-11.112446
B[ 5] = 2^-16.281079
B[ 6] = 2^-22.674470
B[ 7] = 2^-26.110358
B[ 8] = 2^-31.377126
B[ 9] = 2^-34.175885
B[10] = 2^-43.506585
B[11] = 2^-45.871746
B[12] = 2^-51.574971
B[13] = 2^-55.571639
B[14] = 2^-56.953454
pDDT sizes: Dp 57, Dxy 114 | Cp 190, Cxy 190
 0:        0 <-        0 1.000000 (2^0.000000)
 1: FFFFFFF1 <-        1 0.082855 (2^-3.593264)
 2:        0 <- FFFFFFF1 0.000214 (2^-12.192645)
 3:        F <-        1 0.137421 (2^-2.863329)
 4:        0 <-        0 1.000000 (2^0.000000)
 5: FFFFFFF1 <-        1 0.080505 (2^-3.634771)
 6: FFFFFFFE <- FFFFFFF1 0.001617 (2^-9.272080)
 7:        F <- FFFFFFFF 0.134003 (2^-2.899666)
 8:        0 <-        0 1.000000 (2^0.000000)
 9: FFFFFFF1 <- FFFFFFFF 0.081696 (2^-3.613599)
10:        1 <- FFFFFFF1 0.004211 (2^-7.891476)
11:        0 <-        0 1.000000 (2^0.000000)
12:        1 <- FFFFFFF1 0.006012 (2^-7.377948)
13:        F <-        1 0.081635 (2^-3.614677)
14:        0 <-        0 1.000000 (2^0.000000)

 */

/* --- */
/*
----- End search -----
uint32_t max_lp = 2;

[./tests/tea-add-threshold-search-tests.cc:71] Final trail:
 0: FFFFFFEF <-        1 0.136322 (2^-2.874909)
 1:        0 <-        0 1.000000 (2^0.000000)
 2:        F <-        1 0.082489 (2^-3.599654)
 3:        0 <-        F 0.000153 (2^-12.678072)
 4:        F <-        1 0.125580 (2^-2.993323)
 5:        1 <-       1E 0.002716 (2^-8.524267)
 6: FFFFFFE2 <-        2 0.101990 (2^-3.293504)
 7:        0 <-        0 1.000000 (2^0.000000)
 8: FFFFFFE2 <-        2 0.076019 (2^-3.717491)
p_tot = 0.000000000004538 = 2^-37.681220, Bn = 0.000000 = 2^-37.681220

[./tests/tea-add-threshold-search-tests.cc:81] Final full trail:
 0:        0 <-        0 1.000000 (2^0.000000)
 1:        F <- FFFFFFFF 0.077698 (2^-3.685983)
 2:        1 <-        F 0.003967 (2^-7.977632)
 3:        0 <-        0 1.000000 (2^0.000000)
 4:        1 <-        F 0.005951 (2^-7.392670)
 5: FFFFFFF1 <-        1 0.081696 (2^-3.613599)
 6:        0 <-        0 1.000000 (2^0.000000)
 7: FFFFFFEF <-        1 0.139801 (2^-2.838553)
 8: FFFFFF00 <- FFFFFFEF 0.020599 (2^-5.601256)
p_tot = 0.000000000431568 = 2^-31.109693

real    20m33.862s
user    20m30.309s
sys     0m0.084s

*/

/* --- */
#if 0
	 if(nrounds == 8) {
		printf("[%s:%d] Start highway table R#[%2d]\n", __FILE__, __LINE__, nrounds);
		print_set(diff_set_dx_dy);
		printf("[%s:%d] Start croads table R#[%2d]\n", __FILE__, __LINE__, nrounds);
		print_set(croads_diff_set_dx_dy);
		printf("[%s:%d] End tables R#[%2d]\n", __FILE__, __LINE__, nrounds);
	 }
#endif 



/* --- */

	 //	 std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy;
	 std::multiset<differential_t, struct_comp_diff_p> found_mset_p;
	 if(b_found_in_hways) {
		while((hway_iter->dx == dx) && (hway_iter != diff_set_dx_dy->end())) {
		  found_mset_p.insert(*hway_iter);
		  hway_iter++;
		}
		if((b_found_in_croads) && (cnt_lp <= max_lp)) {
		  while((croad_iter->dx == dx) && (croad_iter != croads_diff_set_dx_dy->end())) {
			 found_mset_p.insert(*croad_iter);
			 croad_iter++;
		  }
		}
	 } else {
		//		assert(b_found_in_croads == true);
		if(b_found_in_croads) {
		  while((croad_iter->dx == dx) && (croad_iter != croads_diff_set_dx_dy->end())) {
			 found_mset_p.insert(*croad_iter);
			 croad_iter++;
		  }
		}
	 }

/* --- */

bool is_dx_in_set_dx_dy(uint32_t dx, std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy)
{
  bool b_is_inset = false;
  std::set<differential_t, struct_comp_diff_dx_dy>::iterator set_iter = diff_set_dx_dy.begin();;
  while((set_iter != diff_set_dx_dy.end()) && (!b_is_inset)) {
	 b_is_inset = (dx == set_iter->dx);
	 set_iter++;
  }
  return b_is_inset;
}

/* --- */

/**
 * Add entries to the pDDT for fixed input diference da. The same as 
 * \ref tea_f_add_pddt_i , but da is fixed .
 * \p cnt_new is the number of new entries that were added .
 */
void tea_f_da_add_pddt_i(const uint32_t k, const uint32_t n, 
								 const uint32_t lsh_const,  const uint32_t rsh_const,
								 gsl_matrix* A[2][2][2][2], gsl_vector* C,
								 const uint32_t da, uint32_t* db, uint32_t* dc, uint32_t* dd, 
								 double* p, const double p_thres,  
								 std::set<differential_t, struct_comp_diff_dx_dy>* hways_diff_set_dx_dy,
								 std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy,
								 std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p,
								 uint32_t* cnt_new)
{
  if(k == n) {
	 // check for property (1)
	 double p_xor3 = adp_xor3(A, da, *db, *dc, *dd);
	 assert((p_xor3 >= 0.0) && (p_xor3 <= 1.0));
	 assert(p_xor3 == *p);
	 bool b_xor3 = (*p >= p_thres);
	 assert(b_xor3);
	 // check for property (2)
	 bool b_lsh = (*db) == (LSH(da, lsh_const));
	 assert(b_lsh);
	 // check for property (3)
	 uint32_t dx[4] = {0, 0, 0, 0};
	 adp_rsh_odiffs(dx, da, rsh_const);
	 bool b_rsh = (*dc == dx[0]) || (*dc == dx[1]) || (*dc == dx[2]) || (*dc == dx[3]);
	 assert(b_rsh);

	 bool b_is_valid = (b_xor3 && b_lsh && b_rsh);
	 assert(b_is_valid);

	 // check if the output difference *dd is in the Highway set 
	 bool b_is_inset = is_dx_in_set_dx_dy(*dd, *hways_diff_set_dx_dy);

	 double p_f = eadp_tea_f(A, da, *dd, &p_f, lsh_const, rsh_const); // eadp_tea_f
	 //	 if(p_f >= p_thres) {
	 if((p_f >= p_thres) && (b_is_inset)){

		differential_t diff;
		diff.dx = da;
		diff.dy = *dd;
		diff.p = p_f;

		if(diff_set_dx_dy->size() < TEA_ADD_MAX_PDDT_SIZE) {
#if 0									  // DEBUG
		  bool b_found = (diff_set_dx_dy->find(diff) != diff_set_dx_dy->end());
		  if(!b_found) {
			 printf("[%s:%d] CNT %d: Dxy add %8X -> %8X  | %f = 2^%4.2f | %15d\n", __FILE__, __LINE__, *cnt_new, diff.dx, diff.dy, diff.p, log2(diff.p), diff_set_dx_dy->size());
		  }
#endif
#if 0
		  double p_min = diff_mset_p->rbegin()->p;
		  if(p_f >= p_min) {
			 diff_mset_p->insert(diff);
		  }
		  //#else
#endif
		  diff_mset_p->insert(diff);
		  diff_set_dx_dy->insert(diff);
		  (*cnt_new)++;
		}
	 }
	 return;
  }

#if 0									  // DEBUG
  printf("\r[%s:%d] %s() [%2d]: 2^%f >? 2%f", __FILE__, __LINE__, __FUNCTION__, k, log2(*p), log2(p_thres));
  fflush(stdout);
#endif

  // init L
  gsl_vector* L = gsl_vector_calloc(ADP_XOR3_MSIZE);
  gsl_vector_set_all(L, 1.0);

  //  for(uint32_t x = 0; x < 2; x++) {
  uint32_t x = (da >> k) & 1;

	 for(uint32_t y = 0; y < 2; y++) {
		for(uint32_t z = 0; z < 2; z++) {
		  for(uint32_t t = 0; t < 2; t++) {
			 gsl_vector* R = gsl_vector_calloc(ADP_XOR3_MSIZE);
			 double new_p = 0.0;

			 // L A C
			 gsl_blas_dgemv(CblasNoTrans, 1.0, A[x][y][z][t], C, 0.0, R);
			 gsl_blas_ddot(L, R, &new_p);

			 // 
			 // For the averaged case adp-f (no-fixed-key) a sufficient condition
			 // for adp-f(da->dd) >= p_thres is adp-xor3(da,db,dc_i->dd) >= p_thres
			 // for every dc_i : dc_i = RSH(da);
			 //			 if(new_p != 0.0) { // <- this finds all differences, but is *slow*
			 if(new_p >= p_thres) {
				uint32_t new_da =  da;//*da | (x << k);
				uint32_t new_db = *db | (y << k);
				uint32_t new_dc = *dc | (z << k);
				uint32_t new_dd = *dd | (t << k);

				bool b_lsh_con = lsh_condition_is_sat(k, new_da, new_db);
				bool b_rsh_con = rsh_condition_is_sat(k, new_da, new_dc);

				if(b_lsh_con && b_rsh_con) {
				  tea_f_da_add_pddt_i(k+1, n, lsh_const, rsh_const, A, R, new_da, &new_db, &new_dc, &new_dd, &new_p, p_thres, hways_diff_set_dx_dy, diff_set_dx_dy, diff_mset_p, cnt_new);
				}
			 }
			 gsl_vector_free(R);

		  } // t
		}	 // z
	 }		 // y
	 //  }		 // x
  gsl_vector_free(L);
}

/**
 * Wrapper for \ref tea_f_da_add_pddt_i .
 * Returns the number of new entries that were added .
 */
uint32_t tea_f_da_add_pddt(uint32_t n, double p_thres, 
									uint32_t lsh_const, uint32_t rsh_const, const uint32_t da,
									std::set<differential_t, struct_comp_diff_dx_dy>* hways_diff_set_dx_dy,
									std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy,
									std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p)
{
#if 0									  // DEBUG
  printf("[%s:%d] %s() enter... dx %8X, p_min 2^%f\n", __FILE__, __LINE__, __FUNCTION__, da, log2(p_thres));
#endif
  assert(n == WORD_SIZE);

  uint32_t k = 0;
  double p = 0.0;
  uint32_t cnt_new = 0;

  // init A
  gsl_matrix* A[2][2][2][2];
  adp_xor3_alloc_matrices(A);
  adp_xor3_sf(A);
  adp_xor3_normalize_matrices(A);

  // init C
  gsl_vector* C = gsl_vector_calloc(ADP_XOR3_MSIZE);
  gsl_vector_set(C, ADP_XOR3_ISTATE, 1.0);

  //  uint32_t da = 0;
  uint32_t db = 0;
  uint32_t dc = 0;
  uint32_t dd = 0;

  // compute Dxy
#if 1
  tea_f_da_add_pddt_i(k, n, lsh_const, rsh_const, A, C, da, &db, &dc, &dd, &p, p_thres, hways_diff_set_dx_dy, diff_set_dx_dy, diff_mset_p, &cnt_new);
#endif
  gsl_vector_free(C);
  adp_xor3_free_matrices(A);
#if 0									  // DEBUG
  //  printf("[%s:%d] %s() exit...\n", __FILE__, __LINE__, __FUNCTION__);
  printf("[%s:%d] %s() exit... dx %8X, p_min 2^%f\n", __FILE__, __LINE__, __FUNCTION__, da, log2(p_thres));
#endif
  return cnt_new;
}

/* --- */

		//		double p_max = 0.0;
		//		uint32_t dy_max = 0;
		//		max_eadp_tea_f(A, dx, &dy_max, &p_max, lsh_const, rsh_const);
		//		if(p_max >= p_min) {}

		// Add the new diff to Dp only if it has better prob. than the min.
		//		uint32_t cnt_new = tea_f_da_add_pddt(WORD_SIZE, p_min, lsh_const, rsh_const, diff_dy.dx, diff_set_dx_dy, croads_diff_set_dx_dy, croads_diff_mset_p);


/* --- */

#if 1
			 printf("\r[%s:%d] %2d*: %8X -> %8X 2^%f, 2^%f", __FILE__, __LINE__, n, dx, dy, log2(pn), log2(*Bn));
			 fflush(stdout);
#endif

/* --- */
#if 0
		  printf("\r[%s:%d] %2d [%3d / %3d]: %8X -> %8X 2^%f, 2^%f", __FILE__, __LINE__, n, cnt, diff_mset_p->size(), dx, dy, log2(pn), log2(*Bn));
		  fflush(stdout);
#endif
#if 0
		  printf("\r[%s:%d] %2d: %8X -> %8X 2^%f, 2^%f", __FILE__, __LINE__, n, dx, dy, log2(pn), log2(*Bn));
		  fflush(stdout);
#endif


/* --- */

#if 0	 // {----
		double p_max = 0.0;
		uint32_t dy_max = 0;
		max_eadp_tea_f(A, dx, &dy_max, &p_max, lsh_const, rsh_const);
#if 1
		printf("\r[%s:%d] %s() %8X -> %8X 2^%f 2^%f", __FILE__, __LINE__, __FUNCTION__, dx, dy_max, log2(p_max), log2(p_min));
		fflush(stdout);
#endif

		if(cnt_lp >= max_lp) {
		  //		  double p_min_orig = p_min;
		  p_min = std::max(p_min, p_thres);
		  //		  if(p_min_orig < p_min) {
		  //			 printf("[%s:%d] cnt_lp %d / %d: adjust min 2^%f -> 2^%f (2^%f)\n", __FILE__, __LINE__, cnt_lp, max_lp, log2(p_min_orig), log2(p_min), log2(p_thres));
		  //		  }
		  //		  fflush(stdout);
		}
#endif  // ---}


/* --- */

void tea_add_threshold_search_full(const int n, const int nrounds, const uint32_t npairs, const uint32_t key[4],
											  gsl_matrix* A[2][2][2][2], double B[NROUNDS], double* Bn,
											  const differential_t diff_in[NROUNDS], differential_t trail[NROUNDS], 
											  uint32_t lsh_const, uint32_t rsh_const,
											  std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p,
											  std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy)
{
  double pn = 0.0;

  // make a local copy of the input diff trail
  differential_t diff[NROUNDS] = {{0, 0, 0, 0.0}};
  for(int i = 0; i < n; i++) {
	 diff[i].dx = diff_in[i].dx;
	 diff[i].dy = diff_in[i].dy;
	 diff[i].p = diff_in[i].p;
  }

#if 1
  uint32_t max_lp = 1;
  uint32_t cnt_lp = 0;
  uint32_t trail_len = n;
  double p_thres = TEA_ADD_P_THRES;
  cnt_lp = tea_add_threshold_count_lp(diff, trail_len, p_thres);
#endif
  //  printf("[%s:%d] cnt_lp %d / %d\n", __FILE__, __LINE__, cnt_lp, max_lp);

  if((n == 0) && (nrounds == 1)) {						  // Only one round
	 //	 assert(*Bn == 0.0);
	 bool b_end = false;
	 std::multiset<differential_t, struct_comp_diff_p>::iterator mset_iter = diff_mset_p->begin();
	 while((mset_iter != diff_mset_p->end()) && (!b_end)) {
		uint32_t dx = mset_iter->dx;
		uint32_t dy = mset_iter->dy;
		pn = mset_iter->p;;
		pn = tea_add_diff_adjust_to_key(npairs, n, dx, dy, key); // adjust the probability to the fixed round key
		if((pn >= *Bn) && (pn != 0.0)) {
		  trail[n].dx = dx;
		  trail[n].dy = dy;
		  trail[n].p = pn;
		  *Bn = pn;
		  B[n] = pn;
		} else {
		  b_end = true;
		}
		mset_iter++;
	 }	// while()
  }

  if((n == 0) && (nrounds > 1)) {						  // Round-0 and not last round
	 bool b_end = false;
	 std::multiset<differential_t, struct_comp_diff_p>::iterator mset_iter = diff_mset_p->begin();
	 while((mset_iter != diff_mset_p->end()) && (!b_end)) {
		uint32_t dx = mset_iter->dx;
		uint32_t dy = mset_iter->dy;
		pn = mset_iter->p;
		pn = tea_add_diff_adjust_to_key(npairs, n, dx, dy, key); // adjust the probability to the fixed round key
		double p = pn * B[nrounds - 1 - (n + 1)];
#if 0
		if(nrounds == 5) {
		  printf("[%s:%d] %8X -> %8X 2^%f | 2^%f >? 2^%f\n", __FILE__, __LINE__, dx, dy, log2(pn), log2(p), log2(*Bn));
		}
#endif
		assert(B[nrounds - 1 - (n + 1)] != 0.0);
		std::multiset<differential_t, struct_comp_diff_p>::iterator begin_iter = diff_mset_p->begin();
		if((p >= *Bn) && (p != 0.0)) {
		  diff[n].dx = dx;
		  diff[n].dy = dy;
		  diff[n].p = pn;
		  tea_add_threshold_search_full(n+1, nrounds, npairs, key, A, B, Bn, diff, trail, lsh_const, rsh_const, diff_mset_p, diff_set_dx_dy);
		} else {
		  b_end = true;
		}
		if(begin_iter != diff_mset_p->begin()) { // if the root was updated, start from beginning
		  mset_iter = diff_mset_p->begin();
		  printf("[%s:%d] Return to beginning\n", __FILE__, __LINE__);
		} else {
		  mset_iter++;
		}
	 }
  }

  if((n == 1) && (n != (nrounds - 1))) {						  // Round-1 and not last round
	 bool b_end = false;
	 std::multiset<differential_t, struct_comp_diff_p>::iterator mset_iter = diff_mset_p->begin();
	 while((mset_iter != diff_mset_p->end()) && (!b_end)) {
		uint32_t dx = mset_iter->dx;
		uint32_t dy = mset_iter->dy;
		pn = mset_iter->p;
		pn = tea_add_diff_adjust_to_key(npairs, n, dx, dy, key); // adjust the probability to the fixed round key
		double p = diff[0].p * pn * B[nrounds - 1 - (n + 1)];
		std::multiset<differential_t, struct_comp_diff_p>::iterator begin_iter = diff_mset_p->begin();
		if((p >= *Bn) && (p != 0.0)) {
		  diff[n].dx = dx;
		  diff[n].dy = dy;
		  diff[n].p = pn;
		  tea_add_threshold_search_full(n+1, nrounds, npairs, key, A, B, Bn, diff, trail, lsh_const, rsh_const, diff_mset_p, diff_set_dx_dy);
		} else {
		  b_end = true;
		} 
		if(begin_iter != diff_mset_p->begin()) { // if the root was updated, start from beginning
		  mset_iter = diff_mset_p->begin();
		  printf("[%s:%d] Return to beginning\n", __FILE__, __LINE__);
		} else {
		  mset_iter++;
		}
	 }	// while()
  }

  //  if((n >= 2) && (n != (nrounds - 1))) { // Round-i and not last round
 if((n >= 2) && (n != (nrounds - 1)) && (cnt_lp <= max_lp)) {
	 uint32_t dx = ADD(diff[n - 2].dx, diff[n - 1].dy);
	 uint32_t dy = 0;

	 differential_t diff_dy;
	 diff_dy.dx = dx;  
	 diff_dy.dy = 0;
	 diff_dy.p = 0.0;

#if 0
	 std::set<differential_t, struct_comp_diff_dx_dy> new_diff_set_dx_dy;
#endif
	 // check if the differential is not already in the set
	 std::set<differential_t, struct_comp_diff_dx_dy>::iterator find_iter = diff_set_dx_dy->lower_bound(diff_dy);
 	 bool b_found = (find_iter != diff_set_dx_dy->end()) && (find_iter->dx == dx);
	 if(!b_found) {				  // if not found, add new
		double p_min = 0.0;
		// p_i >= p_min = Bn / p1 * p2 ... * p{i-1} * B{n-i} 
		p_min = 1.0;
		for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
		  p_min *= diff[i].p;
		}
		p_min = p_min * 1.0 * B[nrounds - 1 - (n + 1)]; 
		p_min = *Bn / p_min;
		assert(p_min <= 1.0);

#if 0	 // {----
		double p_max = 0.0;
		uint32_t dy_max = 0;
		max_eadp_tea_f(A, dx, &dy_max, &p_max, lsh_const, rsh_const);
#if 1
		printf("\r[%s:%d] %s() %8X -> %8X 2^%f 2^%f", __FILE__, __LINE__, __FUNCTION__, dx, dy_max, log2(p_max), log2(p_min));
		fflush(stdout);
#endif

		if(cnt_lp >= max_lp) {
		  //		  double p_min_orig = p_min;
		  p_min = std::max(p_min, p_thres);
		  //		  if(p_min_orig < p_min) {
		  //			 printf("[%s:%d] cnt_lp %d / %d: adjust min 2^%f -> 2^%f (2^%f)\n", __FILE__, __LINE__, cnt_lp, max_lp, log2(p_min_orig), log2(p_min), log2(p_thres));
		  //		  }
		  //		  fflush(stdout);
		}
#endif  // ---}

		//		if(p_max >= p_min) {
		  // Add the new diff to Dp only if it has better prob. than the min.
		  uint32_t cnt_new = tea_f_da_add_pddt(WORD_SIZE, p_min, lsh_const, rsh_const, diff_dy.dx, diff_set_dx_dy, diff_mset_p);
		  if(cnt_new != 0) {
			 printf("[%s:%d] Added %d new elements: p_min = %f (2^%f). New sizes: Dxy %d, Dp %d (cnt_lp %d / %d).\n", 
					  __FILE__, __LINE__, cnt_new, p_min, log2(p_min), diff_set_dx_dy->size(), diff_mset_p->size(), cnt_lp, max_lp);
		  } else {
#if 0
			 if(diff_set_dx_dy->size() < TEA_ADD_MAX_PDDT_SIZE) {
				differential_t diff;
				diff.dx = dx;
				diff.dy = dy_max;
				diff.p = p_max;
				diff_set_dx_dy->insert(diff);
				printf("[%s:%d] Added 1 new element: p_min = %f (2^%f). New sizes: Dxy %d, Dp %d.\n", 
						 __FILE__, __LINE__, p_min, log2(p_min), diff_set_dx_dy->size(), diff_mset_p->size());
			 }
#endif
		  }

		  find_iter = diff_set_dx_dy->lower_bound(diff_dy);
#if 0									  // EDBUG
		  printf("\r[%s:%d] p_min = 2^%f / (", __FILE__, __LINE__, log2(*Bn));
		  for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
			 printf("[%d] 2^%f * ", i, log2(diff[i].p));
		  }
		  printf("B[%d] 2^%f) = ", nrounds - 1 - (n + 1), log2(B[nrounds - 1 - (n + 1)]));
		  printf(" 2^%f | p_thres 2^%f", log2(p_min), log2(TEA_ADD_P_THRES));
		  fflush(stdout);
#endif // #if 0									  // EDBUG
		  //		}
	 } 

	 //	 if((find_iter->dx == dx) && (cnt_lp < max_lp)) {
	 if(find_iter->dx == dx) {
		//		printf("[%s:%d] cnt_lp %d, max_lp %d\n", __FILE__, __LINE__, cnt_lp, max_lp);
		//		assert(cnt_lp < max_lp);
		while((find_iter->dx < (dx + 1)) && (find_iter != diff_set_dx_dy->end())) {
		//		while((find_iter->dx < (dx + 1)) && (find_iter != new_diff_set_dx_dy.end())) {
		  assert((find_iter->dx == dx));
		  diff_dy = *find_iter;

		  dx = diff_dy.dx;
		  dy = diff_dy.dy;
		  pn = diff_dy.p;
		  pn = tea_add_diff_adjust_to_key(npairs, n, dx, dy, key); // adjust the probability to the fixed round key

		  double p = 1.0;
		  for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
			 p *= diff[i].p;
		  }
		  p = p * pn * B[nrounds - 1 - (n + 1)]; 

		  // store the beginnig
#if 1
		  std::set<differential_t, struct_comp_diff_dx_dy>::iterator begin_iter = diff_set_dx_dy->begin();
#endif
		  if((p >= *Bn) && (p != 0.0)) {
			 diff[n].dx = dx;
			 diff[n].dy = dy;
			 diff[n].p = pn;
			 tea_add_threshold_search_full(n+1, nrounds, npairs, key, A, B, Bn, diff, trail, lsh_const, rsh_const, diff_mset_p, diff_set_dx_dy);
		  }
#if 1
		  if(begin_iter != diff_set_dx_dy->begin()) { // if the root was updated, start from beginning
			 diff_dy.dx = dx;  
			 diff_dy.dy = 0;
			 diff_dy.p = 0.0;
			 find_iter = diff_set_dx_dy->lower_bound(diff_dy);
			 printf("[%s:%d] Return to beginning\n", __FILE__, __LINE__);
			 assert((find_iter->dx == dx));
			 assert(1 == 0);
		  } else {
			 find_iter++;
		  }
#else
		  find_iter++;
#endif
		}	// while
	 }	// if
  }

  if((n == (nrounds - 1)) && (nrounds > 1)) {		  // Last round

	 uint32_t dx = 0;
	 uint32_t dy = 0;

	 if(nrounds == 2) { // Last round (n = 1) AND only two rounds - freely choose dx
		dx = diff_mset_p->begin()->dx;
		dy = diff_mset_p->begin()->dy;
		pn = diff_mset_p->begin()->p;
	 } else {

		dx = ADD(diff[n - 2].dx, diff[n - 1].dy);
		dy = 0;

		differential_t diff_max_dy;
		diff_max_dy.dx = dx;  
		diff_max_dy.dy = 0;
		diff_max_dy.p = 0.0;

		// check if a diff with the same dx is already in the set
		std::set<differential_t, struct_comp_diff_dx_dy>::iterator find_iter = diff_set_dx_dy->lower_bound(diff_max_dy);
		bool b_found = (find_iter != diff_set_dx_dy->end()) && (find_iter->dx == dx);
		if(!b_found) {				  // if not found, add new

		  max_eadp_tea_f(A, dx, &dy, &pn, lsh_const, rsh_const); // max_dy eadp_tea_f
		  pn = tea_add_diff_adjust_to_key(npairs, n, dx, dy, key); // adjust the probability to the fixed key

		  diff_max_dy.dx = dx; 
		  diff_max_dy.dy = dy;
		  diff_max_dy.p = pn;

		  // Add the new diff to Dp only if it has better prob. than the min.
		  double p_min = diff_mset_p->rbegin()->p;
		  if(diff_max_dy.p >= p_min) {
			 diff_mset_p->insert(diff_max_dy);
		  }

		  diff_set_dx_dy->insert(diff_max_dy);
		  find_iter = diff_set_dx_dy->lower_bound(diff_max_dy);
		} 
		assert((find_iter->dx == dx));

		diff_max_dy = *find_iter;
		while((find_iter->dx < (dx + 1)) && (find_iter != diff_set_dx_dy->end())) { // get the max among the available
		  double find_iter_p = tea_add_diff_adjust_to_key(npairs, n, find_iter->dx, find_iter->dy, key); // adjust the probability to the fixed key
		  if(find_iter_p > diff_max_dy.p) {
			 diff_max_dy = *find_iter;
		  }
		  find_iter++;
		}
		dx = diff_max_dy.dx;
		dy = diff_max_dy.dy;
		pn = diff_max_dy.p;
	 }

	 double p = 1.0;
	 for(int i = 0; i < n; i++) {
		p *= diff[i].p;
	 }
	 p *= pn;

	 if((p >= *Bn) && (p != 1.0) && (p != 0.0)) { // skip the 0-diff trail (p = 1.0)
#if 1									  // DEBUG
		if (p > *Bn) {
		  printf("[%s:%d] %d | Update best found Bn: 2^%f -> 2^%f\n", __FILE__, __LINE__, n, log2(*Bn), log2(p));
		}
#endif
		diff[n].dx = dx;
		diff[n].dy = dy;
		diff[n].p = pn;
		*Bn = p;
		B[n] = p;
		for(int i = 0; i < nrounds; i++) {
		  trail[i].dx = diff[i].dx;
		  trail[i].dy = diff[i].dy;
		  trail[i].p = diff[i].p;
		}
	 }
  }
}

/* --- */


		//		if(p_max >= p_min) {
		//		  p_max = tea_add_diff_adjust_to_key(npairs, n, dx, dy_max, key); // adjust the probability to the fixed round key
		//		}
		//max_dy_adp_f_fk

/* --- */

#if 0	// {---
uint32_t adp_f_assign_bit_x_dy(const uint32_t n, const uint32_t i, const uint32_t mask_i, const uint32_t x, 
										 const uint32_t lsh_const, const uint32_t rsh_const,
										 const uint32_t k0, const uint32_t k1, const uint32_t delta,
										 const uint32_t dx, const uint32_t dy, uint64_t* x_cnt, 
										 double* ret_prob, uint32_t* ret_dy)
{
  assert(n <= WORD_SIZE);
  assert(n >= (rsh_const * 2));
  assert(i <= (n + rsh_const));
  if((i == WORD_SIZE) && (dx == 0)) {
	 double p = 0.0;
	 if(dy == 0) {
		x_cnt[dy] = ALL_WORDS;	  // ! dy
		p = 1.0;
	 } else {
		x_cnt[dy] = 0;				  // ! dy
		p = 0.0;
	 }
	 if(p >= *ret_prob) {
		*ret_prob = p;
		*ret_dy = dy;				  // ! dy
	 }
	 return 0;
  } else {
	 if(i == (n + rsh_const)) {
#if DEBUG_ADP_TEA_F_FK
		double p = *ret_prob;
		printf("[%s:%d] %2d: # %8llX: %8X -> %8X | x = %8X  %f 2^%f\n", __FILE__, __LINE__, n, x_cnt[dy], dx, dy, x, p, log2(p));
#endif  // DEBUG_ADP_TEA_F_FK
		assert(dy < MOD);
		if(n == (WORD_SIZE)) {
		  bool b_ok = adp_f_check_x(lsh_const, rsh_const, k0, k1, delta, dx, dy, x);
		  assert(b_ok);
		}
		return 1;
	 }
  }
  bool b_adp_f_is_sat = adp_f_is_sat(mask_i, lsh_const, rsh_const, k0, k1, delta, dx, dy, x); // check x[i]
  if(b_adp_f_is_sat) {
	 if(i < (WORD_SIZE - 1)) { // x[30:0] are assigned and we shall assign the last bit x[31]
		uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); // select x[(i+1)-R:0]
		for(uint32_t next_bit_dy = 0; next_bit_dy < 2; next_bit_dy++) { // ! dy
		  uint32_t new_dy = (next_bit_dy << (i + 1)) | dy; // assign dx[i+1]
		  for(uint32_t next_bit_x = 0; next_bit_x < 2; next_bit_x++) {
			 uint32_t new_x = (next_bit_x << (i + 1)) | x; // assign x[i+1]
			 uint32_t ret = 
			 adp_f_assign_bit_x_dy(n, i + 1, mask_i, new_x, lsh_const, rsh_const, k0, k1, delta, dx, new_dy, x_cnt, ret_prob, ret_dy);
			 x_cnt[new_dy] += ret;
		  }
		}
	 } else {
		uint32_t mask_i = MASK;
		uint32_t new_dy = dy;
		uint32_t new_x = x;
		uint32_t ret =  
		adp_f_assign_bit_x_dy(n, i + 1, mask_i, new_x, lsh_const, rsh_const, k0, k1, delta, dx, new_dy, x_cnt, ret_prob, ret_dy);
		x_cnt[new_dy] += ret;
		if((i + 1) == (n + rsh_const)) {
		  double p = (double)x_cnt[new_dy] / (double)ALL_WORDS;
		  if(p >= *ret_prob) {
			 *ret_prob = p;
			 *ret_dy = dy;
		  }
#if DEBUG_ADP_TEA_F_FK
		  printf("\r[%s:%d] %2d: # %8llX: %8X -> %8X | x = %8X  %f 2^%f", __FILE__, __LINE__, n, x_cnt[dy], dx, dy, x, *ret_prob, log2(*ret_prob));
		  fflush(stdout);
#endif
		}
	 }
  } 
  return 0;
}

double max_dy_adp_f_fk(const uint32_t n, const uint32_t dx, uint32_t* ret_dy,
							  const uint32_t k0, const uint32_t k1, const uint32_t delta,
							  const uint32_t lsh_const, const uint32_t rsh_const)
{

#if DEBUG_ADP_TEA_F_FK
  printf("[%s:%d] %s() Input: %d %d %8X %8X %8X \n", __FILE__, __LINE__, __FUNCTION__, 
			lsh_const, rsh_const, k0, k1, delta);
#endif  // DEBUG_ADP_TEA_F_FK

  assert(lsh_const < rsh_const);
  assert(n <= WORD_SIZE);
  assert(n >= (rsh_const * 2));
  if(dx == 0) {					  // zero input difference
	 *ret_dy = 0;
	 return 1.0;
  }
  // number of initial LSB bits
  uint32_t nlsb_init = (rsh_const * 2);
  if(nlsb_init > WORD_SIZE)
	 nlsb_init = WORD_SIZE;
  // all 10-bit values
  uint32_t N = (1U << nlsb_init);
  uint32_t x = 0;
  uint32_t dy = 0;
  double max_p = 0.0;
  uint32_t max_dy = 0;

  //  uint32_t x_cnt[ALL_WORDS] = {0};
  uint64_t* x_cnt = (uint64_t *)calloc((size_t)ALL_WORDS, sizeof(uint64_t));
  if(x_cnt == NULL) {
	 printf("[%s:%d] ERROR: Bad calloc. Not enough memory. Exiting...\n", __FILE__, __LINE__);
	 exit(1);
  }

  //  const uint32_t n = WORD_SIZE; 
  for(uint32_t j = 0; j < N; j++) { // skip the zero difference
	 dy = j;
	 uint32_t dyy = max_dy;
	 double pp = max_p;
#if DEBUG_ADP_TEA_F_FK
	 printf("[%s:%d] dy[%d:0] = %8X\n", __FILE__, __LINE__, (nlsb_init - 1), j);
#endif  // DEBUG_ADP_TEA_F_FK
	 for(uint32_t l = 0; l < N; l++) {
		x = l;							  // assign x[9:0]
		uint32_t i = nlsb_init - 1; // start at x[9]
		uint32_t mask_i = ~(0xffffffff << ((i + 1) - rsh_const)); 
		adp_f_assign_bit_x_dy(n, i, mask_i, x, lsh_const, rsh_const, k0, k1, delta, dx, dy, x_cnt, &pp, &dyy);
#if DEBUG_ADP_TEA_F_FK
		printf("[%s:%d] %8X -> %8X %f 2^%f | max_p = %f\n", __FILE__, __LINE__, dyy, dy, pp, log2(pp), max_p);
#endif  // DEBUG_ADP_TEA_F_FK
	 }
	 if((pp >= max_p) && (pp != 1.0)) { // skip the zero difference (p == 1.0)
#if DEBUG_ADP_TEA_F_FK
		if(max_dy != dyy) {
		  printf("[%s:%d] Update max dy[%d:0] = %8X | %8X -> %8X %f 2^%f\n", __FILE__, __LINE__, (nlsb_init - 1), j, dyy, dy, pp, log2(pp));
		}
#endif  // DEBUG_ADP_TEA_F_FK
		max_p = pp;
		max_dy = dyy;
	 }
  }
  free(x_cnt);
  *ret_dy = max_dy;
  return max_p;
}
#endif // ---}

/* --- */
		double p_min_orig = p_min;
		double scale_fact = (p_min * 0.5);
		if((p_min + scale_fact) <= 1.0) {
		  p_min += scale_fact;
		}

/* --- */

// XXX ---
void tea_add_trail_search_full(uint32_t key[4], double BB[NROUNDS], uint32_t num_rounds)
{
  uint32_t lsh_const = TEA_LSH_CONST; 
  uint32_t rsh_const = TEA_RSH_CONST;
  double p_thres = TEA_ADD_P_THRES;
  uint32_t word_size = WORD_SIZE;
  uint32_t npairs = NPAIRS;
  uint32_t num_rounds = NROUNDS;

  gsl_matrix* A[2][2][2][2];	  // matrices to compute ADP
  differential_t diff[NROUNDS];	  // arrey of differences
  differential_t trail[NROUNDS];  // a differential trail
  double B[NROUNDS];				  // arey of bounds

  // init matrices
  adp_xor3_alloc_matrices(A);
  adp_xor3_sf(A);
  adp_xor3_normalize_matrices(A);

  // init bounds
  for(int i = 0; i < NROUNDS; i++) {
	 B[i] = 0.0;
  }

  std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy; // Dxy
  std::multiset<differential_t, struct_comp_diff_p> diff_mset_p;	 // Dp

  tea_f_add_pddt(word_size, p_thres, lsh_const, rsh_const, &diff_set_dx_dy);
#if 0									  // DEBUG
  printf("[%s:%d] Dxy before adjust key\n", __FILE__, __LINE__);
  print_set(diff_set_dx_dy);
#endif

#if 1
  tea_f_add_pddt_adjust_to_key(num_rounds, npairs, key, p_thres, &diff_set_dx_dy);
#endif
#if 0									  // DEBUG
  printf("[%s:%d] Dxy after adjust key, p_thres = %f 2^%f\n", __FILE__, __LINE__, p_thres, log2(p_thres));
  print_set(diff_set_dx_dy);
#endif

  tea_f_add_pddt_dxy_to_dp(&diff_mset_p, diff_set_dx_dy);
#if 0									  // DEBUG
  printf("[%s:%d] Dp , p_thres = %f 2^%f\n", __FILE__, __LINE__, p_thres, log2(p_thres));
  print_mset(diff_mset_p);
#endif

  printf("Initial set sizes: Dp %d, Dxy %d\n", diff_mset_p.size(), diff_set_dx_dy.size());
  assert(diff_set_dx_dy.size() == diff_mset_p.size());

  double Bn_init = 0.0;

  //  for(uint32_t nrounds = 1; nrounds <= NROUNDS; nrounds++ ) {
  double p_rand = 1.0 / (double)(1ULL << ((2 * WORD_SIZE) - 1));
  printf("[%s:%d] p_rand 2^%f\n", __FILE__, __LINE__, log2(p_rand));

  uint32_t nrounds = 0;
  do {
	 nrounds++;
	 printf("[%s:%d] nrounds = %d, Bn_init = 2^%f : key %8X %8X %8X %8X\n", __FILE__, __LINE__, nrounds, log2(Bn_init), key[0], key[1], key[2], key[3]);
	 double Bn = Bn_init;
	 B[nrounds - 1] = Bn_init;
	 int r = 0;						  // initial round

	 // init diffs
	 for(int i = 0; i < NROUNDS; i++) {
		diff[i].dx = 0;
		diff[i].dy = 0;
		diff[i].p = 0.0;
	 }

	 tea_add_threshold_search(r, nrounds, npairs, key, A, B, &Bn, diff, trail, lsh_const, rsh_const, &diff_mset_p, &diff_set_dx_dy);

	 assert(B[nrounds - 1] == Bn);

#if 1									  // DEBUG
	 for(uint32_t i = 0; i < nrounds; i++) {
		printf("B[%2d] = 2^%f", i, log2(B[i]));
		if(i > 0) {
		  if(B[i-1] < B[i]) {
			 printf(" <-");
		  }
		}
		printf("\n");
	 }
	 printf("pDDT sizes: Dp %d, Dxy %d\n", diff_mset_p.size(), diff_set_dx_dy.size());
#endif
#if 1									  // DEBUG
	 double p_tot = 1.0;
	 for(uint32_t i = 0; i < nrounds; i++) {
		printf("%2d: %8X <- %8X %f (2^%f)\n", i, trail[i].dy, trail[i].dx, trail[i].p, log2(trail[i].p));
		p_tot *= trail[i].p;
	 }
	 printf("p_tot = %16.15f = 2^%f, Bn = %f = 2^%f\n", p_tot, log2(p_tot), Bn, log2(Bn));
#endif  // #if 0									  // DEBUG
#if 1	  // VERIFY
	 if(nrounds >=3) {
		for(uint32_t i = (nrounds - 1); i >= 2; i--) {
		  assert(trail[i].dx == ADD(trail[i - 2].dx, trail[i - 1].dy));
		}
	 }
#endif  // #if 1	  // VERIFY

	 // Compute an initial bound for the next round
	 uint32_t next_round = nrounds;
	 if((next_round >= 2) && (next_round < NROUNDS)) {
		uint32_t dx = ADD(trail[next_round - 2].dx, trail[next_round - 1].dy);
		uint32_t dy = 0;
		double p = 0.0;

		max_eadp_tea_f(A, dx, &dy, &p, lsh_const, rsh_const); // max_dy eadp_tea_f
		p = tea_add_diff_adjust_to_key(npairs, next_round, dx, dy, key); // adjust the probability to the fixed key
		if(p == 0.0) {
		  p = nz_eadp_tea_f(A, 0.0, dx, &dy); // just get an arbitrary non-zero dy
		  p = tea_add_diff_adjust_to_key(npairs, next_round, dx, dy, key); // adjust the probability to the fixed key
		}
		//		assert(p != 0.0);

		Bn_init = B[next_round - 1] * p;
		B[next_round] = Bn_init;

		//		printf("[%s:%d] Set B[%d] = 2^%f\n", __FILE__, __LINE__, next_round, log2(Bn_init));

		trail[next_round].dx = dx;
		trail[next_round].dy = dy;
		trail[next_round].p = p;

		differential_t diff;
		diff.dx = dx;
		diff.dy = dy;
		diff.p = p;
		diff_set_dx_dy.insert(diff);
		diff_mset_p.insert(diff);
	 } else {
		Bn_init = 0.0;
	 }
	 //	 Bn_init = 0.0;

	 // If the bound for i rounds is better than the bound for (i - 1) rounds -- start the search again from round 1
	 uint32_t i = nrounds - 1;
	 if(i > 0) {
		if(B[i-1] < B[i]) {
		  nrounds = 0;
		  Bn_init = 0.0;
		  for(int j = 0; j < NROUNDS; j++) {
			 B[j] = 0.0;
		  }
		  printf("[%s:%d] Start again from round 1\n", __FILE__, __LINE__);
		}
	 }
  } while((nrounds < NROUNDS) && ((B[nrounds - 1] != 0.0) || (nrounds == 0) ) && (B[nrounds - 1] > p_rand));
	 //  } // for(int nrounds = 1 ...

  printf("[%s:%d] nrounds = %d\n", __FILE__, __LINE__, nrounds);
  assert(nrounds <= NROUNDS);

  num_rounds = nrounds;
  tea_add_verify_trail(num_rounds, npairs, key, trail);
  tea_add_verify_differential(num_rounds, npairs, key, trail);

#if 1									  // PATCH
  double BB[NROUNDS] = {0.0};				  // copy original bounds
  differential_t ttrail[NROUNDS] = {{0, 0, 0, 0.0}};  // copy original differential trail

  printf("[%s:%d] Final bounds:\n", __FILE__, __LINE__);
  for(uint32_t i = 0; i < num_rounds; i++) {
	 BB[i] = B[i];
	 ttrail[i] = trail[i];
	 printf("B[%2d] 2^%f\n", i, log2(B[i]));
  }

  for(int i = 0; i < NROUNDS; i++) {
	 trail[i].dx = 0;
	 trail[i].dy = 0;
	 trail[i].p = 0.0;
  }

  // re-init DDTs
#if 1
  diff_set_dx_dy.clear();
  diff_mset_p.clear();			  // re-init
  tea_f_add_pddt(word_size, p_thres, lsh_const, rsh_const, &diff_set_dx_dy);
  tea_f_add_pddt_adjust_to_key(num_rounds, npairs, key, p_thres, &diff_set_dx_dy);
  tea_f_add_pddt_dxy_to_dp(&diff_mset_p, diff_set_dx_dy);
  printf("Initial set sizes: Dp %d, Dxy %d\n", diff_mset_p.size(), diff_set_dx_dy.size());
#endif

  //  uint32_t N = nrounds - 1;
  printf("[%s:%d] num_rounds for second pass: %d\n", __FILE__, __LINE__, num_rounds);

  // SECOND ROUND SEARCH
  double scale_fact = 1.0;
  for(uint32_t nrounds = 1; nrounds <= num_rounds; nrounds++ ) {

#if 0
	 if(nrounds > 7) {
		scale_fact = 0.25;
	 }
	 if(nrounds > 12) {
		scale_fact = 0.01;
	 }
#endif
	 double Bn = BB[nrounds - 1] * scale_fact; // !!!
	 int r = 0;		  // initial round

	 printf("[%s:%d] nrounds = %d, Bn_init = 2^%f (B[%d] = 2^%f) : key %8X %8X %8X %8X\n", __FILE__, __LINE__, nrounds, log2(Bn), nrounds - 1, log2(B[nrounds - 1]), key[0], key[1], key[2], key[3]);

	 // init diffs
	 for(int i = 0; i < NROUNDS; i++) {
		diff[i].dx = 0;
		diff[i].dy = 0;
		diff[i].p = 0.0;
	 }

	 tea_add_threshold_search_full(r, nrounds, npairs, key, A, B, &Bn, diff, trail, lsh_const, rsh_const, &diff_mset_p, &diff_set_dx_dy);

	 //	 assert(B[nrounds - 1] == Bn);

#if 1									  // DEBUG
	 for(uint32_t i = 0; i < nrounds; i++) {
		printf("B[%2d] = 2^%f", i, log2(B[i]));
		if(i > 0) {
		  if(B[i-1] < B[i]) {
			 printf(" <-");
		  }
		}
		printf("\n");
	 }
	 printf("pDDT sizes: Dp %d, Dxy %d\n", diff_mset_p.size(), diff_set_dx_dy.size());
#endif
#if 1									  // DEBUG
	 double p_tot = 1.0;
	 for(uint32_t i = 0; i < nrounds; i++) {
		printf("%2d: %8X <- %8X %f (2^%f)\n", i, trail[i].dy, trail[i].dx, trail[i].p, log2(trail[i].p));
		p_tot *= trail[i].p;
	 }
	 printf("p_tot = %16.15f = 2^%f, Bn = %f = 2^%f\n", p_tot, log2(p_tot), Bn, log2(Bn));
#endif  // #if 0									  // DEBUG
#if 1	  // VERIFY
	 if(nrounds >=3) {
		for(uint32_t i = (nrounds - 1); i >= 2; i--) {
		  if(trail[i].p != 0.0) {
			 assert(trail[i].dx == ADD(trail[i - 2].dx, trail[i - 1].dy));
		  }
		}
	 }
#endif  // #if 1	  // VERIFY

	 // If the bound for i rounds is better than the bound for (i - 1) rounds -- start the search again from round 1
	 uint32_t i = nrounds - 1;
	 if(i > 0) {
		//		if((B[i-1] < B[i]) || (trail[i].p == 0.0)) {
		if((B[i-1] < B[i]) || (scale_fact < 0.00005)) {
		  nrounds = 0;
		  Bn_init = 0.0;
		  for(int j = 0; j < NROUNDS; j++) { // copy the original bounds
			 B[j] = BB[j];
			 trail[j].dx = 0;
			 trail[j].dy = 0;
			 trail[j].p = 0;
		  }
		  printf("[%s:%d] Start again from round 1: trail[%d].p = 2^%f\n", __FILE__, __LINE__, i, log2(trail[i].p));
		} else {
		  if(trail[i].p == 0) {
			 nrounds -= 1;
			 scale_fact *= 0.5;
			 for(int j = 0; j < NROUNDS; j++) { // copy the original bounds
				B[j] = BB[j];
				//				trail[j].dx = 0;
				//				trail[j].dy = 0;
				//				trail[j].p = 0;
			 }
			 printf("[%s:%d] Start again from round %d: scale_fact = %f\n", __FILE__, __LINE__, i, scale_fact);
		  } else {
			 if(scale_fact < 1.0) {
				scale_fact = 1.0;
			 }
		  }
		}
	 }

  } // 2-nd round search

  //  for(uint32_t i = 0; i < NROUNDS; i++) {
  for(uint32_t i = 0; i < num_rounds; i++) {
	 printf("%2d: %8X <- %8X (2^%f) | ", i, ttrail[i].dy, ttrail[i].dx, log2(ttrail[i].p));
	 printf("%8X <- %8X (2^%f)\n", trail[i].dy, trail[i].dx, log2(trail[i].p));
  }
  //  printf("[%s:%d] BB[%2d] 2^%f, B[%2d] 2^%f\n", __FILE__, __LINE__, NROUNDS-1, log2(BB[NROUNDS - 1]), NROUNDS-1, log2(B[NROUNDS - 1]));
  printf("[%s:%d] BB[%2d] 2^%f, B[%2d] 2^%f\n", __FILE__, __LINE__, num_rounds-1, log2(BB[num_rounds - 1]), num_rounds-1, log2(B[num_rounds - 1]));

#endif  // #if 1 // PATCH

  adp_xor3_free_matrices(A);
}

/* --- */

void tea_add_trail_search(uint32_t key[4])
{
  uint32_t lsh_const = TEA_LSH_CONST; 
  uint32_t rsh_const = TEA_RSH_CONST;
  double p_thres = TEA_ADD_P_THRES;
  uint32_t word_size = WORD_SIZE;
  uint32_t npairs = NPAIRS;
  uint32_t num_rounds = NROUNDS;

  gsl_matrix* A[2][2][2][2];	  // matrices to compute ADP
  differential_t diff[NROUNDS];	  // arrey of differences
  differential_t trail[NROUNDS];  // a differential trail
  double B[NROUNDS];				  // arey of bounds

  // init matrices
  adp_xor3_alloc_matrices(A);
  adp_xor3_sf(A);
  adp_xor3_normalize_matrices(A);

  // init bounds
  for(int i = 0; i < NROUNDS; i++) {
	 B[i] = 0.0;
  }

  std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy; // Dxy
  std::multiset<differential_t, struct_comp_diff_p> diff_mset_p;	 // Dp

  tea_f_add_pddt(word_size, p_thres, lsh_const, rsh_const, &diff_set_dx_dy);
#if 0									  // DEBUG
  printf("[%s:%d] Dxy before adjust key\n", __FILE__, __LINE__);
  print_set(diff_set_dx_dy);
#endif

#if 1
  tea_f_add_pddt_adjust_to_key(num_rounds, npairs, key, p_thres, &diff_set_dx_dy);
#endif
#if 0									  // DEBUG
  printf("[%s:%d] Dxy after adjust key, p_thres = %f 2^%f\n", __FILE__, __LINE__, p_thres, log2(p_thres));
  print_set(diff_set_dx_dy);
#endif

  tea_f_add_pddt_dxy_to_dp(&diff_mset_p, diff_set_dx_dy);
#if 0									  // DEBUG
  printf("[%s:%d] Dp , p_thres = %f 2^%f\n", __FILE__, __LINE__, p_thres, log2(p_thres));
  print_mset(diff_mset_p);
#endif

  printf("Initial set sizes: Dp %d, Dxy %d\n", diff_mset_p.size(), diff_set_dx_dy.size());
  assert(diff_set_dx_dy.size() == diff_mset_p.size());

  double Bn_init = 0.0;

  for(uint32_t nrounds = 1; nrounds <= NROUNDS; nrounds++ ) {

	 printf("[%s:%d] nrounds = %d, Bn_init = 2^%f : key %8X %8X %8X %8X\n", __FILE__, __LINE__, nrounds, log2(Bn_init), key[0], key[1], key[2], key[3]);
	 double Bn = Bn_init;
	 B[nrounds - 1] = Bn_init;
	 int r = 0;						  // initial round

	 // init diffs
	 for(int i = 0; i < NROUNDS; i++) {
		diff[i].dx = 0;
		diff[i].dy = 0;
		diff[i].p = 0.0;
	 }

	 tea_add_threshold_search(r, nrounds, npairs, key, A, B, &Bn, diff, trail, lsh_const, rsh_const, &diff_mset_p, &diff_set_dx_dy);

	 assert(B[nrounds - 1] == Bn);

#if 1									  // DEBUG
	 for(uint32_t i = 0; i < nrounds; i++) {
		printf("B[%2d] = 2^%f", i, log2(B[i]));
		if(i > 0) {
		  if(B[i-1] < B[i]) {
			 printf(" <-");
		  }
		}
		printf("\n");
	 }
	 printf("pDDT sizes: Dp %d, Dxy %d\n", diff_mset_p.size(), diff_set_dx_dy.size());
#endif
#if 1									  // DEBUG
	 double p_tot = 1.0;
	 for(uint32_t i = 0; i < nrounds; i++) {
		printf("%2d: %8X <- %8X %f (2^%f)\n", i, trail[i].dy, trail[i].dx, trail[i].p, log2(trail[i].p));
		p_tot *= trail[i].p;
	 }
	 printf("p_tot = %16.15f = 2^%f, Bn = %f = 2^%f\n", p_tot, log2(p_tot), Bn, log2(Bn));
#endif  // #if 0									  // DEBUG
#if 1	  // VERIFY
	 if(nrounds >=3) {
		for(uint32_t i = (nrounds - 1); i >= 2; i--) {
		  assert(trail[i].dx == ADD(trail[i - 2].dx, trail[i - 1].dy));
		}
	 }
#endif  // #if 1	  // VERIFY

	 // Compute an initial bound for the next round
	 uint32_t next_round = nrounds;
	 if((next_round >= 2) && (next_round < NROUNDS)) {
		uint32_t dx = ADD(trail[next_round - 2].dx, trail[next_round - 1].dy);
		uint32_t dy = 0;
		double p = 0.0;

		max_eadp_tea_f(A, dx, &dy, &p, lsh_const, rsh_const); // max_dy eadp_tea_f
		p = tea_add_diff_adjust_to_key(npairs, next_round, dx, dy, key); // adjust the probability to the fixed key
		if(p == 0.0) {
		  p = nz_eadp_tea_f(A, 0.0, dx, &dy); // just get an arbitrary non-zero dy
		  p = tea_add_diff_adjust_to_key(npairs, next_round, dx, dy, key); // adjust the probability to the fixed key
		}
		//		assert(p != 0.0);

		Bn_init = B[next_round - 1] * p;
		B[next_round] = Bn_init;

		//		printf("[%s:%d] Set B[%d] = 2^%f\n", __FILE__, __LINE__, next_round, log2(Bn_init));

		trail[next_round].dx = dx;
		trail[next_round].dy = dy;
		trail[next_round].p = p;

		differential_t diff;
		diff.dx = dx;
		diff.dy = dy;
		diff.p = p;
		diff_set_dx_dy.insert(diff);
		diff_mset_p.insert(diff);
	 } else {
		Bn_init = 0.0;
	 }

	 // If the bound for i rounds is better than the bound for (i - 1) rounds -- start the search again from round 1
	 uint32_t i = nrounds - 1;
	 if(i > 0) {
		if(B[i-1] < B[i]) {
		  nrounds = 0;
		  Bn_init = 0.0;
		  for(int j = 0; j < NROUNDS; j++) {
			 B[j] = 0.0;
		  }
		  printf("[%s:%d] Start again from round 1\n", __FILE__, __LINE__);
		}
	 }

  } // for(int nrounds = 1 ...

  tea_add_verify_trail(num_rounds, npairs, key, trail);
  tea_add_verify_differential(num_rounds, npairs, key, trail);
  adp_xor3_free_matrices(A);
}


/* --- */

	 bool b_none_found = false;
#if 1	  // VERIFY
	 if(nrounds >=3) {
		for(uint32_t i = (nrounds - 1); i >= 2; i--) {
		  if(trail[i].dx != ADD(trail[i - 2].dx, trail[i - 1].dy)) {
			 b_none_found = true;
		  }
		  //		  assert(trail[i].dx == ADD(trail[i - 2].dx, trail[i - 1].dy));
		}
	 }
#endif  // #if 1	  // VERIFY

	 // If the bound for i rounds is better than the bound for (i - 1) rounds -- start the search again from round 1
	 uint32_t i = nrounds - 1;
	 if(i > 0) {
		//		if((B[i-1] < B[i]) || (b_none_found == true) || (trail[i].p == 0.0)) {
		if((B[i-1] < B[i]) || (trail[i].p == 0.0)) {
		  nrounds = 0;
		  Bn_init = 0.0;
		  for(int j = 0; j < NROUNDS; j++) { // copy the original bounds
			 B[j] = BB[j];
		  }
		  printf("[%s:%d] Start again from round 1: trail[%d].p = 2^%f, b_none_found = %d\n", __FILE__, __LINE__, i, log2(trail[i].p), b_none_found);
		}
	 }


/* --- */


First round:

B[ 0] = 2^0.000000
B[ 1] = 2^-1.018254
B[ 2] = 2^-2.055810
B[ 3] = 2^-5.361799
B[ 4] = 2^-11.098062
B[ 5] = 2^-16.388564
B[ 6] = 2^-24.567849
B[ 7] = 2^-34.117833
B[ 8] = 2^-38.116154
B[ 9] = 2^-43.146782
B[10] = 2^-49.195497
B[11] = 2^-56.622590
B[12] = 2^-60.524357
B[13] = 2^-64.153125
	  pDDT sizes: Dp 70, Dxy 1062
	  0:        0 <-        0 1.000000 (2^0.000000)
	  1:       11 <-        1 0.078339 (2^-3.674132)
	  2:        0 <-       11 0.000122 (2^-13.000000)
	  3: FFFFFFEF <-        1 0.141754 (2^-2.818537)
	  4:        0 <-        0 1.000000 (2^0.000000)
	  5:       11 <-        1 0.079132 (2^-3.659594)
	  6:        0 <-       11 0.000061 (2^-14.000000)
	  7: FFFFFFEF <-        1 0.136230 (2^-2.875879)
	  8:        0 <-        0 1.000000 (2^0.000000)
	  9:       11 <-        1 0.078979 (2^-3.662378)
	  10:        0 <-       11 0.000061 (2^-14.000000)
	  11: FFFFFFEF <-        1 0.140259 (2^-2.833837)
	  12:        0 <-        0 1.000000 (2^0.000000)
	  13: FFFFFFF1 <-        1 0.080841 (2^-3.628768)
	  p_tot = 0.000000000000000 = 2^-64.153125, Bn = 0.000000 = 2^-64.153125



Second round:

B[ 1] = 2^-1.025227
B[ 2] = 2^-2.956967
B[ 3] = 2^-5.357931
B[ 4] = 2^-11.086067
B[ 5] = 2^-16.339391
B[ 6] = 2^-24.574305
B[ 7] = 2^-31.805116
B[ 8] = 2^-37.241295
B[ 9] = 2^-42.073683
B[10] = 2^-49.707038
B[11] = 2^-56.045881
B[12] = 2^-60.944141
B[13] = 2^-65.315758
	  pDDT sizes: Dp 71, Dxy 1100
	  0:       1E <-        2 0.134735 (2^-2.891802)
	  1:        F <-        1 0.081085 (2^-3.624417)
	  2:        0 <-       11 0.000397 (2^-11.299560)
	  3: FFFFFFEF <-        1 0.139343 (2^-2.843285)
	  4:        0 <-        0 1.000000 (2^0.000000)
	  5:       11 <-        1 0.080109 (2^-3.641898)
	  6:        0 <-       11 0.000061 (2^-14.000000)
	  7: FFFFFFEF <-        1 0.133911 (2^-2.900652)
	  8:        0 <-        0 1.000000 (2^0.000000)
	  9:       11 <-        1 0.082184 (2^-3.605001)
	  10:        0 <-       11 0.000061 (2^-14.000000)
	  11: FFFFFFEF <-        1 0.139709 (2^-2.839498)
	  12:        0 <-        0 1.000000 (2^0.000000)
	  13: FFFFFFF1 <-        1 0.078583 (2^-3.669643)
	  p_tot = 0.000000000000000 = 2^-65.315758, Bn = 0.000000 = 2^-65.315758


/* --- */
[./src/tea-add-threshold-search.cc:893] Final bounds:
B[ 0] 2^0.000000
B[ 1] 2^-1.013003
B[ 2] 2^-2.051010
B[ 3] 2^-5.326119
B[ 4] 2^-11.092500
B[ 5] 2^-16.420890
B[ 6] 2^-24.819300
B[ 7] 2^-33.665341
B[ 8] 2^-37.764419
B[ 9] 2^-42.717709
B[10] 2^-50.842433
B[11] 2^-55.295289
B[12] 2^-59.329377
B[13] 2^-62.969627
[./src/tea-add-threshold-search.cc:910] nrounds = 1, Bn_init = 2^-2.000000 : key E028DF9A 8819B4C3 3AB116AF  3C50723
B

/* --- */

B[ 0] 2^0.000000
B[ 1] 2^-1.014158
B[ 2] 2^-2.040550
B[ 3] 2^-5.386258
B[ 4] 2^-11.121815
B[ 5] 2^-16.419670
B[ 6] 2^-24.497897
B[ 7] 2^-32.064099
B[ 8] 2^-38.278724
B[ 9] 2^-43.208812
B[10] 2^-48.800461
B[11] 2^-56.974479
B[12] 2^-57.280305
B[13] 2^-60.896061


/* --- */

[ 0] 1.000000 (2^ 0.000) [ 1] 1.000000 (2^ 0.000) [ 2] 1.000000 (2^ 0.000) [ 3] 1.000000 (2^ 0.000)
[ 4] 1.000000 (2^ 0.000) [ 5] 1.000000 (2^ 0.000) [ 6] 1.000000 (2^ 0.000) [ 7] 1.000000 (2^ 0.000)
[ 8] 1.000000 (2^ 0.000) [ 9] 1.000000 (2^ 0.000) [10] 1.000000 (2^ 0.000) [11] 0.118164 (2^-3.081)
[12] 1.000000 (2^ 0.000) [13] 1.000000 (2^ 0.000) [14] 1.000000 (2^ 0.000) [15] 1.000000 (2^ 0.000)
[./tests/salsa-tests.cc:212] PW_exp vs. P_rand:
[ 0]       X (2^ 0.000) [ 1]       X (2^ 0.000) [ 2]       X (2^ 0.000) [ 3]       X (2^ 0.000)
[ 4]       X (2^ 0.000) [ 5]       X (2^ 0.000) [ 6]       X (2^ 0.000) [ 7]       X (2^ 0.000)
[ 8]       X (2^ 0.000) [ 9]       X (2^ 0.000) [10]       X (2^ 0.000) [11]       X (2^-3.000)
[12]       X (2^ 0.000) [13]       X (2^ 0.000) [14]       X (2^ 0.000) [15]       X (2^ 0.000)
[./tests/salsa-tests.cc:214] p = 0.000000 (2^-104.016596), p = 0.118164 (2^-3.081137)
[./tests/salsa-tests.cc:216] S:        0        0       73       28
[./tests/salsa-tests.cc:210] PW_exp:
[ 0] 0.121826 (2^-3.037) [ 1] 0.124512 (2^-3.006) [ 2] 0.034668 (2^-4.850) [ 3] 0.007812 (2^-7.000)
[ 4] 0.250000 (2^-2.000) [ 5] 0.033203 (2^-4.913) [ 6] 0.250977 (2^-1.994) [ 7] 0.062500 (2^-4.000)
[ 8] 0.120361 (2^-3.055) [ 9] 0.251953 (2^-1.989) [10] 1.000000 (2^ 0.000) [11] 0.009277 (2^-6.752)
[12] 0.505371 (2^-0.985) [13] 0.508057 (2^-0.977) [14] 1.000000 (2^ 0.000) [15] 1.000000 (2^ 0.000)
[./tests/salsa-tests.cc:212] PW_exp vs. P_rand:
[ 0]       X (2^-3.000) [ 1]       X (2^-3.000) [ 2]       X (2^-5.000) [ 3]       X (2^-7.000)
[ 4]       X (2^-2.000) [ 5]       X (2^-5.000) [ 6]       X (2^-2.000) [ 7]       X (2^-4.000)
salsa-tests: ./src/salsa.cc:492: void salsa_print_prob_vs_rand(double*, double*): Assertion `0 == 1' failed.
[ 8]       X (2^-3.000) [ 9]       X (2^-2.000) [10]       X (2^ 0.000) [11] 2^-6.752 (2^-8.000) Aborted
vpv@mazirat:~/skcrypto/trunk/work/src/yaarx$ 


/* --- */

		//		double eps = (2 * P[i]) - 1.0;
		//		double eps = 0.5 - P[i];
		//		if(P[i] > 0.5) {
		//		  eps = P[i] - 0.5;
		//		}
		//		printf("[%2d] %6.3f (2^%6.3f) ", i, eps, log2(eps));

/* ---- */

[./tests/salsa-tests.cc:184] PW_the:
[ 0] 0.000000 (2^-37.438) [ 1] 0.000000 (2^-37.708) [ 2] 0.000000 (2^-37.930) [ 3] 0.000000 (2^-40.293)
[ 4] 0.000000 (2^-49.086) [ 5] 0.000000 (2^-51.256) [ 6] 0.000000 (2^-43.802) [ 7] 0.000000 (2^-52.359)
[ 8] 0.000000 (2^-31.563) [ 9] 0.000000 (2^-31.438) [10] 0.000000 (2^-26.956) [11] 0.000000 (2^-32.978)
[12] 0.000000 (2^-30.086) [13] 0.000000 (2^-30.086) [14] 0.000000 (2^-27.823) [15] 0.000000 (2^-34.086)
[./tests/salsa-tests.cc:187] PW_exp:
[ 0] 0.124805 (2^-3.002) [ 1] 0.000512 (2^-10.931) [ 2] 0.001894 (2^-9.045) [ 3] 0.001013 (2^-9.947)
[ 4] 0.000246 (2^-11.992) [ 5] 0.000496 (2^-10.976) [ 6] 0.000032 (2^-14.934) [ 7] 0.000032 (2^-14.934)
[ 8] 0.000479 (2^-11.028) [ 9] 0.001968 (2^-8.989) [10] 0.000992 (2^-9.977) [11] 0.000131 (2^-12.902)
[12] 0.000064 (2^-13.923) [13] 0.000025 (2^-15.272) [14] 0.000248 (2^-11.975) [15] 0.001988 (2^-8.974)
[
	  [./tests/salsa-tests.cc:189] PW_exp vs. P_rand:
	  [ 0]       X (2^-3) [ 1]       X (2^-11) [ 2]       X (2^-9) [ 3]       X (2^-10)
	  [ 4]       X (2^-12) [ 5]       X (2^-11) [ 6]       X (2^-15) [ 7]       X (2^-15)
	  [ 8]       X (2^-11) [ 9]       X (2^-9) [10]       X (2^-10) [11]       X (2^-13)
	  [12]       X (2^-14) [13]       X (2^-15) [14]       X (2^-12) [15]       X (2^-9)
[

	  [./tests/salsa-tests.cc:184] PW_the:
	  [ 0] 0.000000 (2^-42.000) [ 1] 0.000000 (2^-38.000) [ 2] 0.000000 (2^-40.000) [ 3] 0.000000 (2^-45.000)
	  [ 4] 0.000000 (2^-61.000) [ 5] 0.000000 (2^-53.000) [ 6] 0.000000 (2^-56.000) [ 7] 0.000000 (2^-67.000)
	  [ 8] 0.000000 (2^-42.000) [ 9] 0.000000 (2^-42.000) [10] 0.000000 (2^-40.000) [11] 0.000000 (2^-47.000)
	  [12] 0.000000 (2^-35.000) [13] 0.000000 (2^-32.000) [14] 0.000000 (2^-29.000) [15] 0.000000 (2^-36.000)
	  [./tests/salsa-tests.cc:187] PW_exp:
	  [ 0] 0.000017 (2^-15.830) [ 1] 0.000019 (2^-15.715) [ 2] 0.000016 (2^-15.956) [ 3] 0.000016 (2^-15.913)
	  [ 4] 0.000015 (2^-16.000) [ 5] 0.000013 (2^-16.193) [ 6] 0.000020 (2^-15.608) [ 7] 0.000015 (2^-16.000)
	  [ 8] 0.000016 (2^-15.913) [ 9] 0.000016 (2^-15.913) [10] 0.000013 (2^-16.193) [11] 0.000012 (2^-16.300)
	  [12] 0.000014 (2^-16.142) [13] 0.000014 (2^-16.093) [14] 0.000014 (2^-16.142) [15] 0.000015 (2^-16.000)
[
/* --- */

  //  S[9] = random32() & MASK;//1U << (WORD_SIZE);
  uint32_t i_w = random32() % 4; // random index
#if 0
  //  i_w = 9;						  // Crowley
  i_w = 7;							  // Aumasson et al.
  S[9] = 1U << (WORD_SIZE - 1);
#else
  i_w += 6;
  assert((i_w == 6) || (i_w == 7) || (i_w == 8) || (i_w == 9));
  S[i_w] = gen_sparse(1, WORD_SIZE); // set 1 bit difference at random position
#endif

/* --- */

  // random32() & MASK;
#if 0
  S[6] = gen_sparse(8, WORD_SIZE);
  S[7] = gen_sparse(8, WORD_SIZE);
  S[8] = gen_sparse(8, WORD_SIZE);
  S[9] = gen_sparse(8, WORD_SIZE);
#endif


/* --- */
  // WARNING!!! This results in sub-optimal probability,
  // but improves the efficiency.
  //  if((WORD_SIZE == 32)) {
  //	 double p_thres = 1.0/(double)(1ULL << 15);
  //	 if(*r_max >= p_thres)
  //		return;
  //  }



/* --- */

void salsa_gen_word_deps(const uint32_t nrounds, 
								 const uint32_t e[SALSA_STATE + SALSA_STATE][5], 
								 uint32_t dep[SALSA_STATE][MAX_NROUNDS])
{  
  // initialize the dep array to 0
  for(uint32_t i = 0; i < SALSA_STATE; i++) {
	 for(uint32_t s = 0; s < MAX_NROUNDS; s++) {
		dep[i][s] = 0;
	 }
  }
  
  for(uint32_t r = 0; r < MAX_NROUNDS; r++) {
	 // i is index in the array e
	 // it points either to entries 0,1,..,15
	 // or to entries 16,17,...,31 depending
	 // on weather r is even or odd (resp. weather 
	 // we have column round or row round)
	 for(uint32_t i = 0; i < SALSA_STATE; i++) {
		// Copy a row from the array e. If r is even 
		// (r & 1 == 0) it means we have column round
		// (entries 0 to 15 of e[]) so 
		// we copy the i-th row from the array e[]. If
		// r is odd (r & 1 == 1) it means we have a row
		// round (entries 16 to 31 of e[]) so we copy
		// the (i+16)-th row of e[].
		// In summary f contains one row of e[]
		const uint32_t* const f = e[(r & 1) ? (i + 16) : i];		  
		// update the dependencies of the f[0]-th word:
		// the new dependency of the new word f[0]
		// is a composition of the dependencies so far 
		// (ie. up to round r) of the words
		// which participate it its computation ie. words
		// f[1],f[2],f[3] (according to the salsa round function
		// f[0] = f[1] ^ ((f[2]+f[3]) <<< const) ).
		// in our bit representation "composition" is be expressed
		// as a bitwise OR |
		for (int s = 0; s <= r ; ++s) { // vpv
		  //for (int s = 0; s < MAX_NROUNDS; ++s) {
		  dep[f[0]][s] = 
			 dep[f[1]][s] |
			 dep[f[2]][s] |
			 dep[f[3]][s];

		  //printf("round# %d, word[%d], dep[%d] ", r, f[0], s);
		  //print_bits32(dep[f[0]][s]);
		  //printf("\n");
		}
		// word f[0] of course depends also on the addition which
		// participates in the calculation of f[0]. according
		// to our enumeration rules this addition has the same
		// index as f[0]. we store this dependency by setting 
		// the f[0]-th bit of the 16-bit dependency word
		dep[f[0]][r] |= 1 << f[0]; //!!! 20091206 vpv
	 }
  }  
  // test statistics
#if 0
  // counts over words
  for (int i = 0; i < SALSA_STATE; ++i)
	 {
		printf("word %d after round %d depends on:\n", i, MAX_NROUNDS - 1);
		// counts over dependencies
		for (int s = 0; s < MAX_NROUNDS; ++s)
		  //printf("dep[%d][%d]=0x%08x\n", i, s, dep[i][s]);
		  // counts over bits within one dependency word
		  // (we use only the 16 lsb bits of each dep word)
		  for (int j = 0; j < WORD_SIZE/2; ++j)
			 if ((dep[i][s] >> j) & 1)
				printf("  addition %d of round %d\n", j, s);
	 }
#endif  // #if 0
}

/* --- */

/*

- Salsa 5 rounds, 2 stars max, 45 min.

[./tests/salsa-tests.cc:189] Tests, WORD_SIZE  = 32, MASK = FFFFFFFF
	  [./tests/salsa-tests.cc:154] S[ 9] 80000000
	  [./src/salsa.cc:127] round# 0 / 4
	  [./src/salsa.cc:127] round# 1 / 4
	  [./src/salsa.cc:127] round# 2 / 4
	  [./src/salsa.cc:127] round# 3 / 4
	  [./src/salsa.cc:127] round# 4 / 4
R[-1]
	  [ 0]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [ 1]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [ 2]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [ 3]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [ 4]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [ 5]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [ 6]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [ 7]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [ 8]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [ 9] 80000000 10000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [10]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [11]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [12]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [13]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [14]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [15]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |

R[ 0]
	  [ 0]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [ 1]   201000 00000000001000000001000000000000 | 0.500000 (2^-1.000000) |
	  [ 2]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [ 3]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [ 4]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [ 5] 44000080 01000100000000000000000010000000 | 0.125000 (2^-3.000000) |
	  [ 6]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [ 7]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [ 8]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [ 9] 80000000 10000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [10]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [11]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [12]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [13]      100 00000000000000000000000100000000 | 1.000000 (2^0.000000) |
	  [14]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [15]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |

R[ 1]
	  [ 0] 20010880 00100000000000*10000100010000000 | 0.093750 (2^-3.415037) |
	  [ 1]   201000 00000000001000000001000000000000 | 1.000000 (2^0.000000) |
	  [ 2] 40200000 01000000001000000000000000000000 | 0.250000 (2^-2.000000) |
	  [ 3]  2000800 0000001000000000000*100000000000 | 0.250000 (2^-2.000000) |
	  [ 4] 20954010 00100000100101010100000000010000 | 0.002197 (2^-8.830075) |
	  [ 5] 562080D0 010101100*1000001000000011010000 | 0.001465 (2^-9.415037) |
	  [ 6]     4022 0000000000000000010000000*100010 | 0.250000 (2^-2.000000) |
	  [ 7]   814488 00000000100000010100010*10001000 | 0.023438 (2^-5.415037) |
	  [ 8]     8000 00000000000000001000000000000000 | 0.500000 (2^-1.000000) |
	  [ 9] 90080000 10010000000010000000000000000000 | 0.250000 (2^-2.000000) |
	  [10]    24022 00000000000000100100000000100010 | 0.125000 (2^-3.000000) |
	  [11]       40 00000000000000000000000001000000 | 1.000000 (2^0.000000) |
	  [12]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
	  [13]      100 00000000000000000000000100000000 | 1.000000 (2^0.000000) |
	  [14]   200000 00000000001000000000000000000000 | 0.500000 (2^-1.000000) |
	  [15]  4000080 00000100000000000000000010000000 | 0.250000 (2^-2.000000) |

R[ 2]
	  [ 0] 200148C2 00100000000000*1*100100011000*10 | 0.125000 (2^-3.000000) |
	  [ 1]  114BA22 0000000100*1010*1011101000100010 | 0.000057 (2^-14.093109) |
	  [ 2]  4A04402 00000100101000000100010000000010 | 0.015625 (2^-6.000000) |
	  [ 3]  2002802 00000010000000000*1*100000000010 | 0.250000 (2^-2.000000) |
	  [ 4] 20110000 00100000000100010000000000000000 | 0.046875 (2^-4.415037) |
	  [ 5] 70A981C2 01110*001*1*10011000000111000010 | 0.000051 (2^-14.245112) |
	  [ 6]  8800092 0000100010000000000000001**10010 | 0.015625 (2^-6.000000) |
	  [ 7]   D04084 00000000110100000100000*1000*100 | 0.017578 (2^-5.830075) |
	  [ 8] 20118000 00100000000100011000000000000000 | 0.023438 (2^-5.415037) |
	  [ 9] 90402829 10010000010000000*101000001010*1 | 0.002930 (2^-8.415037) |
	  [10] 124250A3 000100100100001001*1000010100011 | 0.001709 (2^-9.192645) |
	  [11]  510400A 0000010100010000*1000000000*1010 | 0.001648 (2^-9.245112) |
	  [12] 10000000 00010000000000000000000000000000 | 0.062500 (2^-4.000000) |
	  [13] 41501384 01000001010100000**1001110000100 | 0.000069 (2^-13.830075) |
	  [14]  1200000 00000001001000000000000000000000 | 0.046875 (2^-4.415037) |
	  [15]  6081180 00000110000*1000000100*110000000 | 0.001648 (2^-9.245112) |

R[ 3]
	  [ 0] 2905424A 001*10*1000001*1*100001001001*10 | 0.000028 (2^-15.129635) |
	  [ 1]  1849A33 0000000110*0010*1*01101000110011 | 0.001236 (2^-9.660150) |
	  [ 2]  CA42643 0000110010100100**10011001000011 | 0.000009 (2^-16.830075) |
	  [ 3]  2022882 000000100000**100*1*100010000010 | 0.000006 (2^-17.415037) |
	  [ 4] 3A02A28A 00111*10000000101*10001010001010 | 0.000002 (2^-19.245112) |
	  [ 5] 3A25E589 00111*100*1**1011110010110001001 | 0.000009 (2^-16.830075) |
	  [ 6] 44C0218A 0100010011000000**1000011**01010 | 0.000549 (2^-10.830075) |
	  [ 7] D1179023 110100010001011110*1000*0010**11 | 0.000039 (2^-14.660150) |
	  [ 8] A4B85024 101001001011100**101000000100100 | 0.000023 (2^-15.437758) |
	  [ 9] 1AC41C38 0001101011000100**011100001110*0 | 0.000033 (2^-14.907243) |
	  [10] C21058B3 110000100**1000001*1100010110011 | 0.000002 (2^-19.299560) |
	  [11]  404044B 00000100000**100*0000100010*1011 | 0.000488 (2^-11.000000) |
	  [12] 84084000 1000010000001000*10000000000000* | 0.008789 (2^-6.830075) |
	  [13] 41F11280 01000001111100*10**1001010000000 | 0.003296 (2^-8.245112) |
	  [14] 23700881 00100*110111000000001000100000*1 | 0.000069 (2^-13.830075) |
	  [15] 2E0C9404 0*101110000*110*100101*000000100 | 0.000360 (2^-11.437758) |

R[ 4]
	  [ 0] A811013A 101*10*000010**1*000000100111*10 | 0.000003 (2^-18.508147) |
	  [ 1] 808A3B63 1000000*10**101*0*11101101100011 | 0.000003 (2^-18.490225) |
	  [ 2]  55D04D1 0*00010101011101**00010011010001 | 0.000011 (2^-16.508147) |
	  [ 3]  2020811 000000100000**100*0*10**00010001 | 0.000032 (2^-14.923184) |
	  [ 4] B88387D8 10111*00100000111*00011111011*00 | 0.000097 (2^-13.338222) |
	  [ 5] BA84E78A 10111*101*0**1001110011110001010 | 0.000003 (2^-18.148251) |
	  [ 6] 60CA0110 01100000110*1010**0000010**1000* | 0.000011 (2^-16.437758) |
	  [ 7] D46F9A63 1101*100011*111110*1101*0110**11 | 0.000011 (2^-16.490225) |
	  [ 8] A3BC4CC5 10100011101111***100110011000101 | 0.000038 (2^-14.700792) |
	  [ 9] 5AA4103C 0101101010100100**01*00*001111*0 | 0.000000 (2^-23.245112) |
	  [10] D393C957 11010*111**10*1111*0100101010111 | 0.000006 (2^-17.370643) |
	  [11] 14020E0F 00010100000***10**001110000*1111 | 0.000000 (2^-22.215365) |
	  [12] F4982100 111101001*0110*0*01000010000000* | 0.000001 (2^-20.923184) |
	  [13] 401808B9 010000000*0110*00**0100010111001 | 0.000002 (2^-18.630403) |
	  [14] 1B746400 00011*1101110100011**100000000*0 | 0.000017 (2^-15.830075) |
	  [15]  E84947F 0*001110100**10*100101*001111111 | 0.000001 (2^-20.660150) |

	  [ 0] 0.000000 (2^  -inf) [ 1] 0.000000 (2^  -inf) [ 2] 0.000000 (2^  -inf) [ 3] 0.000000 (2^  -inf)
	  [ 4] 0.000000 (2^  -inf) [ 5] 0.000000 (2^  -inf) [ 6] 0.000000 (2^  -inf) [ 7] 0.000000 (2^  -inf)
	  [ 8] 0.000000 (2^  -inf) [ 9] 0.000000 (2^  -inf) [10] 0.000000 (2^  -inf) [11] 0.000000 (2^  -inf)
	  [12] 0.000000 (2^  -inf) [13] 0.000000 (2^  -inf) [14] 0.000000 (2^  -inf) [15] 0.000000 (2^  -inf)
	  [./tests/salsa-tests.cc:177] p = 0.000000 (2^-673.424354), p = 0.000000 (2^-inf)
	  [./tests/salsa-tests.cc:178] S[ 9] 80000000

real    44m47.357s
user    44m42.720s
sys     0m0.024s

*/

/* --- */
/* 
Salsa 4 rounds: 3 stars max, 2 hours

vpv@igor:~/skcrypto/trunk/work/src/yaarx$ time ./bin/salsa-tests
[./tests/salsa-tests.cc:175] Tests, WORD_SIZE  = 32, MASK = FFFFFFFF
[./src/salsa.cc:127] round# 0 / 3
[./src/salsa.cc:127] round# 1 / 3
[./src/salsa.cc:127] round# 2 / 3
[./src/salsa.cc:127] round# 3 / 3
R[-1]
 [ 0]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [ 1]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [ 2]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [ 3]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [ 4]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [ 5]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [ 6]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [ 7]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [ 8]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [ 9] 80000000 10000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [10]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [11]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [12]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [13]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [14]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [15]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |

R[ 0]
 [ 0]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [ 1]   201000 00000000001000000001000000000000 | 0.500000 (2^-1.000000) |
 [ 2]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [ 3]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [ 4]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [ 5] 44000080 01000100000000000000000010000000 | 0.125000 (2^-3.000000) |
 [ 6]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [ 7]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [ 8]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [ 9] 80000000 10000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [10]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [11]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [12]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [13]      100 00000000000000000000000100000000 | 1.000000 (2^0.000000) |
 [14]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [15]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |

R[ 1]
 [ 0] 20010880 00100000000000*10000100010000000 | 0.093750 (2^-3.415037) |
 [ 1]   201000 00000000001000000001000000000000 | 1.000000 (2^0.000000) |
 [ 2] 40200000 01000000001000000000000000000000 | 0.250000 (2^-2.000000) |
 [ 3]  2000800 0000001000000000000*100000000000 | 0.250000 (2^-2.000000) |
 [ 4] 20954010 00100000100101010100000000010000 | 0.002197 (2^-8.830075) |
 [ 5] 562080D0 010101100*1000001000000011010000 | 0.001465 (2^-9.415037) |
 [ 6]     4022 0000000000000000010000000*100010 | 0.250000 (2^-2.000000) |
 [ 7]   814488 00000000100000010100010*10001000 | 0.023438 (2^-5.415037) |
 [ 8]     8000 00000000000000001000000000000000 | 0.500000 (2^-1.000000) |
 [ 9] 90080000 10010000000010000000000000000000 | 0.250000 (2^-2.000000) |
 [10]    24022 00000000000000100100000000100010 | 0.125000 (2^-3.000000) |
 [11]       40 00000000000000000000000001000000 | 1.000000 (2^0.000000) |
 [12]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
 [13]      100 00000000000000000000000100000000 | 1.000000 (2^0.000000) |
 [14]   200000 00000000001000000000000000000000 | 0.500000 (2^-1.000000) |
 [15]  4000080 00000100000000000000000010000000 | 0.250000 (2^-2.000000) |

R[ 2]
 [ 0] 200148C2 00100000000000*1*100100011000*10 | 0.125000 (2^-3.000000) |
 [ 1]  D14BA22 000011*10**101001011101000100010 | 0.000047 (2^-14.370643) |
 [ 2]  4A04402 00000100101000000100010000000010 | 0.015625 (2^-6.000000) |
 [ 3]  2002802 00000010000000000*1*100000000010 | 0.250000 (2^-2.000000) |
 [ 4] 20110000 00100000000100010000000000000000 | 0.046875 (2^-4.415037) |
 [ 5] 30A990C0 0*110*001*1*10011001000011000000 | 0.000013 (2^-16.245112) |
 [ 6]  8800092 0000100010000000000000001**10010 | 0.015625 (2^-6.000000) |
 [ 7]   D04084 00000000110100000100000*1000*100 | 0.017578 (2^-5.830075) |
 [ 8] 20118000 00100000000100011000000000000000 | 0.023438 (2^-5.415037) |
 [ 9] 90402829 10010000010000000*1010000*1010*1 | 0.005859 (2^-7.415037) |
 [10] 124250A3 000100100100001001*1000010100011 | 0.001709 (2^-9.192645) |
 [11]  510400A 0000010100010000*1000000000*1010 | 0.001648 (2^-9.245112) |
 [12] 10000000 00010000000000000000000000000000 | 0.062500 (2^-4.000000) |
 [13] 41509384 01000001010100001**100111000*100 | 0.000206 (2^-12.245112) |
 [14]  1200000 00000001001000000000000000000000 | 0.046875 (2^-4.415037) |
 [15]  6081180 00000110000*100000010**110000000 | 0.003296 (2^-8.245112) |

R[ 3]
[ 0]  8054C42 00*01**0000001*1*100110001000*10 | 0.000004 (2^-17.830075) |
[ 1]  D849A33 000011*11**001001*01101000110011 | 0.001236 (2^-9.660150) |
[ 2]  D64264B 000011010110010***10011001001011 | 0.000003 (2^-18.437758) |
[ 3]  2012BCA 000000100000***10*1*101111001010 | 0.000004 (2^-17.830075) |
[ 4] 12806099 0**100101000000001100000100110*1 | 0.000011 (2^-16.490225) |
[ 5] A2005380 1*100*10**0*00000101001110000**0 | 0.000007 (2^-17.075187) |
[ 6] 44C8209A 01000100110010000*1000001**11010 | 0.000412 (2^-11.245112) |
[ 7] C1B39427 110000*11*11001110*1010*0010*111 | 0.000029 (2^-15.075187) |
[ 8] A4B85024 1010*1001011100**101000000100100 | 0.000045 (2^-14.437758) |
[ 9] 1AC41C38 000110101100010***0111000*1110*0 | 0.000049 (2^-14.322280) |
[10] C21058B3 11*000100**1000001*1100010110011 | 0.000003 (2^-18.437758) |
[11]  404044B 00000100000**100*0000100010*1011 | 0.000366 (2^-11.415037) |
[12] 84084000 1000010000001000*1000000000000** | 0.010254 (2^-6.607683) |
[13] 41F19280 01000001111100*11**100101000*000 | 0.000961 (2^-10.022720) |
[14] 1F700881 0001111101110000000010001000***1 | 0.000040 (2^-14.607683) |
[15] 2E0D0002 0*101110000*1101000*0**000000*10 | 0.000029 (2^-15.084121) |

[ 0] 0.000000 (2^  -inf) [ 1] 0.000000 (2^  -inf) [ 2] 0.000000 (2^  -inf) [ 3] 0.000000 (2^  -inf)
[ 4] 0.000000 (2^  -inf) [ 5] 0.000000 (2^  -inf) [ 6] 0.000000 (2^  -inf) [ 7] 0.000000 (2^  -inf)
[ 8] 0.000000 (2^  -inf) [ 9] 0.000000 (2^  -inf) [10] 0.000000 (2^  -inf) [11] 0.000000 (2^  -inf)
[12] 0.000000 (2^  -inf) [13] 0.000000 (2^  -inf) [14] 0.000000 (2^  -inf) [15] 0.000000 (2^  -inf)
[./tests/salsa-tests.cc:164] p = 0.000000 (2^-392.687960), p = 0.000000 (2^-inf)

real    122m21.380s
user    122m8.146s
sys     0m0.020s

 */

/* --- */


/* 

Salsa 4 rounds, max 2 stars, 2 min

[./tests/salsa-tests.cc:175] Tests, WORD_SIZE  = 32, MASK = FFFFFFFF
R[-1]
[ 0]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[ 1]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[ 2]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[ 3]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[ 4]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[ 5]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[ 6]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[ 7]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[ 8]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[ 9] 80000000 10000000000000000000000000000000 | 1.000000 (2^0.000000) |
[10]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[11]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[12]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[13]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[14]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[15]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |

R[ 0]
[ 0]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[ 1]   201000 00000000001000000001000000000000 | 0.500000 (2^-1.000000) |
[ 2]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[ 3]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[ 4]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[ 5] 44000080 01000100000000000000000010000000 | 0.125000 (2^-3.000000) |
[ 6]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[ 7]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[ 8]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[ 9] 80000000 10000000000000000000000000000000 | 1.000000 (2^0.000000) |
[10]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[11]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[12]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[13]      100 00000000000000000000000100000000 | 1.000000 (2^0.000000) |
[14]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[15]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |

R[ 1]
[ 0] 20010880 00100000000000*10000100010000000 | 0.093750 (2^-3.415037) |
[ 1]   201000 00000000001000000001000000000000 | 1.000000 (2^0.000000) |
[ 2] 40200000 01000000001000000000000000000000 | 0.250000 (2^-2.000000) |
[ 3]  2000800 0000001000000000000*100000000000 | 0.250000 (2^-2.000000) |
[ 4] 20954010 00100000100101010100000000010000 | 0.002197 (2^-8.830075) |
[ 5] 562080D0 010101100*1000001000000011010000 | 0.001465 (2^-9.415037) |
[ 6]     4022 0000000000000000010000000*100010 | 0.250000 (2^-2.000000) |
[ 7]   814488 00000000100000010100010*10001000 | 0.023438 (2^-5.415037) |
[ 8]     8000 00000000000000001000000000000000 | 0.500000 (2^-1.000000) |
[ 9] 90080000 10010000000010000000000000000000 | 0.250000 (2^-2.000000) |
[10]    24022 00000000000000100100000000100010 | 0.125000 (2^-3.000000) |
[11]       40 00000000000000000000000001000000 | 1.000000 (2^0.000000) |
[12]        0 00000000000000000000000000000000 | 1.000000 (2^0.000000) |
[13]      100 00000000000000000000000100000000 | 1.000000 (2^0.000000) |
[14]   200000 00000000001000000000000000000000 | 0.500000 (2^-1.000000) |
[15]  4000080 00000100000000000000000010000000 | 0.250000 (2^-2.000000) |

R[ 2]
[ 0] 200148C2 00100000000000*1*100100011000*10 | 0.125000 (2^-3.000000) |
[ 1]  114BA22 0000000100*1010*1011101000100010 | 0.000057 (2^-14.093109) |
[ 2]  4A04402 00000100101000000100010000000010 | 0.015625 (2^-6.000000) |
[ 3]  2002802 00000010000000000*1*100000000010 | 0.250000 (2^-2.000000) |
[ 4] 20110000 00100000000100010000000000000000 | 0.046875 (2^-4.415037) |
[ 5] 70A981C2 01110*001*1*10011000000111000010 | 0.000051 (2^-14.245112) |
[ 6]  8800092 0000100010000000000000001**10010 | 0.015625 (2^-6.000000) |
[ 7]   D04084 00000000110100000100000*1000*100 | 0.017578 (2^-5.830075) |
[ 8] 20118000 00100000000100011000000000000000 | 0.023438 (2^-5.415037) |
[ 9] 90402829 10010000010000000*101000001010*1 | 0.002930 (2^-8.415037) |
[10] 124250A3 000100100100001001*1000010100011 | 0.001709 (2^-9.192645) |
[11]  510400A 0000010100010000*1000000000*1010 | 0.001648 (2^-9.245112) |
[12] 10000000 00010000000000000000000000000000 | 0.062500 (2^-4.000000) |
[13] 41501384 01000001010100000**1001110000100 | 0.000069 (2^-13.830075) |
[14]  1200000 00000001001000000000000000000000 | 0.046875 (2^-4.415037) |
[15]  6081180 00000110000*1000000100*110000000 | 0.001648 (2^-9.245112) |

R[ 3]
[ 0] 2905424A 001*10*1000001*1*100001001001*10 | 0.000028 (2^-15.129635) |
[ 1]  1849A33 0000000110*0010*1*01101000110011 | 0.001236 (2^-9.660150) |
[ 2]  CA42643 0000110010100100**10011001000011 | 0.000009 (2^-16.830075) |
[ 3]  2022882 000000100000**100*1*100010000010 | 0.000006 (2^-17.415037) |
[ 4] 3A02A28A 00111*10000000101*10001010001010 | 0.000002 (2^-19.245112) |
[ 5] 3A25E589 00111*100*1**1011110010110001001 | 0.000009 (2^-16.830075) |
[ 6] 44C0218A 0100010011000000**1000011**01010 | 0.000549 (2^-10.830075) |
[ 7] D1179023 110100010001011110*1000*0010**11 | 0.000039 (2^-14.660150) |
[ 8] A4B85024 101001001011100**101000000100100 | 0.000023 (2^-15.437758) |
[ 9] 1AC41C38 0001101011000100**011100001110*0 | 0.000033 (2^-14.907243) |
[10] C21058B3 110000100**1000001*1100010110011 | 0.000002 (2^-19.299560) |
[11]  404044B 00000100000**100*0000100010*1011 | 0.000488 (2^-11.000000) |
[12] 84084000 1000010000001000*10000000000000* | 0.008789 (2^-6.830075) |
[13] 41F11280 01000001111100*10**1001010000000 | 0.003296 (2^-8.245112) |
[14] 23700881 00100*110111000000001000100000*1 | 0.000069 (2^-13.830075) |
[15] 2E0C9404 0*101110000*110*100101*000000100 | 0.000360 (2^-11.437758) |

[ 0] 0.000000 (2^  -inf) [ 1] 0.000000 (2^  -inf) [ 2] 0.000000 (2^  -inf) [ 3] 0.000000 (2^  -inf)
[ 4] 0.000000 (2^  -inf) [ 5] 0.000000 (2^  -inf) [ 6] 0.000000 (2^  -inf) [ 7] 0.000000 (2^  -inf)
[ 8] 0.000000 (2^  -inf) [ 9] 0.000000 (2^  -inf) [10] 0.000000 (2^  -inf) [11] 0.000000 (2^  -inf)
[12] 0.000000 (2^  -inf) [13] 0.000000 (2^  -inf) [14] 0.000000 (2^  -inf) [15] 0.000000 (2^  -inf)
[./tests/salsa-tests.cc:164] p = 0.000000 (2^-387.004471), p = 0.000000 (2^-inf)

real    2m34.510s
user    2m34.270s
sys     0m0.000s


*/

/* --- */
//
// Test input states for the columnround() from the Salsa20
// specifictaion document (spec.pdf)
//
uint32_t test_state_1[16] = {0x00000001, 0x00000000, 0x00000000, 0x00000000,
									  0x00000001, 0x00000000, 0x00000000, 0x00000000,
									  0x00000001, 0x00000000, 0x00000000, 0x00000000,
									  0x00000001, 0x00000000, 0x00000000, 0x00000000};

uint32_t test_state_2[16] = {0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
									  0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
									  0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
									  0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a};

uint32_t test_state_3[16] = {0x00000000, 0x1fe88837, 0x00000000, 0x00000000,
									  0x00000000, 0x2fc74c2f, 0x00000000, 0x00000000,
									  0x00000000, 0x067f95a6, 0x00000000, 0x00000000,
									  0x00000000, 0xea4d84b7, 0x00000000, 0x00000000};

uint32_t test_state_4[16] = {0x00000000, 0x1fe88837, 0x00000000, 0x00000000,
									  0x00000000, 0x2fc74c2f, 0x00000000, 0x00000000,
									  0x00000000, 0x067f95a6, 0x00000000, 0x00000000,
									  0x00000000, 0xea4d84b7, 0x00000000, 0x00000000};


/* --- */

#if 0
			 uint32_t da_temp = da_set.diff;
			 uint32_t db_temp = db_set.diff;
			 uint32_t max_dc_temp = 0;
			 double p_max_temp = max_xdp_add(A, da_temp, db_temp, &max_dc_temp);
#endif

/* --- */

  //  uint32_t nstar = hw32(da_set.fixed) + hw32(db_set.fixed) + hw32(dc_set->fixed);


/* --- */

#if 1									  // TEST
			 if((da_set.fixed == 0) && (db_set.fixed == 0)) {
				uint32_t da = da_set.diff;
				uint32_t db = db_set.diff;
				uint32_t dc_max = 0;
				double p_max_tmp = max_xdp_add_lm(da, db, &dc_max);
				p_max_tmp /= xdp_add_dset_size(dc_set_2);
				printf("%f %f (%8X %8X) %8X\n", p_max_tmp, p_max_2, dc_set_2.diff, dc_set_2.fixed, dc_max);
				assert(p_max_tmp == p_max_2);
			 }
#endif


/* --- */

#if 1									  // TEST
			 if((da_set.fixed == 0) && (db_set.fixed == 0)) {
				uint32_t da = da_set.diff;
				uint32_t db = db_set.diff;
				uint32_t dc_max = 0;
				double p_max_tmp = max_xdp_add_lm(da, db, &dc_max);
				p_max_tmp /= xdp_add_dset_size(dc_set_max_2);
				printf("%f %f (%8X %8X) %8X\n", p_max_tmp, p_max_2, dc_set_max_2.diff, dc_set_max_2.fixed, dc_max);
				assert(p_max_tmp == p_max_2);
			 }
#endif


/* --- */

		// Add the new diff to Dp only if it has better prob. than the min.
#if 0									  // ORIGINAL
		double p_min = diff_mset_p->rbegin()->p;
		if(diff_dy.p >= p_min) {
		  diff_mset_p->insert(diff_dy);
		}
#else
		// p_i >= p_min = Bn / p1 * p2 ... * p{i-1} * B{n-i} 
		p_min = 1.0;
		for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
		  p_min *= diff[i].p;
		}
		p_min = p_min * 1.0 * B[nrounds - 1 - (n + 1)]; 
		p_min = *Bn / p_min;
		printf("[%s:%d] New: %f, p_min = %f\n", __FILE__, __LINE__, diff_dy.p, p_min);
		assert(p_min <= 1.0);
		tea_f_add_pddt(WORD_SIZE, p_min, lsh_const, rsh_const, diff_set_dx_dy);
#endif

/* --- */

void xdp_add_dset_threefish_mix(gsl_matrix* A[3][3][3], 
									 diff_set_t DX[4], diff_set_t DY[4], double P[4],
									 uint32_t rot_const_0, uint32_t rot_const_1,
									 bool b_single_diff)
{
  //  bool b_single_diff = b_single_diff_in;
#if 0									  // DEBUG
  for(uint32_t j = 0; j < 4; j++) { // copy output to input
	 printf("[%s:%d] ", __FILE__, __LINE__);
	 xdp_add_dset_print_set(DX[j]);
	 printf("\n");
  }
#endif
  uint32_t all_star = 0xFFFFFFFF & MASK;
  uint32_t dx_msb = (1U << (WORD_SIZE - 1));

  //  b_single_diff = b_single_diff_in;
  if((DX[0].fixed == all_star) && (DX[1].fixed == all_star)) {
	 //	 b_single_diff = true;
	 DY[0] = {dx_msb, 0};
	 P[0] = xdp_add_dset_all(A, WORD_SIZE, DX[0], DX[1], DY[0]);
  } else {
	 // MIX 0/0
	 P[0] = rmax_xdp_add_dset(A, DX[0], DX[1], &DY[0], b_single_diff);
  }
  DX[1] = lrot_dset(DX[1], rot_const_0);
  DY[1] = xor_dset(DX[1], DY[0]);
  P[1] = 1.0;

  //  b_single_diff = b_single_diff_in;
  if((DX[2].fixed == all_star) && (DX[3].fixed == all_star)) {
	 //	 b_single_diff = true;
	 DY[2] = {dx_msb, 0};
	 P[2] = xdp_add_dset_all(A, WORD_SIZE, DX[2], DX[3], DY[2]);
  } else {
	 // MIX 0/1
	 P[2] = rmax_xdp_add_dset(A, DX[2], DX[3], &DY[2], b_single_diff);
  }
  DX[3] = lrot_dset(DX[3], rot_const_1);
  DY[3] = xor_dset(DX[3], DY[2]);
  P[3] = 1.0;

#if 0									  // DEBUG
  printf("\n");
  for(uint32_t j = 0; j < 4; j++) { // copy output to input
	 printf("[%s:%d] ", __FILE__, __LINE__);
	 xdp_add_dset_print_set(DY[j]);
	 printf("\n");
  }
#endif
}


/* --- */

diff_set_t xor_dset(diff_set_t da_set_in, diff_set_t db_set_in, double* p, bool b_single_diff) 
{
  *p = 1.0;

  diff_set_t da_set = {da_set_in.diff, da_set_in.fixed};
  diff_set_t db_set = {db_set_in.diff, db_set_in.fixed};
  diff_set_t dc_set = {0, 0};
  // if a single difference is required on the output, 
  // then fix all bits of the input differences and divide
  // the probability by the product of the set sizes
#if 1
  if(b_single_diff == true) {	
	 uint32_t s_da = xdp_add_dset_size(da_set);
	 uint32_t s_db = xdp_add_dset_size(db_set);
	 da_set.fixed = 0;			  // fix all
	 db_set.fixed = 0;			  // fix all
	 *p /= (double)(s_da * s_db);				  // the prob drops by the set size
  }
#endif
  dc_set.fixed = (da_set.fixed | db_set.fixed) & MASK;
  dc_set.diff = ((~dc_set.fixed) & (XOR(da_set.diff, db_set.diff))) & MASK;
  return dc_set;
}


void xdp_add_dset_threefish_mix(gsl_matrix* A[3][3][3], 
									 diff_set_t DX[4], diff_set_t DY[4], double P[4],
									 uint32_t rot_const_0, uint32_t rot_const_1,
									 bool b_single_diff)
{
#if 1									  // DEBUG
  for(uint32_t j = 0; j < 4; j++) { // copy output to input
	 printf("[%s:%d] ", __FILE__, __LINE__);
	 xdp_add_dset_print_set(DX[j]);
	 printf("\n");
  }
#endif

  // MIX 0/0
  P[0] = rmax_xdp_add_dset(A, DX[0], DX[1], &DY[0], b_single_diff);
  DX[1] = lrot_dset(DX[1], rot_const_0);
  DY[1] = xor_dset(DX[1], DY[0], &P[1], b_single_diff);
  //  P[1] = 1.0;//P[0];
#if 1									  // DEBUG
  if(b_single_diff == true) {
	 assert(DY[1].fixed == 0);
  }
#endif

  // MIX 0/1
  P[2] = rmax_xdp_add_dset(A, DX[2], DX[3], &DY[2], b_single_diff);
  DX[3] = lrot_dset(DX[3], rot_const_1);
  DY[3] = xor_dset(DX[3], DY[2], &P[3], b_single_diff);
  //  P[3] = 1.0;//P[2];
#if 1									  // DEBUG
  if(b_single_diff == true) {
	 assert(DY[3].fixed == 0);
  }
#endif

#if 1									  // DEBUG
  printf("\n");
  for(uint32_t j = 0; j < 4; j++) { // copy output to input
	 printf("[%s:%d] ", __FILE__, __LINE__);
	 xdp_add_dset_print_set(DY[j]);
	 printf("\n");
  }
#endif
}

/* --- */

  // ---
  printf("DX[3] ");
  xdp_add_dset_print_set(DX[3]);
  printf("| rot sonst %d\n", rot_const_0);
  printf("DX[3] ");
  xdp_add_dset_print_set(DX[3]);
  printf("\n");
  printf("DY[2] ");
  xdp_add_dset_print_set(DY[2]);
  printf("\n");
  // ---


/* --- */

  uint32_t round_zero = 0;
  for(uint32_t i = 0; i < 4; i++) {
	 DX[i] = {DX_in[round_zero][i].diff, DX_in[round_zero][i].fixed};
	 DY[i] = {0, 0};
  }

/* --- */

  printf("[%s:%d] Input diff:\n", __FILE__, __LINE__);
  for(uint32_t j = 0; j < 4; j++) {
	 DX[j] = DX_set[j].diff;
	 printf("%8X ", DX[j]);
  }
  printf("\n");
  printf("[%s:%d] Output diff:\n", __FILE__, __LINE__);
  for(uint32_t j = 0; j < 4; j++) {
	 DY[j] = DY_set[j].diff;
	 printf("%8X ", DY[j]);
	 xdp_add_dset_print_set(DY_set[j]);
	 printf("\n");
  }
  printf("\n");

/* --- */

#if 0
  diff_set_t da_set = {0,0};
  diff_set_t db_set = {0,0};
  da_set.diff  = random32() & MASK;
  da_set.fixed = random32() & MASK;
  db_set.diff  = random32() & MASK;
  db_set.fixed = random32() & MASK;

  bool b_single_diff = false;
  diff_set_t dc_set = {0,0};
  double p_max = rmax_xdp_add_dset(A, da_set, db_set, &dc_set, b_single_diff);
  uint32_t s_max = xdp_add_dset_size(dc_set);
  double r_max = p_max / (double)s_max; 

  printf("[%s:%d] XDP_ADD_DIFF_SET ", __FILE__, __LINE__);
  printf("\n da = ");
  xdp_add_dset_print_set(da_set);
  printf("\n db = ");
  xdp_add_dset_print_set(db_set);
  printf("\n dc = ");
  xdp_add_dset_print_set(dc_set);
  printf("\n");
  printf("[%s:%d] THE   %f, %d, %f \n", __FILE__, __LINE__, r_max, s_max, p_max);
#endif


/* --- */


void skein256_2r(uint32_t X[4])
{
  uint32_t R_256_0_0 = 7;
  uint32_t R_256_0_1=  9;
  uint32_t R_256_1_0 = 26;
  uint32_t R_256_1_1 = 28;

  // MIX 0/0
  X[0] = ADD(X[0], X[1]); 
  X[1] = LROT(X[1], R_256_0_0); 
  X[1] = XOR(X[1], X[0]);

  // MIX 0/1
  X[2] = ADD(X[2], X[3]); 
  X[3] = LROT(X[3], R_256_0_1); 
  X[3] = XOR(X[3], X[2]);

  // MIX 1/0
  X[0] += X[3]; 
  X[3] = LROT(X[3], R_256_1_0); 
  X[3] ^= X[0];

  // MIX 1/1
  X[2] += X[1]; 
  X[1] = LROT(X[1], R_256_1_1); 
  X[1] ^= X[2];

}

/* --- */
/**
 * \ref max_xdp_add_i
 */
void rmax_xdp_add_dset_i(const uint32_t k_init, const uint32_t k, const uint32_t n, 
								 double* r, double* p, diff_set_t* dc_set,
								 gsl_matrix* A[3][3][3], gsl_vector* B[WORD_SIZE + 1], gsl_vector* C_in,  
								 const diff_set_t da_set, const diff_set_t db_set, diff_set_t* dc_set_max, 
								 double* r_max, double* p_max)
{
  if(k == n) {
	 assert(*r > *r_max);
	 *r_max = *r;
	 *p_max = *p;
	 *dc_set_max = {dc_set->diff, dc_set->fixed};
#if 1									  // DEBUG
	 printf("[%s:%d] Update bound [%2d]: r %f (%f), p %f (%f) | ", __FILE__, __LINE__, 
			  k_init, *r_max, log2(*r_max), *p_max, log2(*p_max));
#if 0
	 printf("\n");
	 xdp_add_dset_print_set(da_set);
	 printf("\n");
	 xdp_add_dset_print_set(db_set);
	 printf("\n");
#endif
	 xdp_add_dset_print_set(*dc_set_max);
	 printf("\n");
#endif
	 return;
  } 

  // get the k-th bit of da_set, db_set
  uint32_t x = 2;					  // *
  bool b_da_is_fixed = (((da_set.fixed >> k) & 1) == FIXED);
  if(b_da_is_fixed) {
	 x = ((da_set.diff >> k) & 1); // 0 or 1
  }
  uint32_t y = 2;					  // *
  bool b_db_is_fixed = (((db_set.fixed >> k) & 1) == FIXED);
  if(b_db_is_fixed) {
	 y = ((db_set.diff >> k) & 1); // 0 or 1
  }

  // cycle over the possible values of the k-th bits of *dc
  //  for(int z = 0; z < 2; z++) { 
  int hi_lim = 1;
  int lo_lim = 0;
  if(b_is_lsb) {
	 hi_lim = 2;
  }

  for(int z = hi_lim; z >= lo_lim; z--) { 

	 diff_set_t new_dc_set = {dc_set->diff, dc_set->fixed};

	 // set the k-th bit of dc_set
	 if((z == 0) || (z == 1)) {	// -
		new_dc_set.diff |= (z << k);
		new_dc_set.fixed |= (FIXED << k);
	 }
	 if(z == 2) {				   // *
		new_dc_set.diff |= (0 << k);
		new_dc_set.fixed |= (STAR << k);
	 }

	 // temp
	 gsl_vector* R = gsl_vector_calloc(XDP_ADD_DSET_MSIZE);
	 double new_p = 0.0;

	 gsl_vector* C = gsl_vector_calloc(XDP_ADD_DSET_MSIZE);
	 gsl_vector_memcpy(C, C_in);

	 if(k == (WORD_SIZE - 1)) {  // L
		bool b_da_msb_is_fixed = (((da_set.fixed >> k) & 1) == FIXED); 
		bool b_db_msb_is_fixed = (((db_set.fixed >> k) & 1) == FIXED); 
		bool b_dc_msb_is_fixed = (((new_dc_set.fixed >> k) & 1) == FIXED); 
		gsl_vector_set_all(B[k + 1], 0.0);
		xdp_add_dset_init_states(k, B[k + 1], da_set, db_set, new_dc_set);
		xdp_add_dset_final_states_norm(B[k + 1], b_da_msb_is_fixed, b_db_msb_is_fixed, b_dc_msb_is_fixed);
	 }
	 if(k == 0) {  // C
		gsl_vector_set_all(C, 0.0);
		xdp_add_dset_init_states(k, C, da_set, db_set, new_dc_set);
	 }
#if 0
	 if((k == k_init) && (k != 0) && (k != (WORD_SIZE - 1))) {
		double f = (1U << (((da_set.fixed >> k_init) & 1) 
								 + ((db_set.fixed >> k_init) & 1)
								 + ((new_dc_set.fixed >> k_init) & 1)));
		//		f = 1.0;
		gsl_vector_scale(C, f);
	 }
#else
	 if((k == k_init) && (k != 0) && (k != (WORD_SIZE - 1))) {
		double f = (1U << ((new_dc_set.fixed >> k_init) & 1));
		gsl_vector_scale(C, f);
		assert(f == 1.0);
	 }
#endif
	 // L A C
	 gsl_blas_dgemv(CblasNoTrans, 1.0, A[x][y][z], C, 0.0, R);
	 gsl_blas_ddot(B[k + 1], R, &new_p);

	 uint64_t s = xdp_add_dset_size(new_dc_set);
	 //	 double new_r = new_p / (double)s;
	 double new_r = new_p;
	 if(k == (WORD_SIZE - 1)) {  // MSB => divide by the set size
		new_r = new_p / (double)s;
	 }

	 // continue only if the probability so far is still bigger than the max. prob.
	 if(new_r > *r_max) {
		rmax_xdp_add_dset_i(k_init, k+1, n, &new_r, &new_p, &new_dc_set, A, B, R, da_set, db_set, dc_set_max, r_max, p_max);
	 }

	 gsl_vector_free(C);
	 gsl_vector_free(R);
  }
  return;
}

/* --- */
  int hi_lim = 1;
  int lo_lim = 0;
  if(b_is_lsb) {
	 hi_lim = 2;
	 if(b_da_is_fixed && b_db_is_fixed) {
		if(x == y) {
		  hi_lim = lo_lim = x;
		}
	 }
  }

/* --- */

  uint32_t da_diff_prev_i = 0;
  uint32_t da_fixed_prev_i = 0;
  uint32_t db_diff_prev_i = 0;
  uint32_t db_fixed_prev_i = 0;
  uint32_t dc_diff_prev_i = 0;
  uint32_t dc_fixed_prev_i = 0;
  if(k > k_init) {
	 da_diff_prev_i = (da_set.diff >> (k - 1)) & 1; 
	 da_fixed_prev_i = (da_set.fixed >> (k - 1)) & 1;
	 db_diff_prev_i = (db_set.diff >> (k - 1)) & 1; 
	 db_fixed_prev_i = (db_set.fixed >> (k - 1)) & 1;
	 dc_diff_prev_i = (dc_set->diff >> (k - 1)) & 1; 
	 dc_fixed_prev_i = (dc_set->fixed >> (k - 1)) & 1;
  }




/* --- */

void xdp_add_input_dset_to_output_dset(gsl_matrix* AA[2][2][2],
													const diff_set_t da_set, 
													const diff_set_t db_set,
													diff_set_t* dc_set)
{
  dc_set->diff = 0;
  dc_set->fixed = 0;

#if 0
  uint32_t i = 0;
  uint32_t da_diff_i = (da_set.diff >> i) & 1; 
  uint32_t da_fixed_i = (da_set.fixed >> i) & 1;
  uint32_t db_diff_i = (db_set.diff >> i) & 1; 
  uint32_t db_fixed_i = (db_set.fixed >> i) & 1;

  if((da_fixed_i == FIXED) && (db_fixed_i == FIXED)) { // (-,-)
	 dc_set->diff |= ((da_diff_i ^ db_diff_i) << i);
	 dc_set->fixed |= (FIXED << i);
  } else {
	 dc_set->diff |= (0 << i);
	 dc_set->fixed |= (FIXED << i);
  }
#endif
  for(uint32_t i = 0; i < WORD_SIZE; i++) {

	 uint32_t word_size = WORD_SIZE;//i + 1; // bits 0, 1, ..., i
	 double r_max = 0.0;
	 diff_set_t dc_set_max = {0, 0};

	 for(int j = 2; j >= 0; j--) {
		diff_set_t dc_set_i = {dc_set->diff, dc_set->fixed};
		if((j == 0) || (j == 1)){				  // -
		  dc_set_i.diff |= (j << i);
		  dc_set_i.fixed |= (FIXED << i);
		}
		if(j == 2) {				  // *
		  dc_set_i.diff |= (0 << i);
		  dc_set_i.fixed |= (STAR << i);
		}
		double p = xdp_add_dset(AA, word_size, da_set, db_set, dc_set_i);
		uint32_t s = xdp_add_dset_size(dc_set_i);
		double r = p / (double)s;
		if(r > r_max) {
		  r_max = r;
		  dc_set_max = {dc_set_i.diff, dc_set_i.fixed};
		}
		//		printf("[%s:%d] %d|%d: %f %d  %f\n", __FILE__, __LINE__, i, j, p, s, r);
	 }

	 *dc_set = {dc_set_max.diff, dc_set_max.fixed};
  }

}


/* --- */
void xdp_add_input_dset_to_output_dset(gsl_matrix* AA[2][2][2],
													const diff_set_t da_set, 
													const diff_set_t db_set,
													diff_set_t* dc_set)
{
  dc_set->diff = 0;
  dc_set->fixed = 0;

  uint32_t i = 0;
  uint32_t da_diff_i = (da_set.diff >> i) & 1; 
  uint32_t da_fixed_i = (da_set.fixed >> i) & 1;
  uint32_t db_diff_i = (db_set.diff >> i) & 1; 
  uint32_t db_fixed_i = (db_set.fixed >> i) & 1;

  if((da_fixed_i == FIXED) && (db_fixed_i == FIXED)) { // (-,-)
	 dc_set->diff |= ((da_diff_i ^ db_diff_i) << i);
	 dc_set->fixed |= (FIXED << i);
  } else {
	 dc_set->diff |= (0 << i);
	 dc_set->fixed |= (FIXED << i);
  }

  for(i = 1; i < WORD_SIZE; i++) {

	 uint32_t word_size = WORD_SIZE;//i + 1; // bits 0, 1, ..., i
	 double r_max = 0.0;
	 diff_set_t dc_set_max = {0, 0};


	 da_diff_i = (da_set.diff >> i) & 1;
	 da_fixed_i = (da_set.fixed >> i) & 1;
	 db_diff_i = (db_set.diff >> i) & 1;
	 db_fixed_i = (db_set.fixed >> i) & 1;

	 uint32_t da_diff_prev_i = 0;
	 uint32_t da_fixed_prev_i = 0;
	 uint32_t db_diff_prev_i = 0;
	 uint32_t db_fixed_prev_i = 0;
	 uint32_t dc_diff_prev_i = 0;
	 uint32_t dc_fixed_prev_i = 0;

	 if(i > 0) {
		da_diff_prev_i = (da_set.diff >> (i - 1)) & 1; 
		da_fixed_prev_i = (da_set.fixed >> (i - 1)) & 1;
		db_diff_prev_i = (db_set.diff >> (i - 1)) & 1; 
		db_fixed_prev_i = (db_set.fixed >> (i - 1)) & 1;
		dc_diff_prev_i = (dc_set->diff >> (i - 1)) & 1; 
		dc_fixed_prev_i = (dc_set->fixed >> (i - 1)) & 1;
	 }

	 bool b_is_prev_eq = 
		(is_eq(da_diff_prev_i, db_diff_prev_i, dc_diff_prev_i)) && 
		((da_fixed_prev_i == FIXED) && (db_fixed_prev_i == FIXED) && (dc_fixed_prev_i == FIXED)) &&
		(i > 0);

	 if(b_is_prev_eq) {

		diff_set_t dc_set_i = {dc_set->diff, dc_set->fixed};
		uint32_t dc_i = 0;
		if((da_fixed_i == FIXED) && (db_fixed_i == FIXED)) {
		  dc_i = da_diff_i ^ db_diff_i ^ da_diff_prev_i;
		} 
		if((da_fixed_i == FIXED) && (db_fixed_i == STAR)) {
		  dc_i = da_diff_i;
		} 
		if((da_fixed_i == STAR) && (db_fixed_i == FIXED)) {
		  dc_i = db_diff_i;
		} 
		//		xdp_add_dset(AA, word_size, da_set, db_set, dc_set_i);
		dc_set_i.diff |= (dc_i << i);
		dc_set_i.fixed |= (FIXED << i);
		dc_set_max = {dc_set_i.diff, dc_set_i.fixed};

	 } else {

		if((da_fixed_i == FIXED) && (db_fixed_i == STAR)) {
		  diff_set_t dc_set_i = {dc_set->diff, dc_set->fixed};
		  uint32_t dc_i = da_diff_i;
		  dc_set_i.diff |= (dc_i << i);
		  dc_set_i.fixed |= (FIXED << i);
		  dc_set_max = {dc_set_i.diff, dc_set_i.fixed};
		} 
		if((da_fixed_i == STAR) && (db_fixed_i == FIXED)) {
		  diff_set_t dc_set_i = {dc_set->diff, dc_set->fixed};
		  uint32_t dc_i = da_diff_i;
		  dc_set_i.diff |= (dc_i << i);
		  dc_set_i.fixed |= (FIXED << i);
		  dc_set_max = {dc_set_i.diff, dc_set_i.fixed};
		} 

		if(((da_fixed_i == FIXED) && (db_fixed_i == FIXED)) ||
			((da_fixed_i == STAR) && (db_fixed_i == STAR))) {

		  for(int j = 2; j >= 0; j--) {
			 diff_set_t dc_set_i = {dc_set->diff, dc_set->fixed};
			 if((j == 0) || (j == 1)){				  // -
				dc_set_i.diff |= (j << i);
				dc_set_i.fixed |= (FIXED << i);
			 }
			 if(j == 2) {				  // *
				dc_set_i.diff |= (0 << i);
				dc_set_i.fixed |= (STAR << i);
			 }
			 double p = xdp_add_dset(AA, word_size, da_set, db_set, dc_set_i);
			 uint32_t s = xdp_add_dset_size(dc_set_i);
			 double r = p / (double)s;
			 if(r > r_max) {
				r_max = r;
				dc_set_max = {dc_set_i.diff, dc_set_i.fixed};
			 }
			 printf("[%s:%d] %d|%d: %f %d  %f\n", __FILE__, __LINE__, i, j, p, s, r);
		  }
		}
	 }
	 *dc_set = {dc_set_max.diff, dc_set_max.fixed};
  }

}



/* ---- */
/**
 * Constructs dc_set by maximizing the ratio r:
 *
 * r = p / s = xdp-add(da_set, db_set, dc_set) / dc_set_size .
 *
 */
void xdp_add_input_dset_to_output_dset(gsl_matrix* AA[2][2][2],
													const diff_set_t da_set, 
													const diff_set_t db_set,
													diff_set_t* dc_set)
{
  dc_set->diff = 0;
  dc_set->fixed = 0;

  uint32_t i = 0;
  uint32_t da_diff_i = (da_set.diff >> i) & 1; 
  uint32_t da_fixed_i = (da_set.fixed >> i) & 1;
  uint32_t db_diff_i = (db_set.diff >> i) & 1; 
  uint32_t db_fixed_i = (db_set.fixed >> i) & 1;

  if((da_fixed_i == FIXED) && (db_fixed_i == FIXED)) { // (-,-)
	 dc_set->diff |= ((da_diff_i ^ db_diff_i) << i);
	 dc_set->fixed |= (FIXED << i);
  } else {
	 dc_set->diff |= (0 << i);
	 dc_set->fixed |= (FIXED << i);
  }

  for(i = 1; i < WORD_SIZE; i++) {

	 uint32_t word_size = i + 1; // bits 0, 1, ..., i
	 double r_max = 0.0;
	 diff_set_t dc_set_max = {0, 0};

	 uint32_t da_diff_prev_i = 0;
	 uint32_t da_fixed_prev_i = 0;
	 uint32_t db_diff_prev_i = 0;
	 uint32_t db_fixed_prev_i = 0;
	 uint32_t dc_diff_prev_i = 0;
	 uint32_t dc_fixed_prev_i = 0;

	 if(i > 0) {
		da_diff_prev_i = (da_set.diff >> (i - 1)) & 1; 
		da_fixed_prev_i = (da_set.fixed >> (i - 1)) & 1;
		db_diff_prev_i = (db_set.diff >> (i - 1)) & 1; 
		db_fixed_prev_i = (db_set.fixed >> (i - 1)) & 1;
		dc_diff_prev_i = (dc_set->diff >> (i - 1)) & 1; 
		dc_fixed_prev_i = (dc_set->fixed >> (i - 1)) & 1;
	 }

	 bool b_is_prev_eq = 
		(is_eq(da_diff_prev_i, db_diff_prev_i, dc_diff_prev_i)) && 
		((da_fixed_prev_i == FIXED) && (db_fixed_prev_i == FIXED) && (dc_fixed_prev_i == FIXED)) &&
		(i > 0);

	 if(b_is_prev_eq) {

		  diff_set_t dc_set_i = {dc_set->diff, dc_set->fixed};
		  uint32_t dc_i = da_diff_i ^ db_diff_i ^ da_diff_prev_i;
		  dc_set_i.diff |= (dc_i << i);
		  dc_set_i.fixed |= (FIXED << i);
		  xdp_add_dset(AA, word_size, da_set, db_set, dc_set_i);
		  dc_set_max = {dc_set_i.diff, dc_set_i.fixed};


	 } else {

		for(int j = 2; j >= 0; j--) {
		  diff_set_t dc_set_i = {dc_set->diff, dc_set->fixed};
		  if((j == 0) || (j == 1)){				  // -
			 dc_set_i.diff |= (j << i);
			 dc_set_i.fixed |= (FIXED << i);
		  }
		  if(j == 2) {				  // *
			 dc_set_i.diff |= (0 << i);
			 dc_set_i.fixed |= (STAR << i);
		  }
		  double p = xdp_add_dset(AA, word_size, da_set, db_set, dc_set_i);
		  uint32_t s = xdp_add_dset_size(dc_set_i);
		  double r = p / (double)s;
		  if(r > r_max) {
			 r_max = r;
			 dc_set_max = {dc_set_i.diff, dc_set_i.fixed};
		  }
		  printf("[%s:%d] %d|%d: %f %d  %f\n", __FILE__, __LINE__, i, j, p, s, r);
		}
	 }

	 *dc_set = {dc_set_max.diff, dc_set_max.fixed};
  }

}

/* --- */

void xdp_add_dset_final_states_norm(gsl_vector* L, 
												bool b_da_msb_is_fixed, bool b_db_msb_is_fixed, bool b_dc_msb_is_fixed)
{
  gsl_vector* V = gsl_vector_calloc(XDP_ADD_DSET_MSIZE);

  // three STAR => divide by 4
  if((!b_da_msb_is_fixed && !b_db_msb_is_fixed && !b_dc_msb_is_fixed)) {
	 gsl_vector_set_all(V, 1.0);
	 double e = 0.25;
	 if(WORD_SIZE == 1) {
		e = 0.4;
	 }
	 gsl_vector_set(V, 0, e);
	 gsl_vector_set(V, 1, e);
	 gsl_vector_set(V, 2, e);
	 gsl_vector_set(V, 3, e);
	 gsl_vector_set(V, 4, e);
	 gsl_vector_set(V, 5, e);
	 gsl_vector_set(V, 6, e);
	 gsl_vector_set(V, 7, e);
	 gsl_vector_mul(L, V);
  }
  // two STAR => divide by 2
  if((!b_da_msb_is_fixed && !b_db_msb_is_fixed && b_dc_msb_is_fixed) ||
	  (b_da_msb_is_fixed && !b_db_msb_is_fixed && !b_dc_msb_is_fixed) ||
	  (!b_da_msb_is_fixed && b_db_msb_is_fixed && !b_dc_msb_is_fixed)) {
	 gsl_vector_set_all(V, 1.0);
	 double e = 0.5;
	 if(WORD_SIZE == 1) {
		e = 1.0 / 1.5;
	 }
	 gsl_vector_set(V, 0, e);
	 gsl_vector_set(V, 1, e);
	 gsl_vector_set(V, 2, e);
	 gsl_vector_set(V, 3, e);
	 gsl_vector_set(V, 4, e);
	 gsl_vector_set(V, 5, e);
	 gsl_vector_set(V, 6, e);
	 gsl_vector_set(V, 7, e);
	 gsl_vector_mul(L, V);
  }
  // one STAR => leave matrix as it is
  if((!b_da_msb_is_fixed && b_db_msb_is_fixed && b_dc_msb_is_fixed) ||
	  (b_da_msb_is_fixed && !b_db_msb_is_fixed && b_dc_msb_is_fixed) ||
	  (b_da_msb_is_fixed && b_db_msb_is_fixed && !b_dc_msb_is_fixed)) {
	 ;
	 if(WORD_SIZE == 1) {
		gsl_vector_set_all(V, 1.0);
		double e = 2.0;
		gsl_vector_set(V, 1, e);
		gsl_vector_set(V, 2, e);
		gsl_vector_set(V, 3, e);
		gsl_vector_set(V, 4, e);
		gsl_vector_set(V, 5, e);
		gsl_vector_set(V, 6, e);
		gsl_vector_mul(L, V);
	 }
  }
  // all fixed (no STAR) => set 0.5 to 1.0
  if(b_da_msb_is_fixed && b_db_msb_is_fixed && b_dc_msb_is_fixed) { 
	 gsl_vector_set_all(V, 1.0);
	 double e = 2.0;
	 gsl_vector_set(V, 1, e);
	 gsl_vector_set(V, 2, e);
	 gsl_vector_set(V, 3, e);
	 gsl_vector_set(V, 4, e);
	 gsl_vector_set(V, 5, e);
	 gsl_vector_set(V, 6, e);
	 gsl_vector_mul(L, V);
  }
  gsl_vector_free(V);
}


/* --- */
// 
// If (-,*) or (*,-) set to (-,-), otherwise leave (*,*)
// 
void xdp_add_input_dset_to_output_dset_old(const diff_set_t da_set, 
														 const diff_set_t db_set,
														 diff_set_t dc_set[2])
{
  for(uint32_t j = 0; j <= 1; j++) {

	 dc_set[j].diff = 0;
	 dc_set[j].fixed = 0;

	 for(uint32_t i = 0; i < WORD_SIZE; i++) {

		uint32_t da_diff_i = (da_set.diff >> i) & 1; 
		uint32_t da_fixed_i = (da_set.fixed >> i) & 1;
		uint32_t db_diff_i = (db_set.diff >> i) & 1; 
		uint32_t db_fixed_i = (db_set.fixed >> i) & 1;

		uint32_t da_diff_prev_i = 0;
		uint32_t da_fixed_prev_i = 0;
		uint32_t db_diff_prev_i = 0;
		uint32_t db_fixed_prev_i = 0;
		uint32_t dc_diff_prev_i = 0;
		uint32_t dc_fixed_prev_i = 0;

		if(i > 0) {
		  da_diff_prev_i = (da_set.diff >> (i - 1)) & 1; 
		  da_fixed_prev_i = (da_set.fixed >> (i - 1)) & 1;
		  db_diff_prev_i = (db_set.diff >> (i - 1)) & 1; 
		  db_fixed_prev_i = (db_set.fixed >> (i - 1)) & 1;
		  dc_diff_prev_i = (dc_set[j].diff >> (i - 1)) & 1; 
		  dc_fixed_prev_i = (dc_set[j].fixed >> (i - 1)) & 1;
		}
		if((da_fixed_i == STAR) && (db_fixed_i == STAR)) { // (*,*)
		  dc_set[j].diff |= (j << i);
		  dc_set[j].fixed |= (FIXED << i);
		} 
		if((da_fixed_i == FIXED) && (db_fixed_i == STAR) && !(is_eq(da_diff_prev_i, db_diff_prev_i, dc_diff_prev_i))) { // (-,*)
		  dc_set[j].diff |= (da_diff_i << i);
		  if(i == 0) {
			 dc_set[j].fixed |= (FIXED << i);
		  } else {
			 dc_set[j].fixed |= (STAR << i);
		  }
		} 
		if((da_fixed_i == STAR) && (db_fixed_i == FIXED) && !(is_eq(da_diff_prev_i, db_diff_prev_i, dc_diff_prev_i))) { // (*,-)
		  dc_set[j].diff |= (db_diff_i << i);
		  if(i == 0) {
			 dc_set[j].fixed |= (FIXED << i);
		  } else {
			 dc_set[j].fixed |= (STAR << i);
		  }
		} 
		if((i > 0) &&
			//		  (((da_fixed_i == FIXED) && (db_fixed_i == STAR)) ||
			//		  ((da_fixed_i == STAR) && (db_fixed_i == FIXED))) &&
		  ((da_fixed_prev_i == FIXED) && (db_fixed_prev_i == FIXED) && (dc_fixed_prev_i == FIXED)) &&
		  (is_eq(da_diff_prev_i, db_diff_prev_i, dc_diff_prev_i))) { // (-,*)

		  uint32_t dc_i = da_diff_i ^ db_diff_i ^ da_diff_prev_i;
		  dc_set[j].diff |= (dc_i << i);
		  dc_set[j].fixed |= (FIXED << i);
		} else {
		  if((da_fixed_i == FIXED) && (db_fixed_i == FIXED)) { // (-,-)

			 if(i == 0) {				  // LSB
				dc_set[j].diff |= ((da_diff_i ^ db_diff_i) << i);
				dc_set[j].fixed |= (FIXED << i);
			 } else {
				if(da_diff_i == db_diff_i) {
				  dc_set[j].diff |= (da_diff_i << i);
				  dc_set[j].fixed |= (FIXED << i);
				} else {
				  dc_set[j].diff |= (j << i);
				  dc_set[j].fixed |= (STAR << i);
				}
			 }

		  }
		} 
	 }
  } // j
}


/* --- */

			 double p[2] = {0.0, 0.0};
			 double pp = 0.0;
			 for(uint32_t j = 0; j < 2; j++) {
				xdp_add_input_diff_to_output_dset(da[j], db[j], &dc_set[j]);
#if 1									  // DEBUG
				printf("\ndc%d = ", j);
				xdp_add_dset_print_set(dc_set[j]);
				printf("\n");
#endif
				diff_set_t da_set_temp = {da[j],0};
				diff_set_t db_set_temp = {db[j],0};
				double pp_temp = xdp_add_dset(AA, da_set_temp, db_set_temp, dc_set[j]);
				printf("[%s:%d]pp[%d] = %f\n", __FILE__, __LINE__, j, pp_temp);
				if(pp_temp > pp) {
				  pp = pp_temp;
				}

				p[j] = xdp_add_dset(AA, da_set, db_set, dc_set[j]);
#if 1								  // DEBUG
				printf("[%s:%d] p[%d] = %f\n", __FILE__, __LINE__, j, p[j]);
#endif
				//				p[j] = pp;
			 }


/* --- */
void test_xdp_add_dc_set_is_max()
{
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  diff_set_t da_set = {0,0};
  diff_set_t db_set = {0,0};
  uint32_t da[2] = {0,0};
  uint32_t db[2] = {0,0};


  for(uint32_t d1 = 0; d1 < ALL_WORDS; d1++) {
	 for(uint32_t f1 = 0; f1 < ALL_WORDS; f1++) {
		for(uint32_t d2 = 0; d2 < ALL_WORDS; d2++) {
		  for(uint32_t f2 = 0; f2 < ALL_WORDS; f2++) {

			 da_set.diff = d1;
			 da_set.fixed = f1;
			 db_set.diff = d2;
			 db_set.fixed = f2;

			 xdp_add_input_dsets_to_diffs(da_set, db_set, da, db);
#if 1
			 printf("[%s:%d] Input sets: da (%8X,%8X), db (%8X,%8X)\n", 
					  __FILE__, __LINE__, da_set.diff, da_set.fixed, db_set.diff, db_set.fixed);
			 printf("[%s:%d] Input diffs: 0:(%8X,%8X), 1:(%8X,%8X)\n",
					  __FILE__, __LINE__, da[0], db[0], da[1], db[1]);
#endif
			 diff_set_t dc_set[2] = {{0,0}};
			 uint32_t dc_set_len[2] = {0};

			 double p[2] = {0.0, 0.0};
			 for(uint32_t j = 0; j < 2; j++) {
				xdp_add_gen_output_dset(da[j], db[j], &dc_set[j]);

				std::vector<uint32_t> dc_set_all;
				xdp_add_diff_set_to_diff_all(dc_set[j], &dc_set_all);

				dc_set_len[j] = dc_set_all.size();

				std::vector<uint32_t>::iterator vec_iter;
				for(vec_iter = dc_set_all.begin(); vec_iter != dc_set_all.end(); vec_iter++) {
				  uint32_t dc_i = *vec_iter;
				  double p_i = xdp_add(A, da[j], db[j], dc_i);
#if 0								  // DEBUG
				  printf("[%s:%d] XDP_ADD[(%8X,%8X)->%8X] = %6.5f\n", 
							__FILE__, __LINE__, da[j], db[j], dc_i, p_i);
#endif
				  assert(p_i != 0.0);
				  p[j] += p_i;
				}
#if 1								  // DEBUG
				printf("[%s:%d] p[%d] = %f\n", __FILE__, __LINE__, j, p[j]);
#endif
			 }

			 double p_max = 0.0;
			 p_max = std::max(p[0],p[1]);

			 diff_set_t dc_set_out = {0,0};
			 uint32_t hw0 = hw32(da[0] ^ db[0]);
			 uint32_t hw1 = hw32(da[1] ^ db[1]);
			 if(hw0 > hw1) {
				dc_set_out = {dc_set[1].diff, dc_set[1].fixed};
				assert(p[0] < p[1]);
			 }
			 if(hw0 < hw1) {
				dc_set_out = {dc_set[0].diff, dc_set[0].fixed};
				assert(p[0] > p[1]);
			 }
			 if(hw0 == hw1) {
				if(dc_set_len[0] >= dc_set_len[1]) {
				  dc_set_out = {dc_set[0].diff, dc_set[0].fixed};
				} else {
				  dc_set_out = {dc_set[1].diff, dc_set[1].fixed};
				}
			 }

			 std::vector<uint32_t> da_set_all;
			 xdp_add_diff_set_to_diff_all(da_set, &da_set_all);
			 std::vector<uint32_t>::iterator da_iter = da_set_all.begin();

			 std::vector<uint32_t> db_set_all;
			 xdp_add_diff_set_to_diff_all(db_set, &db_set_all);
			 std::vector<uint32_t>::iterator db_iter = db_set_all.begin();

			 for(da_iter = da_set_all.begin(); da_iter != da_set_all.end(); da_iter++) {
				for(db_iter = db_set_all.begin(); db_iter != db_set_all.end(); db_iter++) {
				  uint32_t da_i = *da_iter;
				  uint32_t db_i = *db_iter;

				  diff_set_t dc_set_i = {0,0};
				  xdp_add_gen_output_dset(da_i, db_i, &dc_set_i);
				  std::vector<uint32_t> dc_set_all_i;
				  xdp_add_diff_set_to_diff_all(dc_set_i, &dc_set_all_i);

				  double p = 0.0;
				  std::vector<uint32_t>::iterator vec_iter;
				  for(vec_iter = dc_set_all_i.begin(); vec_iter != dc_set_all_i.end(); vec_iter++) {
					 uint32_t dc_i = *vec_iter;
					 double p_i = xdp_add(A, da_i, db_i, dc_i);
#if 0									  // DEBUG
					 printf("[%s:%d] XDP_ADD[(%8X,%8X)->%8X] = %6.5f\n", 
							  __FILE__, __LINE__, da_i, db_i, dc_i, p_i);
#endif
					 assert(p_i != 0.0);
					 p += p_i;
				  }
				  if(p > p_max) {
					 printf("[%s:%d] p_max %f, p %f ", __FILE__, __LINE__, p_max, p);
					 printf("%8X %8X -> {%8X,%8X} vs. {%8X,%8X}\n", da_i, db_i, dc_set_i.diff, dc_set_i.fixed, dc_set_out.diff, dc_set_out.fixed);
				  }
				  //				  assert(p <= p_max);
				}
			 }

		  }
		}
	 }
  }

  xdp_add_free_matrices(A);
}

/* --- */

#if 0
				  uint32_t da_msb_star = (da_set.fixed >> (WORD_SIZE - 1)) & 1;
				  if(da_msb_star == FIXED) {
					 da_set.fixed ^= 1 << (WORD_SIZE - 1); 
				  } 
				  uint32_t db_msb_star = (db_set.fixed >> (WORD_SIZE - 1)) & 1;
				  if(db_msb_star == FIXED) {
					 db_set.fixed ^= 1 << (WORD_SIZE - 1); 
				  } 
				  uint32_t dc_msb_star = (dc_set.fixed >> (WORD_SIZE - 1)) & 1;
				  if(dc_msb_star == FIXED) {
					 dc_set.fixed ^= 1 << (WORD_SIZE - 1); 
				  } 
#endif


/* --- */

		  if(pos == 0) {			  // LSB
			 bool b_is_valid = ((da_0 ^ db_0 ^ dc_0) == 0);
			 if(b_is_valid) {
				uint32_t idx = (dc_0 << 2) | (db_0 << 1) | da_0;
				assert((idx == 0)||(idx == 3)||(idx == 5)||(idx == 6));
				double val = 1.0;
				gsl_vector_set(C, idx, val);
			 }
		  } else {
			 uint32_t idx = (dc_0 << 2) | (db_0 << 1) | da_0;
			 double val = 1.0;
			 gsl_vector_set(C, idx, val);
		  }
		}

/* --- */

void xdp_add_dset_gen_matrices_msb(gsl_matrix* A[2][2][2])
{
  for(int i = 0; i < XDP_ADD_DSET_MSIZE; i++) {
	 int x = i;
	 int da_in = x & 1;
	 x /= 2;
	 int db_in = x & 1;
	 x /= 2;
	 int dc_in = x & 1;
	 x /= 2;

	 //	 printf("[%s:%d] %d = (%d,%d,%d)\n", __FILE__, __LINE__, i, da_in, db_in, dc_in);
	 for(int j = 0; j < XDP_ADD_DSET_MSIZE; j++) {
		int y = j;
		int da_out = y & 1;
		y /= 2;
		int db_out = y & 1;
		y /= 2;
		int dc_out = y & 1;
		y /= 2;

		double e = 0.0;
		// 
		// An xdp-add differential is possible if:
		// da[i] = db[i] = dc[i] => da[i+1] ^ db[i+1] ^ dc[i+1] ^ da[i] = 0
		// 
		bool b_is_possible = ((is_eq(da_in, db_in, dc_in) & 
									  (da_out ^ db_out ^ dc_out ^ db_in)) == 0);
#if 0
		if(b_is_possible) {
		  e = 1.0;
		}
#endif
#if 1
		if(b_is_possible) {
		  //		  if((!is_eq(da_out, db_out, dc_out))) { // not equal
		  if((!is_eq(da_in, db_in, dc_in))) { // not equal
			 e = 0.5;
		  } else {
			 e = 1.0;
		  }
		}
#endif
		uint32_t col = i;
		uint32_t row = j;
		gsl_matrix_set(A[da_in][db_in][dc_in], row, col, e);
		//		uint32_t dc_in_flip = dc_in ^ 1;
		//		gsl_matrix_set(A[da_in][db_in][dc_in_flip], row, col, e);
		//		printf("[%s:%d] %d%d%d: in(%d)->out(%d)\n", __FILE__, __LINE__, da_in, db_in, dc_in, col, row);
	 }
  }
}


/* --- */

  if((!b_da_is_fixed) && (i == (WORD_SIZE - 1))) {
	 gsl_vector* V = gsl_vector_calloc(XDP_ADD_DSET_MSIZE);
	 double e = 0.5;
	 gsl_vector_set(V, 0, e);
	 gsl_vector_set(V, 0, e);
	 gsl_vector_free(V);
  } 

/* --- */
	 if(i == (WORD_SIZE - 1)) {	  // MSB
		for(uint32_t j = 1; j < 7; j++) {
		  double e = gsl_vector_get(R, j);
		  e *= 2.0;
		  gsl_vector_set(R, j, e);
		}
	 }

/* --- */
	 uint32_t da_i = (da_set.diff >> i) & 1;
	 uint32_t db_i = (db_set.diff >> i) & 1;
	 uint32_t dc_i = (dc_set.diff >> i) & 1;

	 bool b_da_is_fixed = ((da_set.fixed & 1) == FIXED);
	 bool b_db_is_fixed = ((db_set.fixed & 1) == FIXED);
	 bool b_dc_is_fixed = ((dc_set.fixed & 1) == FIXED);

/* --- */

void xdp_add_dset_print_matrices_sage(gsl_matrix* A[2][2][2])
{
  printf("# [%s:%d] Matrices for XDP-ADD generated with %s() \n", __FILE__, __LINE__, __FUNCTION__);

  printf("#--- Normalization factor --- \n");
  printf("f = %f\n", XDP_ADD_DSET_NORM);

  // print L
  gsl_vector* L = gsl_vector_calloc(XDP_ADD_DSET_MSIZE);
  gsl_vector_set_all(L, 1.0);
  printf("#--- Vector L --- \n");
  printf("L = vector(QQ,[ ");
  for(int col = 0; col < XDP_ADD_DSET_MSIZE; col++){
	 double e = gsl_vector_get(L, col);
	 printf("%4.3f", e);
	 if(col == XDP_ADD_DSET_MSIZE - 1) {
		printf(" ");
	 } else {
		printf(", ");
	 }
  }
  printf("])\n\n");

  // print C
  gsl_vector* C = gsl_vector_calloc(XDP_ADD_DSET_MSIZE);
  gsl_vector_set_zero(C);
  gsl_vector_set(C, XDP_ADD_DSET_ISTATE, 1.0);
  printf("#--- Vector C --- \n");
  printf("C = vector(QQ,[ ");
  for(int col = 0; col < XDP_ADD_DSET_MSIZE; col++){
	 double e = gsl_vector_get(C, col);
	 printf("%4.3f", e);
	 if(col == XDP_ADD_DSET_MSIZE - 1) {
		printf(" ");
	 } else {
		printf(", ");
	 }
  }
  printf("])\n\n");

  // print A
  for(int i = 0; i < XDP_ADD_DSET_NMATRIX; i++){
	 int a = (i >> 0) & 1;
	 int b = (i >> 1) & 1;
	 int c = (i >> 2) & 1;
	 printf("#---AA%d%d%d--- \n", c, b, a);
	 printf("AA%d%d%d = matrix(QQ,%d,%d,[\n", c, b, a, XDP_ADD_DSET_MSIZE, XDP_ADD_DSET_MSIZE);
	 for(int row = 0; row < XDP_ADD_DSET_MSIZE; row++){
		for(int col = 0; col < XDP_ADD_DSET_MSIZE; col++){
		  double e = gsl_matrix_get(A[a][b][c], row, col);
		  printf("%3.2f", e);
		  if((row == XDP_ADD_DSET_MSIZE - 1) && (col == XDP_ADD_DSET_MSIZE - 1)) {
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
  for(int i = 0; i < XDP_ADD_DSET_NMATRIX; i++){
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

/* --- */
		if(is_eq(da_this, db_this, dc_this) && ()) {
		  fixed_this = 1;
		}


/* --- */

/**
 * Generating a set of non-zero probability outout differences
 * Based on \ref max_adp_add_lm .
 */
void xdp_add_dc_set(uint32_t da, uint32_t db, diff_set_t* dc_set)
{
  uint32_t n = WORD_SIZE;
  uint32_t dc = 0;

  // if fixed[i] = 1, dc[i] can be anything, if fixed[i] = 0, dc[i] is fixed
  uint32_t fixed = 0;

  dc |= (da & 1) ^ (db & 1);

  for(uint32_t i = 1; i < n; i++) {

	 uint32_t da_prev = (da >> (i - 1)) & 1;
	 uint32_t db_prev = (db >> (i - 1)) & 1;
	 uint32_t dc_prev = (dc >> (i - 1)) & 1;
	 uint32_t da_this = (da >> i) & 1;
	 uint32_t db_this = (db >> i) & 1;
	 uint32_t dc_this = 0;		  // to be determined
	 uint32_t fixed_this = 0;		  // is this bit fixeded or no
	 if(is_eq(da_prev, db_prev, dc_prev)) {
		dc_this = (da_this ^ db_this ^ da_prev);
		fixed_this = 0;				  // fixed
	 } else {
#if 0
		if((i == (n-1)) || (da_this != db_this)) {
		  dc_this = 0;
		  fixed_this = 1;			  // can be 0/1 
		} else {
		  dc_this = da_this;
		  fixed_this = 0;				  // fixed
		}
#else
		dc_this = 0;
		fixed_this = 1;			  // can be 0/1 
#endif
	 }
	 dc |= (dc_this << i);
	 fixed |= (fixed_this << i);
  }

#if 0									  // DEBUG
  printf("[%s:%d] %8X %8X (%8X %8X)\n", __FILE__, __LINE__, da, db, dc, fixed);
#endif

  dc_set->diff = dc;
  dc_set->fixed = fixed;
}

/* --- */

		for(uint32_t i = 0; i < WORD_SIZE; i++) {
		  uint32_t t = (dc_set.fixed >> i) & 1;
		  if(t == 0)
			 continue;

		  uint32_t dc_new = dc_set.diff | (1 << i);
		  double pp = xdp_add_lm(da, db, dc_new);
#if 0									  // DEBUG
		  printf("[%s:%d] %8X %8X (%8X %8X) %f\n", __FILE__, __LINE__, da, db, dc_new, dc_set.fixed, pp);
#endif
		  assert(pp != 0.0);

		  p += pp;

		}


/* --- */
		  if((double)i_pos >= logN) {
			 printf("[%s:%d] %d %f %d\n", __FILE__, __LINE__, i_pos, logN, N);
		  }

/* --- */

  printf(" a[1] = ");
  print_binary(a[1]);
  printf("\n");
  printf("~a[1] = ");
  print_binary(~a[1]);

/* --- */
			 if(i == 1) {
				if(chi_prev == 1) {
				  //				  g |= (star << i);
				  g |= (0 << i);			  // fixed
				  dc |= (da_this << i);			  // dc[i] = da[i] = db[i]
				} else {
				  g |= (0 << i);			  // fixed
				  dc |= (da_this << i);			  // dc[i] = da[i] = db[i]
				}
			 } else {
				dc |= (da_this ^ db_this ^ dc_prev) << i;
			 }

/* --- */

/**
 * Constructing a set of output differences for xdp-add.
 */
void test_xdp_add_gamma_set()
{
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  //  uint32_t da = 0x3F;//random32() & MASK;
  //  uint32_t db = 0x3F;//random32() & MASK;
  for(uint32_t da = 0; da < ALL_WORDS; da++) 
	 {
		for(uint32_t db = 0; db < ALL_WORDS; db++) 
		  {

		uint32_t chi = (da ^ db);

		// if g[i] = 1, dc[i] can be anything i.e. g[i] == *
		uint32_t g = 0;
		uint32_t star = 1;

		uint32_t dc = 0;

		dc |= (da & 1) ^ (db & 1);	  // dc[0] = da[0] ^ db[0]

		//				g |= (star << 0);		  // *

		for(uint32_t i = 1; i < WORD_SIZE; i++) {

		  uint32_t dc_prev = (dc >> (i - 1)) & 1;
		  uint32_t g_prev = (g >> (i - 1)) & 1;
		  uint32_t chi_this = (chi >> i) & 1;
		  uint32_t da_this = (da >> i) & 1;
		  uint32_t db_this = (db >> i) & 1;
		  uint32_t da_prev = (da >> (i - 1)) & 1;
		  uint32_t db_prev = (db >> (i - 1)) & 1;

		  if((g_prev != star) || (i == 1)) { // dc[i] = da[i] ^ db[i] ^ dc[i-1]
			 dc |= (da_this ^ db_this ^ dc_prev) << i;
#if 0
			 if(i == 1) {
				if((da_prev != db_prev) || (da_prev != dc_prev)) {
				  if(chi_this == 0) {
					 g |= (0 << i);			  // fixed
					 dc |= (da_this << i);			  // dc[i] = da[i] = db[i]
				  } else {
					 //					 g |= (star << i);		  // *
					 //					 dc |= (0 << i);			  // dc[i] = *x
				  }
				}
			 }
#endif
		  } else {
			 //			 assert(1 == 0);
			 if(chi_this == 1) {
				g |= (star << i);		  // *
				dc |= (0 << i);			  // dc[i] = *
			 } else {
				g |= (0 << i);			  // fixed
				dc |= (da_this << i);			  // dc[i] = da[i] = db[i]
			 }
		  }
		}

		//		g |= (0xFFFFFFFE & MASK);

		double p = xdp_add(A, da, db, dc);
		printf("[%s:%d] %8X %8X (%8X %8X) %f\n", __FILE__, __LINE__, da, db, dc, g, p);
		assert(p != 0.0);

		for(uint32_t i = 0; i < WORD_SIZE; i++) {

		  uint32_t t = (g >> i) & 1;
		  if(t == 0)
			 continue;

		  uint32_t dc_new = dc ^ (1 << i);
		  double pp = xdp_add(A, da, db, dc_new);
		  printf("[%s:%d] %8X %8X (%8X %8X) %f\n", __FILE__, __LINE__, da, db, dc_new, g, pp);
		  assert(pp != 0.0);

		  p += pp;
		}
#if 0
		print_binary(da);
		printf("\n");
		print_binary(db);
		printf("\n");
		print_binary(dc);
		printf("\n");
#endif
		double p_max = max_xdp_add(A, da, db, &dc);
		if(p > p_max) {
		  printf("%f %f\n", p, p_max);
		}
		//		printf("Total: %f, max (%f %8X)\n", p, p_max, dc);
#if 0
		print_binary(da);
		printf("\n");
		print_binary(db);
		printf("\n");
		print_binary(dc);
		printf("\n");
#endif
	 }
  }

  xdp_add_free_matrices(A);
}


/* --- */

#if 0
		  if(i == 1) {
			 if(da_prev != db_prev) {
				g_prev = star;				  // *
				g |= (star << (i - 1));		  // *
			 }
		  }
#endif
//		g = g & 0xE;						  // set the LSB to 0


/* --- */

/**
 * Test if the condition for a non-zero probability ADP-XOR differential
 * (cf. Theorem 2, Wallen) is valid for XDP-ADD
 */
void test_xdp_add_nonzero_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);

  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  //  uint32_t q = random32() % WORD_SIZE; // initial bit position
  //		uint32_t x = (random32() % 2);
  //		uint32_t y = (random32() % 2);
  for(uint32_t q = 0; q < WORD_SIZE; q++) {

	 for(uint32_t r = 1; r < 8; r++) { // skip x = y = 0

		const uint32_t x = (r >> 0) & 1;
		const uint32_t y = (r >> 1) & 1;
		const uint32_t z = (r >> 2) & 1;

		printf("\n[%s:%d] --- q = %2d | %d %d %d ---\n", __FILE__, __LINE__, q, x, y, z);
		uint32_t cnt_all = 0;

		uint64_t N = (1ULL << (WORD_SIZE - q - 1)); // bits da[n-1:q+1]
		for(uint32_t i = 0; i < N; i++) {
		  for(uint32_t j = 0; j < N; j++) {
			 uint32_t cnt_o = 0;	  // output diffs
			 for(uint32_t k = 0; k < N; k++) {

				uint32_t da, db, dc;
				da = db = dc = 0;
				da |= (x << q);					  // da[q:0] = da[q] | 0*
				db |= (y << q);					  // db[q:0] = db[q] | 0*
				dc |= (z << q);					  // dc[q:0] = dc[q] | 0*

				da |= (i << (q+1));	  // da[n-1:q+1]
				db |= (j << (q+1));	  // db[n-1:q+1]
				dc |= (k << (q+1));	  // dc[n-1:q+1]

#if 0
				printf("%10d ", cnt_all);
				print_binary(da);
				print_binary(db);
				print_binary(dc);
				print_binary(dc_unaf);
				printf("\n");
#endif
				double p = xdp_add(A, da, db, dc);
				if(p != 0.0) {
				  cnt_all++;
				  cnt_o++;
				}
			 }
			 uint32_t tot_o_th = std::pow(2, (WORD_SIZE - q - 1));
			 printf("[%s:%d]Total out: %d %d (2^%f)\n", __FILE__, __LINE__, cnt_o, tot_o_th, log2(cnt_o));
		  }
		}
		uint32_t tot_th = std::pow(2, (3 * (WORD_SIZE - q - 1)));
		printf("[%s:%d]Total: %d %d (2^%f)\n", __FILE__, __LINE__, cnt_all, tot_th, log2(cnt_all));
		//		printf("\n[%s:%d] q = %2d | %d %d %d | total: %d (2^%f) | %d\n", __FILE__, __LINE__, q, x, y, z, cnt_all, log2(cnt_all), tot_th);
	 }

  }
  xdp_add_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}


/* --- */

/**
 * Test if the condition for a non-zero probability ADP-XOR differential
 * (cf. Theorem 2, Wallen) is valid for XDP-ADD
 */
void test_xdp_add_nonzero_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);

  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  //  uint32_t q = random32() % WORD_SIZE; // initial bit position
  //		uint32_t x = (random32() % 2);
  //		uint32_t y = (random32() % 2);
  for(uint32_t q = 0; q < WORD_SIZE; q++) {

	 for(uint32_t r = 1; r < 4; r++) { // skip x = y = 0

		const uint32_t x = r & 1;
		const uint32_t y = (r >> 1) & 1;
		const uint32_t z = x ^ y;

		printf("\n[%s:%d] --- q = %2d | %d %d %d ---\n", __FILE__, __LINE__, q, x, y, z);
		uint32_t cnt_all = 0;

		uint64_t N = (1ULL << (WORD_SIZE - q - 1)); // bits da[n-1:q+1]
		for(uint32_t i = 0; i < N; i++) {
		  for(uint32_t j = 0; j < N; j++) {
			 uint32_t cnt_o = 0;	  // output diffs
			 for(uint32_t k = 0; k < N; k++) {

				uint32_t da, db, dc;
				da = db = dc = 0;
				da |= (x << q);					  // da[q:0] = da[q] | 0*
				db |= (y << q);					  // db[q:0] = db[q] | 0*
				dc |= (z << q);					  // dc[q:0] = dc[q] | 0*

				da |= (i << (q+1));	  // da[n-1:q+1]
				db |= (j << (q+1));	  // db[n-1:q+1]
				dc |= (k << (q+1));	  // dc[n-1:q+1]

				bsd_t dc_naf = naf(dc);
				uint32_t dc_unaf = dc_naf.val;

#if 0
				printf("%10d ", cnt_all);
				print_binary(da);
				print_binary(db);
				print_binary(dc);
				print_binary(dc_unaf);
				printf("\n");
#endif
				double p = xdp_add(A, da, db, dc);
				assert(p != 0.0);
				cnt_all++;
				cnt_o++;
			 }
			 uint32_t tot_o_th = std::pow(2, (WORD_SIZE - q - 1));
			 printf("[%s:%d]Total out: %d %d (2^%f)\n", __FILE__, __LINE__, cnt_o, tot_o_th, log2(cnt_o));
			 assert(tot_o_th == cnt_o);
		  }
		}
		uint32_t tot_th = std::pow(2, (3 * (WORD_SIZE - q - 1)));
		printf("[%s:%d]Total: %d %d (2^%f)\n", __FILE__, __LINE__, cnt_all, tot_th, log2(cnt_all));
		assert(tot_th == cnt_all);
		//		printf("\n[%s:%d] q = %2d | %d %d %d | total: %d (2^%f) | %d\n", __FILE__, __LINE__, q, x, y, z, cnt_all, log2(cnt_all), tot_th);
	 }

  }
  xdp_add_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}


/* --- */
				printf("[%s:%d] q=%d |  %d %d %d\n", __FILE__, __LINE__, q, x, y, z);

				printf("[%s:%d] %d %d %d\n", __FILE__, __LINE__, da, db, dc);


/* --- */
void test_max_adp_arx(uint32_t N)
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);

  gsl_matrix* A[2][2][2][2];
  adp_arx_alloc_matrices(A);
  adp_arx_sf(A);
  adp_arx_normalize_matrices(A);

  for(uint32_t i = 0; i < N; i++) {

	 uint32_t r = random32() % WORD_SIZE;
	 uint32_t da = random32() & MASK;
	 uint32_t db = random32() & MASK;
	 uint32_t dd = random32() & MASK;
	 uint32_t de_max = 0;

	 double p1 = max_adp_arx(A, r, da, db, dd, &de_max);
	 double p2 = adp_arx(A, r, da, db, dd, de_max);
	 assert((p2 >= 0.0) && (p2 <= 1.0));

#if 1
	 printf("[%s:%d] ADP_ARX_MAX[(%2d|%8X,%8X,%8X)->%8X] = %6.5f (2^%f)\n", 
			  __FILE__, __LINE__, r, da, db, dd, de_max, p1, log2(p1));
	 printf("[%s:%d] ADP_ARX_THE[(%2d|%8X,%8X,%8X)->%8X] = %6.5f (2^%f)\n", 
			  __FILE__, __LINE__, r, da, db, dd, de_max, p2, log2(p2));
#else
	 printf("\r[%s:%d] %2d / %2d | %2d %f %f", __FILE__, __LINE__, r, WORD_SIZE, r, p1, p2);
	 fflush(stdout);
#endif
	 assert(p1 == p2);
  }

  adp_arx_free_matrices(A);
  printf("\n");
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}


/* --- */

/**
 * Compute an \em upper \em bound \f$B[k][i]\f$ on the maximum probability 
 * of the differential \f$(dc[n-1:k], dd[n-1:k] \rightarrow de[n-1:k])\f$,
 * where \f$dc = da + db\f$ and \f$da, db\f$ are the inputs to \ref ADD in \ref ARX, 
 * starting from initial state \p i of the S-function i.e.
 * \f$\mathrm{dp}(dc[n-1:k],dd[n-1:k] \rightarrow de[n-1:k]) = 
 * L A_{n-1} A_{n-2} \ldots A_{k} C^{i}_{k-1}\f$,
 * given the upper bounds \f$B[k][i]\f$ on the probabilities of the differentials
 * \f$(dc[n-1:j], dd[n-1:j] \rightarrow de[n-1:j])\f$ for \f$j = k+1, k+2, \ldots, n-1\f$,
 * where \f$L = [1~1~\ldots~1]\f$ is a row vector of size \p A_size and \f$C^{i}_{k-1}\f$ 
 * is a unit column vector of size \p A_size with 1 at position \f$i\f$
 * and \f$C^{i}_{-1} = C\f$.
 *
 * \note Note that \f$dc = da + db\f$, where \f$da, db\f$ are the inputs to
 *       \ref ADD in the \ref ARX operation so that the DP of \ref ARX is:
 *       \f$\mathrm{adp}^{\mathrm{ARX}}(da,db,dd \rightarrow de)\f$.
 *       
 * \param i index of the state of the S-function: \p A_size \f$> i \ge 0\f$.
 * \param k current bit position: \f$ n > k \ge 0\f$.
 * \param n word size.
 * \param lrot_const left-rotatoin constant.
 * \param p the estimated probability at bit position \p k.
 * \param de output difference.
 * \param A transition probability matrices.
 * \param B array of size \p A_size rows by (\p n + 1) columns containing upper bounds on the 
 *        maximum probabilities of all \p j bit differentials \f$n \ge j \ge 1\f$
 *        beginning from any state \p i: \p A_size \f$> i \ge 0\f$.
 * \param C unit row vector of size \p A_size rows, initialized with 1 at state index \p i.
 * \param dc first input difference.
 * \param dd second input difference.
 * \param de_max maximum probability output difference.
 * \param p_max the maximum probability.
 *
 * \b Algorithm \b Outline:
 *
 * Recursively assign values to the bits of the output difference \p dc starting 
 * at bit popsition \f$j = k\f$ and terminating at bit position \p n. The recursion 
 * proceeds to bit postion \f$j + 1\f$ only if the  probability \f$p_j\f$ of the 
 * partially constructed differential \f$(dc[j:k], dd[j:k] \rightarrow de[j:k])\f$ 
 * multiplied by the bound of the probability until the end \f$B[j+1]\f$ is bigger than 
 * the best probability found so far i.e. if:
 * \f$\sum_{s} B[s][j+1] A_{j} A_{j-1} \ldots A_{k} C^{i}_{k-1} > p_{\mathrm{max}}\f$.
 * When \f$j = n\f$ update the max.: 
 * \f$p_{\mathrm{max}} \leftarrow p_{n-1} = 
 * \mathrm{dp}(dc[n-1:k],dd[n-1:k] \rightarrow de[n-1:k])\f$.
 *
 * \note Note that since \f$dc = da + db\f$, where \f$da, db\f$ are the inputs to
 *       \ref ADD in the \ref ARX operation so that the DP of \ref ARX is:
 *       \f$\mathrm{max}_{de}~\mathrm{dp}(dc[n-1:k],dd[n-1:k] \rightarrow de[n-1:k]) = 
 *       \mathrm{max}_{de}~\mathrm{adp}^{\mathrm{ARX}}
 *       (da[n-1:k],db[n-1:k],dd[n-1:k] \rightarrow de[n-1:k])\f$.
 */
void max_adp_arx_i(const uint32_t k, const uint32_t n, 
						 const uint32_t lrot_const, double p_is[ADP_ARX_NISTATES], double* p, uint32_t* de, 
						 gsl_matrix* A[2][2][2][2], gsl_vector* B[ADP_ARX_NISTATES][WORD_SIZE + 1], gsl_vector* C[ADP_ARX_NISTATES],  
						 const uint32_t dc, const uint32_t dd, uint32_t* de_max, 
						 double p_max_is[ADP_ARX_NISTATES], double* p_max)
{
  if(k == n) {
	 assert(*p > *p_max);
#if 0									  // DEBUG
	 printf("[%s:%d] B[%2d] updcte 2^%f -> 2^%f\n", __FILE__, __LINE__, i, log2(*p_max), log2(*p));
#endif
	 for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) {
		p_max_is[is] = p_is[is];
	 }
	 *p_max = *p;
	 *de_max = *de;
	 return;
  } 

  uint32_t spos = 0;			  // special position
  uint32_t k_rot = ((k + lrot_const) % WORD_SIZE); // (i+r) mod n
  if(k_rot == 0) {
	 spos = 1;
  }

  // get the k-th bit of dc and  dd
  uint32_t x = (dc >> k) & 1;
  uint32_t y = (dd >> k_rot) & 1;


  // cycle over the possible values of the k-th bits of *de
  for(uint32_t t = 0; t < 2; t++) { 

	 double new_p = 0.0;

	 // temp
	 gsl_vector* R[ADP_ARX_NISTATES];
	 double new_p_is[ADP_ARX_NISTATES];
	 for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) {
		R[is] = gsl_vector_calloc(ADP_ARX_MSIZE);
		new_p_is[is] = 0.0;
	 }

	 for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) { // initial states

		// L A C
		gsl_blas_dgemv(CblasNoTrans, 1.0, A[spos][x][y][t], C[is], 0.0, R[is]);
		gsl_blas_ddot(B[is][k + 1], R[is], &new_p_is[is]);

		new_p += new_p_is[is];

	 }	// is

    // continue only if the probability so far is still bigger than the threshold 
	 if(new_p > *p_max) {
		uint32_t new_de = *de | (t << k);
		max_adp_arx_i(k+1, n, lrot_const, new_p_is, &new_p, &new_de, A, B, R, dc, dd, de_max, p_max_is, p_max);
	 }

	 for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) {
		gsl_vector_free(R[is]);
	 }

  } // t

  //  gsl_vector_free(L);
  return;
}

/**
 * Compute an array of bounds that can be used in the computation
 * of the maximum differential probability.
 *
 * \param A transition probability matrices.
 * \param B array of size \p A_size rows by (\p n + 1) columns containing upper bounds on the 
 *        maximum probabilities of all \p j bit differentials \f$n \ge j \ge 1\f$
 *        beginning from any state \p i: \p A_size \f$> i \ge 0\f$.
 * \param lrot_const left-rotatoin constant.
 * \param da first input difference.
 * \param db second input difference.
 * \param dd_max maximum probability output difference.
 *
 * \see max_adp_xor_bounds
 */
void max_adp_arx_bounds(gsl_matrix* A[2][2][2][2], gsl_vector* B[WORD_SIZE + 1], gsl_vector* C[ADP_ARX_NISTATES],
								const uint32_t lrot_const, const uint32_t dc,
								const uint32_t dd, uint32_t* de_max)
{
  // dc is the input to the rotation
  //  uint32_t dc = ADD(da, db);
  gsl_vector* C[ADP_ARX_NISTATES];
  for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) {
	 C[is] = gsl_vector_calloc(ADP_ARX_MSIZE);
  }
  for(uint32_t k = (WORD_SIZE - 1); k > 0; k--) {

	 for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) {

		for(uint32_t i = 0; i < ADP_ARX_MSIZE; i++) {

		  gsl_vector_set_all(C[is], 0.0);
		  gsl_vector_set(C[is], i, 1.0);

		  uint32_t n = WORD_SIZE;
		  uint32_t de_init = 0;
		  double p_init = 0.0;
		  double p_is_init[ADP_ARX_NISTATES] = {0.0};
		  double p_max = 0.0;
		  double p_max_is[ADP_ARX_NISTATES] = {0.0};
		  max_adp_arx_i(k, n, lrot_const, p_is_init, &p_init, &de_init, A, B, C, dc, dd, de_max, p_max_is, &p_max);

		  gsl_vector_set(B[is][k], i, p_max_is[is]);

#if 0
		  double p_max_i = 0.0;
		  for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) {
			 if(p_max_is[is] > p_max_i) {
				p_max_i = p_max_is[is];
			 }
			 assert(p_max_is[is] <= 1.0);
		  }
		  for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) {
			 gsl_vector_set(B[is][k], i, p_max_i);
		  }
#endif
		} // i
	 }	// is
  } // k
  for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) {
	 gsl_vector_free(C[is]);
  }
}

/**
 * Compute the maximum differential probability over all output differences:
 * \f$\mathrm{max}_{dc}~\mathrm{adp}^{\oplus}(da,db \rightarrow dc)\f$.
 * \b Complexity c: \f$O(n) \le c \le O(2^n)\f$.
 * 
 * \param A transition probability matrices.
 * \param lrot_const left-rotatoin constant.
 * \param da first input difference.
 * \param db second input difference.
 * \param dd_max maximum probability output difference.
 * \return \f$\mathrm{max}_{dc}~\mathrm{adp}^{\oplus}(da,db \rightarrow dc)\f$.
 *
 * \see max_adp_arx_bounds
 */
double max_adp_arx(gsl_matrix* A[2][2][2][2], const uint32_t lrot_const, 
						 const uint32_t da, const uint32_t db, const uint32_t dd, uint32_t* de_max)
{
  // dc is the input to the rotation
  uint32_t dc = ADD(da, db);

  // alloc the four initial states C
  gsl_vector* C[ADP_ARX_NISTATES];
  for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) {
	 C[is] = gsl_vector_calloc(ADP_ARX_MSIZE);
  }

  // alloc separate vector of bounds for each initial state
  gsl_vector* B[ADP_ARX_NISTATES][WORD_SIZE + 1];
  for(uint32_t i = 0; i < WORD_SIZE + 1; i++) {
	 for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) { // 4 initial states
		B[is][i] = gsl_vector_calloc(ADP_ARX_MSIZE);
	 }
  }

  // init the four initial states C[i], i = 0,1,2,3 and the 
  for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) {
	 uint32_t istate = ADP_ARX_ISTATES[is];
	 gsl_vector_set(C[is], istate, 1.0);
  }

  // init the final states B[i][n] corresponding to each initial state
  for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) {
	 for(uint32_t fs = 0; fs < ADP_ARX_NFSTATES; fs++) {
		uint32_t fstate = ADP_ARX_FSTATES[is][fs];
		gsl_vector_set(B[is][WORD_SIZE], fstate, 1.0); // init B[n] to the final states
	 }
  }

  //  max_adp_arx_bounds(A, B, C, lrot_const, dc, dd, de_max);
  max_adp_arx_bounds(A, B, lrot_const, dc, dd, de_max);

  // init the four initial states C[i], i = 0,1,2,3 and the 
  for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) {
	 gsl_vector_set_all(C[is], 0.0);
	 uint32_t istate = ADP_ARX_ISTATES[is];
	 gsl_vector_set(C[is], istate, 1.0);
  }

  uint32_t n = WORD_SIZE;
  uint32_t k = 0;
  uint32_t de_init = 0;
  double p_init = 0.0;
  double p_is_init[ADP_ARX_NISTATES] = {0.0};
  double p_max = 0.0;
  double p_max_is[ADP_ARX_NISTATES] = {0.0};
  max_adp_arx_i(k, n, lrot_const, p_is_init, &p_init, &de_init, A, B, C, dc, dd, de_max, p_max_is, &p_max);

  // rotate back
  // *de_max = RROT(*de_max, lrot_const);
  *de_max = LROT(*de_max, lrot_const);

#if 1									  // DEBUG
  double p_the = adp_arx(A, lrot_const, da, db, dd, *de_max);
#if 0
  printf("[%s:%d] ADP_ARX_MAX[(%2d|%8X,%8X,%8X)->%8X] = %6.5f\n", 
			__FILE__, __LINE__, lrot_const, da, db, dd, *de_max, p_max);
  printf("[%s:%d] ADP_ARX_THE[(%2d|%8X,%8X,%8X)->%8X] = %6.5f\n", 
			__FILE__, __LINE__, lrot_const, da, db, dd, *de_max, p_the);
#endif
  assert(p_max == p_the);
#endif

  // free array of vectors for the initial states
  for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) {
	 gsl_vector_free(C[is]);
  }

  // free the vector of bounds for each initial state
  for(uint32_t i = 0; i < WORD_SIZE + 1; i++) {
	 for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) { // 4 initial states
		gsl_vector_free(B[is][i]);
	 }
  }

  return p_max;
}


/* --- */

void max_adp_arx_i(const uint32_t k, const uint32_t n, 
						 const uint32_t lrot_const, double p_is[ADP_ARX_NISTATES], double* p, uint32_t* de, 
						 gsl_matrix* A[2][2][2][2], gsl_vector* B[ADP_ARX_NISTATES][WORD_SIZE + 1], gsl_vector* C[ADP_ARX_NISTATES],  
						 const uint32_t dc, const uint32_t dd, uint32_t* de_max, 
						 double p_max_is[ADP_ARX_NISTATES], double* p_max)
{
  if(k == n) {
	 assert(*p > *p_max);
#if 0									  // DEBUG
	 printf("[%s:%d] B[%2d] updcte 2^%f -> 2^%f\n", __FILE__, __LINE__, i, log2(*p_max), log2(*p));
#endif
	 for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) {
		p_max_is[is] = p_is[is];
	 }
	 *p_max = *p;
	 *de_max = *de;
	 return;
  } 

  uint32_t spos = 0;			  // special position
  uint32_t k_rot = ((k + lrot_const) % WORD_SIZE); // (i+r) mod n
  if(k_rot == 0) {
	 spos = 1;
  }

  // get the k-th bit of dc and  dd
  uint32_t x = (dc >> k) & 1;
  uint32_t y = (dd >> k_rot) & 1;


  // cycle over the possible values of the k-th bits of *de
  for(uint32_t t = 0; t < 2; t++) { 

	 double new_p = 0.0;

	 // temp
	 gsl_vector* R[ADP_ARX_NISTATES];
	 double new_p_is[ADP_ARX_NISTATES];
	 for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) {
		R[is] = gsl_vector_calloc(ADP_ARX_MSIZE);
		new_p_is[is] = 0.0;
	 }

	 for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) { // initial states

		// L A C
		gsl_blas_dgemv(CblasNoTrans, 1.0, A[spos][x][y][t], C[is], 0.0, R[is]);
		gsl_blas_ddot(B[is][k + 1], R[is], &new_p_is[is]);

		new_p += new_p_is[is];

	 }	// is

    // continue only if the probability so far is still bigger than the threshold 
	 if(new_p > *p_max) {
		uint32_t new_de = *de | (t << k);
		max_adp_arx_i(k+1, n, lrot_const, new_p_is, &new_p, &new_de, A, B, R, dc, dd, de_max, p_max_is, p_max);
	 }

	 for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) {
		gsl_vector_free(R[is]);
	 }

  } // t

  //  gsl_vector_free(L);
  return;
}

/* --- */
	 uint32_t spos = 0;			  // special position
	 uint32_t rot_pos = ((k + lrot_const) % WORD_SIZE); // (i+r) mod n
	 if(rot_pos == 0) {
		spos = 1;
	 }



/* --- */

  // alloc the composite array of bounds B that will be
  // computed as the sum of the four arrays B[is]
  gsl_vector* B_sum[WORD_SIZE + 1];
  for(uint32_t i = 0; i < WORD_SIZE + 1; i++) {
	 B_sum[i] = gsl_vector_calloc(ADP_XOR3_MSIZE);
  }


  // init the composite array of bounds B as the sum of the four arrays B[is]
  for(int k = 0; k < WORD_SIZE; k++) { // bit pos
	 for(int i = 0; i < ADP_XOR3_MSIZE; i++) { // state index
		double p_sum_i = 0.0;
		for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) {
		  double p_is_i = gsl_vector_get(B[is][k], i);
		  p_sum_i += p_is_i;
		}
		gsl_vector_set(B_sum[k], i, p_sum_i);
	 }
  }
  gsl_vector_set_all(B_max[WORD_SIZE], 1.0); // ?

  //  max_adp_arx_bounds(A, B, lrot_const, da, db, dd_max, ADP_ARX_MSIZE);



/* --- */

/**
 * Compute an array of bounds that can be used in the computation
 * of the maximum differential probability.
 *
 * \param A transition probability matrices.
 * \param B array of size \p A_size rows by (\p n + 1) columns containing upper bounds on the 
 *        maximum probabilities of all \p j bit differentials \f$n \ge j \ge 1\f$
 *        beginning from any state \p i: \p A_size \f$> i \ge 0\f$.
 * \param lrot_const left-rotatoin constant.
 * \param da first input difference.
 * \param db second input difference.
 * \param dd_max maximum probability output difference.
 *
 * \see max_adp_xor_bounds
 */
void max_adp_arx_bounds(gsl_matrix* A[2][2][2][2], gsl_vector* B[WORD_SIZE + 1],
								const uint32_t lrot_const, const uint32_t da, const uint32_t db,
								const uint32_t dd, uint32_t* de_max)
{
  // dc is the input to the rotation
  uint32_t dc = ADD(da, db);

  for(uint32_t k = (WORD_SIZE - 1); k > 0; k--) {

	 for(uint32_t i = 0; i < ADP_ARX_MSIZE; i++) {

		gsl_vector* C = gsl_vector_calloc(ADP_ARX_MSIZE);
		gsl_vector_set(C, i, 1.0);

		uint32_t n = WORD_SIZE;
		uint32_t de_init = 0;
		double p_init = gsl_vector_get(B[k], i);
		double p_max_i = 0.0;
		max_adp_arx_i(i, k, n, lrot_const, &p_init, &de_init, A, B, C, dc, dd, de_max, &p_max_i);
		gsl_vector_set(B[k], i, p_max_i);

		gsl_vector_free(C);
	 } // i
  } // k
}



/* --- */

/**
 * Compute an array of bounds that can be used in the computation
 * of the maximum differential probability.
 *
 * \param A transition probability matrices.
 * \param B array of size \p A_size rows by (\p n + 1) columns containing upper bounds on the 
 *        maximum probabilities of all \p j bit differentials \f$n \ge j \ge 1\f$
 *        beginning from any state \p i: \p A_size \f$> i \ge 0\f$.
 * \param lrot_const left-rotatoin constant.
 * \param da first input difference.
 * \param db second input difference.
 * \param dd_max maximum probability output difference.
 *
 * \see max_adp_xor_bounds
 */
void max_adp_arx_bounds(gsl_matrix* A[2][2][2][2], gsl_vector* B[ADP_ARX_NISTATES][WORD_SIZE + 1],
								const uint32_t lrot_const, const uint32_t da, const uint32_t db,
								const uint32_t dd, uint32_t* de_max)
{
  // dc is the input to the rotation
  uint32_t dc = ADD(da, db);

  for(uint32_t k = (WORD_SIZE - 1); k > 0; k--) {

	 gsl_vector* C[ADP_ARX_NISTATES];
	 for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) {
		C[is] = gsl_vector_calloc(ADP_ARX_MSIZE);
	 }

	 for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) { // 4 initial states

		gsl_vector_set_all(B[is][WORD_SIZE], 0.0); // clear the final state B[n] = L
		uint32_t istate = ADP_ARX_ISTATES[is];
		for(uint32_t fs = 0; fs < ADP_ARX_NFSTATES; fs++) {
		  uint32_t fstate = ADP_ARX_FSTATES[is][fs];
		  gsl_vector_set(B[is][WORD_SIZE], fstate, 1.0); // init B[n] to the final states
		}

		for(uint32_t i = 0; i < ADP_ARX_MSIZE; i++) {

		  gsl_vector_set_all(C[is], 0.0);
		  gsl_vector_set(C[is], i, 1.0);

		  uint32_t n = WORD_SIZE;
		  uint32_t de_init = 0;
		  double p_init = gsl_vector_get(B[is][k], i);
		  double p_max_i = 0.0;
		  max_adp_arx_i(i, k, n, lrot_const, &p_init, &de_init, A, B, C, dc, dd, de_max, &p_max_i);
		  gsl_vector_set(B[is][k], i, p_max_i);
		} // i

	 }	  // is

	 for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) {
		gsl_vector_free(C[is]);
	 }

  } // k

}


/* --- */
	 // compute the final bound at bit k as the sum of the bounds 
    // BB[0], BB[1], BB[2], BB[3] for each of the four initial  states 'is'
	 for(uint32_t i = 0; i < A_size; i++) {
		// B[k][i] = \sum_{is} BB[is][k][i] 
		double pk_sum_i = 0.0;										 // sum at bit k of the i-th state for each BB
		for(uint32_t is = 0; is < ADP_ARX_NISTATES; is++) { // initial states
		  pk_sum_i += gsl_vector_get(BB[is][k], i);			 // get the i-th state of each max BB
		}
		gsl_vector_set(B[k], i, pk_sum_i)
	 }


/* --- */
/**
 * Compute an \em upper \em bound \f$B[k][i]\f$ on the maximum probability 
 * of the differential \f$(dc[n-1:k], dd[n-1+r:k+r] \rightarrow de[n-1+r:k+r])\f$,
 * where \f$r\f$ is the rotation constant of \ref ARX, \f$dc = da + db\f$, 
 * where \f$da, db\f$ are the inputs to \ref ADD in \ref ARX, 
 * starting from initial state \p i of the S-function i.e.
 * \f$\mathrm{dp}(dc[n-1:k],dd[n-1+r:k+r] \rightarrow de[n-1+r:k+r]) = 
 * L A_{n-1} A_{n-2} \ldots A_{k} C^{i}_{k-1}\f$,
 * given the upper bounds \f$B[k][i]\f$ on the probabilities of the differentials
 * \f$(dc[n-1:j], dd[n-1+r:j+r] \rightarrow de[n-1+r:j+r])\f$ for \f$j = k+1, k+2, \ldots, n-1\f$,
 * where \f$L = [1~1~\ldots~1]\f$ is a row vector of size \p A_size and \f$C^{i}_{k-1}\f$ 
 * is a unit column vector of size \p A_size with 1 at position \f$i\f$
 * and \f$C^{i}_{-1} = C\f$.
 *
 * \note Note that \f$dc = da + db\f$, where \f$da, db\f$ are the inputs to
 *       \ref ADD in the \ref ARX operation so that the DP of \ref ARX is:
 *       \f$\mathrm{adp}^{\mathrm{ARX}}(da,db,dd \rightarrow de)\f$.
 *       
 * \param i index of the state of the S-function: \p A_size \f$> i \ge 0\f$.
 * \param k current bit position: \f$ n > k \ge 0\f$.
 * \param n word size.
 * \param p the estimated probability at bit position \p k.
 * \param de output difference.
 * \param A transition probability matrices.
 * \param B array of size \p A_size rows by (\p n + 1) columns containing upper bounds on the 
 *        maximum probabilities of all \p j bit differentials \f$n \ge j \ge 1\f$
 *        beginning from any state \p i: \p A_size \f$> i \ge 0\f$.
 * \param C unit row vector of size \p A_size rows, initialized with 1 at state index \p i.
 * \param dc first input difference.
 * \param dd second input difference.
 * \param de_max maximum probability output difference.
 * \param p_max the maximum probability.
 * \param A_size size of the square transition probability matrices
 *        (equivalently, the number of states of the S-function).
 *
 * \b Algorithm \b Outline:
 *
 * Recursively assign values to the bits of the output difference \p dc starting 
 * at bit popsition \f$j = k\f$ and terminating at bit position \p n. The recursion 
 * proceeds to bit postion \f$j + 1\f$ only if the  probability \f$p_j\f$ of the 
 * partially constructed differential \f$(dc[j:k], dd[j+r:k+r] \rightarrow de[j+r:k+r])\f$ 
 * multiplied by the bound of the probability until the end \f$B[j+1]\f$ is bigger than 
 * the best probability found so far i.e. if:
 * \f$B[j+1] A_{j} A_{j-1} \ldots A_{k} C^{i}_{k-1} > p_{\mathrm{max}}\f$.
 * When \f$j = n\f$ update the max.: 
 * \f$p_{\mathrm{max}} \leftarrow p_{n-1} = 
 * \mathrm{dp}(dc[n-1:k],dd[n-1+r:k+r] \rightarrow de[n-1+r:k+r])\f$.
 *
 * \note Note that since \f$dc = da + db\f$, where \f$da, db\f$ are the inputs to
 *       \ref ADD in the \ref ARX operation so that the DP of \ref ARX is:
 *       \f$\mathrm{max}_{de}~\mathrm{dp}(dc[n-1:k],dd[n-1+r:k+r] \rightarrow de[n-1+r:k+r]) = 
 *       \mathrm{max}_{de}~\mathrm{adp}^{\mathrm{ARX}}
 *       (da[n-1:k],db[n-1:k],dd[n-1+r:k+r] \rightarrow de[n-1+r:k+r])\f$.
 *
 * \see max_adp_xor_i
 */
void max_adp_arx_i(const int i, const uint32_t k, const uint32_t n, double* p, uint32_t* de,
						 gsl_matrix* A[2][2][2][2], gsl_vector* B[WORD_SIZE + 1], gsl_vector* C,  
						 const uint32_t dc, const uint32_t dd, uint32_t* de_max, 
						 double* p_max, uint32_t A_size)
{
  if(k == n) {
	 assert(*p > *p_max);
#if 0									  // DEBUG
	 printf("[%s:%d] B[%2d] updcte 2^%f -> 2^%f\n", __FILE__, __LINE__, i, log2(*p_max), log2(*p));
#endif
	 *p_max = *p;
	 *de_max = *de;
	 return;
  } 

  // get the k-th bit of dc, dd, dc
  uint32_t x = (dc >> k) & 1;
  uint32_t y = (dd >> k) & 1;

  // cycle over the possible values of the k-th bits of *de
  for(uint32_t t = 0; t < 2; t++) { 

	 // temp
	 //	 gsl_vector* R = gsl_vector_calloc(ADP_XOR_MSIZE);
	 gsl_vector* R = gsl_vector_calloc(A_size);
	 double new_p = 0.0;

	 // L A C
	 gsl_blas_dgemv(CblasNoTrans, 1.0, A[x][y][t], C, 0.0, R);
	 gsl_blas_deot(B[k + 1], R, &new_p);

	 // continue only if the probability so far is still bigger than the threshold 
	 if(new_p > *p_max) {
		uint32_t new_de = *de | (t << k);
		max_adp_arx_i(i, k+1, n, &new_p, &new_de, A, B, R, dc, dd, de_max, p_max, A_size);
	 }
	 gsl_vector_free(R);

  }
  //  gsl_vector_free(L);
  return;
}


/* --- */

/*
 * \note Note that since \f$dc = da + db\f$, where \f$da, db\f$ are the inputs to
 *       \ref ADD in the \ref ARX operation so that the DP of \ref ARX is:
 *       \f$\mathrm{max}_{de}~\mathrm{dp}(dc[n-1:k],dd[n-1:k] \rightarrow de[n-1:k]) = 
 *          \mathrm{max}_{de}~\mathrm{adp}^{\mathrm{ARX}}(da,db,dd \rightarrow de)\f$.
 *
 */

/* --- */

/**
 * Compute an upper bound \f$B[k][i]\f$ on the maximum probability 
 * of the differential \f$(da[n-1:k], db[n-1:k], dc[n-1:k] \rightarrow dd[n-1:k])\f$
 * starting from initial state \p i of the S-function 
 * given the upper bounds \f$B[k][i]\f$ on the probabilities of the differentials
 * \f$(da[n-1:j], db[n-1:j], dc[n-1:j] \rightarrow dd[n-1:j])\f$ 
 * for \f$j = k+1, k+2, \ldots, n-1\f$.
 * 
 * \param i index of the state of the S-function: \p A_size \f$> i \ge 0\f$.
 * \param k current bit position: \f$ n > k \ge 0\f$.
 * \param n word size.
 * \param p the transition probability of state \p i at bit position \p k.
 * \param de output difference.
 * \param A transition probability matrices.
 * \param B array of size \p A_size rows by (\p n + 1) columns containing upper bounds on the 
 *        maximum probabilities of all \p j bit differentials \f$n \ge j \ge 1\f$
 *        beginning from any state \p i: \p A_size \f$> i \ge 0\f$.
 * \param C unit row vector of size \p A_size rows, initialized with 1 at state index \p i.
 * \param da first input difference.
 * \param db second input difference.
 * \param dd third input difference.
 * \param de_max maximum probability output difference.
 * \param p_max the maximum probability.
 *
 * \see max_adp_xor3_i
 */
void max_adp_arx_i(const int i, const uint32_t k, const uint32_t n, double* p, uint32_t* de,
						 gsl_matrix* A[2][2][2][2], gsl_vector* B[WORD_SIZE + 1], gsl_vector* C,  
						 const uint32_t da, const uint32_t db, const uint32_t dd, uint32_t* de_max, 
						 double* p_max)
{
  if(k == n) {
	 assert(*p > *p_max);
#if 0									  // DEBUG
	 printf("[%s:%d] B[%2d] update 2^%f -> 2^%f\n", __FILE__, __LINE__, i, log2(*p_max), log2(*p));
#endif
	 *p_max = *p;
	 *de_max = *de;
	 return;
  } 

  uint32_t dc = ADD(da, db);	  // input to ROT

  // get the k-th bit of da, db, dd
  uint32_t x = (da >> k) & 1;
  uint32_t y = (db >> k) & 1;
  uint32_t z = (dd >> k) & 1;

  // cycle over the possible values of the k-th bits of *de
  for(uint32_t t = 0; t < 2; t++) { 

	 // temp
	 gsl_vector* R = gsl_vector_calloc(ADP_XOR3_MSIZE);
	 double new_p = 0.0;

	 // L A C
	 gsl_blas_dgemv(CblasNoTrans, 1.0, A[x][y][z][t], C, 0.0, R);
	 gsl_blas_deot(B[k + 1], R, &new_p);

	 // continue only if the probability so far is still bigger than the threshold 
	 if(new_p > *p_max) {
		uint32_t new_de = *de | (t << k);
		max_adp_xor3_i(i, k+1, n, &new_p, &new_de, A, B, R, da, db, dd, de_max, p_max);
	 }
	 gsl_vector_free(R);

  }
  //  gsl_vector_free(L);
  return;
}

/* --- */
/**
 *
 * Compute an upper bound \f$B[k][i]\f$ on the maximum probability 
 * of the differential  
 * \f$(da[n-1:k],db[n-1:k],de[n-1:k]\rightarrow dd[n-1:k])\f$,
 * starting from the four initial states \ref ADP_ARX_ISTATES 
 * of the \f$\mathrm{adp}^{\mathrm{ARX}}\f$ S-function and
 * given the upper bounds \f$B[k][i]\f$ on the probabilities of the differentials
 * \f$(da[n-1:j],db[n-1:j],de[n-1:j]\rightarrow dd[n-1:j])\f$,
 * for \f$j = k+1, k+2, \ldots, n-1\f$.
 * 
 * \param i index of the state of the S-function: \p A_size \f$> i \ge 0\f$.
 * \param k current bit position: \f$ n > k \ge 0\f$.
 * \param n word size.
 * \param p the estimated probability at bit position \p k.
 * \param de output difference.
 * \param A transition probability matrices.
 * \param B array of size \p A_size rows by (\p n + 1) columns containing upper bounds on the 
 *        maximum probabilities of all \p j bit differentials \f$n \ge j \ge 1\f$
 *        beginning from any state \p i: \p A_size \f$> i \ge 0\f$.
 * \param C unit row vector of size \p A_size rows, initialized with 1 at state index \p i.
 * \param da first input difference.
 * \param db second input difference.
 * \param dd set of input differences.
 * \param de_max maximum probability output difference.
 * \param p_max the maximum probability.
 *
 * \b Algorithm \b Outline:
 *
 * \TODO
 *
 * \see max_adp_xor3_set_i
 */
void max_adp_arx_i(const int i, const uint32_t k, const uint32_t n, double* p, uint32_t* de,
						 gsl_matrix* A[2][2][2][2], gsl_vector* B[WORD_SIZE + 1], gsl_vector* C[ADP_XOR3_SET_SIZE],  
						 const uint32_t da, const uint32_t db, const uint32_t dd[ADP_XOR3_SET_SIZE], uint32_t* de_max, 
						 double* p_max)
{
  if(k == n) {
	 assert(*p >= *p_max);
	 *p_max = *p;
	 *de_max = *de;
	 return;
  } 

  // get the k-th bit of da, db, dd
  uint32_t x = (da >> k) & 1;
  uint32_t y = (db >> k) & 1;

  // cycle over the possible values of the k-th bits of *de
  for(uint32_t t = 0; t < 2; t++) { // choose the k-th bit of de

	 double new_p = 0.0;

	 gsl_vector* R[ADP_XOR3_SET_SIZE];
	 double p[ADP_XOR3_SET_SIZE];
	 for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) {
		R[j] = gsl_vector_calloc(ADP_XOR3_MSIZE);
		p[j] = 0.0;
	 }

	 for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) { 
		uint32_t z = (dd[j] >> k) & 1;
		// L A C
		gsl_blas_dgemv(CblasNoTrans, 1.0, A[x][y][z][t], C[j], 0.0, R[j]);
		gsl_blas_deot(B[k + 1], R[j], &p[j]);

		new_p += p[j];
	 }

	 // continue only if the probability so far is still bigger than the threshold 
	 if(new_p > *p_max) {
		uint32_t new_de = *de | (t << k);
		max_adp_xor3_set_i(i, k+1, n, &new_p, &new_de, A, B, R, da, db, dd, de_max, p_max);
	 }

	 for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) {
		gsl_vector_free(R[j]);
	 }
  }
  //  gsl_vector_free(L);
  return;
}

/* --- */
#if 0										  // DEBUG
	 printf("[%s:%d] istate = %d: ", __FILE__, __LINE__, istate);
#endif
#if 0										  // DEBUG
		printf("%d ", fstate);
#endif
#if 0										  // DEBUG
	 printf("\n");
#endif


/* --- */

  for(uint32_t r = 0; r < WORD_SIZE; r++) {

	 }

/* --- */
// The ARX operation: (((a + b) <<< k) ^ d) == xor(d,(rot(add(a+b),k)))
uint32_t arx(uint32_t a, uint32_t b, uint32_t d, uint32_t k)
{
	  uint32_t e;
	  e = XOR(d,ROT(ADD(a,b),k));
	  return e;
}

/* --- */
/**
 * Initial states for the \f$\mathrm{adp}^{\mathrm{ARX}}\f$ S-function.
 */
#ifndef ADP_ARX_ISTATE
#define ADP_ARX_ISTATE_1 0 /**< First initial state for the \f$\mathrm{adp}^{\mathrm{ARX}}\f$ S-function. */
#define ADP_ARX_ISTATE_2 2 /**< Second initial state for the \f$\mathrm{adp}^{\mathrm{ARX}}\f$ S-function. */
#define ADP_ARX_ISTATE_3 4 /**< Third initial state for the \f$\mathrm{adp}^{\mathrm{ARX}}\f$ S-function. */
#define ADP_ARX_ISTATE_4 6 /**< Fourth initial state for the \f$\mathrm{adp}^{\mathrm{ARX}}\f$ S-function. */
#endif

/* --- */

/* 

 * <a href="https://en.wikipedia.org/wiki/MD4">MD4</a>
 * <a href="https://en.wikipedia.org/wiki/MD5">MD5</a>
 * <a href="https://en.wikipedia.org/wiki/BLAKE_%28hash_function%29">BLAKE</a>
 * <a href="https://en.wikipedia.org/wiki/Skein_%28hash_function%29">Skein</a>
 * <a href="https://131002.net/siphash/">SipHash</a>
 * <a href="https://en.wikipedia.org/wiki/RC5">RC5</a>
 * <a href="https://en.wikipedia.org/wiki/FEAL">FEAL</a>
 * <a href="https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm">TEA</a>
 * <a href="https://en.wikipedia.org/wiki/XTEA">XTEA</a>
 * <a href="https://en.wikipedia.org/wiki/Salsa20">Salsa20</a>

 */

/* --- */

/*
 * <tr>
 * <td></td>
 * <td></td>
 * <td>Automatic search for ADD differential trails in block cipher TEA.</td>
 * <td></td>
 * </tr>
 *
 * <tr>
 * <td></td>
 * <td></td>
 * <td>Automatic search for ADD differential trails in block cipher XTEA.</td>
 * <td></td>
 * </tr>
 * <tr>
 * <td></td>
 * <td></td>
 * <td>Automatic search for XOR differential trails in block cipher XTEA.</td>
 * <td></td>
 * </tr>
 *
 * <tr>
 * <td></td>
 * <td></td>
 * <td>Computing an ADD partial difference distribution table (pDDT) for the F-function of block cipher XTEA.</td>
 * <td></td>
 * </tr>
 *
 * <tr>
 * <td></td>
 * <td></td>
 * <td>Computing an XOR partial difference distribution table (pDDT) for the F-function of block cipher XTEA.</td>
 * <td></td>
 * </tr>
 *
 * <tr>
 * <td></td>
 * <td></td>
 * <td>Computing an ADD partial difference distribution table (pDDT) for the F-function of block cipher TEA.</td>
 * <td></td>
 * </tr>
 */

/* ---- */

/*
 * <tr>
 * <td></td>
 * <td></td>
 * <td>\f$\mathrm{adp}^{\ll}\f$</td>
 * <td>The ADD differential probability of left shift (LSH).</td>
 * <td><center>\f$O(1)\f$</center></td>
 * </tr>

 * <tr>
 * <td></td>
 * <td></td>
 * <td>\f$\mathrm{adp}^{\gg}\f$</td>
 * <td>The ADD differential probability of right shift (RSH).</td>
 * <td><center>\f$O(1)\f$</center></td>
 * </tr>

 * <tr>
 * <td></td>
 * <td></td>
 * <td>\f$\mathrm{adp}^{\gg\oplus}\f$</td>
 * <td>The ADD differential probability of RSH followed by XOR.</td>
 * <td><center>\f$O(n)\f$</center></td>
 * </tr>

 * <tr>
 * <td></td>
 * <td></td>
 * <td></td>
 * <td></td>
 * <td><center>\f$O()\f$</center></td>
 * </tr>

 * <tr>
 * <td></td>
 * <td></td>
 * <td></td>
 * <td></td>
 * <td><center>\f$O()\f$</center></td>
 * </tr>

 * <tr>
 * <td></td>
 * <td></td>
 * <td>\f$\mathrm{adp}^{3\oplus}(da,db,dc \rightarrow dd)\f$</td>
 * <td>The ADD differential probability of XOR with three inputs.</td>
 * <td><center>\f$O(n)\f$</center></td>
 * </tr>

 * <tr>
 * <td></td>
 * <td></td>
 * <td>\f$\mathrm{adp}^{\oplus}(da,db \rightarrow dc)\f$</td>
 * <td>The ADD differential probability of XOR.</td>
 * <td><center>\f$O(n)\f$</center></td>
 * </tr>

 * <tr>
 * <td></td>
 * <td></td>
 * <td>\f$\mathrm{adp}^{\oplus}_{\mathrm{FI}}(a,db \rightarrow db)\f$</td>
 * <td>The ADD differential probability of XOR with one fixed input.</td>
 * <td><center>\f$O(n)\f$</center></td>
 * </tr>

 * <tr>
 * <td></td>
 * <td></td>
 * <td></td>
 * <td></td>
 * <td><center>\f$O()\f$</center></td>
 * </tr>

 * <tr>
 * <td></td>
 * <td></td>
 * <td></td>
 * <td></td>
 * <td><center>\f$O()\f$</center></td>
 * </tr>

 * <tr>
 * <td></td>
 * <td></td>
 * <td></td>
 * <td></td>
 * <td><center>\f$O()\f$</center></td>
 * </tr>

 * <tr>
 * <td></td>
 * <td></td>
 * <td></td>
 * <td></td>
 * <td><center>\f$O()\f$</center></td>
 * </tr>

 * <tr>
 * <td></td>
 * <td></td>
 * <td>\f$\mathrm{xdp}^{+}(da,db \rightarrow dc)\f$</td>
 * <td>The XOR differential probability of ADD.</td>
 * <td><center>\f$O(n)\f$</center></td>
 * </tr>

 * <tr>
 * <td></td>
 * <td></td>
 * <td>\f$\max_{dc}~\mathrm{adp}^{\oplus}(da, db \rightarrow dc)\f$</td>
 * <td>The maximum ADD differential probability of XOR.</td>
 * <td><center>\f$O(n) \le c \le O(2^n)\f$</center></td>
 * </tr>

 * <tr>
 * <td></td>
 * <td></td>
 * <td>\f$\max_{dc}~\mathrm{xdp}^{+}(da, db \rightarrow dc)\f$</td>
 * <td>The maximum XOR differential probability of ADD.</td>
 * <td><center>\f$O(n) \le c \le O(2^n)\f$</center></td>
 * </tr>

 * <tr>
 * <td></td>
 * <td></td>
 * <td></td>
 * <td></td>
 * <td><center>\f$O()\f$</center></td>
 * </tr>

 * <tr>
 * <td></td>
 * <td></td>
 * <td>row 2, cell 1</td>
 * <td>row 2, cell 2</td>
 * <td>row 2, cell 3</td>
 * </tr>
 */

/* --- */
Indeed, providing a generic implementaion for 

it is not a trivial task to come up with an implementation that can handle any ARX design, since the degrees of freedom are too much to assess. For example, 

is can be applied as it is to perform the require computation. 

 and only then apply to apply it the problem at hand.



/*
 * All YAARX files:
 * 
 * yaarx/include/adp-rsh-xor.hh
 * yaarx/include/adp-shift.hh
 * yaarx/include/adp-tea-f-fk-ddt.hh
 * yaarx/include/adp-tea-f-fk-noshift.hh
 * yaarx/include/adp-tea-f-fk.hh
 * yaarx/include/adp-xor-fi.hh
 * yaarx/include/adp-xor-pddt.hh
 * yaarx/include/adp-xor.hh
 * yaarx/include/adp-xor3.hh
 * yaarx/include/adp-xtea-f-fk.hh
 * yaarx/include/common.hh
 * yaarx/include/eadp-tea-f.hh
 * yaarx/include/max-adp-xor-fi.hh
 * yaarx/include/max-adp-xor.hh
 * yaarx/include/max-adp-xor3-set.hh
 * yaarx/include/max-adp-xor3.hh
 * yaarx/include/max-xdp-add.hh
 * yaarx/include/tea-add-ddt-search.hh
 * yaarx/include/tea-add-threshold-search.hh
 * yaarx/include/tea-f-add-pddt.hh
 * yaarx/include/tea.hh
 * yaarx/include/xdp-add-pddt.hh
 * yaarx/include/xdp-add.hh
 * yaarx/include/xdp-tea-f-fk.hh
 * yaarx/include/xdp-xtea-f-fk.hh
 * yaarx/include/xtea-add-threshold-search.hh
 * yaarx/include/xtea-f-add-pddt.hh
 * yaarx/include/xtea-f-xor-pddt.hh
 * yaarx/include/xtea-xor-threshold-search.hh
 * yaarx/include/xtea.hh
 *
 * yaarx/src/adp-lsh-program.cc
 * yaarx/src/adp-rsh-program.cc
 * yaarx/src/adp-rsh-xor.cc
 * yaarx/src/adp-shift.cc
 * yaarx/src/adp-tea-f-fk-ddt.cc
 * yaarx/src/adp-tea-f-fk-noshift.cc
 * yaarx/src/adp-tea-f-fk.cc
 * yaarx/src/adp-xor-fi-program.cc
 * yaarx/src/adp-xor-fi.cc
 * yaarx/src/adp-xor-pddt.cc
 * yaarx/src/adp-xor-program.cc
 * yaarx/src/adp-xor.cc
 * yaarx/src/adp-xor3-program.cc
 * yaarx/src/adp-xor3.cc
 * yaarx/src/adp-xtea-f-fk.cc
 * yaarx/src/common.cc
 * yaarx/src/eadp-tea-f-program.cc
 * yaarx/src/eadp-tea-f.cc
 * yaarx/src/max-adp-xor-fi-program.cc
 * yaarx/src/max-adp-xor-fi.cc
 * yaarx/src/max-adp-xor-program.cc
 * yaarx/src/max-adp-xor.cc
 * yaarx/src/max-adp-xor3-program.cc
 * yaarx/src/max-adp-xor3-set.cc
 * yaarx/src/max-adp-xor3.cc
 * yaarx/src/max-eadp-tea-f-program.cc
 * yaarx/src/max-xdp-add-program.cc
 * yaarx/src/max-xdp-add.cc
 * yaarx/src/tea-add-ddt-search.cc
 * yaarx/src/tea-add-threshold-search.cc
 * yaarx/src/tea-f-add-pddt.cc
 * yaarx/src/tea.cc
 * yaarx/src/xdp-add-pddt.cc
 * yaarx/src/xdp-add-program.cc
 * yaarx/src/xdp-add.cc
 * yaarx/src/xdp-tea-f-fk.cc
 * yaarx/src/xdp-xtea-f-fk.cc
 * yaarx/src/xtea-add-threshold-search.cc
 * yaarx/src/xtea-f-add-pddt.cc
 * yaarx/src/xtea-f-xor-pddt.cc
 * yaarx/src/xtea-xor-threshold-search.cc
 * yaarx/src/xtea.cc
 *
 * yaarx/tests/adp-rsh-xor-tests.cc
 * yaarx/tests/adp-shift-tests.cc
 * yaarx/tests/adp-tea-f-fk-ddt-tests.cc
 * yaarx/tests/adp-tea-f-fk-noshift-tests.cc
 * yaarx/tests/adp-tea-f-fk-tests.cc
 * yaarx/tests/adp-xor-fi-tests.cc
 * yaarx/tests/adp-xor-pddt-tests.cc
 * yaarx/tests/adp-xor-tests.cc
 * yaarx/tests/adp-xor3-tests.cc
 * yaarx/tests/adp-xtea-f-fk-tests.cc
 * yaarx/tests/eadp-tea-f-tests.cc
 * yaarx/tests/max-adp-xor-fi-tests.cc
 * yaarx/tests/max-adp-xor-tests.cc
 * yaarx/tests/max-adp-xor3-set-tests.cc
 * yaarx/tests/max-adp-xor3-tests.cc
 * yaarx/tests/max-xdp-add-tests.cc
 * yaarx/tests/tea-add-ddt-search-tests.cc
 * yaarx/tests/tea-add-threshold-search-tests.cc
 * yaarx/tests/tea-f-add-pddt-tests.cc
 * yaarx/tests/xdp-add-pddt-tests.cc
 * yaarx/tests/xdp-add-tests.cc
 * yaarx/tests/xdp-tea-f-fk-tests.cc
 * yaarx/tests/xdp-xtea-f-fk-tests.cc
 * yaarx/tests/xtea-add-threshold-search-tests.cc
 * yaarx/tests/xtea-xor-threshold-search-tests.cc
 *
 * Committed revision 3648.
 */

/* --- */

// 
// Automatic search for n-round differentials for XTEA using XOR differences,
// based on Matsui search strategy. Uses a threshold to cut-off low probability differentials.
// Not guaranteed to find *the best* trail.
// 
// n - number of current round
// nrounds - total number of rounds
// A - matrices used to compute ADP-XOR
// B - arrey with the best differential probabilities for i rounds: 0 <= i < n
// Bn - the best probability on n rounds. It is updated recursively.
// diff - arrey of differentials
// trail - the actual differential trail for n-rounds
// diff_vec_p  - vector of differentials (dx,dy,p) sorted by probability p
// diff_vec_xy - vector of differentials containing the same elements as diff_vec_p,
//               but sorted by index k = (dx 2^{n} + dy)
// 
// the final prob. is the product of the probabilities of the F-function (F) and the second addition (ADD2):
// 
// F-function: y = F(x) = x + ((x << 4) ^ (x >> 5))
// ADD2:       yy = xx + (y ^ (delta + key))
// 
// Thus xdp-f2 ~= xdp-add2 * xdp-f
// 
// Every entry in the trail[] and diff[] arrays contain dx, dyy and xdp-f2:
// 
// trail[i].dx = dx
// trail[i].dy = dyy
// trail[i].p = xdp-f2~ = xdp-add2(dxx, dy -> dyy) * xdp-f(dx, dx_lxr -> dy)
// 
// where dxx = trail[i-1].dx, if i > 0 and dxx = 0 if i = 0
// 
// Note: All diff sets contain differences and probabilities for the XTEA F-function
// i.e. they do NOT include the second ADD operation!!!
// 
// See also: tea_add_threshold_search()
// 

/* --- */

// 
//
// Recursively compute all differentials (dx -> dy) 
// that have probability larger than a threshold P_THRES
// for the the F-function (the first ADD operation) of XTEA:
// 
// y = x + ((x << 4) ^ (x >> 5))
// 
// Logic sketch:
// 
// 1) Treat the input a = ((x << 4) ^ (x >> 5)) as independent from the input x
// 2) Compute a list of differentials (da, dx, dy) for the ADD operation
// 3) Store in a vector only the differentials for which da == ((dx << 4) ^ (dx >> 5))
// 
// See also: tea_f_add_pddt_i
// 
//void mmult_xdp_xtea_f_v2(const uint32_t k, const uint32_t n, 


/* --- */
// 
// Construct a list of differentials for the XTEA F-function
// that have probability above certain threshold p_thres
// An updated version of adp_xtea_f_diff_vector() using STL sets
// 
// See also: adp-xtea-f.cc:adp_xtea_f_diff_vector(), xtea-search-xor-threshold-v2.cc:xtea_xor_pddt()
// 

/* --- */

// 
// This procedure recursively computes a list of differentials (da -> dd)  
// for the F funtion of XTEA that have probability ADP_F_LXR(da -> dd) 
// that is bigger than a pre-defined threshold p_thres.
// 
// da: input to the F-function
// db, dc: inputs to the first XOR
// dd: output from the secon XOR
// dk = 0, dz = (da + dd): inputs to the second XOR
// dy: output from the second XOR and from the F-function
// 
// db = da << 4
// dc \in {(da >> 5), (da >> 5) + 1, (da >> 5) - 2^{n-5}, (da >> 5) - 2^{n-5} + 1}
// dd: (db, dc -> dd) through xor
//  A[2][2][2] - matrices for computation of adp_xor
// AA[2][2][2] - matrices for computation of adp_xor with one fixed input
//         key - secret key for the round
//       delta - pre-defined round constant
// diff_set_dx_dy - set of differentials with probability >= p_thres (a pDDT)
// 


/* --- */
// 
// Automatic search for n-round differentials for XTEA. Based on Matsui search strategy.
// Uses a threshold to cut-off low probability differentials.
// Does not find *the best* trail.
// 
// n - number of current round
// nrounds - total number of rounds
// A - matrices used to compute ADP-XOR
// AA - matrices used to compute ADP-XOR with one input -- a fixed value and not a difference
// B - arrey with the best differential probabilities for i rounds: 0 <= i < n
// Bn - the best probability on n rounds. It is updated recursively.
// diff - arrey of differentials
// trail - the actual differential trail for n-rounds
// diff_vec_p  - vector of differentials (dx,dy,p) sorted by probability p
// diff_vec_xy - vector of differentials containing the same elements as diff_vec_p,
//               but sorted by index k = (dx 2^{n} + dy)
// 
// See also: tea-search-threshold.cc:round_thres()
// 

/* --- */

//
// An updated version of adp-tea-f.cc:mmult_f. The changes are
// 
// - Uses STL set instead of vector
// - Computes expected probabilities averaged over all keys and delta-s rather than fixed-key probabilities
// 
// The main logic is the same as adp-tea-f.cc:mmult_f():
// 
// This procedure recursively lists all differentials for XOR3: (da, db, dc -> dd) 
// that satisfy the following properties:
// 
// (1) adp-xor3(da, db, dc -> dd) > p_thres
// (2) db = da << 4
// (3) dc \in {(da >> 5), (da >> 5) + 1, (da >> 5) - 2^{n-5}, (da >> 5) - 2^{n-5} + 1} = {dx[0], dx[1], dx[2], dx[3]}
//     where da >> 5 = dx[i], 0 <= i < 3
// 
// Only the entries for which EADP_F(da -> dd) > p_thres are stored
//
// See also: adp-tea-f.cc:mmult_f() and adp-tea-f.cc:mmult()
// 
// old name: mmult_f__v2
// 

/* -- */
/**
 * 
 * For two partially constructed differences \f$da\f$ and \f$dc\f$, respectively input and output of the RSH operation, 
 * Given are two differences da and dc, that are only partially constructed 
 * up to bit k (counting from the LSB)
 * 
 * This function performs checks on da and dc and outputs if dc is such that dc = RSH(da, R).
 * The idea is to be able to discrad pairs of diferences (da, dc) before they have been 
 * fully constructed. This allows to more efficiently constrct a list of valid differentials for 
 * TEA-F recursively. We use these conditions in mmult_f() to discard invalid entries early.
 * Note: the function is NOT optimal. It is overly-restrictive i.e. all diferences (da,dc)
 * which pass the conditions are valid, there exist also valid differences that
 * do not pass the checks. The reason is that it is hard to detect all valid pairs
 * before they have been constructed.
 * 
 * \param k bit position: \ref WORD_SIZE \f$< k \ge 0\f$.
 * \param new_da input difference to RSH partially constructed up to bit \f$k\f$.
 * \param new_dc output difference from RSH partially constructed up to bit \f$k\f$.
 *
 * We use the following relations:
 * 
 * dc = RSH(da, R) iff dc \in {dc_0, dc_1, dc_2, dc_3} where:
 * 
 * dc_0 = (da >> R)                      (1)
 * dc_2 = (da >> R) - 2^{n-R}            (2)
 * dc_1 = (da >> R) + 1                  (3)
 * dc_3 = (da >> R) - 2^{n-R} + 1        (4)
 * 
 * Based on the above we perform the following checks:
 * 
 * Check-1: (k >= R) check (k-R) LSBits
 * 
 * if (k >= R) we check if the first (k-R) LSB bits of (da>>R) are equal to the first (k-R) bits 
 * of dc_0 plus the additional factors from the above equations. So we check which of the following 
 * four equations hold:
 * 
 * (da >> R)[0:(k - R)] = (dc_0)[0:(k - R)]                   (1a)
 * (da >> R)[0:(k - R)] = (dc_0 + 2^{n-R})[0:(k - R)]         (2a)
 * (da >> R)[0:(k - R)] = (dc_0 - 1)[0:(k - R)]               (3a)
 * (da >> R)[0:(k - R)] = (dc_0 + 2^{n-R} - 1)[0:(k - R)]     (4a)
 * 
 * Check-2: check that R LSBits of da are not zero: da[(r-1):0] != 0 (why??)
 * 
 * Check-3: (k >= R) AND (k > (n - R)) check ((n-R) MSBits)
 * 
 * When (k > (n-R)), (da >> R)[k] = 0 and we check the top (n-R) MSBits of ds. We check if 
 * the intial four equations hold for the (n-R) MSBits of the operands:
 * 
 * dc_0[(n-1):(n-R+1)] = (da >> R)[(n-1):(n-R+1)]
 * dc_1[(n-1):(n-R+1)] = ((da >> R) + 1)[(n-1):(n-R+1)]
 * dc_2[(n-1):(n-R+1)] = ((da >> R) - 2^{n-R})[(n-1):(n-R+1)]
 * dc_3[(n-1):(n-R+1)] = ((da >> R) - 2^{n-R} + 1)[(n-1):(n-R+1)]
 * 
 *
 */

/* --- */
// 
// Compute the max for the i-th state
// 
// Recursively computes dd_max = MAX_{dd} ADP-XOR3(da, db, dc -> dd)
// by starting at bit position k = 0 and proceeding up to k = 32 
// only if the probability so far (p) is still above
// the maximum that was found up to now (p_max)
// 
// Note: The maximum p_max is obtained using a pre-computed array of bounds B[WORD_SIZE+1][NSTATES]
// For every bit position j the arrey B[j] contains the maximum probabilities p_max_i 
// for each of the NSTATES number of states (p_max_i: 0 <= i < NSTATES)
// By using bound on every single state p_max_i we obtain a tighter bound p_max
// on the max ptobability. As a result the search is more efficient as compared
// to adp-xor3.cc:mmult_maxt_rec() (adp-xor3.cc:max_adp_xor3_rec()).
// 
// Note: The array of bound B is computed by running the same function max_adp_xor3_i()
// for every bit position k and every state i (see adp_xor3.cc:max_adp_xor3_bounds())
// 
// See also: max_adp_xor_i()
// 

/* --- */
/**
 * 
 * Recursively compute the maximum differential probability over all output differences
 * of the partial \f$(n-k)\f$-bit differential
 * \f$\mathrm{max}_{dc}~\mathrm{adp}^{\oplus}(da[n-1:k],db[n-1:k],dc[n-1:k] \rightarrow dd[n-1:k])\f$.
 * 
 * \param k current bit position: \f$ n > k \ge 0\f$.
 * \param n word size.
 * \param p the transition probability of state \p i at bit position \p k.
 * \param dd output difference.
 * \param A transition probability matrices.
 * \param C unit row vector initialized with 1 at the nitial state.
 * \param da first input difference.
 * \param db second input difference.
 * \param dc third input difference.
 * \param dd_max maximum probability output difference.
 * \param p_max the maximum probability.
 *
 * \b Algorithm \b Sketch:
 *
 * The function works recursively over the bits of the output difference
 * starting at the LS bit position \f$k = 0\f$ and proceeding to \f$k+1\f$ 
 * only if the probability so far is still above
 * the maximum that was found up to now. The initial value for the maximum 
 * probability \p p_max is 0 and is updated dynamically during the process
 * every time a higher probability is encountered. The recursion
 * stops at the MSB \f$k = n\f$.
 *
 * \note This function is more efficient than exhaustive search over all 
 *       output differences \ref max_adp_xor3_exper, but is less efficient
 *       than the function \ref max_adp_xor3 that uses using bounds.
 *       The reason is that this function \ref \ref max_adp_xor3_rec_i, 
 *       at every bit position implicitly assumes that the remaining probability until 
 *       the end (i.e. until the MSB) is 1, while the bounds computed by \ref max_adp_xor3
 *       are tighter than that and thus more branches of the recursion are cur
 *       earlier in the computation.
 * 
 * See also: max_adp_xor_i()
 * 
 */

/* --- */
// 
// Compute the max for the i-th state (for definintion of "state" see S-functions)
// 
// Recursively computes dd_max = MAX_{dd} ADP-XOR3(da, db -> dd)
// by starting at bit position k = 0 and proceeding up to k = 32 
// only if the probability so far (p) is still above
// the maximum that was found up to now (p_max)
// 
// Note: The maximum p_max is obtained using a pre-computed array of bounds B[WORD_SIZE+1][NSTATES]
// For every bit position j the arrey B[j] contains the maximum probabilities p_max_i 
// for each of the NSTATES number of states (p_max_i: 0 <= i < NSTATES)
// By using bound on every single state p_max_i we obtain a tighter bound p_max
// on the max probability. As a result the search is more efficient as compared
// to a direct recursive search.
// 
// Note: The array of bounds B is computed by running the same function mmult_max_i()
// for every bit position k and every state i (see max_adp_xor_bounds()).
// 
// See also: adp-xor3.cc:mmult_max_i()
// 

/* --- */
/**
 *
 * \param i index of the state of the S-function: \p A_size \f$> i \ge 0\f$.
 * \param k current bit position: \f$ n > k \ge 0\f$.
 * \param n word size.
 * \param p the transition probability of state \p i at bit position \p k.
 * \param dd output difference.
 * \param A transition probability matrices.
 * \param B array of size \p A_size rows by (\p n + 1) columns containing upper bounds on the 
 *        maximum transition probabilities of every state \p i at every bit position \p k
 * \param C unit vector, initialized with 1 at state index \p i.
 * \param da first input difference.
 * \param db second input difference.
 * \param dd_max maximum probability output difference.
 * \param p_max the maximum probability.
 * \param A_size size of the square transition probability matrices
 *        (equivalently, the number of states of the S-function).
 * 
 * Meaning of the array of bounds \p B[\p n][\p A_size].
 * 
 * Let \f$ B[k][i] = \bar{p}\f$ for some i: \p A_size \f$> i \ge 0\f$ and some k: \f$ n > k \ge 0\f$. 
 * The probability \f$\bar{p}\f$ is a \em bound in the following sense.
 * 
 * For any output difference dc
 * 
 * Let \f$dc[k-1:0]\f$ be a partially constructed \f$k\f$-bit output difference
 * and let \f$H[k-1] = A_{k-1} A_{k-2} \ldots A_{0}\f$. 
 *
 * Let \f$dc[n-1:k]\f$ be any assignment of the remaining \f$(n-k)\f$ MS bits of dc
 * and let \f$G[k] = L A_{n-1} A_{n-2} \ldots A_{k}\f$ be the multiplication of the 
 * corresponding transition probability matrices. Then 
 * \f$\mathrm{dp}(da,db \rightarrow dc) = G[k] H[k-1] \le B[k] H[k-1]\f$ 
 * for \em any choice of \f$dc[n-1:k]\f$.
 *
 * In other words, for any choice of \f$dc[n-1:k]\f$ the actual probabilities
 * \f$G[k][i]\f$ will always be less than the bound probabilities \f$B[k][i]\f$ for all \p i.
 *
 * \f$B[k][i]\f$ is an \em upper \em bound on the probability of state \p i at bit position \p k
 * because clearly for any choice \f$dc[n-1:k]\f$ of the \f$(n-k)\f$ MS bits of dc, the probability
 * \f$ L A_{n-1} A_{n-2} \ldots A_{k} C^i_{k-1}\f$ will never be bigger than \f$B[k][i]\f$.
 * Consequently, for any transition probability vector at bit position \p k:
 * \f$H[k-1] = A_{k-1} A_{k-2} \ldots A_{0}\f$ the total probability of any differential it holds
 * \f[\mathrm{dp}(da,db \rightarrow dc) = G[k] H[k-1] \le B[k] H[k-1]\f].
 *
 */

/* --- */

/*
 * ADP_XTEA_F(da -> dd) ~= ADP_XOR(db, dc -> dy) x ADP_XOR_FIXED_INPUT((key + delta), (dy + da) -> dd) > 0.0
 * 
 * where
 * 
 * db = da << 4
 * dc[i] \in {(da >> 5), (da >> 5) + 1, (da >> 5) - 2^{n-5}, (da >> 5) - 2^{n-5} + 1}
 * 
 * Algorithm sketch: 
 * 
 *   -# Compute dy: dx_{dc[i]} ADP_XOR(db, dc[i] -> dy) 
 *   -# Compute dt = dy + da
 *   -# Compute dd: max_{dd} ADP_XOR((key + delta), dt -> dd)
 *   -# For da and dd compute the exact probability: p = ADP_XTEA_F(da -> dd)
 *   -# return p, dd
 */

/* --- */
// 
// Assigns the i-th bit of x, dx, and the key (k0 and k1)
// 
// x_cnt[k0][k1][dx] - stores the number of right pairs for a given key k0, k1 and input difference dx
// 


/* --- */

// Assigns the i-th bit of x and dx
// This function is used to compute the maximum probability input difference dx 
// for a given output difference dy (max_dx_adp_f_fk())
// 

/* --- */
// 
// For the TEA F-function, for fixed keys k0 and k1, fixed constant delta,
// and fixed input and output differences (resp. dx, dy),
// count the number of values x for which the following equation holds:
// 
// y2 - y1 = dy ,  where y1 = tea_f(x), y2 = tea_f(x + dx):
// 
// y1 = ((x << 4) + k0) ^ (x + delta) ^ ((x >> 5) + k1) ,
// y2 = (((x + dx) << 4) + k0) ^ ((x + dx) + delta) ^ (((x + dx) >> 5) + k1) .
// 
// Return the probability based on this count i.e.
// basically computes ADP_F for fixed key and delta.
// 
/*  */

/*  *  \f$y = F'(k_0, k_1, \delta | x) = ((x \ll 4) + k_0) \oplus (x + \delta) ^ ((x \gg 5) + k_1)\f$.
 */

/* --- */
/*  * \brief The ADD differential probability of the TEA F-function for a fixed key and
 *        round constants (\f$\mathrm{adp}^{F}(k_0, k_1, \delta | da \rightarrow dd)\f$) 
 *        computed using full DDT. Complexity \f$O(2^n)\f$.
 */


// ---

# --- ADP-XOR ---

ADP_XOR_OBJ = $(OBJ_PATH)adp-xor.o $(OBJ_PATH)adp-xor-program.o
ADP_XOR_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)adp-xor-tests.o

adp-xor: adp-xor.o adp-xor-program.o
	$(CC) $(LFLAGS) $(ADP_XOR_OBJ) -o $(BIN_PATH)adp-xor $(GSL_LIB)

adp-xor-tests: common.o adp-xor.o adp-xor-tests.o
	$(CC) $(LFLAGS) $(ADP_XOR_TESTS_OBJ) -o $(BIN_PATH)adp-xor-tests $(GSL_LIB)

adp-xor.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-xor.cc -o $(OBJ_PATH)adp-xor.o

adp-xor-program.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-xor-program.cc -o $(OBJ_PATH)adp-xor-program.o

adp-xor-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-xor-tests.cc -o $(OBJ_PATH)adp-xor-tests.o

// ---

XDP_TEA_F_FK_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)tea.o $(OBJ_PATH)xdp-tea-f-fk.o $(OBJ_PATH)xdp-tea-f-fk-tests.o

xdp-tea-f-fk-tests: common.o xdp-add.o max-xdp-add.o tea.o xdp-tea-f-fk.o xdp-tea-f-fk-tests.o
	$(CC) $(LFLAGS) $(XDP_TEA_F_FK_TESTS_OBJ) -o $(BIN_PATH)xdp-tea-f-fk-tests $(GSL_LIB)

xdp-tea-f-fk.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xdp-tea-f-fk.cc -o $(OBJ_PATH)xdp-tea-f-fk.o

xdp-tea-f-fk-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)xdp-tea-f-fk-tests.cc -o $(OBJ_PATH)xdp-tea-f-fk-tests.o

// ---

typedef struct {
  uint64_t diff;					  // Ox:   (dx,dy)
  double p;							  // Oy:    p(dx -> dy)
  uint64_t nparams;				  // Label: number of (k0,k1,delta) for which (dx -> dy) with probability p
} coord_t;

// fixed parameters to the F-function of TEA
typedef struct {
  uint32_t key_0;
  uint32_t key_1;
  uint32_t delta;
  double p;
} fparams_t;

bool operator<(fparams_t x, fparams_t y)
{
  if(x.p >= y.p)
	 return true;
  return false;
}

// 
// Investigate EADP_F (expected ADP_F) vs ADP_F_FK (ADP_F for fixed key and delta)
// 
// - fix da, db
// - compute EADP_F(da -> db)
// - for every key and delta compute ADP_F_FK(key, delta | da -> db)
// - Show that EADP_F is the average ADP_F over all keys and delta-s
// - Show that even when EADP_F != 0.0, there exist keys and deltas s.t. ADP_F_FK = 0,0
// - Compute the biggest deviation of ADP_F_FK from EADP_F
// 
void test_eadp_f_vs_adp_f_fixed_key(std::vector<coord_t>* plot_vec)
{
  uint32_t lsh_const = TEA_LSH_CONST; 
  uint32_t rsh_const = TEA_RSH_CONST;

  // init matrices
  gsl_matrix* A[2][2][2][2];	  // matrices to compute ADP
  adp_xor3_alloc_matrices(A);
  adp_xor3_sf(A);
  adp_xor3_normalize_matrices(A);

  uint64_t all_diffs = ALL_WORDS * ALL_WORDS;
  for(uint64_t i = 0; i < all_diffs; i++) { // fix dx, dy
	 uint64_t temp = i;
	 uint32_t dx = temp & MASK;
	 temp /= ALL_WORDS; 
	 uint32_t dy = temp & MASK;
	 temp /= ALL_WORDS; 

	 double p_eadp = eadp_tea_f(A, dx, dy, &p_eadp, lsh_const, rsh_const);
#if 0
	 printf("[%s:%d] %2d %2d | EADP_F(%8X -> %8X) = %6.5f\n", __FILE__, __LINE__, lsh_const, rsh_const, dx, dy, p_eadp);
#endif
	 uint64_t cnt_rpairs_all = 0;  // count the right pairs for all keys and delta
	 uint64_t all_inputs = ALL_WORDS * ALL_WORDS * ALL_WORDS * ALL_WORDS;
	 uint64_t all_keysndeltas = ALL_WORDS * ALL_WORDS * ALL_WORDS;

	 std::vector<fparams_t> fparams_vector;

	 for(uint64_t j = 0; j < all_keysndeltas; j++) { // for all k0, k1, delta
		uint64_t temp = j;
		uint32_t delta = temp & MASK;
		temp /= ALL_WORDS; 
		uint32_t k1 = temp & MASK;
		temp /= ALL_WORDS; 
		uint32_t k0 = temp & MASK;
		temp /= ALL_WORDS; 

		uint32_t cnt_rpairs = 0;
		uint64_t all_pairs = ALL_WORDS;
		for(uint32_t x1 = 0; x1 < ALL_WORDS; x1++) {
		  uint32_t x2 = ADD(x1, dx);
		  uint32_t y1 = tea_f(x1, k0, k1, delta, lsh_const, rsh_const);
		  uint32_t y2 = tea_f(x2, k0, k1, delta, lsh_const, rsh_const);
		  uint32_t y_sub = SUB(y2, y1);
		  if(y_sub == dy) {
			 cnt_rpairs++;
		  }
		}
		cnt_rpairs_all += cnt_rpairs;
		double p_adp_fk = (double)cnt_rpairs / (double)(all_pairs);
#if 0
		printf("[%s:%d] %2d %2d | ADP_F_FK(%8X %8X %8X | %8X -> %8X) = %6.5f\n", __FILE__, __LINE__, lsh_const, rsh_const, k0, k1, delta, dx, dy, p_adp_fk);
#endif
		fparams_t fparams;
		fparams.key_0 = k0;
		fparams.key_1 = k1;
		fparams.delta = delta;
		fparams.p = p_adp_fk;
		fparams_vector.push_back(fparams);
	 }	// k0, k1, delta

	 assert(fparams_vector.size() == all_keysndeltas);
	 std::vector<fparams_t>::iterator vec_iter;
#if 0
	 uint32_t cnt_el = 0;
	 double p_prev = fparams_vector.begin()->p;
#endif
	 for(vec_iter = fparams_vector.begin(); vec_iter != fparams_vector.end(); vec_iter++) {
#if 1
		fparams_t fparams = *vec_iter;
		uint32_t k0 = fparams.key_0;
		uint32_t k1 = fparams.key_1;
		uint32_t delta = fparams.delta;
		double p = fparams.p;
		printf("[%s:%d] %2d %2d | ADP_F_FK(%8X %8X %8X | %8X -> %8X) = %6.5f\n", __FILE__, __LINE__, lsh_const, rsh_const, k0, k1, delta, dx, dy, p);
#else
		double p = vec_iter->p;
		if(p == p_prev) {
		  cnt_el++;
		} else {
#if 0
		  double percent = ((double)cnt_el / (double)all_keysndeltas) * (100.0);
		  printf("[%s:%d] ADP_F_FK(%8X -> %8X) = %f | %5d %3.0f%%\n", __FILE__, __LINE__, dx, dy, p_prev, cnt_el, percent);
#endif
		  coord_t coord;
		  coord.diff = i;
		  coord.nparams = cnt_el;
		  coord.p = p_prev;
		  plot_vec->push_back(coord);
		  p_prev = p;
		  cnt_el = 1;
		}
		// print the last one
		std::vector<fparams_t>::iterator next = vec_iter;
		next++;
		if(next == fparams_vector.end()) {
#if 0
		  double percent = ((double)cnt_el / (double)all_keysndeltas) * (100.0);
		  printf("[%s:%d] ADP_F_FK(%8X -> %8X) = %f | %5d %3.0f%%\n", __FILE__, __LINE__, dx, dy, p_prev, cnt_el, percent);
#endif
		  coord_t coord;
		  coord.diff = i;
		  coord.nparams = cnt_el;
		  coord.p = p_prev;
		  plot_vec->push_back(coord);
		}
#endif
	 }
	 double p_adp_avrg = (double)cnt_rpairs_all / (double)all_inputs;
#if 0									  // plot average
	 printf("%5lld %f\n", i, p_adp_avrg);
#endif
#if 1
	 printf("[%s:%d] %2d %2d |     EADP_F(%8X -> %8X) = %6.5f\n", __FILE__, __LINE__, lsh_const, rsh_const, dx, dy, p_eadp);
	 printf("[%s:%d] %2d %2d | ADP_F_AVRG(%8X -> %8X) = %6.5f\n", __FILE__, __LINE__, lsh_const, rsh_const, dx, dy, p_adp_avrg);
	 printf("\n");
#endif
	 assert(p_eadp == p_adp_avrg);
  } // dx, dy
  adp_xor3_free_matrices(A);
}

// ---

typedef struct {
  uint64_t diff;					  // Ox:   (dx,dy)
  double p;							  // Oy:    p(dx -> dy)
  uint64_t nparams;				  // Label: number of (k0,k1,delta) for which (dx -> dy) with probability p
} coord_t;

// fixed parameters to the F-function of TEA
typedef struct {
  uint32_t key_0;
  uint32_t key_1;
  uint32_t delta;
  double p;
} fparams_t;

bool operator<(fparams_t x, fparams_t y)
{
  if(x.p >= y.p)
	 return true;
  return false;
}


// ---

void test_max_dx_adp_f_fk()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(TEA_LSH_CONST < TEA_RSH_CONST);
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;
  uint32_t delta = DELTA_INIT & MASK; 
  const uint32_t n = WORD_SIZE;

  uint32_t k0 = random32() & MASK; 
  uint32_t k1 = random32() & MASK; 
  uint32_t dx = random32() & MASK; 
  uint32_t dy = random32() & MASK; 

  double p_the = max_dx_adp_f_fk(n, &dx, dy, k0, k1, delta, lsh_const, rsh_const);

#if DEBUG_ADP_TEA_F_FK_TESTS
  printf("[%s:%d] n %d, key %8X %8X, delta %8X, L %d, R %d\n", __FILE__, __LINE__, WORD_SIZE, k0, k1, delta, lsh_const, rsh_const);
  printf("[%s:%d] ADP_F_FK(%d %d | %8X %8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, lsh_const, rsh_const, delta, k0, k1, dx, dy, p_the, log2(p_the));
#endif  // #if DEBUG_ADP_TEA_F_FK_TESTS
  assert(p_the == p_the);		  // avoid compilation warnings
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

// ---

  if(n < (rsh_const * 2)) {
	 printf("[%s:%d] n = %d, rsh_const = %d\n", __FILE__, __LINE__, n, rsh_const);
  }
  if(n < (rsh_const * 2)) {
	 printf("[%s:%d] n = %d, rsh_const = %d\n", __FILE__, __LINE__, n, rsh_const);
  }

// # --- ADP-TEA-F-FK ---

ADP_TEA_F_FK_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-tea-f-fk.o

adp-tea-f-fk-tests: common.o adp-tea-f-fk.o
	$(CC) $(LFLAGS) $(TEA_F_ADD_PDDT_TESTS_OBJ) -o $(BIN_PATH)adp-tea-f-fk-tests $(GSL_LIB)


// ---
//#define MASK (uint32_t)(~((uint64_t)0xffffffff << WORD_SIZE)) /**< A mask for the WORD_SIZE LS bits of a word. */


// ---
void test_max_eadp_tea_f_all()
{
  uint32_t lsh_const;
  uint32_t rsh_const;

  // init matrices
  gsl_matrix* A[2][2][2][2];	  // matrices to compute ADP
  adp_xor3_alloc_matrices(A);
  adp_xor3_sf(A);
  adp_xor3_normalize_matrices(A);

  for(lsh_const = 0; lsh_const < WORD_SIZE; lsh_const++) {
	 for(rsh_const = 0; rsh_const < WORD_SIZE; rsh_const++) {
		if((lsh_const + rsh_const) > WORD_SIZE)
		  continue;
		for(uint32_t dx = 0; dx < ALL_WORDS; dx++) {
		  uint32_t dy = 0;
		  double p1 = max_eadp_tea_f(A, dx, &dy, &p1, lsh_const, rsh_const);
		  printf("[%s:%d] %d %d | MAX_EADP_TEA_F_TH3(%8X -> %8X) = %31.30f = 2^%f\n", __FILE__, __LINE__, lsh_const, rsh_const, dx, dy, p1, log2(p1));
		  double p2 = eadp_tea_f(A, dx, dy, &p2, lsh_const, rsh_const);
		  printf("[%s:%d] %d %d | MAX_EADP_TEA_F_TH2(%8X -> %8X) = %31.30f = 2^%f\n", __FILE__, __LINE__, lsh_const, rsh_const, dx, dy, p2, log2(p2));

		  if(p1 != p2) {
			 printf("[%s:%d] WARNING:     p_adp = 2^%f !=  p_max_adp = 2^%f\n", __FILE__, __LINE__, log2(p1), log2(p2));
		  }
		  assert(p1 == p2);
		  //			 assert(float_equals(p1, p2));
		}
	 }
  }
  adp_xor3_free_matrices(A);
}

// ---

EADP_TEA_F_OBJ = 
$(OBJ_PATH)common.o 
$(OBJ_PATH)adp-xor3.o  
$(OBJ_PATH)max-adp-xor3.o  
$(OBJ_PATH)max-adp-xor3-set.o  
$(OBJ_PATH)adp-shift.o  
$(OBJ_PATH)tea.o  
$(OBJ_PATH)eadp-tea-f.o  
$(OBJ_PATH)eadp-tea-f-program.o

// ---

//double adp_rsh_xor_approx(uint32_t da, uint32_t dx, uint32_t db, int r)
double adp_rsh_xor_approx(uint32_t da, uint32_t db, int r)
{
  gsl_matrix* A[2][2][2];
  double p_tot = 0.0;

  // allocate memory
  adp_xor_alloc_matrices(A);
  adp_xor_sf(A);
  adp_xor_normalize_matrices(A);

  // compute
  uint32_t dx[4] = {0, 0, 0, 0};

  adp_rsh_odiffs(dx, da, r);

  for(int i = 0; i < 4; i++) {

	 double p1 = adp_rsh(da, dx[i], r);
	 double p2 = adp_xor(A, da, dx[i], db);
#if DEBUG_ADP_RSH_XOR
	 printf("[%s:%d] ADP_RSH[(%d -%d-> %d)] = %6.5f\n", 
			  __FILE__, __LINE__, da, r, dx[i], p1);
	 printf("[%s:%d] ADP_XOR[(%d, %d -> %d)] = %6.5f\n", 
			  __FILE__, __LINE__, da, dx[i], db, p2);
#endif
	 p_tot += (p1 * p2);
  }
  printf("p_tot = %f\n", p_tot);

  // free memory
  adp_xor_free_matrices(A);

  return p_tot;
}

// ---

#if 0									  // generate non 1.0 probabilities
			 if(ADP_XOR3_SET_SIZE == 2) {
				p_dc[0] = (double)(random() % 101) / (double)100;
				assert((p_dc[0] >= 0) && (p_dc[0] <= 1.0));
				p_dc[1] = 1.0 - p_dc[0];
				assert((p_dc[1] >= 0) && (p_dc[1] <= 1.0));
			 }
#endif

// ---
				p_dc[j] = (double)(random() % 101) / (double)100;
				assert((p_dc[j] >= 0) && (p_dc[j] <= 1.0));
