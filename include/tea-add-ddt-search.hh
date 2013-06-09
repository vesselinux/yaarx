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
 * \file  tea-add-ddt-search.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Declarations for tea-add-ddt-search.cc. \copybrief tea-add-ddt-search.cc.
 */ 
#ifndef TEA_ADD_DDT_SEARCH_H
#define TEA_ADD_DDT_SEARCH_H

double verify_trail(uint64_t npairs, differential_t trail[NROUNDS], uint32_t nrounds, uint32_t key[4],
						  uint32_t delta, uint32_t lsh_const, uint32_t rsh_const);

void round_ddt(const int n, const int nrounds, 
					differential_t** RSDDT_E, differential_t** RSDDT_O, differential_t* SDDT_O,
					double B[NROUNDS], double* Bn,
					const differential_t diff_in[NROUNDS], differential_t trail[NROUNDS]);


void tea_search_ddt(uint32_t key[4]);

void round_xddt(const int n, const int nrounds, 
					 differential_t*** XRSDDT_E, differential_t*** XRSDDT_O, differential_t** XSDDT_O,
					 const double B[NROUNDS], double* Bn,
					 differential_t diff[NROUNDS], differential_t trail[NROUNDS]);

void tea_search_xddt(uint32_t key[4]);

void round_xddt_bottom_up(const int n, const int nrounds, 
								  differential_t*** XRSDDT_E, differential_t*** XRSDDT_O, 
								  differential_t** XSDDT_E, differential_t** XSDDT_O, 
								  const double B[NROUNDS], double* Bn,
								  differential_t diff[NROUNDS], differential_t trail[NROUNDS]);

void tea_search_xddt_bottom_up(uint32_t key[4]);

#endif  // #ifndef TEA_ADD_DDT_SEARCH_H
