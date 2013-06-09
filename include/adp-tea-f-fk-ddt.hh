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
 * \file  adp-tea-f-fk-ddt.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for adp-tea-f-fk-ddt.cc: \copybrief adp-tea-f-fk-ddt.cc.
 */ 
#ifndef ADP_TEA_F_FK_DDT_H
#define ADP_TEA_F_FK_DDT_H

void ddt_sort_rows(differential_t** T);

bool comp_rows(differential_t* a, differential_t* b);

void ddt_sort_first_col(differential_t** T);

void ddt_to_list(uint32_t** DDT, differential_t* SDDT);

void ddt_to_diff_struct(uint32_t** DDT, differential_t** SDDT);

void ddt_sort(differential_t* SDDT);

void print_rsddt(differential_t** RSDDT);

void print_sddt(differential_t* SDDT);

double adp_f_exper_fixed_key_all(const uint32_t da, const uint32_t db, 
											const uint32_t k0, const uint32_t k1, const uint32_t delta,
											uint32_t lsh_const, uint32_t rsh_const);

double max_adp_f_exper_fixed_key_all(const uint32_t da, uint32_t* db, 
												 const uint32_t k0, const uint32_t k1, const uint32_t delta,
												 uint32_t lsh_const, uint32_t rsh_const);

differential_t** rsddt_alloc();

void rsddt_free(differential_t** T);

differential_t* sddt_alloc();

void sddt_free(differential_t* ST);

uint32_t** ddt_alloc();

void ddt_free(uint32_t** T);

void ddt_f(uint32_t** T, uint32_t k0, uint32_t k1, uint32_t delta, uint32_t lsh_const, uint32_t rsh_const);

void ddt_print(uint32_t** T);

double adp_f_ddt(uint32_t** DDT, uint32_t dx, uint32_t dy);

double max_adp_f_ddt(uint32_t** DDT, uint32_t dx, uint32_t* dy);

double max_adp_f_rsddt(differential_t** TS, uint32_t dx, uint32_t* dy);

uint32_t*** xddt_alloc();

void xddt_free(uint32_t*** T);

differential_t*** xrsddt_alloc();

void xrsddt_free(differential_t*** T);

differential_t** xsddt_alloc();

void xsddt_free(differential_t** ST);

#endif  // #ifndef ADP_TEA_F_FK_DDT_H
