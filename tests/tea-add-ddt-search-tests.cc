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
 * \file  tea-add-ddt-search-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for tea-add-ddt-search.cc.
 *
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef TEA_H
#include "tea.hh"
#endif
#ifndef ADP_TEA_F_FK_DDT_H
#include "adp-tea-f-fk-ddt.hh"
#endif
#ifndef TEA_ADD_DDT_SEARCH_H
#include "tea-add-ddt-search.hh"
#endif


void test_tea_search_ddt()
{
  uint32_t key[4];
  key[0] = random32() & MASK;
  key[1] = random32() & MASK;
  key[2] = random32() & MASK;
  key[3] = random32() & MASK;

  tea_search_ddt(key);
}

void test_tea_search_xddt()
{
  uint32_t key[4];
  key[0] = random32() & MASK;
  key[1] = random32() & MASK;
  key[2] = random32() & MASK;
  key[3] = random32() & MASK;

  tea_search_xddt(key);
}

void test_tea_search_xddt_bottom_up()
{
  uint32_t key[4];
  key[0] = random32() & MASK;
  key[1] = random32() & MASK;
  key[2] = random32() & MASK;
  key[3] = random32() & MASK;

  tea_search_xddt_bottom_up(key);
}

void test_tea_search_ddt_xddt_xddt_bottom_up()
{
  uint32_t key[4];
  key[0] = random32() & MASK;
  key[1] = random32() & MASK;
  key[2] = random32() & MASK;
  key[3] = random32() & MASK;

  tea_search_ddt(key);
  tea_search_xddt(key);
  tea_search_xddt_bottom_up(key);
}


int main()
{
  srandom(time(NULL));
  test_tea_search_ddt();
  test_tea_search_xddt();
  test_tea_search_xddt_bottom_up();
  //  test_tea_search_ddt_xddt_xddt_bottom_up();
}
