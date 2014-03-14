/******************************************************************************
||  gash.cpp                                                                 ||
||===========================================================================||
||                                                                           ||
||    Author: Gary Hammock, PE                                               ||
||    Creation Date: 2008-09-17                                              ||
||    Last Edit Date: 2014-03-13                                             ||
||                                                                           ||
||===========================================================================||
||  DESCRIPTION                                                              ||
||===========================================================================||
||    Gash is a command-line, multiple hash algorithm file integrity         ||
||    checking program.                                                      ||
||                                                                           ||
||===========================================================================||
||  LICENSE    (MIT/X11 License)                                             ||
||===========================================================================||
||    Copyright (C) 2008-2014 Gary Hammock                                   ||
||                                                                           ||
||    Permission is hereby granted, free of charge, to any person obtaining  ||
||    a copy of this software and associated documentation files (the        ||
||    "Software"), to deal in the Software without restriction, including    ||
||    without limitation the rights to use, copy, modify, merge, publish,    ||
||    distribute, sublicense, and/or sell copies of the Software, and to     ||
||    permit persons to whom the Software is furnished to do so, subject to  ||
||    the following conditions:                                              ||
||                                                                           ||
||    The above copyright notice and this permission notice shall be         ||
||    included in all copies or substantial portions of the Software.        ||
||                                                                           ||
||    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,        ||
||    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF     ||
||    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. ||
||    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY   ||
||    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,   ||
||    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE      ||
||    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                 ||
||                                                                           ||
******************************************************************************/

/** @file gash.h
 *  @author Gary Hammock, PE
 *  @date 2014-03-13
*/

#ifndef _GASH_DEF_H
#define _GASH_DEF_H

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>

#include "Hashes/adler32.h"
#include "Hashes/crc32.h"
#include "Hashes/elf.h"
#include "Hashes/md5.h"
#include "Hashes/sha256.h"

using std::string;
using std::ifstream;
using std::stringstream;
using std::cout;
using std::cerr;
using std::endl;
using std::ios;

#define _VERSION_ "1.0.0"

///////////////////////////////////////
//    Function Declarations
////////////////////////
bool getFileHandle (string filename, ifstream &file);
void displayHelp (void);
void dispCredits (void);

#endif