/******************************************************************************
||  elf.cpp                                                                  ||
||===========================================================================||
||                                                                           ||
||    Author: Gary Hammock, PE                                               ||
||    Creation Date: 2009-12-18                                              ||
||    Last Edit Date: 2014-02-28                                             ||
||                                                                           ||
||===========================================================================||
||  DESCRIPTION                                                              ||
||===========================================================================||
||    This abstract data type is used to calculate the ELF checksum of an    ||
||    input message or data stream.                                          ||
||                                                                           ||
||===========================================================================||
||  CODE DEPENDENCIES                                                        ||
||===========================================================================||
||    hash_abstract.cpp (hash_abstract.lib)                                  ||
||    hash_abstract.h                                                        ||
||                                                                           ||
||===========================================================================||
||  REFERENCES                                                               ||
||===========================================================================||
||    Tool Interface Standards.  "Executable and Linking Format".  Portable  ||
||        Formats Specification, Version 1.1.                                ||
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

/** @file elf.cpp
 *  @author Gary Hammock, PE
 *  @date 2014-02-28
*/
#include "elf.h"

/******************************************************
**            Constructors / Destructors             **
******************************************************/

/** Default constructor.  */
ELF::ELF ()
    : MessageHash(32)
{}

/** Copy constructor.
 *
 *  @pre none.
 *  @post A new object is instantiated from the copied ELF object.
 *  @param copyFrom The ELF object whose values are to be copied.
*/
ELF::ELF (const ELF &copyFrom)
    : MessageHash(copyFrom)
{}

/** Initialize an ELF object by hashing an input std::string.
 *
 *  @pre none.
 *  @post A new object is instantiated containing the
 *        hashed value of the input data.
 *  @param str The std::string that is to be hashed.
*/
ELF::ELF (const string &str)
    : MessageHash(32)
{
    calculateHash(str);
}

/** Initialize an ELF object by hashing an input data stream.
 *
 *  @pre none.
 *  @post A new object is instantiated containing the
 *        hashed value of the input data.
 *  @param data The data that is to be hashed.
*/
ELF::ELF (const vector < byte > &data)
    : MessageHash(32)
{
    calculateHash(data);
}

/** Initialize an ELF object by hashing an input file stream.
 *
 *  @pre none.
 *  @post A new object is instantiated containing the
 *        hashed value of the input data.
 *  @param file A handle to the file that is to be hashed.
*/
ELF::ELF (ifstream &file)
    : MessageHash(32)
{
    calculateHash(file);
}

/** Default destructor.  */
ELF::~ELF ()  { }

/******************************************************
**               Accessors / Mutators                **
******************************************************/

////////////////////
//    Setters
////////////////////

/** Calculate the ELF value from an input std::string.
 *
 *  @pre The object is instantiated.
 *  @post The ELF sum is stored in the _hash values.
 *  @param str The string whose value is to be hashed.
 *  @return The ELF value as a std::string.
*/
string ELF::calculateHash (const string &str)
{
    return calculateHash(vector < byte >(str.begin(), str.end()));
}

/** Calculate the ELF value from an input data stream.
 *
 *  @pre The object is instantiated.
 *  @post The ELF sum is stored in the _hash values.
 *  @param data The data that is to be hashed.
 *  @return The ELF value as a std::string.
*/
string ELF::calculateHash (const vector < byte > &data)
{
    _initialize(32);

    uint32 temp;

    vector < byte >::const_iterator it;
    for (it = data.begin(); it != data.end(); ++it)
    {
        _hash.at(0) = (_hash.at(0) << 4) + (uint32)(*it);

        temp = _hash.at(0) & 0xf0000000;

        if (temp != 0x00000000)
            _hash.at(0) ^= (temp >> 24);

        _hash.at(0) &= ~temp;
    }

    return asString();
}

/** Calculate the ELF value of a file.
 *
 *  @pre The object is instantiated.
 *  @post The ELF sum is stored in the _hash values.
 *  @param file The file whose ELF is to be calculated.
 *  @return The ELF value as a std::string.
*/
string ELF::calculateHash (ifstream &file)
{
    _initialize(32);

    // Check that the file is valid before doing anything else.
    // This will return an MD5 value of all zeros.
    if (file.fail() || !file.good())
        return asString();

    uint32 temp;
    byte value;

    while (file.peek() != -1)
    {
        value = file.get();

        _hash.at(0) = (_hash.at(0) << 4) + (uint32)value;

        temp = _hash.at(0) & 0xf0000000;

        if (temp != 0x00000000)
            _hash.at(0) ^= (temp >> 24);

        _hash.at(0) &= ~temp;
    }

    // Reset the file flags and return to the file head.
    file.clear();
    file.seekg(0);  // Return to the head of the file.

    return asString();
}