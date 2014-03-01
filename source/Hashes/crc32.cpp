/******************************************************************************
||  crc32.cpp                                                                ||
||===========================================================================||
||                                                                           ||
||    Author: Gary Hammock, PE                                               ||
||    Creation Date: 2009-12-17                                              ||
||    Last Edit Date: 2014-02-28                                             ||
||                                                                           ||
||===========================================================================||
||  DESCRIPTION                                                              ||
||===========================================================================||
||    This abstract data type is used to calculate the CRC32 sum of an input ||
||    message or data stream.                                                ||
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
||    Wikipedia. Website.  "Cyclic Redundancy Check".                        ||
||        http://en.wikipedia.org/wiki/Cyclic_redundancy_check               ||
||        Retrieved on: 2009-12-17.                                          ||
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

/** @file crc32.cpp
 *  @author Gary Hammock, PE
 *  @date 2014-02-28
*/

#include "crc32.h"

// CRC32 Polynomial = x32 + x26 + x23 + x22 + x16
//                       + x12 + x11 + x10 + x8 + x7
//                            + x5 + x4 + x2 + x + 1
//
// Using little-endian mode (least-significant bit first),
// this corresponds to a bit-wise polynomial of the
// form: 1110 1101 1011 1000 1000 0011 0010 0000 (1)
const uint32 CRC32::_polynomial = 0xedb88320;

/******************************************************
**            Constructors / Destructors             **
******************************************************/

/** Default constructor.  */
CRC32::CRC32 ()
    : MessageHash(32)
{
    _makeTable();
}

/** Copy constructor.
 *
 *  @pre none.
 *  @post A new object is instantiated from the copied CRC32 object.
 *  @param copyFrom The CRC32 object whose values are to be copied.
*/
CRC32::CRC32 (const CRC32 &copyFrom)
    : MessageHash(copyFrom)
{
    _makeTable();
}

/** Initialize a CRC32 object by hashing an input std::string.
 *
 *  @pre none.
 *  @post A new object is instantiated containing the
 *        hashed value of the input data.
 *  @param str The std::string that is to be hashed.
*/
CRC32::CRC32 (const string &str)
    : MessageHash(32)
{
    _makeTable();
    calculateHash(str);
}

/** Initialize a CRC32 object by hashing an input data stream.
 *
 *  @pre none.
 *  @post A new object is instantiated containing the
 *        hashed value of the input data.
 *  @param data The data that is to be hashed.
*/
CRC32::CRC32 (const vector < byte > &data)
    : MessageHash(32)
{
    _makeTable();
    calculateHash(data);
}

/** Initialize a CRC32 object by hashing an input file stream.
 *
 *  @pre none.
 *  @post A new object is instantiated containing the
 *        hashed value of the input data.
 *  @param file A handle to the file that is to be hashed.
*/
CRC32::CRC32 (ifstream &file)
    : MessageHash(32)
{
    _makeTable();
    calculateHash(file);
}

/** Default destructor.  */
CRC32::~CRC32 ()  { }

/******************************************************
**               Accessors / Mutators                **
******************************************************/

////////////////////
//    Setters
////////////////////

/** Calculate the CRC32 value from an input std::string.
 *
 *  @pre The object is instantiated.
 *  @post The CRC32 sum is stored in the _hash values.
 *  @param str The string whose value is to be hashed.
 *  @return The CRC32 value as a std::string.
*/
string CRC32::calculateHash (const string &str)
{
    return calculateHash(vector < byte >(str.begin(), str.end()));
}

/** Calculate the CRC32 value from an input data stream.
 *
 *  @pre The object is instantiated.
 *  @post The CRC32 sum is stored in the _hash values.
 *  @param data The data that is to be hashed.
 *  @return The CRC32 value as a std::string.
*/
string CRC32::calculateHash (const vector < byte > &data)
{
    _initialize(32);

    // Compute the Cyclic Redundancy Check of the message
    // using the precomputed table.
    _hash.at(0) = 0xFFFFFFFF;
    for (uint32 i = 0; i < data.size(); ++i)
    {
        _hash.at(0) =  (_hash.at(0) >> 8)
                      ^ _table[(_hash.at(0) & 0xFF) ^ data.at(i)];
    }

    _hash.at(0) = ~(_hash.at(0));

    return asString();
}

/** Calculate the CRC32 value of a file.
 *
 *  @pre The object is instantiated.
 *  @post The CRC32 sum is stored in the _hash values.
 *  @param file The file whose CRC32 is to be calculated.
 *  @return The CRC32 value as a std::string.
*/
string CRC32::calculateHash (ifstream &file)
{
    _initialize(32);

    // Check that the file is valid before doing anything else.
    // This will return an MD5 value of all zeros.
    if (file.fail() || !file.good())
        return asString();

    byte value;  // A byte read from the file.

    // Compute the Cyclic Redundancy Check of the message
    // using the precomputed table.
    _hash.at(0) = 0xFFFFFFFF;
    while (file.peek() != -1)
    {
        value = file.get();

        _hash.at(0) =  (_hash.at(0) >> 8)
                      ^ _table[(_hash.at(0) & 0xFF) ^ value];
    }

    _hash.at(0) = ~(_hash.at(0));

    // Reset the file flags and return to the file head.
    file.clear();
    file.seekg(0);  // Return to the head of the file.

    return asString();
}

/******************************************************
**                   Helper Methods                  **
******************************************************/

/** Build the CRC32 table so we can operate on byte values.
 *
 *  @pre none.
 *  @post The 256 element _table is filled with CRC masks.
 *  @return none.
*/
void CRC32::_makeTable (void)
{
    uint32 value;

    // Prepare the CRC table so that we can operate
    // on byte values as opposed to individual bits
    for (uint32 i = 0; i < 256; ++i)
    {
        value = i;

        for (uint32 j = 0; j < 8; ++j)
        {
            if ((value & 0x00000001) == 1)
                value = (value >> 1) ^ _polynomial;
            else
                value >>= 1;
        }

        _table[i] = value;
    }

    return;
}