/******************************************************************************
||  crc32.h                                                                  ||
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

/** @file crc32.h
 *  @author Gary Hammock, PE
 *  @date 2014-02-28
*/

#ifndef _GH_CRC32_DEF_H
#define _GH_CRC32_DEF_H

#include "hash_abstract.h"

/**
 *  @class CRC32 Used to calculate the Cyclic Redundancy Check
 *         for a given data stream.
*/
class CRC32 : public MessageHash
{
  public:
    /******************************************************
    **            Constructors / Destructors             **
    ******************************************************/

    /** Default constructor.  */
    CRC32 ();

    /** Copy constructor.
     *
     *  @pre none.
     *  @post A new object is instantiated from the copied CRC32 object.
     *  @param copyFrom The CRC32 object whose values are to be copied.
    */
    CRC32 (const CRC32 &copyFrom);

    /** Initialize a CRC32 object by hashing an input std::string.
     *
     *  @pre none.
     *  @post A new object is instantiated containing the
     *        hashed value of the input data.
     *  @param str The std::string that is to be hashed.
    */
    CRC32 (const string &str);

    /** Initialize a CRC32 object by hashing an input data stream.
     *
     *  @pre none.
     *  @post A new object is instantiated containing the
     *        hashed value of the input data.
     *  @param data The data that is to be hashed.
    */
    CRC32 (const vector < byte > &data);

    /** Initialize a CRC32 object by hashing an input file stream.
     *
     *  @pre none.
     *  @post A new object is instantiated containing the
     *        hashed value of the input data.
     *  @param file A handle to the file that is to be hashed.
    */
    CRC32 (ifstream &file);

    /** Default destructor.  */
    ~CRC32 ();

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
    string calculateHash (const string &str);

    /** Calculate the CRC32 value from an input data stream.
     *
     *  @pre The object is instantiated.
     *  @post The CRC32 sum is stored in the _hash values.
     *  @param data The data that is to be hashed.
     *  @return The CRC32 value as a std::string.
    */
    string calculateHash (const vector < byte > &data);

    /** Calculate the CRC32 value of a file.
     *
     *  @pre The object is instantiated.
     *  @post The CRC32 sum is stored in the _hash values.
     *  @param file The file whose CRC32 is to be calculated.
     *  @return The CRC32 value as a std::string.
    */
    string calculateHash (ifstream &file);

  private:
    /******************************************************
    **                      Members                      **
    ******************************************************/

    // CRC32 Polynomial = x32 + x26 + x23 + x22 + x16
    //                       + x12 + x11 + x10 + x8 + x7
    //                            + x5 + x4 + x2 + x + 1
    //
    // Using little-endian mode (least-significant bit first),
    // this corresponds to a bit-wise polynomial of the
    // form: 1110 1101 1011 1000 1000 0011 0010 0000 (1)
    static const uint32 _polynomial;

    uint32 _table[256];

    /******************************************************
    **                   Helper Methods                  **
    ******************************************************/

    /** Build the CRC32 table so we can operate on byte values.
     *
     *  @pre none.
     *  @post The 256 element _table is filled with CRC masks.
     *  @return none.
    */
    void _makeTable (void);

};  // End class CRC32.

#endif