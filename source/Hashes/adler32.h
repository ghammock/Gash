/******************************************************************************
||  adler32.h                                                                ||
||===========================================================================||
||                                                                           ||
||    Author: Gary Hammock, PE                                               ||
||    Creation Date: 2009-12-17                                              ||
||    Last Edit Date: 2014-03-13                                             ||
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
||    Wikipedia. "Adler-32".  http://en.wikipedia.org/wiki/Adler-32          ||
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

/** @file adler32.h
 *  @author Gary Hammock, PE
 *  @date 2014-03-13
*/

#ifndef _GH_ADLER32_DEF_H
#define _GH_ADLER32_DEF_H

#include "hash_abstract.h"

/**
 *  @class Adler32 Used to calculate the Adler-32 checksum
 *         for a given data stream.
*/
class Adler32 : public MessageHash
{
  public:
    /******************************************************
    **            Constructors / Destructors             **
    ******************************************************/

    /** Default constructor.  */
    Adler32 ();

    /** Copy constructor.
     *
     *  @pre none.
     *  @post A new object is instantiated from the copied Adler32 object.
     *  @param copyFrom The Adler32 object whose values are to be copied.
    */
    Adler32 (const Adler32 &copyFrom);

    /** Initialize an Adler32 object by hashing an input std::string.
     *
     *  @pre none.
     *  @post A new object is instantiated containing the
     *        hashed value of the input data.
     *  @param str The std::string that is to be hashed.
    */
    Adler32 (const string &str);

    /** Initialize an Adler32 object by hashing an input data stream.
     *
     *  @pre none.
     *  @post A new object is instantiated containing the
     *        hashed value of the input data.
     *  @param data The data that is to be hashed.
    */
    Adler32 (const vector < byte_t > &data);

    /** Initialize an Adler32 object by hashing an input file stream.
     *
     *  @pre none.
     *  @post A new object is instantiated containing the
     *        hashed value of the input data.
     *  @param file A handle to the file that is to be hashed.
    */
    Adler32 (ifstream &file);

    /** Default destructor.  */
    ~Adler32 ();

    /******************************************************
    **               Accessors / Mutators                **
    ******************************************************/

    ////////////////////
    //    Setters
    ////////////////////

    /** Calculate the Adler32 value from an input std::string.
     *
     *  @pre The object is instantiated.
     *  @post The Adler32 sum is stored in the _hash values.
     *  @param str The string whose value is to be hashed.
     *  @return The Adler32 value as a std::string.
    */
    string calculateHash (const string &str);

    /** Calculate the Adler32 value from an input data stream.
     *
     *  @pre The object is instantiated.
     *  @post The Adler32 sum is stored in the _hash values.
     *  @param data The data that is to be hashed.
     *  @return The Adler32 value as a std::string.
    */
    string calculateHash (const vector < byte_t > &data);

    /** Calculate the Adler32 value of a file.
     *
     *  @pre The object is instantiated.
     *  @post The Adler32 sum is stored in the _hash values.
     *  @param file The file whose Adler32 is to be calculated.
     *  @return The Adler32 value as a std::string.
    */
    string calculateHash (ifstream &file);

};  // End class CRC32.

#endif