/******************************************************************************
||  sha256.cpp                                                               ||
||===========================================================================||
||                                                                           ||
||    Author: Gary Hammock, PE                                               ||
||    Creation Date: 2008-08-27                                              ||
||    Last Edit Date: 2014-03-13                                             ||
||                                                                           ||
||===========================================================================||
||  DESCRIPTION                                                              ||
||===========================================================================||
||    This abstract data type is used to calculate the SHA-256 hash of an    ||
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
||    FIPS 180-1, "Secure Hash Standard".  17 Apr 1995.  National Institute  ||
||        of Standards and Technology.                                       ||
||                                                                           ||
||    FIPS 180-2, "Secure Hash Standard".  01 Aug 2002.  National Institute  ||
||        of Standards and Technology.                                       ||
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

/** @file sha256.h
 *  @author Gary Hammock, PE
 *  @date 2014-03-13
*/

#ifndef _GH_SHA_256_DEF_H
#define _GH_SHA_256_DEF_H

#include "hash_abstract.h"

/**
 *  @class SHA256 An abstract data type to calculate and
 *         manipulate SHA-256 hashes.
*/
class SHA256 : public MessageHash
{
  public:
    /******************************************************
    **            Constructors / Destructors             **
    ******************************************************/

    /** Default constructor.  */
    SHA256 ();

    /** Copy constructor.
     *
     *  @pre none.
     *  @post A new object is instantiated from the copied SHA256 object.
     *  @param copyFrom The SHA256 object whose values are to be copied.
    */
    SHA256 (const SHA256 &copyFrom);

    /** Initialize an SHA256 object by hashing an input std::string.
     *
     *  @pre none.
     *  @post A new object is instantiated containing the
     *        hashed value of the input data.
     *  @param str The std::string that is to be hashed.
    */
    SHA256 (const string &str);

    /** Initialize an SHA256 object by hashing an input data stream.
     *
     *  @pre none.
     *  @post A new object is instantiated containing the
     *        hashed value of the input data.
     *  @param data The data that is to be hashed.
    */
    SHA256 (const vector < byte_t > &data);

    /** Initialize an SHA256 object by hashing an input file stream.
     *
     *  @pre none.
     *  @post A new object is instantiated containing the
     *        hashed value of the input data.
     *  @param file A handle to the file that is to be hashed.
    */
    SHA256 (ifstream &file);

    /** Default destructor.  */
    ~SHA256 ();

    /******************************************************
    **               Accessors / Mutators                **
    ******************************************************/

    ////////////////////
    //    Setters
    ////////////////////

    /** Calculate the hash from an input std::string.
     *
     *  @pre The object is instantiated.
     *  @post The computed hash is stored in the _hash values.
     *  @param str The string whose value is to be hashed.
     *  @return The hash as a std::string.
    */
    string calculateHash (const string &str);

    /** Calculate the SHA256 hash from an input data stream.
     *
     *  @pre The object is instantiated.
     *  @post The SHA256 sum is stored in the _hash values.
     *  @param data The data that is to be hashed.
     *  @return The SHA256 hash as a std::string.
    */
    string calculateHash (const vector < byte_t > &data);

    /** Calculate the SHA256 hash of a file.
     *
     *  @pre The object is instantiated.
     *  @post The SHA256 sum is stored in the _hash values.
     *  @param file The file whose SHA256 is to be calculated.
     *  @return The SHA256 hash as a std::string.
    */
    string calculateHash (ifstream &file);

  private:
    /******************************************************
    **                      Members                      **
    ******************************************************/
    static const uint32_t _K[64];  // SHA-256 constants.  These represent the
                                   // first 32 bits of the fractional parts of
                                   // the cube roots of the first 64 prime
                                   // numbers.

    /******************************************************
    **                   Helper Methods                  **
    ******************************************************/

    /** Initialize the SHA256 hash.
     *
     *  @pre The object is instantiated.
     *  @post The values in _hash are initialized to the
     *        chaining variable values.
     *  @return none.
    */
    void _initializeHash (void);

    /** Pad the message contents to meet FIPS 180-2.
     *
     *  @pre The object is instantiated.
     *  @post none.
     *  @param data The data that is to be hashed.
     *  @return A vector containing the padded data.
    */
    vector < byte_t > _padVector (const vector < byte_t > &data) const;

    /** Pad the message contents to meet FIPS 180-2.
     *
     *  @pre The object is instantiated.
     *  @post none.
     *  @param lastBlock The last block of data from the file (the block
     *         that is to be padded).
     *  @param dataInBlock The number of bytes of message data in the block.
     *  @param bitsInFile The size of the message in bits.
     *  @return none.
    */
    void _padLastBlock (vector < uint32_t > &lastBlock, uint32_t dataInBlock,
                        uint64_t bitsInFile) const;

    /** The first of 6 logical functions used by SHA-256.
     *
     *  @pre none.
     *  @post none.
     *  @param x The first 32-bit word in the function.
     *  @param y The second 32-bit word in the function.
     *  @param z The final 32-bit word in the function.
     *  @return A 32-bit word that is the result of the logical function.
    */
    inline uint32_t _Ch (uint32_t x, uint32_t y, uint32_t z) const;

    /** The second of 6 logical functions used by SHA-256.
     *
     *  @pre none.
     *  @post none.
     *  @param x The first 32-bit word in the function.
     *  @param y The second 32-bit word in the function.
     *  @param z The final 32-bit word in the function.
     *  @return A 32-bit word that is the result of the logical function.
    */
    inline uint32_t _Maj (uint32_t x, uint32_t y, uint32_t z) const;

    /** The third of 6 logical functions used by SHA-256.
     *
     *  @pre none.
     *  @post none.
     *  @param x The value that is to be used in the shifts.
     *  @return A 32-bit word that is the result of the logical function.
    */
    inline uint32_t _Sigma0 (uint32_t x) const;

    /** The fourth of 6 logical functions used by SHA-256.
     *
     *  @pre none.
     *  @post none.
     *  @param x The value that is to be used in the shifts.
     *  @return A 32-bit word that is the result of the logical function.
    */
    inline uint32_t _Sigma1 (uint32_t x) const;

    /** The fifth of 6 logical functions used by SHA-256.
     *
     *  @pre none.
     *  @post none.
     *  @param x The value that is to be used in the shifts.
     *  @return A 32-bit word that is the result of the logical function.
    */
    inline uint32_t _sig0 (uint32_t x) const;

    /** The sixth of 6 logical functions used by SHA-256.
     *
     *  @pre none.
     *  @post none.
     *  @param x The value that is to be used in the shifts.
     *  @return A 32-bit word that is the result of the logical function.
    */
    inline uint32_t _sig1 (uint32_t x) const;

};  // End class SHA256.

#endif