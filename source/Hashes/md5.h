/******************************************************************************
||  md5.cpp                                                                  ||
||===========================================================================||
||                                                                           ||
||    Author: Gary Hammock, PE                                               ||
||    Creation Date: 2008-09-17                                              ||
||    Last Edit Date: 2014-03-13                                             ||
||                                                                           ||
||===========================================================================||
||  DESCRIPTION                                                              ||
||===========================================================================||
||    This abstract data type is used to calculate the Rivest MD5 message    ||
||    digest / hash of an input data stream.                                 ||
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
||    Rivest, Ron.  RFC 1321.  "The MD5 Message-Digest Algorithm".  MIT      ||
||        Laboratory for Computer Science and RSA Data Security, Inc.        ||
||        Apr 1992.                                                          ||
||                                                                           ||
||    Schneier, Bruce.  "Applied Cryptography".  2nd Edition.                ||
||        John Wiley & Sons, Inc.  New York.  1996.                          ||
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

/** @file md5.h
 *  @author Gary Hammock, PE
 *  @date 2014-03-13
*/

#ifndef _GH_MD5_DEF_H
#define _GH_MD5_DEF_H

#include "hash_abstract.h"

/**
 *  @class MD5 An abstract data type to calculate and manipulate MD5 sums.
*/
class MD5 : public MessageHash
{
  public:
    /******************************************************
    **            Constructors / Destructors             **
    ******************************************************/

    /** Default constructor.  */
    MD5 ();

    /** Copy constructor.
     *
     *  @pre none.
     *  @post A new object is instantiated from the copied MD5 object.
     *  @param copyFrom The MD5 object whose values are to be copied.
    */
    MD5 (const MD5 &copyFrom);

    /** Initialize an MD5 object by hashing an input std::string.
     *
     *  @pre none.
     *  @post A new object is instantiated containing the
     *        hashed value of the input data.
     *  @param str The std::string that is to be hashed.
    */
    MD5 (const string &str);

    /** Initialize an MD5 object by hashing an input data stream.
     *
     *  @pre none.
     *  @post A new object is instantiated containing the
     *        hashed value of the input data.
     *  @param data The data that is to be hashed.
    */
    MD5 (const vector < byte_t > &data);

    /** Initialize an MD5 object by hashing an input file stream.
     *
     *  @pre none.
     *  @post A new object is instantiated containing the
     *        hashed value of the input data.
     *  @param file A handle to the file that is to be hashed.
    */
    MD5 (ifstream &file);

    /** Default destructor.  */
    ~MD5 ();

    /******************************************************
    **               Accessors / Mutators                **
    ******************************************************/

    ////////////////////
    //    Setters
    ////////////////////

    /** Calculate the MD5 value from an input std::string.
     *
     *  @pre The object is instantiated.
     *  @post The MD5 sum is stored in the _hash values.
     *  @param str The string whose value is to be hashed.
     *  @return The MD5 value as a std::string.
    */
    string calculateHash (const string &str);

    /** Calculate the MD5 value from an input data stream.
     *
     *  @pre The object is instantiated.
     *  @post The MD5 sum is stored in the _hash values.
     *  @param data The data that is to be hashed.
     *  @return The MD5 value as a std::string.
    */
    string calculateHash (const vector < byte_t > &data);

    /** Calculate the MD5 value of a file.
     *
     *  @pre The object is instantiated.
     *  @post The MD5 sum is stored in the _hash values.
     *  @param file The file whose MD5 is to be calculated.
     *  @return The MD5 value as a std::string.
    */
    string calculateHash (ifstream &file);

  private:
    /******************************************************
    **                   Helper Methods                  **
    ******************************************************/

    /** Initialize the MD5 hash.
     *
     *  @pre The object is instantiated.
     *  @post The values in _hash are initialized to the
     *        chaining variable values.
     *  @return none.
    */
    void _initializeHash (void);

    /** Pad the message contents to meet RFC1321.
     *
     *  @pre The object is instantiated.
     *  @post none.
     *  @param data The data that is to be hashed.
     *  @return A vector containing the padded data.
    */
    vector < byte_t > _padVector (const vector < byte_t > &data) const;

    /** Pad the message contents to meet RFC1321.
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

    /** Convert the hash from big endian to little endian format.
     *
     *  @pre The object is instantiated.
     *  @post The values of _hash are rearranged to little endian format.
     *  @return none.
    */
    void _convertToLittleEndian (void);

    /** Avalanche effect, Round 1.
     *
     *  @pre The object is instantiated.
     *  @post The values of _hash are manipulated.
     *  @param b512 The 512-bit message block (16, 32-bit words).
     *  @return none.
    */
    void _round1 (vector < uint32_t > b512);

    /** Avalanche effect, Round 2.
     *
     *  @pre The object is instantiated.
     *  @post The values of _hash are manipulated.
     *  @param b512 The 512-bit message block (16, 32-bit words).
     *  @return none.
    */
    void _round2 (vector < uint32_t > b512);

    /** Avalanche effect, Round 3.
     *
     *  @pre The object is instantiated.
     *  @post The values of _hash are manipulated.
     *  @param b512 The 512-bit message block (16, 32-bit words).
     *  @return none.
    */
    void _round3 (vector < uint32_t > b512);

    /** Avalanche effect, Round 4.
     *
     *  @pre The object is instantiated.
     *  @post The values of _hash are manipulated.
     *  @param b512 The 512-bit message block (16, 32-bit words).
     *  @return none.
    */
    void _round4 (vector < uint32_t > b512);

    // These functions are used for the rounding (avalanche effect)
    // of the MD5 algorithm as specified by RFC 1321

    /** The avalanche function used for Round 1 as specified by RFC 1321.
     *
     *  @pre The object is instantiated.
     *  @post The _hash values are manipulated.
     *  @param a The current chaining variable of the _hash sub-part A.
     *  @param b The current chaining variable of the _hash sub-part B.
     *  @param c The current chaining variable of the _hash sub-part C.
     *  @param d The current chaining variable of the _hash sub-part D.
     *  @param Mi The i-th sub-block of the message.
     *  @param s The number of bits used in the left circular shift.
     *  @param t A constant which is the integer part of:
     *           t[i] = 2^32 * abs(sin(i)),  where i is in radians.
     *  @return none.
    */
    void _FF (uint32_t &a, uint32_t b, uint32_t c, uint32_t d,
              uint32_t Mi, uint32_t s, uint32_t t);

    /** The avalanche function used for Round 2 as specified by RFC 1321.
     *
     *  @pre The object is instantiated.
     *  @post The _hash values are manipulated.
     *  @param a The current chaining variable of the _hash sub-part A.
     *  @param b The current chaining variable of the _hash sub-part B.
     *  @param c The current chaining variable of the _hash sub-part C.
     *  @param d The current chaining variable of the _hash sub-part D.
     *  @param Mi The i-th sub-block of the message.
     *  @param s The number of bits used in the left circular shift.
     *  @param t A constant which is the integer part of:
     *           t[i] = 2^32 * abs(sin(i)),  where i is in radians.
     *  @return none.
    */
    void _GG (uint32_t &a, uint32_t b, uint32_t c, uint32_t d,
              uint32_t Mi, uint32_t s, uint32_t t);

    /** The avalanche function used for Round 3 as specified by RFC 1321.
     *
     *  @pre The object is instantiated.
     *  @post The _hash values are manipulated.
     *  @param a The current chaining variable of the _hash sub-part A.
     *  @param b The current chaining variable of the _hash sub-part B.
     *  @param c The current chaining variable of the _hash sub-part C.
     *  @param d The current chaining variable of the _hash sub-part D.
     *  @param Mi The i-th sub-block of the message.
     *  @param s The number of bits used in the left circular shift.
     *  @param t A constant which is the integer part of:
     *           t[i] = 2^32 * abs(sin(i)),  where i is in radians.
     *  @return none.
    */
    void _HH (uint32_t &a, uint32_t b, uint32_t c, uint32_t d,
              uint32_t Mi, uint32_t s, uint32_t t);

    /** The avalanche function used for Round 4 as specified by RFC 1321.
     *
     *  @pre The object is instantiated.
     *  @post The _hash values are manipulated.
     *  @param a The current chaining variable of the _hash sub-part A.
     *  @param b The current chaining variable of the _hash sub-part B.
     *  @param c The current chaining variable of the _hash sub-part C.
     *  @param d The current chaining variable of the _hash sub-part D.
     *  @param Mi The i-th sub-block of the message.
     *  @param s The number of bits used in the left circular shift.
     *  @param t A constant which is the integer part of:
     *           t[i] = 2^32 * abs(sin(i)),  where i is in radians.
     *  @return none.
    */
    void _II (uint32_t &a, uint32_t b, uint32_t c, uint32_t d,
              uint32_t Mi, uint32_t s, uint32_t t);

};  // End class MD5.

#endif