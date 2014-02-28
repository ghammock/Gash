/******************************************************************************
||  hash_abstract.h                                                          ||
||===========================================================================||
||                                                                           ||
||    Author: Gary Hammock, PE                                               ||
||    Creation Date: 2014-02-27                                              ||
||    Last Edit Date: 2014-02-27                                             ||
||                                                                           ||
||===========================================================================||
||  DESCRIPTION                                                              ||
||===========================================================================||
||    This abstract base class (ABC) can be used to implement various hash   ||
||    objects.  Basically, this provides a container for a set of contiguous ||
||    integer values to use as the hash and provides methods for calculating ||
||    the hash as well as basic functions that are useful to computing hash  ||
||    values.                                                                ||
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

/** @file hash_abstract.h
 *  @author Gary Hammock, PE
 *  @date 2014-02-27
*/

#ifndef _GH_HASH_ABC_DEF_H
#define _GH_HASH_ABC_DEF_H

#include <ostream>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

using std::ostream;
using std::ifstream;
using std::ios;
using std::string;
using std::stringstream;
using std::vector;
using std::setw;
using std::setfill;
using std::hex;

///////////////////////////////////////
//    Type definitions
////////////////////////
typedef unsigned char byte;
typedef unsigned int  uint32;

/**
 *  @class Hash An Abstract Base Class (ABC) for use in implementing
 *         various message/data hashing algorithms.
*/
class MessageHash
{
  public:
    /******************************************************
    **            Constructors / Destructors             **
    ******************************************************/

    /** Default constructor.  */
    MessageHash (uint32 bits);

    /** Copy constructor.
     *
     *  @pre none.
     *  @post A new object is instantiated from the copied MessageHash object.
     *  @param copyFrom The MessageHash object whose values are to be copied.
    */
    MessageHash (const MessageHash &copyFrom);

    /** Initialize an MessageHash object by hashing an input std::string.
     *
     *  @pre none.
     *  @post A new object is instantiated containing the
     *        hashed value of the input data.
     *  @param bits The number of bits in the hash.
     *  @param str The std::string that is to be hashed.
    */
    MessageHash (uint32 bits, const string &str);

    /** Default destructor.  */
    virtual ~MessageHash ();

    /******************************************************
    **               Accessors / Mutators                **
    ******************************************************/
    
    ////////////////////
    //    Getters
    ////////////////////
    
    /** Retrieve the MessageHash value as a string.
     *
     *  @pre The object is instantiated.
     *  @post none.
     *  @return The value of the SHA256 sum as a std::string.
    */
    string asString (void) const;
    
    /** Retrieve the MessageHash value as an array of values.
     *
     *  @pre The object is instantiated.
     *  @post none.
     *  @param store The integer array (with size of at least n values)
     *         that is to receive the hash.
     *  @return none.
    */
    void asArray (uint32 store[]) const;

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
    virtual string calculateHash (const string &str) = 0;

    /** Calculate the hash from an input data stream.
     *
     *  @pre The object is instantiated.
     *  @post The computed hash is stored in the _hash values.
     *  @param data The data that is to be hashed.
     *  @return The hash as a std::string.
    */
    virtual string calculateHash (const vector < byte > &data) = 0;

    /** Calculate the hash of a file.
     *
     *  @pre The object is instantiated.
     *  @post The computed hash is stored in the _hash values.
     *  @param file The file whose hash value is to be calculated.
     *  @return The hash as a std::string.
    */
    virtual string calculateHash (ifstream &file) = 0;

    /******************************************************
    **                     Operators                     **
    ******************************************************/

    /** Assignment from another MessageHash object.
     *
     *  @pre The object is instantiated.
     *  @post The object contains the values copied from rhs.
     *  @param rhs The MessageHash object whose values are to be copied/stored.
     *  @return A reference to the object.
    */
    MessageHash & operator = (const MessageHash &rhs);

    /** Compare equivalence with another MessageHash object.
     *
     *  @pre Both objects are instantiated.
     *  @post none.
     *  @param rhs The MessageHash object to compare with.
     *  @return true Both objects have the same hash value.
     *  @return false The hashes of the two objects differ.
    */
    bool operator == (const MessageHash &rhs) const;

    /** Compare equivalence with another MessageHash object.
     *
     *  @pre Both objects are instantiated.
     *  @post none.
     *  @param rhs The MessageHash object to compare with.
     *  @return false Both objects have the same hash.
     *  @return true The hashes of the two objects differ.
    */
    bool operator != (const MessageHash &rhs) const;

    /** Output to a stream.
     *
     *  @pre The object is instantiated.
     *  @post none.
     *  @param os The output stream that is to be manipulated.
     *  @param hash The object that is to be output to the stream.
     *  @return A reference to the altered output stream.
    */
    friend ostream & operator << (ostream &os, const MessageHash &hash);

  protected:
    /******************************************************
    **                      Members                      **
    ******************************************************/
    vector < uint32 > _hash;
    bool _littleEndian; // A flag to denote the endianness of the system.

    /******************************************************
    **                   Helper Methods                  **
    ******************************************************/

    /** Initialize the object.
     *
     *  @pre The object is instantiated.
     *  @post The _hash values are all zero and _littleEndian is set.
     *  @param hashSizeBits The number of bits in the message hash.
     *  @return none.
    */
    void _initialize (uint32 hashSizeBits);

    /** Determine the endianness of the system.
     *
     *  @pre none.
     *  @post none.
     *  @return true The system is little endian.
     *  @return false The system is big endian.
    */
    bool _isLittleEndian (void) const;

    /** Perform a bitwise left circular-shift.
     *
     *  @param x The value to shift.
     *  @param y The number of bits to shift.
     *  @return The shifted value.
    */
    uint32 _lcshift (uint32 value, uint32 shift) const;

    /** Perform a bitwise right circular-shift.
     *
     *  @param x The value to shift.
     *  @param y The number of bits to shift.
     *  @return The shifted value.
    */
    uint32 _rcshift (uint32 value, uint32 shift) const;

};  // End abstract base class MessageHash.

#endif