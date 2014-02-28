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

/** @file hash_abstract.cpp
 *  @author Gary Hammock, PE
 *  @date 2014-02-27
*/

#include "hash_abstract.h"

/******************************************************
**            Constructors / Destructors             **
******************************************************/

/** Default constructor.  */
MessageHash::MessageHash (uint32 bits)
{
    _initialize(bits);
}

/** Copy constructor.
 *
 *  @pre none.
 *  @post A new object is instantiated from the copied MessageHash object.
 *  @param copyFrom The MessageHash object whose values are to be copied.
*/
MessageHash::MessageHash (const MessageHash &copyFrom)
    : _hash(copyFrom._hash.begin(), copyFrom._hash.end()),
      _littleEndian(copyFrom._littleEndian)
{}

/** Default destructor.  */
MessageHash::~MessageHash ()
{
    _hash.clear();
}

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
string MessageHash::asString (void) const
{
    stringstream ss;
    ss << setfill('0') << hex;

    vector < uint32 >::const_iterator it;
    for (it = _hash.begin(); it != _hash.end(); ++it)
        ss << setw(8) << *it;
        
    return ss.str();
}
    
/** Retrieve the MessageHash value as an array of values.
 *
 *  @pre The object is instantiated.
 *  @post none.
 *  @param store The integer array (with size of at least n values)
 *         that is to receive the hash.
 *  @return none.
*/
void MessageHash::asArray (uint32 store[]) const
{
    vector < uint32 >::const_iterator it;
    uint32 i = 0;

    for (it = _hash.begin(); it != _hash.end(); ++it)
        store[i++] = *it;
    
    return;
}

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
MessageHash & MessageHash::operator = (const MessageHash &rhs)
{
    if (this != &rhs)
    {
        _littleEndian = rhs._littleEndian;
        _hash.assign(rhs._hash.begin(), rhs._hash.end());
    }

    return *this;
}

/** Compare equivalence with another MessageHash object.
*
*  @pre Both objects are instantiated.
*  @post none.
*  @param rhs The MessageHash object to compare with.
*  @return true Both objects have the same hash value.
*  @return false The hashes of the two objects differ.
*/
bool MessageHash::operator == (const MessageHash &rhs) const
{
    // The size of the two hashes must be equal for the hashes to be equal.
    if (_hash.size() != rhs._hash.size())
        return false;

    bool match = true;

    vector < uint32 >::const_iterator lhs_it;
    vector < uint32 >::const_iterator rhs_it;

    for (  lhs_it = _hash.begin(), rhs_it = rhs._hash.begin();
           match && (lhs_it != _hash.end()) && (rhs_it != rhs._hash.end());
           ++lhs_it, ++rhs_it
         )
    {
        if (*lhs_it != *rhs_it)
            match = false;
    }

    return match;
}

/** Compare equivalence with another MessageHash object.
*
*  @pre Both objects are instantiated.
*  @post none.
*  @param rhs The MessageHash object to compare with.
*  @return false Both objects have the same hash.
*  @return true The hashes of the two objects differ.
*/
bool MessageHash::operator != (const MessageHash &rhs) const
{
    return !(*this == rhs);
}

/** Output to a stream.
*
*  @pre The object is instantiated.
*  @post none.
*  @param os The output stream that is to be manipulated.
*  @param hash The object that is to be output to the stream.
*  @return A reference to the altered output stream.
*/
ostream & operator << (ostream &os, const MessageHash &hash)
{
    os << hash.asString();
    return os;
}

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
void MessageHash::_initialize (uint32 hashSizeBits)
{
    uint32 words = hashSizeBits / 32;

    _hash.assign(words, 0x00000000);

    if (_isLittleEndian())
        _littleEndian = true;

    return;
}

/** Determine the endianness of the system.
 *
 *  @pre none.
 *  @post none.
 *  @return true The system is little endian.
 *  @return false The system is big endian.
*/
bool MessageHash::_isLittleEndian (void) const
{
    uint32 i = 0x89badcfe;
    byte *p = (byte *)&i;

    // Big endian systems.
    if (p[0] == 0x89)
        return false;

    // Little endian systems (p[0] = 0xfe).
    else
        return true;
}

/** Perform a bitwise left circular-shift.
*
*  @param x The value to shift.
*  @param y The number of bits to shift.
*  @return The shifted value.
*/
uint32 MessageHash::_lcshift (uint32 value, uint32 shift) const
{  return ((value << shift) | (value >> (32 - shift)));  }

/** Perform a bitwise right circular-shift.
 *
 *  @param x The value to shift.
 *  @param y The number of bits to shift.
 *  @return The shifted value.
*/
uint32 MessageHash::_rcshift (uint32 value, uint32 shift) const
{  return ((value >> shift) | (value << (32 - shift)));  }