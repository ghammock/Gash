/******************************************************************************
||  sha256.cpp                                                               ||
||===========================================================================||
||                                                                           ||
||    Author: Gary Hammock, PE                                               ||
||    Creation Date: 2008-08-27                                              ||
||    Last Edit Date: 2014-02-27                                             ||
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

/** @file sha256.cpp
 *  @author Gary Hammock, PE
 *  @date 2014-02-27
*/

#include "sha256.h"

// SHA-256 uses a sequence of 64 constant 32-bit words.  These words
// represent the first 32 bits of the fractional parts of the
// cube roots of the first 64 prime numbers.
const uint32 SHA256::_K[64] =
                     { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                       0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                       0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                       0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                       0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                       0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                       0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                       0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                       0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                       0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                       0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                       0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                       0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                       0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                       0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                       0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
                     };

/******************************************************
**            Constructors / Destructors             **
******************************************************/

/** Default constructor.  */
SHA256::SHA256 ()
    : MessageHash(256)
{}

/** Copy constructor.
 *
 *  @pre none.
 *  @post A new object is instantiated from the copied SHA256 object.
 *  @param copyFrom The SHA256 object whose values are to be copied.
*/
SHA256::SHA256 (const SHA256 &copyFrom)
    : MessageHash(copyFrom)
{}

/** Initialize an SHA256 object by hashing an input std::string.
 *
 *  @pre none.
 *  @post A new object is instantiated containing the
 *        hashed value of the input data.
 *  @param str The std::string that is to be hashed.
*/
SHA256::SHA256 (const string &str)
    : MessageHash(256)
{
    calculateHash(str);
}

/** Initialize an SHA256 object by hashing an input data stream.
 *
 *  @pre none.
 *  @post A new object is instantiated containing the
 *        hashed value of the input data.
 *  @param data The data that is to be hashed.
*/
SHA256::SHA256 (const vector < byte > &data)
    : MessageHash(256)
{
    calculateHash(data);
}

/** Initialize an SHA256 object by hashing an input file stream.
 *
 *  @pre none.
 *  @post A new object is instantiated containing the
 *        hashed value of the input data.
 *  @param file A handle to the file that is to be hashed.
*/
SHA256::SHA256 (ifstream &file)
    : MessageHash(256)
{
    calculateHash(file);
}

/** Default destructor.  */
SHA256::~SHA256 ()  { }

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
string SHA256::calculateHash (const string &str)
{
    return calculateHash(vector < byte >(str.begin(), str.end()));
}

/** Calculate the SHA256 hash from an input data stream.
 *
 *  @pre The object is instantiated.
 *  @post The SHA256 sum is stored in the _hash values.
 *  @param data The data that is to be hashed.
 *  @return The SHA256 hash as a std::string.
*/
string SHA256::calculateHash (const vector < byte > &data)
{
    _initialize(256);

    vector < byte > message = _padVector(data);

    // The message must be processed in 512-bit (64-byte) chunks
    uint32 chunks = message.size() / 64;

    // We need to initialize the hash to the chaining variables.
    _initializeHash();

    // A message schedule of 64 32-bit words (this is the
    // message block + the schedule).
    vector < uint32 > schedule;

    uint32 offset,  // A calculated offset into the data.
           append,  // A concatenation of 4 bytes into 1 32-bit word.
           a,       // The chaining variable associated with _hash[0].
           b,       // The chaining variable associated with _hash[1].
           c,       // The chaining variable associated with _hash[2].
           d,       // The chaining variable associated with _hash[3].
           e,       // The chaining variable associated with _hash[4].
           f,       // The chaining variable associated with _hash[5].
           g,       // The chaining variable associated with _hash[6].
           h,       // The chaining variable associated with _hash[7].
           t1,      // A temporary word to hold the part of the avalanche.
           t2;      // A temporary word to hold the part of the avalanche.

    // We need to process N message blocks (chunks).
    for (uint32 i = 0; i < chunks; ++i)
    {
        // Initialize the eight 32-bit chaining variables.
        a = _hash.at(0);
        b = _hash.at(1);
        c = _hash.at(2);
        d = _hash.at(3);
        e = _hash.at(4);
        f = _hash.at(5);
        g = _hash.at(6);
        h = _hash.at(7);

        // Reset the 64 32-bit block to all zeros.
        schedule.assign(64, 0x00000000);

        // According to FIP 180-2, we first need to prepare the
        // message schedule where the first 16 words are the
        // 512-bit message block.
        for (uint32 j = 0; j < 16; ++j)
        {
            // The current offset into the message data.
            offset = (i * 64) + (j * 4);

            // The words are appended in little-endian format, i.e.
            // if the hardware is big-endian, we have to convert the
            // bytes to little-endian.
            if (_littleEndian)
            {
                append =   ((uint32)message.at(offset    ) << 24)
                         | ((uint32)message.at(offset + 1) << 16)
                         | ((uint32)message.at(offset + 2) <<  8)
                         | ((uint32)message.at(offset + 3)      );
            }
            else
            {
                append =   ((uint32)message.at(offset    )      )
                         | ((uint32)message.at(offset + 1) <<  8)
                         | ((uint32)message.at(offset + 2) << 16)
                         | ((uint32)message.at(offset + 3) << 24);
            }

            schedule.at(j) = append;

        }  // End for-loop j [ 0, 15].

        // The remaining 48 words in the message schedule are computed
        // from the logical functions using the previous words in the
        // schedule for avalanching the later indices in the schedule.
        for (uint32 j = 16; j < 64; ++j)
        {
            schedule.at(j) =   _sig1(schedule.at(j -  2))
                                   + schedule.at(j -  7)
                             + _sig0(schedule.at(j - 15))
                                   + schedule.at(j - 16);

        }  // End for-loop j [16, 63].

        // The actual avalance effect is performed in this loop.
        for (uint32 j = 0; j < 64; ++j)
        {
            t1 = h + _Sigma1(e) + _Ch(e, f, g) + _K[j] + schedule.at(j);
            t2 = _Sigma0(a) + _Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }  // End for-loop j.

        // The i-th intermediate hash value.
        _hash.at(0) += a;
        _hash.at(1) += b;
        _hash.at(2) += c;
        _hash.at(3) += d;
        _hash.at(4) += e;
        _hash.at(5) += f;
        _hash.at(6) += g;
        _hash.at(7) += h;

    } // End for-loop i.

    return asString();
}

/** Calculate the SHA256 hash of a file.
*
*  @pre The object is instantiated.
*  @post The SHA256 sum is stored in the _hash values.
*  @param file The file whose SHA256 is to be calculated.
*  @return The SHA256 hash as a std::string.
*/
string SHA256::calculateHash (ifstream &file)
{
    _initialize(256);

    // Check that the file is valid before doing anything else.
    // This will return an MD5 value of all zeros.
    if (file.fail() || !file.good())
        return asString();

    uint32 filesize,    // The size of the file in bytes.
           paddedSize,  // The size of the data after padding.
           filebits;    // The filesize in bits.

    // We need to get the size of the file.
    file.seekg(0, ios::end);
    filesize = (uint32)file.tellg();
    filebits = filesize * 8;
    file.seekg(0);  // Return to the head of the file.

    // We need to append 9 bytes to the data and fill the extra padding
    // with zeros to get a 512-bit boundary.
    paddedSize = filesize + 9;
    while ((paddedSize % 64) != 0) ++paddedSize;

    // The message must be processed in 512-bit (64-byte) chunks
    uint32 chunks = paddedSize / 64;

    // A message schedule of 64 32-bit words (this is the
    // message block + the schedule).
    vector < uint32 > schedule;

    uint32 append,  // A concatenation of 4 bytes into 1 32-bit word.
           a,       // The chaining variable associated with _hash[0].
           b,       // The chaining variable associated with _hash[1].
           c,       // The chaining variable associated with _hash[2].
           d,       // The chaining variable associated with _hash[3].
           e,       // The chaining variable associated with _hash[4].
           f,       // The chaining variable associated with _hash[5].
           g,       // The chaining variable associated with _hash[6].
           h,       // The chaining variable associated with _hash[7].
           t1,      // A temporary word to hold the part of the avalanche.
           t2,      // A temporary word to hold the part of the avalanche.
           blockData;  // The number of message bytes in each block.

    bool endOfStream = false;

    // We need to initialize the hash to the chaining variables.
    _initializeHash();

    // We need to process N message blocks (chunks).
    for (uint32 i = 0; i < chunks; ++i)
    {
        // Initialize the eight 32-bit chaining variables.
        a = _hash.at(0);
        b = _hash.at(1);
        c = _hash.at(2);
        d = _hash.at(3);
        e = _hash.at(4);
        f = _hash.at(5);
        g = _hash.at(6);
        h = _hash.at(7);

        // Reset the 64 32-bit block to all zeros.
        schedule.assign(64, 0x00000000);
        blockData = 0;

        // According to FIP 180-2, we first need to prepare the
        // message schedule where the first 16 words are the
        // 512-bit message block.
        for (uint32 j = 0; j < 16; ++j)
        {
            // Initialize the data to be appended.
            append = 0x00000000;

            // The words are appended in little-endian format, i.e.
            // if the hardware is big-endian, we have to convert the
            // bytes to little-endian.
            for (uint32 m = 0; (m < 4) && !endOfStream; ++m)
            {
                // Check for EOF.
                if (file.peek() == -1)
                    endOfStream = true;

                else
                {
                    if (_littleEndian)
                        append |= ((uint32)file.get() << (24 - (m * 8)));
                    else
                        append |= ((uint32)file.get() <<       (m * 8) );

                    // Increment the number of message bytes.
                    ++blockData;
                }
            }

            schedule.at(j) = append;

        }  // End for-loop j [ 0, 15].

        if (endOfStream)
            _padLastBlock(schedule, blockData, filebits);

        // The remaining 48 words in the message schedule are computed
        // from the logical functions using the previous words in the
        // schedule for avalanching the later indices in the schedule.
        for (uint32 j = 16; j < 64; ++j)
        {
            schedule.at(j) =   _sig1(schedule.at(j -  2))
                                   + schedule.at(j -  7)
                             + _sig0(schedule.at(j - 15))
                                   + schedule.at(j - 16);

        }  // End for-loop j [16, 63].

        // The actual avalance effect is performed in this loop.
        for (uint32 j = 0; j < 64; ++j)
        {
            t1 = h + _Sigma1(e) + _Ch(e, f, g) + _K[j] + schedule.at(j);
            t2 = _Sigma0(a) + _Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }  // End for-loop j.

        // The i-th intermediate hash value.
        _hash.at(0) += a;
        _hash.at(1) += b;
        _hash.at(2) += c;
        _hash.at(3) += d;
        _hash.at(4) += e;
        _hash.at(5) += f;
        _hash.at(6) += g;
        _hash.at(7) += h;

    } // End for-loop i.

    // Reset the file flags and return to the file head.
    file.clear();
    file.seekg(0);  // Return to the head of the file.

    return asString();

}    // End method sha256compute (ifstream &file).

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
void SHA256::_initializeHash (void)
{
    _hash.at(0) = 0x6a09e667;
    _hash.at(1) = 0xbb67ae85;
    _hash.at(2) = 0x3c6ef372;
    _hash.at(3) = 0xa54ff53a;
    _hash.at(4) = 0x510e527f;
    _hash.at(5) = 0x9b05688c;
    _hash.at(6) = 0x1f83d9ab;
    _hash.at(7) = 0x5be0cd19;

    return;
}

/** Pad the message contents to meet FIPS 180-2.
 *
 *  @pre The object is instantiated.
 *  @post none.
 *  @param data The data that is to be hashed.
 *  @return A vector containing the padded data.
*/
vector < byte > SHA256::_padVector (const vector < byte > &data) const
{
    vector < byte > message = data;

    uint32 size = data.size();  // The size of the original data.

    // We need to append 9 bytes to the data and fill the extra padding
    // with zeros to get a 512-bit boundary.
    uint32 datasize = data.size() + 9;
    while ((datasize % 64) != 0) ++datasize;

    // The first padded bit is a '1' followed by zeros until we reach the
    // the final 64-bits of the message.
    message.push_back(0x80);
    for (uint32 i = (size + 1); i < datasize; ++i)
        message.push_back(0x00);

    // The final 64-bits (8-bytes) is the 64-bit representation of the
    // message size in bits presented as a little endian value.  For
    // simplicity, I'll only use a 32-bit value (assume the MSBs are 0x00).
    uint32 dataBits = size * 8;
    // message.at(datasize - 8) = 0x00;
    // message.at(datasize - 7) = 0x00;
    // message.at(datasize - 6) = 0x00;
    // message.at(datasize - 5) = 0x00;
    message.at(datasize - 4) = (byte)((dataBits & 0xff000000) >> 24);
    message.at(datasize - 3) = (byte)((dataBits & 0x00ff0000) >> 16);
    message.at(datasize - 2) = (byte)((dataBits & 0x0000ff00) >>  8);
    message.at(datasize - 1) = (byte)((dataBits & 0x000000ff)      );

    return message;
}

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
void SHA256::_padLastBlock (vector < uint32 > &lastBlock, uint32 dataInBlock,
                            uint32 bitsInFile) const
{
    // If there is no more data, we need to pad the block.
    // The first padded bit is a '1' followed by zeros until we reach the
    // the final 64-bits of the message.
    uint32 shift = (dataInBlock % 4);

    uint32 paddingWord = (dataInBlock / 4) % 16;

    uint32 append = lastBlock.at(paddingWord);

    if (_littleEndian)
        append |= (0x00000080 << (24 - (shift * 8)));
    else
        append |= (0x00000080 <<       (shift * 8) );

    lastBlock.at(paddingWord) = append;

    for (uint32 i = (paddingWord + 1); i < 16; ++i)
        lastBlock.at(i) = 0x00000000;

    // The final 64-bits (8-bytes) is the 64-bit representation of the
    // message size in bits presented as a big endian value.  For simplicity,
    // I'll only use a 32-bit value (assume the MSBs are 0x00).

    // lastBlock.at(14) = 0x00000000;  // 64-bit MSBs.
    lastBlock.at(15) = bitsInFile;

    return;
}

/** The first of 6 logical functions used by SHA-256.
 *
 *  @pre none.
 *  @post none.
 *  @param x The first 32-bit word in the function.
 *  @param y The second 32-bit word in the function.
 *  @param z The final 32-bit word in the function.
 *  @return A 32-bit word that is the result of the logical function.
*/
inline uint32 SHA256::_Ch (uint32 x, uint32 y, uint32 z) const
{  return ((x & y) ^ (~x & z));  }

/** The second of 6 logical functions used by SHA-256.
 *
 *  @pre none.
 *  @post none.
 *  @param x The first 32-bit word in the function.
 *  @param y The second 32-bit word in the function.
 *  @param z The final 32-bit word in the function.
 *  @return A 32-bit word that is the result of the logical function.
*/
inline uint32 SHA256::_Maj (uint32 x, uint32 y, uint32 z) const
{  return ((x & y) ^ (x & z) ^ (y & z));  }

/** The third of 6 logical functions used by SHA-256.
 *
 *  @pre none.
 *  @post none.
 *  @param x The value that is to be used in the shifts.
 *  @return A 32-bit word that is the result of the logical function.
*/
inline uint32 SHA256::_Sigma0 (uint32 x) const
{  return (_rcshift(x, 2) ^ _rcshift(x, 13) ^ _rcshift(x, 22));  }

/** The fourth of 6 logical functions used by SHA-256.
 *
 *  @pre none.
 *  @post none.
 *  @param x The value that is to be used in the shifts.
 *  @return A 32-bit word that is the result of the logical function.
*/
inline uint32 SHA256::_Sigma1 (uint32 x) const
{  return (_rcshift(x, 6) ^ _rcshift(x, 11) ^ _rcshift(x, 25));  }

/** The fifth of 6 logical functions used by SHA-256.
 *
 *  @pre none.
 *  @post none.
 *  @param x The value that is to be used in the shifts.
 *  @return A 32-bit word that is the result of the logical function.
*/
inline uint32 SHA256::_sig0 (uint32 x) const
{  return (_rcshift(x, 7) ^ _rcshift(x, 18) ^ (x >> 3));  }

/** The sixth of 6 logical functions used by SHA-256.
 *
 *  @pre none.
 *  @post none.
 *  @param x The value that is to be used in the shifts.
 *  @return A 32-bit word that is the result of the logical function.
*/
inline uint32 SHA256::_sig1 (uint32 x) const
{  return (_rcshift(x, 17) ^ _rcshift(x, 19) ^ (x >> 10));  }