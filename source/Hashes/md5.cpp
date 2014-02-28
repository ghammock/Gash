/******************************************************************************
||  md5.cpp                                                                  ||
||===========================================================================||
||                                                                           ||
||    Author: Gary Hammock, PE                                               ||
||    Creation Date: 2008-09-17                                              ||
||    Last Edit Date: 2014-02-27                                             ||
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

/** @file md5.cpp
 *  @author Gary Hammock, PE
 *  @date 2014-02-27
*/

#include "md5.h"

/******************************************************
**            Constructors / Destructors             **
******************************************************/

/** Default constructor.  */
MD5::MD5 ()
    : MessageHash(128)
{}

/** Copy constructor.
 *
 *  @pre none.
 *  @post A new object is instantiated from the copied MD5 object.
 *  @param copyFrom The MD5 object whose values are to be copied.
*/
MD5::MD5 (const MD5 &copyFrom)
    : MessageHash(copyFrom)
{}

/** Initialize an MD5 object by hashing an input std::string.
 *
 *  @pre none.
 *  @post A new object is instantiated containing the
 *        hashed value of the input data.
 *  @param str The std::string that is to be hashed.
*/
MD5::MD5 (const string &str)
    : MessageHash(128)
{
    calculateHash(str);
}

/** Initialize an MD5 object by hashing an input data stream.
 *
 *  @pre none.
 *  @post A new object is instantiated containing the
 *        hashed value of the input data.
 *  @param data The data that is to be hashed.
*/
MD5::MD5 (const vector < byte > &data)
    : MessageHash(128)
{
    calculateHash(data);
}

/** Initialize an MD5 object by hashing an input file stream.
 *
 *  @pre none.
 *  @post A new object is instantiated containing the
 *        hashed value of the input data.
 *  @param file A handle to the file that is to be hashed.
*/
MD5::MD5 (ifstream &file)
    : MessageHash(128)
{
    calculateHash(file);
}

/** Default destructor.  */
MD5::~MD5 ()  { }

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
string MD5::calculateHash (const string &str)
{
    return calculateHash(vector < byte >(str.begin(), str.end()));
}

/** Calculate the MD5 value from an input data stream.
 *
 *  @pre The object is instantiated.
 *  @post The MD5 sum is stored in the _hash values.
 *  @param data The data that is to be hashed.
 *  @return The MD5 value as a std::string.
*/
string MD5::calculateHash (const vector < byte > &data)
{
    _initialize(128);

    vector < byte > message = _padVector(data);

    // The message must be processed in 512-bit (64-byte) chunks
    uint32 chunks = message.size() / 64;

    // We need to initialize the hash to the chaining variables.
    _initializeHash();

    // The 512-bit (16, 32-bit) message block.
    vector < uint32 > block;

    uint32 offset,  // A calculated offset into the data.
           append,  // A concatenation of 4 bytes into 1 32-bit word.
           A,       // The chaining variable associated with _hash[0].
           B,       // The chaining variable associated with _hash[1].
           C,       // The chaining variable associated with _hash[2].
           D;       // The chaining variable associated with _hash[3].

    for (uint32 i = 0; i < chunks; ++i)
    {
        // Initialize the four 32-bit chaining variables.
        A = _hash[0];
        B = _hash[1];
        C = _hash[2];
        D = _hash[3];

        // Reset the 16 32-bit block to all zeros.
        block.assign(16, 0x00000000);

        // We need to concatenate the message contents into 512-bit block.
        for (uint32 j = 0; j < 16; ++j)
        {
            // The current offset into the message data.
            offset = (i * 64) + (j * 4);

            // With MD5, the words are appended in big-endian format, i.e.
            // if the hardware is little-endian, we have to convert the
            // bytes to big-endian.
            if (_littleEndian)
            {
                append =   ((uint32)message.at(offset    )      )
                         | ((uint32)message.at(offset + 1) <<  8)
                         | ((uint32)message.at(offset + 2) << 16)
                         | ((uint32)message.at(offset + 3) << 24);
            }
            else
            {
                append =   ((uint32)message.at(offset    ) << 24)
                         | ((uint32)message.at(offset + 1) << 16)
                         | ((uint32)message.at(offset + 2) <<  8)
                         | ((uint32)message.at(offset + 3)      );
            }

            block.at(j) = append;

        }  // End for-loop j.

        // These are the four rounds per chunk that are performed to compute
        // the chaining variables which becomes the hash.
        _round1(block);
        _round2(block);
        _round3(block);
        _round4(block);

        // After the rounds are complete, the calculated sub hash values
        // are added to the chaining variables.  The final output is
        // this concatenation.
        _hash[0] += A;
        _hash[1] += B;
        _hash[2] += C;
        _hash[3] += D;

    }  // End for-loop i.

    // We need to flip the byte order if the system is little endian.
    if (_littleEndian)
        _convertToLittleEndian();

    return asString();
}  // End method md5compute (const vector < byte > data).

/** Calculate the MD5 value of a file.
 *
 *  @pre The object is instantiated.
 *  @post The MD5 sum is stored in the _hash values.
 *  @param file The file whose MD5 is to be calculated.
 *  @return The MD5 value as a std::string.
*/
string MD5::calculateHash (ifstream &file)
{
    _initialize(128);

    // Check that the file is valid before doing anything else.
    // This will return an MD5 value of all zeros.
    if (file.fail() || !file.good())
        return "00000000000000000000000000000000";

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

    // The 512-bit (16, 32-bit) message block.
    vector < uint32 > block;

    uint32 append,     // A concatenation of 4 bytes into 1 32-bit word.
           A,          // The chaining variable associated with _hash[0].
           B,          // The chaining variable associated with _hash[1].
           C,          // The chaining variable associated with _hash[2].
           D,          // The chaining variable associated with _hash[3].
           blockData;  // The number of message bytes in each block.

    bool endOfStream = false;

    // We need to initialize the hash to the chaining variables.
    _initializeHash();

    for (uint32 i = 0; i < chunks; ++i)
    {
        // Initialize the four 32-bit chaining variables.
        A = _hash[0];
        B = _hash[1];
        C = _hash[2];
        D = _hash[3];

        // Reset the 16 32-bit block to all zeros.
        block.assign(16, 0x00000000);
        blockData = 0;

        // We need to concatenate the message contents into 512-bit block.
        for (uint32 j = 0; (j < 16) && !endOfStream; ++j)
        {
            // Initialize the data to be appended.
            append = 0x00000000;

            // With MD5, the words are appended in big-endian format, i.e.
            // if the hardware is little-endian, we have to convert the
            // bytes to big-endian.
            for (uint32 m = 0; (m < 4) && !endOfStream; ++m)
            {
                // Check for EOF.
                if (file.peek() == -1)
                    endOfStream = true;

                else
                {
                    if (_littleEndian)
                        append |= ((uint32)file.get() << (m * 8));
                    else
                        append |= ((uint32)file.get() << (24 - (m * 8)));

                    // Increment the number of message bytes.
                    ++blockData;
                }
            }

            block.at(j) = append;

        }  // End for-loop j.

        if (endOfStream)
            _padLastBlock(block, blockData, filebits);

        // These are the four rounds per chunk that are performed to compute
        // the chaining variables which becomes the hash.
        _round1(block);
        _round2(block);
        _round3(block);
        _round4(block);

        // After the rounds are complete, the calculated sub hash values
        // are added to the chaining variables.  The final output is
        // this concatenation.
        _hash[0] += A;
        _hash[1] += B;
        _hash[2] += C;
        _hash[3] += D;

    }  // End for-loop i.

    // We need to flip the byte order if the system is little endian.
    if (_littleEndian)
        _convertToLittleEndian();

    // Reset the file flags and return to the file head.
    file.clear();
    file.seekg(0);  // Return to the head of the file.

    return asString();

}  // End method md5compute (ifstream &file).

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
void MD5::_initializeHash (void)
{
    // MD5 uses a big-endian format.  So if the hardware is little-endian,
    //    we have to initialize the chaining variables accordingly
    if (_littleEndian)
    {
        _hash[0] = 0x67452301;
        _hash[1] = 0xefcdab89;
        _hash[2] = 0x98badcfe;
        _hash[3] = 0x10325476;
    }

    else  // Big Endian.
    {
        _hash[0] = 0x01234567;
        _hash[1] = 0x89abcdef;
        _hash[2] = 0xfedcba98;
        _hash[3] = 0x76543210;
    }

    return;
}

/** Pad the message contents to meet RFC1321.
 *
 *  @pre The object is instantiated.
 *  @post none.
 *  @param data The data that is to be hashed.
 *  @return A vector containing the padded data.
*/
vector < byte > MD5::_padVector (const vector < byte > &data) const
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
    // message size in bits presented as a big endian value.  For simplicity,
    // I'll only use a 32-bit value (assume the MSBs are 0x00).
    uint32 dataBits = size * 8;
    // message.at(datasize - 1) = 0x00;
    // message.at(datasize - 2) = 0x00;
    // message.at(datasize - 3) = 0x00;
    // message.at(datasize - 4) = 0x00;
    message.at(datasize - 5) = (byte)((dataBits & 0xff000000) >> 24);
    message.at(datasize - 6) = (byte)((dataBits & 0x00ff0000) >> 16);
    message.at(datasize - 7) = (byte)((dataBits & 0x0000ff00) >>  8);
    message.at(datasize - 8) = (byte)((dataBits & 0x000000ff)      );

    return message;
}

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
void MD5::_padLastBlock (vector < uint32 > &lastBlock, uint32 dataInBlock,
                         uint32 bitsInFile) const
{
    // If there is no more data, we need to pad the block.
    // The first padded bit is a '1' followed by zeros until we reach the
    // the final 64-bits of the message.
    uint32 shift = (dataInBlock % 4);

    uint32 paddingWord = (dataInBlock / 4) % 16;

    uint32 append = lastBlock.at(paddingWord);

    if (_littleEndian)
        append |= (0x00000080 << (shift * 8));
    else
        append |= (0x00000080 << (24 - (shift * 8)));

    lastBlock.at(paddingWord) = append;

    for (uint32 i = (paddingWord + 1); i < 16; ++i)
        lastBlock.at(i) = 0x00000000;

    // The final 64-bits (8-bytes) is the 64-bit representation of the
    // message size in bits presented as a big endian value.  For simplicity,
    // I'll only use a 32-bit value (assume the MSBs are 0x00).

    // lastBlock.at(15) = 0x00000000;  // 64-bit MSBs.
    lastBlock.at(14) = bitsInFile;

    return;
}

/** Convert the hash from big endian to little endian format.
 *
 *  @pre The object is instantiated.
 *  @post The values of _hash are rearranged to little endian format.
 *  @return none.
*/
void MD5::_convertToLittleEndian (void)
{
    // Flip the byte order of the 32-bit words.
    for (uint32 i = 0; i < 4; ++i)
    {
        _hash[i] =   ((_hash[i] & 0x000000ff) << 24)
                   + ((_hash[i] & 0x0000ff00) << 8)
                   + ((_hash[i] & 0x00ff0000) >> 8)
                   + ((_hash[i] & 0xff000000) >> 24);
    }

    return;
}

/** Avalanche effect, Round 1.
 *
 *  @pre The object is instantiated.
 *  @post The values of _hash are manipulated.
 *  @param b512 The 512-bit message block (16, 32-bit words).
 *  @return none.
*/
void MD5::_round1 (vector < uint32 > b512)
{
    ///////////////////////////////////////////////////////////////////////
    // There are four rounds per chunk that are performed to compute
    // the chaining variables per chunk.  The hexadecimal constants are
    // chosen because they are the integer part of
    //        t[i] = 2^32 * abs(sin(i)),  where i is in radians.

    // Round 1.
    _FF(_hash[0], _hash[1], _hash[2], _hash[3], b512.at( 0),  7, 0xd76aa478);
    _FF(_hash[3], _hash[0], _hash[1], _hash[2], b512.at( 1), 12, 0xe8c7b756);
    _FF(_hash[2], _hash[3], _hash[0], _hash[1], b512.at( 2), 17, 0x242070db);
    _FF(_hash[1], _hash[2], _hash[3], _hash[0], b512.at( 3), 22, 0xc1bdceee);
    _FF(_hash[0], _hash[1], _hash[2], _hash[3], b512.at( 4),  7, 0xf57c0faf);
    _FF(_hash[3], _hash[0], _hash[1], _hash[2], b512.at( 5), 12, 0x4787c62a);
    _FF(_hash[2], _hash[3], _hash[0], _hash[1], b512.at( 6), 17, 0xa8304613);
    _FF(_hash[1], _hash[2], _hash[3], _hash[0], b512.at( 7), 22, 0xfd469501);
    _FF(_hash[0], _hash[1], _hash[2], _hash[3], b512.at( 8),  7, 0x698098d8);
    _FF(_hash[3], _hash[0], _hash[1], _hash[2], b512.at( 9), 12, 0x8b44f7af);
    _FF(_hash[2], _hash[3], _hash[0], _hash[1], b512.at(10), 17, 0xffff5bb1);
    _FF(_hash[1], _hash[2], _hash[3], _hash[0], b512.at(11), 22, 0x895cd7be);
    _FF(_hash[0], _hash[1], _hash[2], _hash[3], b512.at(12),  7, 0x6b901122);
    _FF(_hash[3], _hash[0], _hash[1], _hash[2], b512.at(13), 12, 0xfd987193);
    _FF(_hash[2], _hash[3], _hash[0], _hash[1], b512.at(14), 17, 0xa679438e);
    _FF(_hash[1], _hash[2], _hash[3], _hash[0], b512.at(15), 22, 0x49b40821);

    return;
}

/** Avalanche effect, Round 2.
 *
 *  @pre The object is instantiated.
 *  @post The values of _hash are manipulated.
 *  @param b512 The 512-bit message block (16, 32-bit words).
 *  @return none.
*/
void MD5::_round2 (vector < uint32 > b512)
{
    ///////////////////////////////////////////////////////////////////////
    // There are four rounds per chunk that are performed to compute
    // the chaining variables per chunk.  The hexadecimal constants are
    // chosen because they are the integer part of
    //        t[i] = 2^32 * abs(sin(i)),  where i is in radians.

    // Round 2.
    _GG(_hash[0], _hash[1], _hash[2], _hash[3], b512.at( 1),  5, 0xf61e2562);
    _GG(_hash[3], _hash[0], _hash[1], _hash[2], b512.at( 6),  9, 0xc040b340);
    _GG(_hash[2], _hash[3], _hash[0], _hash[1], b512.at(11), 14, 0x265e5a51);
    _GG(_hash[1], _hash[2], _hash[3], _hash[0], b512.at( 0), 20, 0xe9b6c7aa);
    _GG(_hash[0], _hash[1], _hash[2], _hash[3], b512.at( 5),  5, 0xd62f105d);
    _GG(_hash[3], _hash[0], _hash[1], _hash[2], b512.at(10),  9, 0x02441453);
    _GG(_hash[2], _hash[3], _hash[0], _hash[1], b512.at(15), 14, 0xd8a1e681);
    _GG(_hash[1], _hash[2], _hash[3], _hash[0], b512.at( 4), 20, 0xe7d3fbc8);
    _GG(_hash[0], _hash[1], _hash[2], _hash[3], b512.at( 9),  5, 0x21e1cde6);
    _GG(_hash[3], _hash[0], _hash[1], _hash[2], b512.at(14),  9, 0xc33707d6);
    _GG(_hash[2], _hash[3], _hash[0], _hash[1], b512.at( 3), 14, 0xf4d50d87);
    _GG(_hash[1], _hash[2], _hash[3], _hash[0], b512.at( 8), 20, 0x455a14ed);
    _GG(_hash[0], _hash[1], _hash[2], _hash[3], b512.at(13),  5, 0xa9e3e905);
    _GG(_hash[3], _hash[0], _hash[1], _hash[2], b512.at( 2),  9, 0xfcefa3f8);
    _GG(_hash[2], _hash[3], _hash[0], _hash[1], b512.at( 7), 14, 0x676f02d9);
    _GG(_hash[1], _hash[2], _hash[3], _hash[0], b512.at(12), 20, 0x8d2a4c8a);

    return;
}

/** Avalanche effect, Round 3.
*
*  @pre The object is instantiated.
*  @post The values of _hash are manipulated.
*  @param b512 The 512-bit message block (16, 32-bit words).
*  @return none.
*/
void MD5::_round3 (vector < uint32 > b512)
{
    ///////////////////////////////////////////////////////////////////////
    // There are four rounds per chunk that are performed to compute
    // the chaining variables per chunk.  The hexadecimal constants are
    // chosen because they are the integer part of
    //        t[i] = 2^32 * abs(sin(i)),  where i is in radians.

    // Round 3.
    _HH(_hash[0], _hash[1], _hash[2], _hash[3], b512.at( 5),  4, 0xfffa3942);
    _HH(_hash[3], _hash[0], _hash[1], _hash[2], b512.at( 8), 11, 0x8771f681);
    _HH(_hash[2], _hash[3], _hash[0], _hash[1], b512.at(11), 16, 0x6d9d6122);
    _HH(_hash[1], _hash[2], _hash[3], _hash[0], b512.at(14), 23, 0xfde5380c);
    _HH(_hash[0], _hash[1], _hash[2], _hash[3], b512.at( 1),  4, 0xa4beea44);
    _HH(_hash[3], _hash[0], _hash[1], _hash[2], b512.at( 4), 11, 0x4bdecfa9);
    _HH(_hash[2], _hash[3], _hash[0], _hash[1], b512.at( 7), 16, 0xf6bb4b60);
    _HH(_hash[1], _hash[2], _hash[3], _hash[0], b512.at(10), 23, 0xbebfbc70);
    _HH(_hash[0], _hash[1], _hash[2], _hash[3], b512.at(13),  4, 0x289b7ec6);
    _HH(_hash[3], _hash[0], _hash[1], _hash[2], b512.at( 0), 11, 0xeaa127fa);
    _HH(_hash[2], _hash[3], _hash[0], _hash[1], b512.at( 3), 16, 0xd4ef3085);
    _HH(_hash[1], _hash[2], _hash[3], _hash[0], b512.at( 6), 23, 0x04881d05);
    _HH(_hash[0], _hash[1], _hash[2], _hash[3], b512.at( 9),  4, 0xd9d4d039);
    _HH(_hash[3], _hash[0], _hash[1], _hash[2], b512.at(12), 11, 0xe6db99e5);
    _HH(_hash[2], _hash[3], _hash[0], _hash[1], b512.at(15), 16, 0x1fa27cf8);
    _HH(_hash[1], _hash[2], _hash[3], _hash[0], b512.at( 2), 23, 0xc4ac5665);

    return;
}

/** Avalanche effect, Round 4.
*
*  @pre The object is instantiated.
*  @post The values of _hash are manipulated.
*  @param b512 The 512-bit message block (16, 32-bit words).
*  @return none.
*/
void MD5::_round4 (vector < uint32 > b512)
{
    ///////////////////////////////////////////////////////////////////////
    // There are four rounds per chunk that are performed to compute
    // the chaining variables per chunk.  The hexadecimal constants are
    // chosen because they are the integer part of
    //        t[i] = 2^32 * abs(sin(i)),  where i is in radians.

    // Round 4.
    _II(_hash[0], _hash[1], _hash[2], _hash[3], b512.at( 0),  6, 0xf4292244);
    _II(_hash[3], _hash[0], _hash[1], _hash[2], b512.at( 7), 10, 0x432aff97);
    _II(_hash[2], _hash[3], _hash[0], _hash[1], b512.at(14), 15, 0xab9423a7);
    _II(_hash[1], _hash[2], _hash[3], _hash[0], b512.at( 5), 21, 0xfc93a039);
    _II(_hash[0], _hash[1], _hash[2], _hash[3], b512.at(12),  6, 0x655b59c3);
    _II(_hash[3], _hash[0], _hash[1], _hash[2], b512.at( 3), 10, 0x8f0ccc92);
    _II(_hash[2], _hash[3], _hash[0], _hash[1], b512.at(10), 15, 0xffeff47d);
    _II(_hash[1], _hash[2], _hash[3], _hash[0], b512.at( 1), 21, 0x85845dd1);
    _II(_hash[0], _hash[1], _hash[2], _hash[3], b512.at( 8),  6, 0x6fa87e4f);
    _II(_hash[3], _hash[0], _hash[1], _hash[2], b512.at(15), 10, 0xfe2ce6e0);
    _II(_hash[2], _hash[3], _hash[0], _hash[1], b512.at( 6), 15, 0xa3014314);
    _II(_hash[1], _hash[2], _hash[3], _hash[0], b512.at(13), 21, 0x4e0811a1);
    _II(_hash[0], _hash[1], _hash[2], _hash[3], b512.at( 4),  6, 0xf7537e82);
    _II(_hash[3], _hash[0], _hash[1], _hash[2], b512.at(11), 10, 0xbd3af235);
    _II(_hash[2], _hash[3], _hash[0], _hash[1], b512.at( 2), 15, 0x2ad7d2bb);
    _II(_hash[1], _hash[2], _hash[3], _hash[0], b512.at( 9), 21, 0xeb86d391);

    return;
}

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
void MD5::_FF (uint32 &a, uint32 b, uint32 c, uint32 d,
               uint32 Mi, uint32 s, uint32 t)
{
    // This is the non-linear function used in Round 1.
    uint32 F_func = (b & c) | ((~b) & d);

    a = (b + _lcshift((a + F_func + Mi + t), s));

    return;
}

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
void MD5::_GG (uint32 &a, uint32 b, uint32 c, uint32 d,
               uint32 Mi, uint32 s, uint32 t)
{
    // This is the non-linear function used in Round 2.
    uint32 G_func = (b & d) | (c & (~d));

    a = (b + _lcshift((a + G_func + Mi + t), s));

    return;
}

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
void MD5::_HH (uint32 &a, uint32 b, uint32 c, uint32 d,
               uint32 Mi, uint32 s, uint32 t)
{
    // This is the non-linear function used in Round 3.
    uint32 H_func = b ^ c ^ d;

    a = (b + _lcshift((a + H_func + Mi + t), s));

    return;
}

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
void MD5::_II (uint32 &a, uint32 b, uint32 c, uint32 d,
               uint32 Mi, uint32 s, uint32 t)
{
    // This is the non-linear function used in Round 4.
    uint32 I_func = c ^ (b | (~d));

    a = (b + _lcshift((a + I_func + Mi + t), s));

    return;
}