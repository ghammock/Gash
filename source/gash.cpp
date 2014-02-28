/******************************************************************************
||  gash.cpp                                                                 ||
||===========================================================================||
||                                                                           ||
||    Author: Gary Hammock, PE                                               ||
||    Creation Date: 2008-09-17                                              ||
||    Last Edit Date: 2014-02-27                                             ||
||                                                                           ||
||===========================================================================||
||  DESCRIPTION                                                              ||
||===========================================================================||
||    Gash is a command-line, multiple hash algorithm file integrity         ||
||    checking program.                                                      ||
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

/** @file gash.cpp
 *  @author Gary Hammock, PE
 *  @date 2014-02-27
*/

#include "gash.h"

int main (int argc, char *argv[])
{
    ifstream file;  // A handle to the file to be hashed.
    string filename(argv[argc - 1]);
    stringstream arg;

    cout << "Gash version: " << _VERSION_ << endl;

    // If too few arguments were given, display the usage information.
    if (argc < 2)
    {
        displayHelp();
        return 0;
    }

    // Check to make sure that we can access the file specified by the caller.
    if (!getFileHandle(filename, file))
    {
        cerr << "Error: could not open file \"" << filename << "\"."
             << endl << endl;

        return 1;
    }

    // Echo the name of the file.
    cout << "File: " << filename << endl;

    // If no specific hash algoritm is given use MD5.
    if (argc == 2)
        cout << "MD5: " << MD5(file);
    else
    {
        arg << argv[1];

        if (arg.str() == "-sha256")
            cout << "SHA-256: " << SHA256(file);
        else if (arg.str() == "-md5")
            cout << "MD5: " << MD5(file);
        else
            displayHelp();
    }

    // Tidy up the console.
    cout << endl << endl;

    return 0;
}

bool getFileHandle (string filename, ifstream &file)
{
    // Open the named file in binary mode (this is important)!
    file.open(filename.c_str(), ios::in | ios::binary);

    if (!file.fail())
        return true;
    else
        return false;
}

void displayHelp (void)
{
    cout << "Usage:" << endl
         << "    gash <hashType> [filename]" << endl
         << "    gash <options>" << endl
         << endl
         << "Where <hashType> can be any of:" << endl
         << "    -md5 : MD5" << endl
         << "    -sha256 : SHA-256" << endl
         << "And <options> can include:" << endl
         << "    -c : credits" << endl
         << endl;

    return;
}