#ifndef LOADEOT_H
#define LOADEOT_H

using namespace std;
using std::vector;

// File size in MB
#define MAX_FILE            (1 * 1024 * 1024)

// If we don't define these, they get defined in windef.h (derived from windows.h). 
// We want to use std::min and std::max
#undef max
#define max max
#undef min
#define min min
#define DEFAULT_CHARSET 1

typedef unsigned char UChar;
typedef unsigned __int8 UInt8;
#ifndef _MSC_VER
# include <stdint.h>
#else
typedef unsigned char uint8_t;
#endif


#endif