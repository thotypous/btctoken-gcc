#ifndef TYPES_H
#define TYPES_H

#ifdef __MIKROC_PRO_FOR_ARM__
typedef unsigned char uint8_t;
typedef unsigned int uint16_t;
typedef unsigned long uint32_t;
typedef unsigned long long uint64_t;

typedef char int8_t;
typedef int int16_t;
typedef long int32_t;
typedef long long int64_t;
#else
#include <stdint.h>
#endif

#endif // TYPES_H
