#ifndef KAINE_TEMPLATE_COMMON_H
#define KAINE_TEMPLATE_COMMON_H

#include "../../headers/Kaine.h"

//
// kaine module reasons
//
#define KAINE_MDL_REASON_ATTACH  0x0
#define KAINE_MDL_REASON_CONFIG  0x1
#define KAINE_MDL_REASON_MAIN    0x2
#define KAINE_MDL_REASON_ROUTINE 0x3
#define KAINE_MDL_REASON_DETACH  0x4

#define MDL_ENTRY EXTERN_C D_SEC( A )
#define U_32( x )          ( ( ULONG ) x )

typedef struct _UNGUARD_CFG {
    union {
        ULONG Value;
        struct {
            ULONG MovRax   : 1;
            ULONG Reserved : 31;
        };
    };
} CFG;

EXTERN_C UINT_PTR KnUnguardPtr(
    _In_ UINT_PTR Target,
    _In_ PVOID    Gadget
);

typedef PIMAGE_EXPORT_DIRECTORY PIMG_EXP_DIR;
typedef PIMAGE_NT_HEADERS       PIMG_NT_HDR;

__forceinline
SIZE_T KNAPI KnUtilStrLenA(
    _In_ PCSTR String
) {
    PCSTR String2;

    for ( String2 = String; *String2; ++String2 );

    return ( String2 - String );
}

#endif //KAINE_TEMPLATE_COMMON_H
