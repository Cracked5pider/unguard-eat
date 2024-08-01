#define DEBUG

#include <Common.h>
#include <Constexpr.h>

D_SEC( A ) NTSTATUS Main(
    KnSelf,
    _In_ ULONG   Reason,
    _In_ PPARSER CfgParser
) {
    KnSymbolPointer();

    if ( Reason == KAINE_MDL_REASON_ATTACH )
    {
        //
        // just hook the export address table pointer resolving function
        //
        Self->Api.KnFunctionEat = G_PTR( KnFunctionEat );
    }
    else if ( Reason == KAINE_MDL_REASON_CONFIG )
    {
        //
        // nothing
        //
    }
    else if ( Reason == KAINE_MDL_REASON_MAIN )
    {
        //
        // nothing
        //
    }
    else if ( Reason == KAINE_MDL_REASON_ROUTINE )
    {
        //
        // nothing
        //
    }
    else if ( Reason == KAINE_MDL_REASON_DETACH )
    {
        //
        // nothing
        //
    }

    return STATUS_SUCCESS;
}

ULONG KNAPI KnDeobfuscate(
    _In_ ULONG Hash
) {
    return Hash ^ KnObf::KeyHashObf;
}

PVOID KNAPI MmGadgetFind(
    _In_ PVOID  Memory,
    _In_ SIZE_T Length,
    _In_ PVOID  PatternBuffer,
    _In_ SIZE_T PatternLength
) {
    //
    // check if required arguments have been specified
    //
    if ( ( ! Memory        || ! Length        ) ||
         ( ! PatternBuffer || ! PatternLength )
    ) {
        return NULL;
    }

    //
    // now search for gadgets/pattern
    //
    for ( SIZE_T Len = 0; Len < Length; Len++ ) {
        if ( memory::cmp( C_PTR( U_PTR( Memory ) + Len ), PatternBuffer, PatternLength ) == 0 ) {
            return C_PTR( U_PTR( Memory ) + Len );
        }
    }

    return NULL;
}

/*!
 * @brief
 *  resolve symbol by using either the name hash or string
 *  via gadgets to bypass PAGE_GUARD protected headers which
 *  check for the memory that is trying to read the nt header
 *
 * @param Library
 *  library base address
 *
 * @param Function
 *  function name hashed to resolve
 *
 * @return
 *  resolved symbol pointer
 */
PVOID KNAPI KnFunctionEat(
    KnSelf,
    _In_ PVOID Library,
    _In_ ULONG Function
) {
    PIMG_NT_HDR  NtHeader             = { 0 };
    PIMG_EXP_DIR ExpDir               = { 0 };
    DWORD        ExpDirSize           = { 0 };
    PDWORD       AddrNames            = { 0 };
    PDWORD       AddrFuncs            = { 0 };
    PWORD        AddrOrdns            = { 0 };
    ULONG        NameCount            = { 0 };
    DWORD        ForwOffs             = { 0 };
    DWORD        ForwSize             = { 0 };
    CHAR         ForwName[ MAX_PATH ] = { 0 };
    PVOID        ForwData[ 2 ]        = { 0 };
    PSTR         Name                 = { 0 };
    PVOID        Address              = { 0 };
    PVOID        Module               = { 0 };
    PVOID        Gadget               = { 0 };
    BYTE         Pattern[]            = { 0x48, 0x8B, 0x00, 0xC3 };
    volatile CFG Config               = { KAINE_TAG };

    if ( ! Library || ! Function ) {
        return NULL;
    }

    memory::zero( ForwName, sizeof( ForwName ) );

    //
    // search in the specified library a gadget that can be used
    //
    if ( Config.MovRax ) {
        //
        // find gadget inside ntdll
        //
        if ( ! ( Gadget = MmGadgetFind(
            C_PTR( U_PTR( Self->Api.KnLibraryHandle( KnObf::Int32( H_LIB_NTDLL ) ) ) + 0x1000 ),
            0x1000 * 0x1000,
            Pattern,
            sizeof( Pattern )
        ) ) ) {
            return NULL;
        }
    }

    //
    // parse the header export address table
    //
    NtHeader   = PIMG_NT_HDR ( U_PTR( Library  ) + U_32( KnUnguardPtr( U_PTR( Library ) + FIELD_OFFSET( IMAGE_DOS_HEADER, e_lfanew ), Gadget ) ) );
    ExpDir     = PIMG_EXP_DIR( U_PTR( Library  ) + U_32( KnUnguardPtr( U_PTR( NtHeader ) + FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader.DataDirectory ), Gadget ) ) );
    ExpDirSize = U_32( KnUnguardPtr( U_PTR( NtHeader ) + FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader.DataDirectory ) + sizeof( ULONG ), Gadget ) );

    //
    // resolve the function name and address arrays
    //
    AddrNames = PDWORD( U_PTR( Library ) + U_32( KnUnguardPtr( U_PTR( ExpDir ) + FIELD_OFFSET( IMAGE_EXPORT_DIRECTORY, AddressOfNames        ), Gadget ) ) );
    AddrFuncs = PDWORD( U_PTR( Library ) + U_32( KnUnguardPtr( U_PTR( ExpDir ) + FIELD_OFFSET( IMAGE_EXPORT_DIRECTORY, AddressOfFunctions    ), Gadget ) ) );
    AddrOrdns = PWORD ( U_PTR( Library ) + U_32( KnUnguardPtr( U_PTR( ExpDir ) + FIELD_OFFSET( IMAGE_EXPORT_DIRECTORY, AddressOfNameOrdinals ), Gadget ) ) );
    NameCount = ULONG ( U_PTR( Library ) + U_32( KnUnguardPtr( U_PTR( ExpDir ) + FIELD_OFFSET( IMAGE_EXPORT_DIRECTORY, NumberOfNames         ), Gadget ) ) );

    //
    // iterate over export address table director
    //
    for ( int i = 0; i < NameCount; i++ ) {
        //
        // retrieve function name
        //
        Name = PSTR( U_PTR( Library ) + AddrNames[ i ] );

        //
        // hash function name from Iat and
        // check the function name is what we are searching for.
        // if not found keep searching.
        //
        if ( Self->Api.KnHashString( Name, 0 ) != Function ) {
            continue;
        }

        //
        // resolve function pointer
        //
        Address = C_PTR( U_PTR( Library ) + AddrFuncs[ AddrOrdns[ i ] ] );

        //
        // check if function is a forwarded function
        //
        if ( ( U_PTR( Address ) >= U_PTR( ExpDir ) ) &&
             ( U_PTR( Address ) <  U_PTR( ExpDir ) + ExpDirSize )
        ) {
            //
            // get size of the forwarded function
            // string and back it up
            //
            ForwSize = KnUtilStrLenA( C_STR( Address ) );
            memory::copy( ForwName, Address, ForwSize );

            //
            // find the '.' in the 'module.function' forwarded function string */
            //
            for ( ForwOffs = 0; ForwOffs < ForwSize; ForwOffs++ ) {
                if ( ForwName[ ForwOffs ] == '.' ) {
                    break;
                }
            }

            //
            // split the forwarded function string into two strings
            //
            ForwName[ ForwOffs ] = 0;

            //
            // save module & function string
            //
            ForwData[ 0 ] = ForwName;
            ForwData[ 1 ] = ForwName + ForwOffs + 1;

            if ( ! NT_SUCCESS( Self->Api.KnLibraryLoad( Self, ForwData[ 0 ], &Module, KNLDR_LIB_FLAG_DLL | KNLDR_LIB_FLAG_ANSI ) ) ) {
                return 0;
            }

            //
            // call this function again to resolve the actual address
            //
            Address = KnFunctionEat( Self, Module, Self->Api.KnHashString( ForwData[ 1 ], 0 ) );
        }

        break;
    }

    memory::zero( ForwName, sizeof( ForwName ) );

    return Address;
}
