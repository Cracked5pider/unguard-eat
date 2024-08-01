cmake_minimum_required( VERSION 3.27 )

set( CMAKE_CXX_STANDARD 11 )
set( CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++ )

set( CMAKE_C_STANDARD 11 )
set( CMAKE_C_COMPILER x86_64-w64-mingw32-gcc )

add_compile_definitions( KAINE_OBF_KEY_HASH=0 )

include_directories( include )
include_directories( ../../include )

file( GLOB SRC_FILES
    src/*.cc
)

add_library( ModuleUnguardEat ${SRC_FILES} )
