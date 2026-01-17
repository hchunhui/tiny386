//Include this file to get all of rawdraw.  You usually will not
//want to include this in your build, but instead, #include "CNFG.h"
//after #define CNFG_IMPLEMENTATION in one of your C files.

// Defined here for universal definition
int CNFGLastCharacter = 0;
int CNFGLastScancode = 0;

#if defined( CNFGHTTP )
#include "CNFGHTTP.c"
#elif defined( CNFG_WASM )
#include "CNFGWASMDriver.c"
#elif defined( CNFG_WINDOWS )
#include "CNFGWinDriver.c"
#elif defined( EGL_LEAN_AND_MEAN )
#include "CNFGEGLLeanAndMean.c"
#elif defined( CNFG_ANDROID )
#include "CNFGEGLDriver.c"
#else
#include "CNFGXDriver.c"
#endif

//#include "CNFGFunctions.c"
int CNFGPenX, CNFGPenY;
uint32_t CNFGBGColor;
uint32_t CNFGLastColor;

#ifdef CNFGOGL
#include "CNFGOGL.c"
#endif

#ifdef CNFGVK
#ifndef CNFGCONTEXTONLY
#include "CNFGVK.c"
#endif
#endif

#ifdef CNFG3D
#include "CNFG3D.c"
#endif

