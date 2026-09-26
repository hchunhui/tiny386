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
#if defined( CNFG_WAYLAND )
#include "wayland/CNFGWLDriver.c"
#endif

typedef struct {
	void (*UpdateScreenWithBitmap)( uint32_t * data, int w, int h );
	int (*HandleInput)();
	void (*ConfineMouse)( int confined );
	void (*SetCursor)( CNFGCursorShape shape );
} CNFGIntf;

CNFGIntf __CNFGIntf;

void CNFGUpdateScreenWithBitmap( uint32_t * data, int w, int h )
{
	__CNFGIntf.UpdateScreenWithBitmap(data, w, h);
}

int CNFGHandleInput()
{
	return __CNFGIntf.HandleInput();
}

void CNFGConfineMouse( int confined )
{
	__CNFGIntf.ConfineMouse(confined);
}

void CNFGSetCursor( CNFGCursorShape shape )
{
	__CNFGIntf.SetCursor(shape);
}

void CNFGUpdateScreenWithBitmap_dummy( uint32_t * data, int w, int h )
{
}

int CNFGHandleInput_dummy()
{
	return 1;
}

void CNFGConfineMouse_dummy( int confined )
{
}

void CNFGSetCursor_dummy( CNFGCursorShape shape )
{
}

int CNFGSetup( const char * WindowName, int w, int h )
{
	if (CNFGSetup_X(WindowName, w, h) == 0) {
		__CNFGIntf.UpdateScreenWithBitmap = CNFGUpdateScreenWithBitmap_X;
		__CNFGIntf.HandleInput = CNFGHandleInput_X;
		__CNFGIntf.ConfineMouse = CNFGConfineMouse_X;
		__CNFGIntf.SetCursor = CNFGSetCursor_X;
		return 0;
	}
#if defined( CNFG_WAYLAND )
	if (CNFGSetup_WL(WindowName, w, h) == 0) {
		__CNFGIntf.UpdateScreenWithBitmap = CNFGUpdateScreenWithBitmap_WL;
		__CNFGIntf.HandleInput = CNFGHandleInput_WL;
		__CNFGIntf.ConfineMouse = CNFGConfineMouse_WL;
		__CNFGIntf.SetCursor = CNFGSetCursor_WL;
		return 0;
	}
#endif
	fprintf( stderr, "Could not get an X/Wayland Display.\n%s",
		 "Are you in text mode or using SSH without X11-Forwarding?\n" );
	exit(1);
	__CNFGIntf.UpdateScreenWithBitmap = CNFGUpdateScreenWithBitmap_dummy;
	__CNFGIntf.HandleInput = CNFGHandleInput_dummy;
	__CNFGIntf.ConfineMouse = CNFGConfineMouse_dummy;
	__CNFGIntf.SetCursor = CNFGSetCursor_dummy;
	return 1;
}
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

