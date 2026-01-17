// Copyright 2010-2021 <>< CNLohr, et. al. (Several other authors, many but not all mentioned)
//	Licensed under the MIT/x11 or NewBSD License you choose.
//
//	CN Foundational Graphics Main Header File.  This is the main header you
//	should include.  See README.md for more details.


#ifndef _CNFG_H
#define _CNFG_H

#ifdef __cplusplus
extern "C" {
#endif

/* Rawdraw flags:
	CNFG3D -> Enable the weird 3D functionality that rawdraw has to allow you to
		write apps which emit basic rawdraw primitives but look 3D!
		CNFG_USE_DOUBLE_FUNCTIONS -> Use double-precision floating point for CNFG3D.
	CNFGOGL -> Use an OpenGL Backend for all rawdraw functionality.
		->Caveat->If using CNFG_HAS_XSHAPE, then, we do something realy wacky.
	CNFGVK -> Use the experimental Vulkan backend
		CNFGVK_VALIDATION_LAYERS -> Enable the validation layers of the batched renderer
		CNFGVK_IMAGE_ALLOCATION -> Specify the amount of VRAM allocated towards images in the batched renderer
	CNFGRASTERIZER -> Software-rasterize the rawdraw calls, and, use
		CNFGUpdateScreenWithBitmap to send video to webpage.
	CNFGCONTEXTONLY -> Don't add any drawing functions, only opening a window to
		get an OpenGL context.

    CNFG_IMPLEMENTATION -> #define this and it will make _this_ the file where the cnfg
		functions actually live.
		
Usually tested combinations:
 * TCC On Windows and X11 (Linux) with:
    - CNFGOGL on or CNFGOGL off.  If CNFGOGL is off you can use
			CNFG_WINDOWS_DISABLE_BATCH to disable all batching.
		-or-
	- CNFGRASTERIZER

	NOTE: Sometimes you can also use CNFGOGL + CNFGRASTERIZER

 * WASM driver supports both: CNFGRASTERIZER and without CNFGRASTERIZER (Recommended turn rasterizer off)
 * ANDROID (But this automatically sets CNFGRASTERIZER OFF and CNFGOGL ON)

 Unusual compiler flags:

 * CNFGHTTP - Enable the HTTP server-version of rawdraw, where it renders to a website.
 * CNFGHTTPSERVERONLY - if you want to use the HTTP server w/o rawdraw.  You will need to implement:
	- CloseEvent, HTTPCustomCallback, HTTPCustomStart, NewWebSocket, WebSocketData, WebSocketTick
 * CNFG_DISABLE_HTTP_FILES - disable the HTTP file server.

*/


#include <stdint.h>

//Some per-platform logic.
#if defined( WINDOWS ) || defined( WIN32 ) || defined( WIN64 ) || defined( _WIN32 ) || defined( _WIN64 ) || defined( __CYGWIN__ )
	#define CNFG_WINDOWS
#elif defined( __wasm__ )
	#define CNFG_WASM
#elif defined( ANDROID ) || defined( __android__ )
	#define CNFG_ANDROID
	#define CNFGOGL
#else
	#define CNFG_X11
#endif

#if ( defined( CNFGOGL ) || defined( CNFG_WASM ) ) && !defined(CNFG_HAS_XSHAPE)

	#define CNFG_BATCH 8192 //131,072 bytes.

	#if defined( CNFG_ANDROID ) || defined( CNFG_WASM ) || defined( EGL_LEAN_AND_MEAN )
		#define CNFGEWGL //EGL or WebGL
	#else
		#define CNFGDESKTOPGL
	#endif
#endif

#ifdef CNFGVK
	#define CNFG_BATCH 8192
	
	#include <vulkan/vulkan.h>
	
	// The drivers define the CNFG_SURFACE_EXTENSION macro for their required extensions
	VkResult CNFGCreateVkSurface( VkInstance inst, const VkAllocationCallbacks* alloc, VkSurfaceKHR* surface );
#endif

typedef struct {
    short x, y; 
} RDPoint; 

extern int CNFGPenX, CNFGPenY;
extern uint32_t CNFGBGColor;
extern uint32_t CNFGLastColor;
extern uint32_t CNFGDialogColor; //Only used for DrawBox

//Draws text at CNFGPenX, CNFGPenY, with scale of `scale`.
void CNFGDrawText( const char * text, short scale );

//Determine how large a given test would be to draw.
void CNFGGetTextExtents( const char * text, int * w, int * h, int textsize  );

//Draws a box, outline as whatever the last CNFGColor was set to but also draws
//a rectangle as a background as whatever CNFGDialogColor is set to.
void CNFGDrawBox( short x1, short y1, short x2, short y2 );

//To be provided by driver. Rawdraw uses colors in the format 0xRRGGBBAA
//Note that some backends do not support alpha of any kind.
//Some platforms also support alpha blending.  So, be sure to set alpha to 0xFF
uint32_t CNFGColor( uint32_t RGBA );

//This both updates the screen, and flips, all as a single operation.
void CNFGUpdateScreenWithBitmap( uint32_t * data, int w, int h );


//This is only supported on a FEW architectures, but allows arbitrary
//image blitting.  Note that the alpha channel behavior is different
//on different systems.
void CNFGBlitImage( uint32_t * data, int x, int y, int w, int h );

// Only supported with CNFGOGL
#ifdef CNFGOGL
void CNFGDeleteTex( unsigned int tex );
unsigned int CNFGTexImage( uint32_t *data, int w, int h );
void CNFGBlitTex( unsigned int tex, int x, int y, int w, int h );
#endif

#if defined( CNFGOGL ) || defined( CNFGVK )
void CNFGSetVSync( int vson ); // Not supported on all systems
void CNFGSetScissors( int * xywh );
void CNFGGetScissors( int * xywh );
#endif

void CNFGTackPixel( short x1, short y1 );
void CNFGTackSegment( short x1, short y1, short x2, short y2 );
void CNFGTackRectangle( short x1, short y1, short x2, short y2 );
void CNFGTackPoly( RDPoint * points, int verts );
void CNFGClearFrame();
void CNFGSwapBuffers();

void CNFGGetDimensions( short * x, short * y );


//This will setup a window.  Note that w and h have special meaning. On Windows
//and X11, for instance if you set w and h to be negative, then rawdraw will not
//show the window to the user.  This is useful if you just need it for some
//off-screen-rendering purpose.
//
//Return value of 0 indicates success.  Nonzero indicates error.
int CNFGSetup( const char * WindowName, int w, int h ); 

void CNFGSetupFullscreen( const char * WindowName, int screen_number );
int CNFGHandleInput();


//You must provide:
void HandleKey( int keycode, int bDown );
void HandleButton( int x, int y, int button, int bDown );
void HandleButtonRel( int x, int y, int button, int bDown );
void HandleMotion( int x, int y, int mask );
void HandleMotionRel( int x, int y, int mask );
int HandleDestroy(); // Return nonzero if you want to cancel destroy.
#ifdef ANDROID_WANT_WINDOW_TERMINATION
void HandleWindowTermination();
#endif

// Guaranteed to be for the current key inside HandleKey for drivers that support it
// If drivers don't support it, it is 0
extern int CNFGLastCharacter;
extern int CNFGLastScancode;

//Internal function for resizing rasterizer for rasterizer-mode.
void CNFGInternalResize( short x, short y ); //don't call this.

//Not available on all systems.  Use The OGL portion with care.
#ifdef CNFGOGL
void * CNFGGetExtension( const char * extname );
#endif

//Also not available on all systems.  Transparency.
void	CNFGPrepareForTransparency();
void	CNFGDrawToTransparencyMode( int transp );
void	CNFGClearTransparencyLevel();

//Only available on systems that support it.
void	CNFGSetLineWidth( short width );
void	CNFGChangeWindowTitle( const char * windowtitle );
void	CNFGSetWindowIconData( int w, int h, uint32_t * data );
int 	CNFGSetupWMClass( const char * WindowName, int w, int h , char * wm_res_name_ , char * wm_res_class_ );

// Mouse related functions on systems that support it.

// enum just in case we want more cursor shapes
typedef enum {
	CNFG_CURSOR_HIDDEN, CNFG_CURSOR_ARROW, CNFG_CURSOR_LAST
} CNFGCursorShape;

// This may put a motion event into the queue, which will call HandleMotion
void CNFGSetMousePosition( int x, int y );

void CNFGConfineMouse( int confined );
void CNFGSetCursor( CNFGCursorShape shape );


//If you're using a batching renderer, for instance on Android or an OpenGL
//You will need to call this function inbetewen swtiching properties of drawing.  This is usually
//only needed if you calling OpenGL / OGLES functions directly and outside of CNFG.
//
//Note that these are the functions that are used on the backends which support this
//sort of thing.
#ifdef CNFG_BATCH

//If you are not using the CNFGOGL driver, you will need to define these in your driver.
void	CNFGEmitBackendTriangles( const float * vertices, const uint32_t * colors, int num_vertices );
void	CNFGBlitImage( uint32_t * data, int x, int y, int w, int h );

//These need to be defined for the specific driver.  
void 	CNFGClearFrame();
void 	CNFGSwapBuffers();

void 	CNFGFlushRender(); //Emit any geometry (lines, squares, polys) which are slated to be rendered.
void	CNFGInternalResize( short x, short y ); //Driver calls this after resize happens.
void	CNFGSetupBatchInternal(); //Driver calls this after setup is complete.

//Useful function for emitting a non-axis-aligned quad.
void 	CNFGEmitQuad( float cx0, float cy0, float cx1, float cy1, float cx2, float cy2, float cx3, float cy3 );

extern int 	CNFGVertPlace;
extern float CNFGVertDataV[CNFG_BATCH*3];
extern uint32_t CNFGVertDataC[CNFG_BATCH];
#endif

#define CNFG_KEY_FOCUS 0xf000

#ifdef CNFG_WINDOWS

#define CNFG_KEY_BACKSPACE 0x08
#define CNFG_KEY_TAB 0x09
#define CNFG_KEY_CLEAR 0x0C
#define CNFG_KEY_ENTER 0x0D
#define CNFG_KEY_SHIFT 0x10
#define CNFG_KEY_CTRL 0x11
#define CNFG_KEY_ALT 0x12
#define CNFG_KEY_PAUSE 0x13
#define CNFG_KEY_CAPS_LOCK 0x14
#define CNFG_KEY_ESCAPE 0x1B
#define CNFG_KEY_SPACE 0x20
#define CNFG_KEY_PAGE_UP 0x21
#define CNFG_KEY_PAGE_DOWN 0x22
#define CNFG_KEY_END 0x23
#define CNFG_KEY_HOME 0x24
#define CNFG_KEY_LEFT_ARROW 0x25
#define CNFG_KEY_TOP_ARROW 0x26
#define CNFG_KEY_RIGHT_ARROW 0x27
#define CNFG_KEY_BOTTOM_ARROW 0x28
#define CNFG_KEY_SELECT 0x29
#define CNFG_KEY_PRINT 0x2A
#define CNFG_KEY_EXECUTE 0x2B
#define CNFG_KEY_PRINT_SCREEN 0x2C
#define CNFG_KEY_INSERT 0x2D
#define CNFG_KEY_DELETE 0x2E
#define CNFG_KEY_HELP 0x2F
#define CNFG_KEY_LEFT_SUPER 0x5B
#define CNFG_KEY_RIGHT_SUPER 0x5C
#define CNFG_KEY_NUM_0 0x60
#define CNFG_KEY_NUM_1 0x61
#define CNFG_KEY_NUM_2 0x62
#define CNFG_KEY_NUM_3 0x63
#define CNFG_KEY_NUM_4 0x64
#define CNFG_KEY_NUM_5 0x65
#define CNFG_KEY_NUM_6 0x66
#define CNFG_KEY_NUM_7 0x67
#define CNFG_KEY_NUM_8 0x68
#define CNFG_KEY_NUM_9 0x69
#define CNFG_KEY_NUM_MULTIPLY 0x6A
#define CNFG_KEY_NUM_ADD 0x6B
#define CNFG_KEY_NUM_SEPARATOR 0x6C
#define CNFG_KEY_NUM_SUBTRACT 0x6D
#define CNFG_KEY_NUM_DECIMAL 0x6E
#define CNFG_KEY_NUM_DIVIDE 0x6F
#define CNFG_KEY_F1 0x70
#define CNFG_KEY_F2 0x71
#define CNFG_KEY_F3 0x72
#define CNFG_KEY_F4 0x73
#define CNFG_KEY_F5 0x74
#define CNFG_KEY_F6 0x75
#define CNFG_KEY_F7 0x76
#define CNFG_KEY_F8 0x77
#define CNFG_KEY_F9 0x78
#define CNFG_KEY_F10 0x79
#define CNFG_KEY_F11 0x7A
#define CNFG_KEY_F12 0x7B
#define CNFG_KEY_F13 0x7C
#define CNFG_KEY_F14 0x7D
#define CNFG_KEY_F15 0x7E
#define CNFG_KEY_F16 0x7F
#define CNFG_KEY_F17 0x80
#define CNFG_KEY_F18 0x81
#define CNFG_KEY_F19 0x82
#define CNFG_KEY_F20 0x83
#define CNFG_KEY_F21 0x84
#define CNFG_KEY_F22 0x85
#define CNFG_KEY_F23 0x86
#define CNFG_KEY_F24 0x87
#define CNFG_KEY_NUM_LOCK 0x90
#define CNFG_KEY_SCROLL_LOCK 0x91
#define CNFG_KEY_LEFT_SHIFT 0xA0
#define CNFG_KEY_RIGHT_SHIFT 0xA1
#define CNFG_KEY_LEFT_CONTROL 0xA2
#define CNFG_KEY_RIGHT_CONTROL 0xA3
#define CNFG_KEY_LEFT_ALT 0xA4
#define CNFG_KEY_RIGHT_ALT 0xA5

#elif defined( EGL_LEAN_AND_MEAN ) // doesn't have any keys
#elif defined( CNFG_ANDROID )      // ^
#elif defined( CNFG_WASM )

#define CNFG_KEY_BACKSPACE 8
#define CNFG_KEY_TAB 9
#define CNFG_KEY_CLEAR 12
#define CNFG_KEY_ENTER 13
#define CNFG_KEY_SHIFT 16
#define CNFG_KEY_CTRL 17
#define CNFG_KEY_ALT 18
#define CNFG_KEY_PAUSE 19
#define CNFG_KEY_CAPS_LOCK 20
#define CNFG_KEY_ESCAPE 27
#define CNFG_KEY_SPACE 32
#define CNFG_KEY_PAGE_UP 33
#define CNFG_KEY_PAGE_DOWN 34
#define CNFG_KEY_END 35
#define CNFG_KEY_HOME 36
#define CNFG_KEY_LEFT_ARROW 37
#define CNFG_KEY_TOP_ARROW 38
#define CNFG_KEY_RIGHT_ARROW 39
#define CNFG_KEY_BOTTOM_ARROW 40
#define CNFG_KEY_SELECT 41
#define CNFG_KEY_PRINT 42
#define CNFG_KEY_EXECUTE 43
#define CNFG_KEY_PRINT_SCREEN 44
#define CNFG_KEY_INSERT 45
#define CNFG_KEY_DELETE 46
#define CNFG_KEY_HELP 47
#define CNFG_KEY_LEFT_SUPER 91
#define CNFG_KEY_RIGHT_SUPER 92
#define CNFG_KEY_NUM_0 96
#define CNFG_KEY_NUM_1 97
#define CNFG_KEY_NUM_2 98
#define CNFG_KEY_NUM_3 99
#define CNFG_KEY_NUM_4 100
#define CNFG_KEY_NUM_5 101
#define CNFG_KEY_NUM_6 102
#define CNFG_KEY_NUM_7 103
#define CNFG_KEY_NUM_8 104
#define CNFG_KEY_NUM_9 105
#define CNFG_KEY_NUM_MULTIPLY 106
#define CNFG_KEY_NUM_ADD 107
#define CNFG_KEY_NUM_SEPARATOR 108
#define CNFG_KEY_NUM_SUBTRACT 109
#define CNFG_KEY_NUM_DECIMAL 110
#define CNFG_KEY_NUM_DIVIDE 111
#define CNFG_KEY_F1 112
#define CNFG_KEY_F2 113
#define CNFG_KEY_F3 114
#define CNFG_KEY_F4 115
#define CNFG_KEY_F5 116
#define CNFG_KEY_F6 117
#define CNFG_KEY_F7 118
#define CNFG_KEY_F8 119
#define CNFG_KEY_F9 120
#define CNFG_KEY_F10 121
#define CNFG_KEY_F11 122
#define CNFG_KEY_F12 123
#define CNFG_KEY_F13 124
#define CNFG_KEY_F14 125
#define CNFG_KEY_F15 126
#define CNFG_KEY_F16 127
#define CNFG_KEY_F17 128
#define CNFG_KEY_F18 129
#define CNFG_KEY_F19 130
#define CNFG_KEY_F20 131
#define CNFG_KEY_F21 132
#define CNFG_KEY_F22 133
#define CNFG_KEY_F23 134
#define CNFG_KEY_F24 135
#define CNFG_KEY_NUM_LOCK 144
#define CNFG_KEY_SCROLL_LOCK 145
#define CNFG_KEY_LEFT_SHIFT 160
#define CNFG_KEY_RIGHT_SHIFT 161
#define CNFG_KEY_LEFT_CONTROL 162
#define CNFG_KEY_RIGHT_CONTROL 163
#define CNFG_KEY_LEFT_ALT 164
#define CNFG_KEY_RIGHT_ALT 165

#else // most likely x11

#define CNFG_KEY_BACKSPACE 65288
#define CNFG_KEY_TAB 65289
#define CNFG_KEY_CLEAR 65291
#define CNFG_KEY_ENTER 65293
#define CNFG_KEY_SHIFT 65505
#define CNFG_KEY_CTRL 65507
#define CNFG_KEY_ALT 65513
#define CNFG_KEY_PAUSE 65299
#define CNFG_KEY_CAPS_LOCK 65509
#define CNFG_KEY_ESCAPE 65307
#define CNFG_KEY_SPACE 32
#define CNFG_KEY_PAGE_UP 65365
#define CNFG_KEY_PAGE_DOWN 65366
#define CNFG_KEY_END 65367
#define CNFG_KEY_HOME 65360
#define CNFG_KEY_LEFT_ARROW 65361
#define CNFG_KEY_TOP_ARROW 65362
#define CNFG_KEY_RIGHT_ARROW 65363
#define CNFG_KEY_BOTTOM_ARROW 65364
#define CNFG_KEY_SELECT 65376
#define CNFG_KEY_PRINT 65377
#define CNFG_KEY_EXECUTE 65378
#define CNFG_KEY_PRINT_SCREEN 64797
#define CNFG_KEY_INSERT 65379
#define CNFG_KEY_DELETE 65535
#define CNFG_KEY_HELP 65386
#define CNFG_KEY_LEFT_SUPER 65515
#define CNFG_KEY_RIGHT_SUPER 65516
#define CNFG_KEY_NUM_0 65456
#define CNFG_KEY_NUM_1 65457
#define CNFG_KEY_NUM_2 65458
#define CNFG_KEY_NUM_3 65459
#define CNFG_KEY_NUM_4 65460
#define CNFG_KEY_NUM_5 65461
#define CNFG_KEY_NUM_6 65462
#define CNFG_KEY_NUM_7 65463
#define CNFG_KEY_NUM_8 65464
#define CNFG_KEY_NUM_9 65465
#define CNFG_KEY_NUM_MULTIPLY 65450
#define CNFG_KEY_NUM_ADD 65451
#define CNFG_KEY_NUM_SEPARATOR 65452
#define CNFG_KEY_NUM_SUBTRACT 65453
#define CNFG_KEY_NUM_DECIMAL 65454
#define CNFG_KEY_NUM_DIVIDE 65455
#define CNFG_KEY_F1 65470
#define CNFG_KEY_F2 65471
#define CNFG_KEY_F3 65472
#define CNFG_KEY_F4 65473
#define CNFG_KEY_F5 65474
#define CNFG_KEY_F6 65475
#define CNFG_KEY_F7 65476
#define CNFG_KEY_F8 65477
#define CNFG_KEY_F9 65478
#define CNFG_KEY_F10 65479
#define CNFG_KEY_F11 65480
#define CNFG_KEY_F12 65481
#define CNFG_KEY_F13 65482
#define CNFG_KEY_F14 65483
#define CNFG_KEY_F15 65484
#define CNFG_KEY_F16 65485
#define CNFG_KEY_F17 65486
#define CNFG_KEY_F18 65487
#define CNFG_KEY_F19 65488
#define CNFG_KEY_F20 65489
#define CNFG_KEY_F21 65490
#define CNFG_KEY_F22 65491
#define CNFG_KEY_F23 65492
#define CNFG_KEY_F24 65493
#define CNFG_KEY_NUM_LOCK 65407
#define CNFG_KEY_SCROLL_LOCK 65300
#define CNFG_KEY_LEFT_SHIFT 65505
#define CNFG_KEY_RIGHT_SHIFT 65506
#define CNFG_KEY_LEFT_CONTROL 65507
#define CNFG_KEY_RIGHT_CONTROL 65508
#define CNFG_KEY_LEFT_ALT 65513
#define CNFG_KEY_RIGHT_ALT 65514

#define CNFG_X11_EXPOSE 0xff00 //65280

#endif

#ifdef CNFG3D

#ifndef CNFG_WASM
#include <math.h>
#endif

#ifdef CNFG_USE_DOUBLE_FUNCTIONS
#define tdCOS cos
#define tdSIN sin
#define tdTAN tan
#define tdSQRT sqrt
#else
#define tdCOS cosf
#define tdSIN sinf
#define tdTAN tanf
#define tdSQRT sqrtf
#endif

#ifdef CNFG_WASM
void tdMATCOPY( float * x, const float * y ); //Copy y into x
#else
#define tdMATCOPY(x,y) memcpy( x, y, 16*sizeof(float))
#endif

#define tdQ_PI 3.141592653589
#define tdDEGRAD (tdQ_PI/180.)
#define tdRADDEG (180./tdQ_PI)


//General Matrix Functions
void tdIdentity( float * f );
void tdZero( float * f );
void tdTranslate( float * f, float x, float y, float z );		//Operates ON f
void tdScale( float * f, float x, float y, float z );			//Operates ON f
void tdRotateAA( float * f, float angle, float x, float y, float z ); 	//Operates ON f
void tdRotateQuat( float * f, float qw, float qx, float qy, float qz ); 	//Operates ON f
void tdRotateEA( float * f, float x, float y, float z );		//Operates ON f
void tdMultiply( float * fin1, float * fin2, float * fout );		//Operates ON f
void tdPrint( const float * f );
void tdTransposeSelf( float * f );

//Specialty Matrix Functions
void tdPerspective( float fovy, float aspect, float zNear, float zFar, float * out ); //Sets, NOT OPERATES. (FOVX=degrees)
void tdLookAt( float * m, float * eye, float * at, float * up );	//Operates ON m
//General point functions
#define tdPSet( f, x, y, z ) { f[0] = x; f[1] = y; f[2] = z; }
void tdPTransform( const float * pin, float * f, float * pout );
void tdVTransform( const float * vin, float * f, float * vout );
void td4Transform( float * kin, float * f, float * kout );
void td4RTransform( float * kin, float * f, float * kout );
void tdNormalizeSelf( float * vin );
void tdCross( float * va, float * vb, float * vout );
float tdDistance( float * va, float * vb );
float tdDot( float * va, float * vb );
#define tdPSub( x, y, z ) { (z)[0] = (x)[0] - (y)[0]; (z)[1] = (x)[1] - (y)[1]; (z)[2] = (x)[2] - (y)[2]; }
#define tdPAdd( x, y, z ) { (z)[0] = (x)[0] + (y)[0]; (z)[1] = (x)[1] + (y)[1]; (z)[2] = (x)[2] + (y)[2]; }

//Stack Functionality
#define tdMATRIXMAXDEPTH 32
extern float * gSMatrix;
void tdPush();
void tdPop();
void tdMode( int mode );
#define tdMODELVIEW 0
#define tdPROJECTION 1

//Final stage tools
void tdSetViewport( float leftx, float topy, float rightx, float bottomy, float pixx, float pixy );
void tdFinalPoint( float * pin, float * pout );

float tdNoiseAt( int x, int y );
float tdFLerp( float a, float b, float t );
float tdPerlin2D( float x, float y );

#endif

extern const unsigned char RawdrawFontCharData[1405];
extern const unsigned short RawdrawFontCharMap[256];

#ifdef __cplusplus
};
#endif


#ifdef CNFG_ANDROID
#include "CNFGAndroid.h"
#endif

#ifdef CNFG_IMPLEMENTATION
#include "CNFG.c"
#endif

#endif
