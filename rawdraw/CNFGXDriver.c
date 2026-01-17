//Copyright (c) 2011, 2017, 2018 <>< Charles Lohr - Under the MIT/x11 or NewBSD License you choose.
//portions from 
//http://www.xmission.com/~georgeps/documentation/tutorials/Xlib_Beginner.html

//#define HAS_XINERAMA
//#define CNFG_HAS_XSHAPE
//#define FULL_SCREEN_STEAL_FOCUS

#ifndef _CNFGXDRIVER_C
#define _CNFGXDRIVER_C

#include "CNFG.h"

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/Xos.h>
#include <X11/Xatom.h>
#include <X11/cursorfont.h>
#include <X11/keysym.h>

#include <stdio.h>
#include <stdlib.h>

#ifdef HAS_XINERAMA
	#include <X11/extensions/shape.h>
	#include <X11/extensions/Xinerama.h>
#endif
#ifdef CNFG_HAS_XSHAPE
	#include <X11/extensions/shape.h>
	static    XGCValues xsval;
	static    Pixmap xspixmap;
	static    GC xsgc;

	static	int taint_shape;
	static	int prepare_xshape;
	static int was_transp;

#endif

#ifdef CNFG_BATCH
void CNFGSetupBatchInternal();
#endif

XWindowAttributes CNFGWinAtt;
XClassHint *CNFGClassHint;
char * wm_res_name = 0;
char * wm_res_class = 0;
Display *CNFGDisplay;
Atom CFNGWMDeleteWindow;
Window CNFGWindow;
int CNFGWindowInvisible;
Pixmap CNFGPixmap;
GC     CNFGGC;
GC     CNFGWindowGC;
int CNFGDepth;
int CNFGScreen;
Visual * CNFGVisual;
VisualID CNFGVisualID;
int CNFGRelPos;

#ifdef CNFGOGL
#include <GL/glx.h>
#include <GL/glxext.h>

GLXContext CNFGCtx;
void * CNFGGetExtension( const char * extname ) { return (void*)glXGetProcAddressARB((const GLubyte *) extname); }
GLXFBConfig CNFGGLXFBConfig;
GLXFBConfig* CNFGGLXFBConfigs;


void CNFGGLXSetup( )
{
	int attribs[] = { 
		GLX_RENDER_TYPE, GLX_RGBA_BIT,
		GLX_DOUBLEBUFFER, True,
		GLX_RED_SIZE, 1,
		GLX_GREEN_SIZE, 1,
		GLX_BLUE_SIZE, 1,
		GLX_DEPTH_SIZE, 1,
		None };
	int elements = 0;
	GLXFBConfig * cfgs = glXChooseFBConfig(	CNFGDisplay, CNFGScreen, attribs, &elements );
	if( elements == 0 )
	{
		fprintf( stderr, "Error: could not get valid GLXFBConfig visual.\n" );
		exit( -1 );
	}
	CNFGGLXFBConfigs = cfgs;
	CNFGGLXFBConfig = cfgs[0];
	XVisualInfo * vis = glXGetVisualFromFBConfig( CNFGDisplay, CNFGGLXFBConfig );
	CNFGVisual = vis->visual;
	CNFGVisualID = vis->visualid;
	CNFGDepth = vis->depth;
	CNFGCtx = glXCreateContext( CNFGDisplay, vis, NULL, True );
	XFree( vis );
}

#endif

#ifdef CNFGVK
#include <vulkan/vulkan_xlib.h>
#define CNFG_SURFACE_EXTENSION "VK_KHR_xlib_surface", "VK_KHR_surface"
VkResult CNFGCreateVkSurface( VkInstance inst, const VkAllocationCallbacks* alloc, VkSurfaceKHR* surface )
{
	VkXlibSurfaceCreateInfoKHR sci = {
		.sType = VK_STRUCTURE_TYPE_XLIB_SURFACE_CREATE_INFO_KHR,
		.pNext = NULL, .dpy = CNFGDisplay, .window = CNFGWindow,
	};
	return vkCreateXlibSurfaceKHR( inst, &sci, alloc, surface );
}
#endif

int CNFGX11ForceNoDecoration;
XImage *xi;

XIM CNFGXIM = NULL;
XIC CNFGXIC = NULL;

int g_x_global_key_state;
int g_x_global_shift_key;

void 	CNFGSetWindowIconData( int w, int h, uint32_t * data )
{
	static Atom net_wm_icon;
	static Atom cardinal; 

	if( !net_wm_icon ) net_wm_icon = XInternAtom( CNFGDisplay, "_NET_WM_ICON", False );
	if( !cardinal ) cardinal = XInternAtom( CNFGDisplay, "CARDINAL", False );

	unsigned long outdata[w*h];
	int i;
	for( i = 0; i < w*h; i++ )
	{
		outdata[i+2] = data[i];
	}
	outdata[0] = w;
	outdata[1] = h;
	XChangeProperty(CNFGDisplay, CNFGWindow, net_wm_icon, cardinal,
		32, PropModeReplace, (const unsigned char*)outdata, 2 + w*h);
}


#ifdef CNFG_HAS_XSHAPE
void	CNFGPrepareForTransparency() { prepare_xshape = 1; }
void	CNFGDrawToTransparencyMode( int transp )
{
	static Pixmap BackupCNFGPixmap;
	static GC     BackupCNFGGC;
	if( was_transp && ! transp )
	{
		CNFGGC = BackupCNFGGC;
		CNFGPixmap = BackupCNFGPixmap;
	}
	if( !was_transp && transp )
	{
		BackupCNFGPixmap = CNFGPixmap;
		BackupCNFGGC = CNFGGC;
		taint_shape = 1;
		CNFGGC = xsgc;
		CNFGPixmap = xspixmap;
	}
	was_transp = transp;
}
void	CNFGClearTransparencyLevel()
{
	taint_shape = 1;
	XSetForeground(CNFGDisplay, xsgc, 0);
	XFillRectangle(CNFGDisplay, xspixmap, xsgc, 0, 0, CNFGWinAtt.width, CNFGWinAtt.height);
	XSetForeground(CNFGDisplay, xsgc, 1);
}
#endif

void CNFGSetMousePosition( int x, int y ) {
	XWarpPointer( CNFGDisplay, None, CNFGWindow, 0, 0, 0, 0, x, y );
}

void CNFGConfineMouse( int confined ) {
	if (confined) {
		XGrabPointer( CNFGDisplay, CNFGWindow, True, 0, GrabModeAsync, GrabModeAsync, CNFGWindow, None, CurrentTime );
		XGrabKeyboard( CNFGDisplay, CNFGWindow, True, GrabModeAsync, GrabModeAsync, CurrentTime );
		CNFGRelPos = 1;
	} else {
		XUngrabPointer( CNFGDisplay, CurrentTime );
		XUngrabKeyboard( CNFGDisplay, CurrentTime );
		CNFGRelPos = 0;
	}
}

Cursor CNFGCursors[CNFG_CURSOR_LAST] = { None };

void CNFGSetCursor( CNFGCursorShape shape ) {
	if (shape == CNFG_CURSOR_ARROW) XUndefineCursor( CNFGDisplay, CNFGWindow );
	else XDefineCursor( CNFGDisplay, CNFGWindow, CNFGCursors[shape] );
}

int FullScreen = 0;

void CNFGGetDimensions( short * x, short * y )
{
	static int lastx;
	static int lasty;

	*x = CNFGWinAtt.width;
	*y = CNFGWinAtt.height;

	if( lastx != *x || lasty != *y )
	{
		lastx = *x;
		lasty = *y;
#ifndef CNFGCONTEXTONLY
		CNFGInternalResize( lastx, lasty );
#endif
	}
}

void	CNFGChangeWindowTitle( const char * WindowName )
{
	XSetStandardProperties( CNFGDisplay, CNFGWindow, WindowName, 0, 0, 0, 0, 0 );
}

static void InternalLinkScreenAndGo( const char * WindowName )
{
	XFlush(CNFGDisplay);
	XGetWindowAttributes( CNFGDisplay, CNFGWindow, &CNFGWinAtt );

	if( !wm_res_name ) wm_res_name = strdup( "rawdraw" );
	if( !wm_res_class ) wm_res_class = strdup( "rawdraw" );

	XGetClassHint( CNFGDisplay, CNFGWindow, CNFGClassHint );
	if (!CNFGClassHint) {
		CNFGClassHint = XAllocClassHint();
		if (CNFGClassHint) {
			CNFGClassHint->res_name = wm_res_name;
			CNFGClassHint->res_class = wm_res_class;
			XSetClassHint( CNFGDisplay, CNFGWindow, CNFGClassHint );
		} else {
			fprintf( stderr, "Failed to allocate XClassHint!\n" );
		}
	} else {
		fprintf( stderr, "Pre-existing XClassHint\n" );
	}

	XSelectInput (CNFGDisplay, CNFGWindow, KeyPressMask | KeyReleaseMask | ButtonPressMask | ButtonReleaseMask | ExposureMask | PointerMotionMask | FocusChangeMask );


	CNFGWindowGC = XCreateGC(CNFGDisplay, CNFGWindow, 0, 0);


	if( CNFGX11ForceNoDecoration )
	{
		Atom window_type = XInternAtom(CNFGDisplay, "_NET_WM_WINDOW_TYPE", False);
		long value = XInternAtom(CNFGDisplay, "_NET_WM_WINDOW_TYPE_SPLASH", False);
		XChangeProperty(CNFGDisplay, CNFGWindow, window_type,
		   XA_ATOM, 32, PropModeReplace, (unsigned char *) &value,1 );
	}

	CNFGPixmap = XCreatePixmap( CNFGDisplay, CNFGWindow, CNFGWinAtt.width, CNFGWinAtt.height, CNFGWinAtt.depth );
	CNFGGC = XCreateGC(CNFGDisplay, CNFGPixmap, 0, 0);
	XSetLineAttributes(CNFGDisplay, CNFGGC, 1, LineSolid, CapRound, JoinRound);
	CNFGChangeWindowTitle( WindowName );
	if( !CNFGWindowInvisible )
		XMapWindow(CNFGDisplay, CNFGWindow);

	CNFGXIM = XOpenIM(CNFGDisplay, NULL, wm_res_name, wm_res_class);
	CNFGXIC = XCreateIC(CNFGXIM, XNInputStyle, XIMPreeditNothing | XIMStatusNothing, NULL);

#ifdef CNFG_HAS_XSHAPE
	if( prepare_xshape )
	{
	    xsval.foreground = 1;
	    xsval.line_width = 1;
	    xsval.line_style = LineSolid;
	    xspixmap = XCreatePixmap(CNFGDisplay, CNFGWindow, CNFGWinAtt.width, CNFGWinAtt.height, 1);
	    xsgc = XCreateGC(CNFGDisplay, xspixmap, 0, &xsval);
		XSetLineAttributes(CNFGDisplay, xsgc, 1, LineSolid, CapRound, JoinRound);
	}
#endif
}

void CNFGSetupFullscreen( const char * WindowName, int screen_no )
{
#ifdef HAS_XINERAMA
	XineramaScreenInfo *screeninfo = NULL;
	int screens;
	int event_basep, error_basep, a, b;
	CNFGDisplay = XOpenDisplay(NULL);
	CNFGScreen = XDefaultScreen(CNFGDisplay);
	int xpos, ypos;

	if (!XShapeQueryExtension(CNFGDisplay, &event_basep, &error_basep)) {
		fprintf( stderr, "X-Server does not support shape extension\n" );
		exit( 1 );
	}

 	CNFGVisual = DefaultVisual(CNFGDisplay, CNFGScreen);
	CNFGVisualID = 0;
	CNFGWinAtt.depth = DefaultDepth(CNFGDisplay, CNFGScreen);

#ifdef CNFGOGL
	CNFGGLXSetup();
#endif

	if (XineramaQueryExtension(CNFGDisplay, &a, &b ) &&
		(screeninfo = XineramaQueryScreens(CNFGDisplay, &screens)) &&
		XineramaIsActive(CNFGDisplay) && screen_no >= 0 &&
		screen_no < screens ) {

		CNFGWinAtt.width = screeninfo[screen_no].width;
		CNFGWinAtt.height = screeninfo[screen_no].height;
		xpos = screeninfo[screen_no].x_org;
		ypos = screeninfo[screen_no].y_org;
	} else
	{
		CNFGWinAtt.width = XDisplayWidth(CNFGDisplay, CNFGScreen);
		CNFGWinAtt.height = XDisplayHeight(CNFGDisplay, CNFGScreen);
		xpos = 0;
		ypos = 0;
	}
	if (screeninfo)
	XFree(screeninfo);


	XSetWindowAttributes setwinattr;
	setwinattr.override_redirect = 1;
	setwinattr.save_under = 1;
#ifdef CNFG_HAS_XSHAPE

	if (prepare_xshape && !XShapeQueryExtension(CNFGDisplay, &event_basep, &error_basep))
	{
    	fprintf( stderr, "X-Server does not support shape extension" );
		exit( 1 );
	}

	setwinattr.event_mask = 0;
#else
	//This code is probably made irrelevant by the XSetEventMask in InternalLinkScreenAndGo, if this code is not found needed by 2019-12-31, please remove.
	//setwinattr.event_mask = StructureNotifyMask | SubstructureNotifyMask | ExposureMask | ButtonPressMask | ButtonReleaseMask | ButtonPressMask | PointerMotionMask | ButtonMotionMask | EnterWindowMask | LeaveWindowMask |KeyPressMask |KeyReleaseMask | SubstructureNotifyMask | FocusChangeMask;
#endif
	setwinattr.border_pixel = 0;
	setwinattr.colormap = XCreateColormap( CNFGDisplay, RootWindow(CNFGDisplay, 0), CNFGVisual, AllocNone);

	CNFGWindow = XCreateWindow(CNFGDisplay, XRootWindow(CNFGDisplay, CNFGScreen),
		xpos, ypos, CNFGWinAtt.width, CNFGWinAtt.height,
		0, CNFGWinAtt.depth, InputOutput, CNFGVisual, 
		CWBorderPixel/* | CWEventMask */ | CWOverrideRedirect | CWSaveUnder | CWColormap, 
		&setwinattr);

	FullScreen = 1;
	InternalLinkScreenAndGo( WindowName );
#ifdef CNFGOGL
	glXMakeCurrent( CNFGDisplay, CNFGWindow, CNFGCtx );
#endif
#ifdef CNFG_BATCH
#ifndef CNFGCONTEXTONLY
	CNFGSetupBatchInternal();
#endif
#endif

#else
	CNFGSetup( WindowName, 640, 480 );
#endif
}


void CNFGTearDown()
{
	HandleDestroy();
	if( xi ) free( xi );
	if ( CNFGClassHint ) XFree( CNFGClassHint );
	if ( CNFGGC ) XFreeGC( CNFGDisplay, CNFGGC );
	if ( CNFGWindowGC ) XFreeGC( CNFGDisplay, CNFGWindowGC );
	if ( CNFGDisplay ) XCloseDisplay( CNFGDisplay );
	if ( CNFGXIC ) XDestroyIC( CNFGXIC );
	if ( CNFGXIM ) XCloseIM( CNFGXIM );

#ifdef CNFGOGL
	if ( CNFGGLXFBConfigs ) XFree( CNFGGLXFBConfigs );
	CNFGGLXFBConfigs = NULL;
#endif
	CNFGDisplay = NULL;
	CNFGWindowGC = CNFGGC = NULL;
	CNFGClassHint = NULL;
	CFNGWMDeleteWindow = None;
}

int CNFGSetupWMClass( const char * WindowName, int w, int h , char * wm_res_name_ , char * wm_res_class_ )
{
	wm_res_name = wm_res_name_;
	wm_res_class = wm_res_class_;
	return CNFGSetup( WindowName, w, h);
}

int CNFGSetup( const char * WindowName, int w, int h )
{
	CNFGDisplay = XOpenDisplay(NULL);
	if ( !CNFGDisplay ) {
		fprintf( stderr, "Could not get an X Display.\n%s", 
				 "Are you in text mode or using SSH without X11-Forwarding?\n" );
		exit( 1 );
	}
	atexit( CNFGTearDown );

	CNFGScreen = DefaultScreen(CNFGDisplay);
	CNFGDepth = DefaultDepth(CNFGDisplay, CNFGScreen);
 	CNFGVisual = DefaultVisual(CNFGDisplay, CNFGScreen);
	CNFGVisualID = 0;
	Window wnd = DefaultRootWindow( CNFGDisplay );

#ifdef CNFGOGL
	CNFGGLXSetup( );
#endif

	XSetWindowAttributes attr;
	attr.background_pixel = 0;
	attr.colormap = XCreateColormap( CNFGDisplay, wnd, CNFGVisual, AllocNone);
	if( w  > 0 && h > 0 ) {
		CNFGWindow = XCreateWindow(CNFGDisplay, wnd, 1, 1, w, h, 0, CNFGDepth, InputOutput, CNFGVisual, CWBackPixel | CWColormap, &attr );
		XSizeHints *size_hints = XAllocSizeHints();
		if (size_hints) {
			size_hints->flags = PMinSize | PMaxSize;
			size_hints->min_width = size_hints->max_width = w;
			size_hints->min_height = size_hints->max_height = h;
			XSetWMNormalHints(CNFGDisplay, CNFGWindow, size_hints);
			XFree(size_hints);
		}
	}
	else
	{
		if( w < 0 ) w = -w;
		if( h < 0 ) h = -h;
		CNFGWindow = XCreateWindow(CNFGDisplay, wnd, 1, 1, w, h, 0, CNFGDepth, InputOutput, CNFGVisual, CWBackPixel | CWColormap, &attr );
		CNFGWindowInvisible = 1;
	}

	InternalLinkScreenAndGo( WindowName );

//Not sure of the purpose of this code - if it's still commented out after 2019-12-31 and no one knows why, please delete it.
	CFNGWMDeleteWindow = XInternAtom( CNFGDisplay, "WM_DELETE_WINDOW", False );
	XSetWMProtocols( CNFGDisplay, CNFGWindow, &CFNGWMDeleteWindow, 1 );

	// X11 doesn't have a concept of a hidden cursor. Make a blank cursor as a substitute
	XColor col = { 0 };
	Pixmap blank = XCreateBitmapFromData( CNFGDisplay, CNFGWindow, (char*)(&col), 1, 1 );
	CNFGCursors[CNFG_CURSOR_HIDDEN] = XCreatePixmapCursor( CNFGDisplay, blank, blank, &col, &col, 0, 0 );
	XFreePixmap( CNFGDisplay, blank );

#ifdef CNFGOGL
	glXMakeCurrent( CNFGDisplay, CNFGWindow, CNFGCtx );
#endif

#ifdef CNFG_BATCH
#ifndef CNFGCONTEXTONLY
	CNFGSetupBatchInternal();
#endif
#endif

	return 0;
}

int CNFGHandleInput()
{
	if( !CNFGWindow ) return 0;
	static int ButtonsDown;
	XEvent report;

	int bKeyDirection = 1;
	while( XPending( CNFGDisplay ) )
	{
		XNextEvent( CNFGDisplay, &report );

		bKeyDirection = 1;
		switch  (report.type)
		{
		case NoExpose:
			break;
		case Expose:
			XGetWindowAttributes( CNFGDisplay, CNFGWindow, &CNFGWinAtt );
			if( CNFGPixmap ) XFreePixmap( CNFGDisplay, CNFGPixmap );
			CNFGPixmap = XCreatePixmap( CNFGDisplay, CNFGWindow, CNFGWinAtt.width, CNFGWinAtt.height, CNFGWinAtt.depth );
			if( CNFGGC ) XFreeGC( CNFGDisplay, CNFGGC );
			CNFGGC = XCreateGC(CNFGDisplay, CNFGPixmap, 0, 0);

			CNFGLastScancode = 0;
			HandleKey( CNFG_X11_EXPOSE, 0 );
			break;
		case KeyRelease:
		{
			bKeyDirection = 0;
			//Tricky - handle key repeats cleanly.
			if( XPending( CNFGDisplay ) )
			{
				XEvent nev;
				XPeekEvent( CNFGDisplay, &nev );
				if (nev.type == KeyPress && nev.xkey.time == report.xkey.time && nev.xkey.keycode == report.xkey.keycode )
					bKeyDirection = 2;
			}
		}
		case KeyPress:
			g_x_global_key_state = report.xkey.state;
			g_x_global_shift_key = XLookupKeysym(&report.xkey, 1);
			
			CNFGLastScancode = report.xkey.keycode;

			// Chars should ONLY be handled on Key Press
			if (report.type == KeyPress) { 
				char buf[8] = {0};
				if (Xutf8LookupString(CNFGXIC, &report.xkey, buf, 8, NULL, NULL)) CNFGLastCharacter = *((int*)buf);
				else CNFGLastCharacter = 0;
			}

			KeySym sym = XLookupKeysym(&report.xkey, 0);
			HandleKey( sym, bKeyDirection );
			
			// Don't confuse the program when CNFGLastCharacter is set on KeyRelease.
			// Since we shouldn't be using CNFGLastCharacter outside HandleKey anyways, just clear it here.
			CNFGLastCharacter = 0;

			break;
		case ButtonRelease:
			bKeyDirection = 0;
		case ButtonPress:
			if (CNFGRelPos) {
				int x0 = CNFGWinAtt.width / 2;
				int y0 = CNFGWinAtt.height / 2;
				int relx = report.xbutton.x - x0;
				int rely = report.xbutton.y - y0;
				HandleButtonRel( relx, rely, report.xbutton.button, bKeyDirection );
			} else {
				HandleButton( report.xbutton.x, report.xbutton.y, report.xbutton.button, bKeyDirection );
			}
			ButtonsDown = (ButtonsDown & (~(1<<report.xbutton.button))) | ( bKeyDirection << report.xbutton.button );

			//Intentionall fall through -- we want to send a motion in event of a button as well.
		case MotionNotify:
			if (CNFGRelPos) {
				int x0 = CNFGWinAtt.width / 2;
				int y0 = CNFGWinAtt.height / 2;
				int relx = report.xmotion.x - x0;
				int rely = report.xmotion.y - y0;
				if (relx || rely) {
					HandleMotionRel( relx, rely, ButtonsDown>>1 );
					XWarpPointer( CNFGDisplay, None, CNFGWindow, 0, 0, 0, 0,
						      x0, y0 );
				}
			} else {
				HandleMotion( report.xmotion.x, report.xmotion.y, ButtonsDown>>1 );
			}
			break;
		case FocusIn:
		case FocusOut:
			CNFGLastScancode = 0;
			HandleKey( CNFG_KEY_FOCUS, report.type == FocusIn );
			break;
		case ClientMessage:
			if ( report.xclient.data.l[0] == CFNGWMDeleteWindow )
				return 0;
			break;
		default:
			break;
			//printf( "Event: %d\n", report.type );
		}
	}
	return 1;
}


#ifdef CNFGOGL

void   CNFGSetVSync( int vson )
{
	void (*glfn)( int );
	void (*glfnXE)( Display *, GLXDrawable, int );
	glfn = (void (*)( int ))CNFGGetExtension( "glXSwapIntervalMESA" );	if( glfn ) glfn( vson );
	glfn = (void (*)( int ))CNFGGetExtension( "glXSwapIntervalSGI" );	if( glfn ) glfn( vson );
	glfnXE = (void (*)( Display *, GLXDrawable, int ))CNFGGetExtension( "glXSwapIntervalEXT" );	if( glfn ) glfnXE( CNFGDisplay, CNFGWindow, vson );
}

#ifdef CNFGRASTERIZER
void CNFGSwapBuffersInternal()
#else
void CNFGSwapBuffers()
#endif
{
	if( CNFGWindowInvisible ) return;

#ifndef CNFGRASTERIZER
#ifndef CNFGCONTEXTONLY
	CNFGFlushRender();
#endif
#endif

#ifdef CNFG_HAS_XSHAPE
	if( taint_shape )
	{
		XShapeCombineMask(CNFGDisplay, CNFGWindow, ShapeBounding, 0, 0, xspixmap, ShapeSet);
		taint_shape = 0;
	}
#endif //CNFG_HAS_XSHAPE
	glXSwapBuffers( CNFGDisplay, CNFGWindow );

#ifdef FULL_SCREEN_STEAL_FOCUS
	if( FullScreen )
		XSetInputFocus( CNFGDisplay, CNFGWindow, RevertToParent, CurrentTime );
#endif //FULL_SCREEN_STEAL_FOCUS
}

#else //CNFGOGL

#ifndef CNFG_BATCH
#ifndef CNFGRASTERIZER
void CNFGBlitImage( uint32_t * data, int x, int y, int w, int h )
{
	static int lw, lh;

	if( lw != w || lh != h || !xi )
	{
		if( xi ) free( xi );
		xi = XCreateImage(CNFGDisplay, CNFGVisual, CNFGDepth, ZPixmap, 0, (char*)data, w, h, 32, w*4 );
		lw = w;
		lh = h;
	}
	xi->data = (char*)data;
	//Draw image to pixmap (not a screen flip)
	XPutImage(CNFGDisplay, CNFGPixmap, CNFGGC, xi, 0, 0, x, y, w, h );
}
#endif

void CNFGUpdateScreenWithBitmap( uint32_t * data, int w, int h )
{
	static int lw, lh;

	if( lw != w || lh != h || !xi )
	{
		if( xi ) free( xi );
		xi = XCreateImage(CNFGDisplay, CNFGVisual, CNFGDepth, ZPixmap, 0, (char*)data, w, h, 32, w*4 );
		lw = w;
		lh = h;
	}
	xi->data = (char*)data;
	//Directly write image to screen (effectively a flip)
	XPutImage(CNFGDisplay, CNFGWindow, CNFGWindowGC, xi, 0, 0, 0, 0, w, h );
}

#endif
#endif //CNFGOGL

#if !defined( CNFG_BATCH )
#define AGLF(x) x
#else
#define AGLF(x) static inline BACKEND_##x
#endif

#if defined( CNFGRASTERIZER ) 
#include "CNFGRasterizer.c"
#undef AGLF
#define AGLF(x) static inline BACKEND_##x
#endif

uint32_t AGLF(CNFGColor)( uint32_t RGB )
{
	CNFGLastColor = RGB;
	unsigned char red = ( RGB >> 24 ) & 0xFF;
	unsigned char grn = ( RGB >> 16 ) & 0xFF;
	unsigned char blu = ( RGB >> 8 ) & 0xFF;
	unsigned long color = (red<<16)|(grn<<8)|(blu);
	XSetForeground(CNFGDisplay, CNFGGC, color);
	return color;
}

void AGLF(CNFGClearFrame)()
{
	XGetWindowAttributes( CNFGDisplay, CNFGWindow, &CNFGWinAtt );
	XSetForeground(CNFGDisplay, CNFGGC, CNFGColor(CNFGBGColor) );	
	XFillRectangle(CNFGDisplay, CNFGPixmap, CNFGGC, 0, 0, CNFGWinAtt.width, CNFGWinAtt.height );
}

void AGLF(CNFGSwapBuffers)()
{
#ifdef CNFG_HAS_XSHAPE
	if( taint_shape )
	{
		XShapeCombineMask(CNFGDisplay, CNFGWindow, ShapeBounding, 0, 0, xspixmap, ShapeSet);
		taint_shape = 0;
	}
#endif
	XCopyArea(CNFGDisplay, CNFGPixmap, CNFGWindow, CNFGWindowGC, 0,0,CNFGWinAtt.width,CNFGWinAtt.height,0,0);
	XFlush(CNFGDisplay);
#ifdef FULL_SCREEN_STEAL_FOCUS
	if( FullScreen )
		XSetInputFocus( CNFGDisplay, CNFGWindow, RevertToParent, CurrentTime );
#endif
}

void AGLF(CNFGTackSegment)( short x1, short y1, short x2, short y2 )
{
	if( x1 == x2 && y1 == y2 )
	{
		//On some targets, zero-length lines will not show up.
		//This is tricky - since this will also cause more draw calls for points on systems like GLAMOR.
		XDrawPoint( CNFGDisplay, CNFGPixmap, CNFGGC, x2, y2 );
	}
	else
	{
		//XXX HACK!  See discussion here: https://github.com/cntools/cnping/issues/68
		XDrawLine( CNFGDisplay, CNFGPixmap, CNFGGC, x1, y1, x2, y2 );
		XDrawLine( CNFGDisplay, CNFGPixmap, CNFGGC, x2, y2, x1, y1 );
	}
}

void AGLF(CNFGTackPixel)( short x1, short y1 )
{
	XDrawPoint( CNFGDisplay, CNFGPixmap, CNFGGC, x1, y1 );
}

void AGLF(CNFGTackRectangle)( short x1, short y1, short x2, short y2 )
{
	XFillRectangle(CNFGDisplay, CNFGPixmap, CNFGGC, x1, y1, x2-x1, y2-y1 );
}

void AGLF(CNFGTackPoly)( RDPoint * points, int verts )
{
	XFillPolygon(CNFGDisplay, CNFGPixmap, CNFGGC, (XPoint *)points, verts, Convex, CoordModeOrigin );
}

void AGLF(CNFGInternalResize)( short x, short y ) { }

void AGLF(CNFGSetLineWidth)( short width )
{
	XSetLineAttributes(CNFGDisplay, CNFGGC, width, LineSolid, CapRound, JoinRound);
}

#endif // _CNFGXDRIVER_C

