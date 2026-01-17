//Copyright <>< 2010-2020 Charles Lohr (And other authors as cited)
//CNFA is licensed under the MIT/x11, ColorChord or NewBSD Licenses. You choose.
//
// CN's Platform-agnostic, foundational sound driver subsystem.
// Easily output and input sound on a variety of platforms.
//
// Options:
//  * #define CNFA_IMPLEMENTATION before this header and it will build all
//    definitions in.
//


#ifndef _CNFA_H
#define _CNFA_H



//this #define is per-platform.  For instance on Linux, you have ALSA, Pulse and null
#define MAX_CNFA_DRIVERS 4

struct CNFADriver;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef BUILD_DLL
	#ifdef WINDOWS
		#define DllExport __declspec( dllexport )
	#else
		#define DllExport extern
	#endif
#else
	#define DllExport
#endif

//NOTE: Some drivers have synchronous duplex mode, other drivers will use two different callbacks.  If ether is unavailable, it will be NULL.
//I.e. if `out` is null, only use in to read.  If in is null, only place samples in out.
typedef void(*CNFACBType)( struct CNFADriver * sd, short * out, short * in, int framesp, int framesr );

typedef void*(CNFAInitFn)( CNFACBType cb, const char * your_name, int reqSPSPlay, int reqSPSRec, int reqChannelsPlay, int reqChannelsRec, int sugBufferSize, const char * outputSelect, const char * inputSelect, void * opaque );

struct CNFADriver
{
	void (*CloseFn)( void * object );
	int (*StateFn)( void * object );
	CNFACBType callback;
	short channelsPlay;
	short channelsRec;
	int spsPlay;
	int spsRec;
	void * opaque;

	//More fields may exist on a per-sound-driver basis
};

//Accepts:
//If DriverName = 0 or empty, will try to find best driver.
//
// our_source_name is an optional argument, but on some platforms controls the name of your endpoint.
// reqSPSPlay = 44100 is guaranteed on many platforms.
// reqSPSRec = 44100 is guaranteed on many platforms.
//   NOTE: Some platforms do not allow SPS play and REC to deviate from each other.
// reqChannelsRec = 1 or 2 guaranteed on many platforms.
// reqChannelsPlay = 1 or 2 guaranteedon many platforms. NOTE: Some systems require ChannelsPlay == ChannelsRec!
// sugBufferSize = No promises.
// outputSelect = No standardization, NULL is OK for default.
// inputSelect = No standardization, NULL is OK for default.

DllExport struct CNFADriver * CNFAInit( const char * driver_name, const char * your_name, CNFACBType cb, int reqSPSPlay, int reqSPSRec, int reqChannelsPlay,
	int reqChannelsRec, int sugBufferSize, const char * outputSelect, const char * inputSelect, void * opaque );
	
DllExport int CNFAState( struct CNFADriver * cnfaobject ); //returns bitmask.  1 if mic recording, 2 if play back running, 3 if both running.
DllExport void CNFAClose( struct CNFADriver * cnfaobject );


//Called by various sound drivers.  Notice priority must be greater than 0.  Priority of 0 or less will not register.
//This is an internal function.  Applications shouldnot call it.
void RegCNFADriver( int priority, const char * name, CNFAInitFn * fn );

#if defined(_MSC_VER) && !defined(__clang__)
#define REGISTER_CNFA( cnfadriver, priority, name, function ) \
	void REGISTER##cnfadriver() { RegCNFADriver( priority, name, function ); }
#else
#define REGISTER_CNFA( cnfadriver, priority, name, function ) \
	void __attribute__((constructor)) REGISTER##cnfadriver() { RegCNFADriver( priority, name, function ); }
#endif

#if defined(WINDOWS) || defined(__WINDOWS__) || defined(_WINDOWS) \
                     || defined(_WIN32)      || defined(_WIN64) \
                     || defined(WIN32)       || defined(WIN64) \
                     || defined(__WIN32__)   || defined(__CYGWIN__) \
                     || defined(__MINGW32__) || defined(__MINGW64__) \
                     || defined(__TOS_WIN__)
#define CNFA_WINDOWS 1
#elif defined( ANDROID ) || defined( __android__ ) || defined(ANDROID)
#define CNFA_ANDROID 1
#elif defined(__NetBSD__) || defined(__NetBSD) || defined(__sun) || defined(sun)
#define CNFA_SUN 1
#elif defined(__linux) || defined(__linux__) || defined(linux) || defined(__LINUX__)
#define CNFA_LINUX 1
//#define CNFA_PULSE 1
#endif

#if defined(PULSEAUDIO)
#define CNFA_PULSE 1
#endif

#ifdef __TINYC__
#ifndef TCC
#define TCC
#endif
#endif

#ifdef CNFA_IMPLEMENTATION
#include "CNFA.c"
//#include "CNFA_null.c"
#if CNFA_WINDOWS
#include "CNFA_winmm.c"
#include <ntverp.h> // This probably won't work on pre-NT systems
#if VER_PRODUCTBUILD >= 7601
#include "CNFA_wasapi.c"
#endif
#elif CNFA_ANDROID
#include "CNFA_android.c"
#elif CNFA_SUN
#include "CNFA_sun.c"
#elif CNFA_LINUX
#include "CNFA_alsa.c"
#if CNFA_PULSE
#include "CNFA_pulse.c"
#endif
#elif defined(__APPLE__)
#include "CNFA_coreaudio.c"
#if defined(PULSEAUDIO)
#include "CNFA_pulse.c"
#endif
#endif
#endif


#ifdef __cplusplus
};
#endif



#endif

