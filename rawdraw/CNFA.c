//Copyright <>< 2010-2020 Charles Lohr (And other authors as cited)
//CNFA is licensed under the MIT/x11, ColorChord or NewBSD Licenses. You choose.

#ifndef _CNFA_C
#define _CNFA_C

#include "CNFA.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(_MSC_VER)
#if CNFA_WINDOWS
#ifndef strdup
#define strdup _strdup
#endif
#endif 
#endif

static CNFAInitFn * CNFADrivers[MAX_CNFA_DRIVERS];
static char * CNFADriverNames[MAX_CNFA_DRIVERS];
static int CNFADriverPriorities[MAX_CNFA_DRIVERS];

void RegCNFADriver( int priority, const char * name, CNFAInitFn * fn )
{
	int j;

	if( priority <= 0 )
	{
		return;
	}

	printf("[CNFA] Registering Driver: %s\n", name);

	for( j = MAX_CNFA_DRIVERS-1; j >= 0; j-- )
	{
		//Cruise along, find location to insert
		if( j > 0 && ( !CNFADrivers[j-1] || CNFADriverPriorities[j-1] < priority ) )
		{
			CNFADrivers[j] = CNFADrivers[j-1];
			CNFADriverNames[j] = CNFADriverNames[j-1];
			CNFADriverPriorities[j] = CNFADriverPriorities[j-1];
		}
		else
		{
			CNFADrivers[j] = fn;
			CNFADriverNames[j] = strdup( name );
			CNFADriverPriorities[j] = priority;
			break;
		}
	}
}

struct CNFADriver * CNFAInit( const char * driver_name, const char * your_name, CNFACBType cb, int reqSPSPlay, int reqSPSRec,
	int reqChannelsPlay, int reqChannelsRec, int sugBufferSize, const char * outputSelect, const char * inputSelect, void * opaque)
{

#if CNFA_ANDROID
	//Android can't run static-time code.
	void REGISTERAndroidCNFA();
	REGISTERAndroidCNFA();
#endif

	int i;
	struct CNFADriver * ret = 0;
	int minprio = 0;
	CNFAInitFn * bestinit = 0;
	if( driver_name == 0 || strlen( driver_name ) == 0 )
	{
		//Search for a driver.
		for( i = 0; i < MAX_CNFA_DRIVERS; i++ )
		{
			if( CNFADrivers[i] == 0 )
			{
				break;
			}
			if( CNFADriverPriorities[i] > minprio )
			{
				minprio = CNFADriverPriorities[i];
				bestinit = CNFADrivers[i];
			}
		}
		if( bestinit )
		{
			ret = (struct CNFADriver *)bestinit( cb, your_name, reqSPSPlay, reqSPSRec, reqChannelsPlay, reqChannelsRec, sugBufferSize, outputSelect, inputSelect, opaque );
		}
		if( ret )
		{
			return ret;
		}
	}
	else
	{
		for( i = 0; i < MAX_CNFA_DRIVERS; i++ )
		{
			if( CNFADrivers[i] == 0 )
			{
				break;
			}
			if( strcmp( CNFADriverNames[i], driver_name ) == 0 )
			{
				return (struct CNFADriver *)CNFADrivers[i]( cb, your_name, reqSPSPlay, reqSPSRec, reqChannelsPlay, reqChannelsRec, sugBufferSize, outputSelect, inputSelect, opaque );
			}
		}
	}
	printf( "CNFA Driver not found.\n" );
	return 0;
}

int CNFAState( struct CNFADriver * cnfaobject )
{
	if( cnfaobject )
	{
		return cnfaobject->StateFn( cnfaobject );
	}
	return -1;
}

void CNFAClose( struct CNFADriver * cnfaobject )
{
	if( cnfaobject )
	{
		cnfaobject->CloseFn( cnfaobject );
	}
}

#endif


