//Copyright 2015-2020 <>< Charles Lohr under the ColorChord License, MIT/x11 license or NewBSD Licenses.

#include <windows.h>
#include "CNFA.h"
#include "os_generic.h"
#include <stdio.h>
#include <mmsystem.h>
#include <stdlib.h>

//Include -lwinmm, or, C:/windows/system32/winmm.dll

#if defined(_MSC_VER)
#if CNFA_WINDOWS
#ifndef strdup
#define strdup _strdup
#endif
#endif

#if defined(WIN32)
#pragma comment(lib,"winmm.lib")
#endif
#endif

#define BUFFS 3

struct CNFADriverWin
{
	//Standard header - must remain.
	void (*CloseFn)( void * object );
	int (*StateFn)( void * object );
	CNFACBType callback;
	short channelsPlay;
	short channelsRec;
	int spsPlay;
	int spsRec;
	void * opaque;

	char * sInputDev;
	char * sOutputDev;

	int buffer;
	int isEnding;
	int GOBUFFRec;
	int GOBUFFPlay;

	int recording;
	int playing;

	HWAVEIN hMyWaveIn;
	HWAVEOUT hMyWaveOut;
	WAVEHDR WavBuffIn[BUFFS];
	WAVEHDR WavBuffOut[BUFFS];
};


static struct CNFADriverWin * w;

void CloseCNFAWin( void * v )
{
	struct CNFADriverWin * r = (struct CNFADriverWin *)v;
	int i;

	if( r )
	{
		if( r->hMyWaveIn )
		{
			waveInStop(r->hMyWaveIn);
			waveInReset(r->hMyWaveIn);
			for ( i=0;i<BUFFS;i++)
			{
				waveInUnprepareHeader(r->hMyWaveIn,&(r->WavBuffIn[i]),sizeof(WAVEHDR));
				free ((r->WavBuffIn[i]).lpData);
			}
			waveInClose(r->hMyWaveIn);
		}

		if( r->hMyWaveOut )
		{
			waveOutPause(r->hMyWaveOut);
			waveOutReset(r->hMyWaveOut);

			for ( i=0;i<BUFFS;i++)
			{
				waveInUnprepareHeader(r->hMyWaveIn,&(r->WavBuffOut[i]),sizeof(WAVEHDR));
				free ((r->WavBuffOut[i]).lpData);
			}
			waveInClose(r->hMyWaveIn);
			waveOutClose(r->hMyWaveOut);
		}
		free( r );
	}
}

int CNFAStateWin( void * v )
{
	struct CNFADriverWin * soundobject = (struct CNFADriverWin *)v;

	return soundobject->recording | (soundobject->playing?2:0);
}

void CALLBACK HANDLEMIC(HWAVEIN hwi, UINT umsg, DWORD dwi, DWORD hdr, DWORD dwparm)
{
	int ob;
	unsigned int maxWave=0;

	if (w->isEnding) return;

	switch (umsg)
	{
	case MM_WIM_OPEN:
		printf( "Mic Open.\n" );
		w->recording = 1;
		break;

	case MM_WIM_DATA:
		ob = (w->GOBUFFRec+(BUFFS))%BUFFS;
		w->callback( (struct CNFADriver*)w, 0, (short*)(w->WavBuffIn[w->GOBUFFRec]).lpData, 0, w->buffer );
		waveInAddBuffer(w->hMyWaveIn,&(w->WavBuffIn[w->GOBUFFRec]),sizeof(WAVEHDR));
		w->GOBUFFRec = ( w->GOBUFFRec + 1 ) % BUFFS;
		break;
	}
}


void CALLBACK HANDLESINK(HWAVEIN hwi, UINT umsg, DWORD dwi, DWORD hdr, DWORD dwparm)
{
	unsigned int maxWave=0;

	if (w->isEnding) return;

	switch (umsg)
	{
	case MM_WOM_OPEN:
		printf( "Sink Open.\n" );
		w->playing = 1;
		break;

	case MM_WOM_DONE:
		w->callback( (struct CNFADriver*)w, (short*)(w->WavBuffOut[w->GOBUFFPlay]).lpData, 0, w->buffer, 0 );
		waveOutWrite( w->hMyWaveOut, &(w->WavBuffOut[w->GOBUFFPlay]),sizeof(WAVEHDR) );
		w->GOBUFFPlay = ( w->GOBUFFPlay + 1 ) % BUFFS;
		break;
	}
}


static struct CNFADriverWin * InitWinCNFA( struct CNFADriverWin * r )
{
	int i;
	WAVEFORMATEX wfmt;
	long dwdeviceR, dwdeviceP;
	memset( &wfmt, 0, sizeof(wfmt) );
	printf ("WFMT Size (debugging temp for TCC): %zu\n", sizeof(wfmt) );
	printf( "WFMT: %d %d %d\n", r->channelsRec, r->spsRec, r->spsRec * r->channelsRec );
	w = r;
	
	wfmt.wFormatTag = WAVE_FORMAT_PCM;
	wfmt.nChannels = r->channelsRec;
	wfmt.nAvgBytesPerSec = r->spsRec * r->channelsRec;
	wfmt.nBlockAlign = r->channelsRec * 2;
	wfmt.nSamplesPerSec = r->spsRec;
	wfmt.wBitsPerSample = 16;
	wfmt.cbSize = 0;

	dwdeviceR = r->sInputDev?atoi(r->sInputDev):WAVE_MAPPER;
	dwdeviceP = r->sOutputDev?atoi(r->sOutputDev):WAVE_MAPPER;

	if( r->channelsRec )
	{
		int p;
		printf( "In Wave Devs: %d; WAVE_MAPPER: %d; Selected Input: %ld\n", waveInGetNumDevs(), WAVE_MAPPER, dwdeviceR );
		p = waveInOpen(&r->hMyWaveIn, dwdeviceR, &wfmt, (intptr_t)(&HANDLEMIC), 0, CALLBACK_FUNCTION);
		if( p )
		{
			fprintf( stderr, "Error performing waveInOpen.  Received code: %d\n", p );
		}
		printf( "waveInOpen: %d\n", p );
		for ( i=0;i<BUFFS;i++)
		{
			memset( &(r->WavBuffIn[i]), 0, sizeof(r->WavBuffIn[i]) );
			(r->WavBuffIn[i]).dwBufferLength = r->buffer*2*r->channelsRec;
			(r->WavBuffIn[i]).dwLoops = 1;
			(r->WavBuffIn[i]).lpData=(char*) malloc(r->buffer*r->channelsRec*2);
			printf( "buffer gen size: %d: %p\n", r->buffer*r->channelsRec*2, (r->WavBuffIn[i]).lpData );
			p = waveInPrepareHeader(r->hMyWaveIn,&(r->WavBuffIn[i]),sizeof(WAVEHDR));
			printf( "WIPr: %d\n", p );
			waveInAddBuffer(r->hMyWaveIn,&(r->WavBuffIn[i]),sizeof(WAVEHDR));
			printf( "WIAr: %d\n", p );
		}
		p = waveInStart(r->hMyWaveIn);
		if( p )
		{
			fprintf( stderr, "Error performing waveInStart.  Received code %d\n", p );
		}
	}

	wfmt.nChannels = r->channelsPlay;
	wfmt.nAvgBytesPerSec = r->spsPlay * r->channelsPlay;
	wfmt.nBlockAlign = r->channelsPlay * 2;
	wfmt.nSamplesPerSec = r->spsPlay;

	if( r->channelsPlay )
	{
		int p;
		printf( "Out Wave Devs: %d; WAVE_MAPPER: %d; Selected Input: %ld\n", waveOutGetNumDevs(), WAVE_MAPPER, dwdeviceP );
		p = waveOutOpen( &r->hMyWaveOut, dwdeviceP, &wfmt, (intptr_t)(void*)(&HANDLESINK), (intptr_t)r, CALLBACK_FUNCTION);
		if( p )
		{
			fprintf( stderr, "Error performing waveOutOpen. Received code: %d\n", p );
		}
		printf( "waveOutOpen: %d\n", p );
		for ( i=0;i<BUFFS;i++)
		{
			int size;
			char * buf;
			memset( &(r->WavBuffOut[i]), 0, sizeof(r->WavBuffOut[i]) );
			(r->WavBuffOut[i]).dwBufferLength = r->buffer*2*r->channelsPlay;
			(r->WavBuffOut[i]).dwLoops = 1;
			size = r->buffer*r->channelsPlay*2;
			buf = (r->WavBuffOut[i]).lpData=(char*) malloc(size);
			memset( buf, 0, size );
			p = waveOutPrepareHeader(r->hMyWaveOut,&(r->WavBuffOut[i]),sizeof(WAVEHDR));
			waveOutWrite( r->hMyWaveOut, &(r->WavBuffOut[i]),sizeof(WAVEHDR));
		}
	}
	
	return r;
}



void * InitCNFAWin( CNFACBType cb, const char * your_name, int reqSPSPlay, int reqSPSRec, int reqChannelsPlay, int reqChannelsRec, int sugBufferSize, const char * outputSelect, const char * inputSelect, void * opaque )
{
	struct CNFADriverWin * r = (struct CNFADriverWin *)malloc( sizeof( struct CNFADriverWin ) );
	memset( r, 0, sizeof(*r) );
	r->CloseFn = CloseCNFAWin;
	r->StateFn = CNFAStateWin;
	r->callback = cb;
	r->opaque = opaque;
	r->spsPlay = reqSPSPlay;
	r->spsRec = reqSPSRec;
	r->channelsPlay = reqChannelsPlay;
	r->channelsRec = reqChannelsRec;
	r->buffer = sugBufferSize;
	r->sInputDev = inputSelect?strdup(inputSelect):0;
	r->sOutputDev = outputSelect?strdup(outputSelect):0;

	r->recording = 0;
	r->playing = 0;
	r->isEnding = 0;
	r->GOBUFFPlay = 0;
	r->GOBUFFRec = 0;

	return InitWinCNFA(r);
}

REGISTER_CNFA( WinCNFA, 10, "WIN", InitCNFAWin );

