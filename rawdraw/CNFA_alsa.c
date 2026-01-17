//Copyright 2015-2020 <>< Charles Lohr under the MIT/x11, NewBSD or ColorChord License.  You choose.

#include "CNFA.h"
#include "os_generic.h"
#include <alsa/asoundlib.h>
#include <string.h>

#define ALSA_PRINT_PREFIX "[CNFA][ALSA]: "

struct CNFADriverAlsa
{
	void (*CloseFn)( void * object );
	int (*StateFn)( void * object );
	CNFACBType callback;
	short channelsPlay;
	short channelsRec;
	int spsPlay;
	int spsRec;
	void * opaque;

	char * devRec;
	char * devPlay;

	snd_pcm_uframes_t bufsize;
	og_thread_t threadPlay;
	og_thread_t threadRec;
	snd_pcm_t *playback_handle;
	snd_pcm_t *record_handle;

	char playing;
	char recording;
};

int CNFAStateAlsa( void * v )
{
	struct CNFADriverAlsa * r = (struct CNFADriverAlsa *)v;
	return ((r->playing)?2:0) | ((r->recording)?1:0);
}

void CloseCNFAAlsa( void * v )
{
	struct CNFADriverAlsa * r = (struct CNFADriverAlsa *)v;
	if( r )
	{
		if( r->threadPlay ) OGJoinThread( r->threadPlay );
		if( r->threadRec ) OGJoinThread( r->threadRec );

		OGUSleep(2000);

		if( r->playback_handle ) snd_pcm_close (r->playback_handle);
		if( r->record_handle ) snd_pcm_close (r->record_handle);

		OGUSleep(2000);

		if( r->devRec ) free( r->devRec );
		if( r->devPlay ) free( r->devPlay );
		free( r );
	}
}


static int SetHWParams( snd_pcm_t * handle, int * samplerate, short * channels, snd_pcm_uframes_t * bufsize, struct CNFADriverAlsa * a )
{
	int err;
	int bufs;
	int dir;
	snd_pcm_hw_params_t *hw_params;
	if ((err = snd_pcm_hw_params_malloc (&hw_params)) < 0) {
		fprintf (stderr, ALSA_PRINT_PREFIX"cannot allocate hardware parameter structure (%s)\n",
			 snd_strerror (err));
		return -1;
	}

	if ((err = snd_pcm_hw_params_any (handle, hw_params)) < 0) {
		fprintf (stderr, ALSA_PRINT_PREFIX"cannot initialize hardware parameter structure (%s)\n",
			 snd_strerror (err));
		goto fail;
	}

	if ((err = snd_pcm_hw_params_set_access (handle, hw_params, SND_PCM_ACCESS_RW_INTERLEAVED)) < 0) {
		fprintf (stderr, ALSA_PRINT_PREFIX"cannot set access type (%s)\n",
			 snd_strerror (err));
		goto fail;
	}

	if ((err = snd_pcm_hw_params_set_format (handle, hw_params,  SND_PCM_FORMAT_S16_LE )) < 0) {
		fprintf (stderr, ALSA_PRINT_PREFIX"cannot set sample format (%s)\n",
			 snd_strerror (err));
		goto fail;
	}

	if ((err = snd_pcm_hw_params_set_rate_near (handle, hw_params, (unsigned int*)samplerate, 0)) < 0) {
		fprintf (stderr, ALSA_PRINT_PREFIX"cannot set sample rate (%s)\n",
			 snd_strerror (err));
		goto fail;
	}

	if ((err = snd_pcm_hw_params_set_channels (handle, hw_params, *channels)) < 0) {
		fprintf (stderr, ALSA_PRINT_PREFIX"cannot set channel count (%s)\n",
			 snd_strerror (err));
		goto fail;
	}

	dir = 0;
	if( (err = snd_pcm_hw_params_set_period_size_near(handle, hw_params, bufsize, &dir)) < 0 )
	{
		fprintf( stderr, ALSA_PRINT_PREFIX"cannot set period size. (%s)\n",
			snd_strerror(err) );
		goto fail;
	}

	//NOTE: This step is critical for low-latency sound.
	bufs = *bufsize*3;
	if( (err = snd_pcm_hw_params_set_buffer_size(handle, hw_params, bufs)) < 0 )
	{
		fprintf( stderr, ALSA_PRINT_PREFIX"cannot set snd_pcm_hw_params_set_buffer_size size. (%s)\n",
			snd_strerror(err) );
//		goto fail;
	}


	if ((err = snd_pcm_hw_params (handle, hw_params)) < 0) {
		fprintf (stderr, ALSA_PRINT_PREFIX"cannot set parameters (%s)\n",
			 snd_strerror (err));
		goto fail;
	}

	snd_pcm_hw_params_free (hw_params);
	return 0;
fail:
	snd_pcm_hw_params_free (hw_params);
	return -2;
}


static int SetSWParams( struct CNFADriverAlsa * d, snd_pcm_t * handle, int isrec )
{
	snd_pcm_sw_params_t *sw_params;
	int err;
	//Time for software parameters:

	if( !isrec )
	{
		if ((err = snd_pcm_sw_params_malloc (&sw_params)) < 0) {
			fprintf (stderr, ALSA_PRINT_PREFIX"cannot allocate software parameters structure (%s)\n",
				 snd_strerror (err));
			goto failhard;
		}
		if ((err = snd_pcm_sw_params_current (handle, sw_params)) < 0) {
			fprintf (stderr, ALSA_PRINT_PREFIX"cannot initialize software parameters structure (%s) (%p)\n", 
				 snd_strerror (err), handle);
			goto fail;
		}

		int buffer_size = d->bufsize*3;
		int period_size = d->bufsize;
		printf( ALSA_PRINT_PREFIX"PERIOD: %d  BUFFER: %d\n", period_size, buffer_size );

		if ((err = snd_pcm_sw_params_set_avail_min (handle, sw_params, period_size )) < 0) {
			fprintf (stderr, ALSA_PRINT_PREFIX"cannot set minimum available count (%s)\n",
				 snd_strerror (err));
			goto fail;
		}
		//if ((err = snd_pcm_sw_params_set_stop_threshold(handle, sw_params, 512 )) < 0) {
		//	fprintf (stderr, ALSA_PRINT_PREFIX"cannot set minimum available count (%s)\n",
		//		 snd_strerror (err));
		//	goto fail;
		//}
		if ((err = snd_pcm_sw_params_set_start_threshold(handle, sw_params, buffer_size - period_size )) < 0) {
			fprintf (stderr, ALSA_PRINT_PREFIX"cannot set minimum available count (%s)\n",
				 snd_strerror (err));
			goto fail;
		}
		if ((err = snd_pcm_sw_params (handle, sw_params)) < 0) {
			fprintf (stderr, ALSA_PRINT_PREFIX"cannot set software parameters (%s)\n",
				 snd_strerror (err));
			goto fail;
		}

		

	}

	if ((err = snd_pcm_prepare (handle)) < 0) {
		fprintf (stderr, ALSA_PRINT_PREFIX"cannot prepare audio interface for use (%s)\n",
			 snd_strerror (err));
		goto fail;
	}

	return 0;
fail:
	if( !isrec )
	{
		snd_pcm_sw_params_free (sw_params);
	}
failhard:
	return -1;
}

void * RecThread( void * v )
{
	struct CNFADriverAlsa * r = (struct CNFADriverAlsa *)v;
	short samples[r->bufsize * r->channelsRec];
	snd_pcm_start(r->record_handle);
	do
	{
		int err = snd_pcm_readi( r->record_handle, samples, r->bufsize );	
		if( err < 0 )
		{
			fprintf( stderr, ALSA_PRINT_PREFIX"Warning: ALSA Recording Failed\n" );
			break;
		}
		if( err != r->bufsize )
		{
			fprintf( stderr, ALSA_PRINT_PREFIX"Warning: ALSA Recording Underflow\n" );
		}
		r->recording = 1;
		r->callback( (struct CNFADriver *)r, 0, samples, 0, err );
	} while( 1 );
	r->recording = 0;
	fprintf( stderr, ALSA_PRINT_PREFIX"ALSA Recording Stopped\n" );
	return 0;
}

void * PlayThread( void * v )
{
	struct CNFADriverAlsa * r = (struct CNFADriverAlsa *)v;
	short samples[r->bufsize * r->channelsPlay];
	int err;
	//int total_avail = snd_pcm_avail(r->playback_handle);

	snd_pcm_start(r->playback_handle);
	r->callback( (struct CNFADriver *)r, samples, 0, r->bufsize, 0 );
	err = snd_pcm_writei(r->playback_handle, samples, r->bufsize);

	while( err >= 0 )
	{
	//	int avail = snd_pcm_avail(r->playback_handle);
	//	printf( ALSA_PRINT_PREFIX"avail: %d\n", avail );
		r->callback( (struct CNFADriver *)r, samples, 0, r->bufsize, 0 );
		err = snd_pcm_writei(r->playback_handle, samples, r->bufsize);
		if( err != r->bufsize )
		{
			fprintf( stderr, ALSA_PRINT_PREFIX"Warning: ALSA Playback Overflow\n" );
		}
		r->playing = 1;
	}
	r->playing = 0;
	fprintf( stderr, ALSA_PRINT_PREFIX"Playback Stopped\n" );
	return 0;
}

static struct CNFADriverAlsa * InitALSA( struct CNFADriverAlsa * r )
{
	printf( ALSA_PRINT_PREFIX"initialized %p %p  (%d %d) %d %d\n", r->playback_handle, r->record_handle, r->spsPlay, r->spsRec, r->channelsPlay, r->channelsRec );

	int err;
	if( r->channelsPlay )
	{
		if ((err = snd_pcm_open (&r->playback_handle, r->devPlay?r->devPlay:"default", SND_PCM_STREAM_PLAYBACK, 0)) < 0) {
			fprintf (stderr, ALSA_PRINT_PREFIX"cannot open output audio device (%s)\n", 
				 snd_strerror (err));
			goto fail;
		}
	}

	if( r->channelsRec )
	{
		if ((err = snd_pcm_open (&r->record_handle, r->devRec?r->devRec:"hw:0,0", SND_PCM_STREAM_CAPTURE, 0)) < 0) {
			fprintf (stderr, ALSA_PRINT_PREFIX"cannot open input audio device (%s)\n", 
				 snd_strerror (err));
			goto fail;
		}
	}

	if( r->playback_handle )
	{
		if( SetHWParams( r->playback_handle, &r->spsPlay, &r->channelsPlay, &r->bufsize, r ) < 0 ) 
			goto fail;
		if( SetSWParams( r, r->playback_handle, 0 ) < 0 )
			goto fail;
	}

	if( r->record_handle )
	{
		if( SetHWParams( r->record_handle, &r->spsRec, &r->channelsRec, &r->bufsize, r ) < 0 )
			goto fail;
		if( SetSWParams( r, r->record_handle, 1 ) < 0 )
			goto fail;
	}

#if 0
	if( r->playback_handle )
	{
		snd_async_handler_t *pcm_callback;
		//Handle automatically cleaned up when stream closed.
		err = snd_async_add_pcm_handler(&pcm_callback, r->playback_handle, playback_callback, r);
		if(err < 0)
		{
			printf(ALSA_PRINT_PREFIX"Playback callback handler error: %s\n", snd_strerror(err));
		}
	}

	if( r->record_handle )
	{
		snd_async_handler_t *pcm_callback;
		//Handle automatically cleaned up when stream closed.
		err = snd_async_add_pcm_handler(&pcm_callback, r->record_handle, record_callback, r);
		if(err < 0)
		{
			printf(ALSA_PRINT_PREFIX"Record callback handler error: %s\n", snd_strerror(err));
		}
	}
#endif

	if( r->playback_handle && r->record_handle )
	{
		err = snd_pcm_link ( r->playback_handle, r->record_handle );
		if(err < 0)
		{
			printf(ALSA_PRINT_PREFIX"snd_pcm_link error: %s\n", snd_strerror(err));
		}
	}

	if( r->playback_handle )
	{
		r->threadPlay = OGCreateThread( PlayThread, r );
	}

	if( r->record_handle )
	{
		r->threadRec = OGCreateThread( RecThread, r );
	}

	printf( ALSA_PRINT_PREFIX"Init Out -> %p %p  (%d %d) %d %d\n", r->playback_handle, r->record_handle, r->spsPlay, r->spsRec, r->channelsPlay, r->channelsRec );

	return r;

fail:
	if( r )
	{
		if( r->playback_handle ) snd_pcm_close (r->playback_handle);
		if( r->record_handle ) snd_pcm_close (r->record_handle);
		free( r );
	}
	fprintf( stderr, ALSA_PRINT_PREFIX"ALSA failed to start.\n" );
	return 0;
}



void * InitALSADriver( CNFACBType cb, const char * your_name, int reqSPSPlay, int reqSPSRec, int reqChannelsPlay, int reqChannelsRec, int sugBufferSize, const char * outputSelect, const char * inputSelect, void * opaque )
{
	struct CNFADriverAlsa * r = (struct CNFADriverAlsa *)malloc( sizeof( struct CNFADriverAlsa ) );

	r->CloseFn = CloseCNFAAlsa;
	r->StateFn = CNFAStateAlsa;
	r->callback = cb;
	r->opaque = opaque;
	r->spsPlay = reqSPSPlay;
	r->spsRec = reqSPSRec;
	r->channelsPlay = reqChannelsPlay;
	r->channelsRec = reqChannelsRec;

	r->devRec = (inputSelect)?strdup(inputSelect):0;
	r->devPlay = (outputSelect)?strdup(outputSelect):0;

	r->playback_handle = 0;
	r->record_handle = 0;
	r->bufsize = sugBufferSize;

	return InitALSA(r);
}

REGISTER_CNFA( ALSA, 10, "ALSA", InitALSADriver );

