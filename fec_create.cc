/* Lziprecover - Data recovery tool
   Copyright (C) 2023-2026 Antonio Diaz Diaz.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _FILE_OFFSET_BITS 64

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <new>
#include <list>
#include <string>
#include <vector>
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "lzip.h"
#include "md5.h"
#include "fec.h"


namespace {

void xinit_mutex( pthread_mutex_t * const mutex )
  {
  const int errcode = pthread_mutex_init( mutex, 0 );
  if( errcode )
    { show_error( "pthread_mutex_init", errcode ); cleanup_and_fail( 1 ); }
  }

void xinit_cond( pthread_cond_t * const cond )
  {
  const int errcode = pthread_cond_init( cond, 0 );
  if( errcode )
    { show_error( "pthread_cond_init", errcode ); cleanup_and_fail( 1 ); }
  }


void xdestroy_mutex( pthread_mutex_t * const mutex )
  {
  const int errcode = pthread_mutex_destroy( mutex );
  if( errcode )
    { show_error( "pthread_mutex_destroy", errcode ); cleanup_and_fail( 1 ); }
  }

void xdestroy_cond( pthread_cond_t * const cond )
  {
  const int errcode = pthread_cond_destroy( cond );
  if( errcode )
    { show_error( "pthread_cond_destroy", errcode ); cleanup_and_fail( 1 ); }
  }


void xlock( pthread_mutex_t * const mutex )
  {
  const int errcode = pthread_mutex_lock( mutex );
  if( errcode )
    { show_error( "pthread_mutex_lock", errcode ); cleanup_and_fail( 1 ); }
  }

void xunlock( pthread_mutex_t * const mutex )
  {
  const int errcode = pthread_mutex_unlock( mutex );
  if( errcode )
    { show_error( "pthread_mutex_unlock", errcode ); cleanup_and_fail( 1 ); }
  }


void xwait( pthread_cond_t * const cond, pthread_mutex_t * const mutex )
  {
  const int errcode = pthread_cond_wait( cond, mutex );
  if( errcode )
    { show_error( "pthread_cond_wait", errcode ); cleanup_and_fail( 1 ); }
  }

void xsignal( pthread_cond_t * const cond )
  {
  const int errcode = pthread_cond_signal( cond );
  if( errcode )
    { show_error( "pthread_cond_signal", errcode ); cleanup_and_fail( 1 ); }
  }


unsigned long out_size;		// size of fec data written to outfd
unsigned deliver_id;		// id of worker writing fec packets to outfd
unsigned check_counter;
unsigned wait_counter;
pthread_mutex_t omutex;
std::vector< pthread_cond_t > may_deliver;	// worker[i] may write
pthread_mutex_t cmutex = PTHREAD_MUTEX_INITIALIZER;	// cleanup mutex


struct Mworker_arg
  {
  const uint8_t * prodata;
  unsigned long prodata_size;
  md5_type * prodata_md5;
  unsigned worker_id;
  };

// compute prodata_md5 and pass the token to the first chksum thread
extern "C" void * mworker( void * arg )
  {
  const Mworker_arg & tmp = *(const Mworker_arg *)arg;
  const unsigned worker_id = tmp.worker_id;

  compute_md5( tmp.prodata, tmp.prodata_size, *tmp.prodata_md5 );
  xlock( &omutex );
  ++check_counter;
  while( worker_id != deliver_id )
    { ++wait_counter; xwait( &may_deliver[worker_id], &omutex ); }
  // allow first chksum worker to update prodata_md5 and write
  ++deliver_id; xsignal( &may_deliver[deliver_id] );
  xunlock( &omutex );
  return 0;
  }


struct Cworker_arg
  {
  const uint8_t * prodata;
  unsigned long prodata_size;
  const md5_type * prodata_md5;
  unsigned worker_id;
  Coded_fbs coded_fbs;
  bool gf16;
  bool first;
  };

// write a chksum packet and, if first, pass the token to the first fec thread
extern "C" void * cworker( void * arg )
  {
  const Cworker_arg & tmp = *(const Cworker_arg *)arg;
  const unsigned worker_id = tmp.worker_id;
  const bool first = tmp.first;

  Chksum_packet chksum_packet( tmp.prodata, tmp.prodata_size,
    *tmp.prodata_md5, tmp.coded_fbs, tmp.gf16, !first );
  const long packet_size = chksum_packet.packet_size();
  xlock( &omutex );
  ++check_counter;
  while( worker_id != deliver_id )
    { ++wait_counter; xwait( &may_deliver[worker_id], &omutex ); }
  chksum_packet.update_prodata_md5( *tmp.prodata_md5 );
  xlock( &cmutex );				// because of cleanup_and_fail
  if( writeblock( outfd, chksum_packet.image(), packet_size ) != packet_size )
    { show_file_error( printable_name( output_filename, false ), wr_err_msg,
                       errno ); xunlock( &cmutex ); cleanup_and_fail( 1 ); }
  xunlock( &cmutex );
  out_size += packet_size;
  if( first )				// allow first fec worker to write
    { deliver_id = 0; xsignal( &may_deliver[deliver_id] ); }
  xunlock( &omutex );
  return 0;
  }


struct Worker_arg
  {
  const uint8_t * prodata;
  const uint8_t * lastbuf;
  unsigned fec_blocks;
  unsigned k;
  unsigned num_workers;
  unsigned worker_id;
  Coded_fbs coded_fbs;
  bool gf16;
  };

// write a fec packet and pass the token to the next thread
extern "C" void * worker( void * arg )
  {
  const Worker_arg & tmp = *(const Worker_arg *)arg;
  const unsigned num_workers = tmp.num_workers;
  const unsigned worker_id = tmp.worker_id;

  for( unsigned fbn = worker_id; fbn < tmp.fec_blocks; fbn += num_workers )
    {
    const Fec_packet fec_packet( tmp.prodata, tmp.lastbuf, fbn, tmp.k,
                                 tmp.coded_fbs, tmp.gf16 );
    const long packet_size = fec_packet.packet_size();
    xlock( &omutex );
    ++check_counter;
    while( worker_id != deliver_id )
      { ++wait_counter; xwait( &may_deliver[worker_id], &omutex ); }
    xlock( &cmutex );				// because of cleanup_and_fail
    if( writeblock( outfd, fec_packet.image(), packet_size ) != packet_size )
      { show_file_error( printable_name( output_filename, false ), wr_err_msg,
                         errno ); xunlock( &cmutex ); cleanup_and_fail( 1 ); }
    xunlock( &cmutex );
    out_size += packet_size;
    if( ++deliver_id >= num_workers ) deliver_id = 0;
    xsignal( &may_deliver[deliver_id] );	// allow next worker to write
    xunlock( &omutex );
    }
  return 0;
  }


/* Start the workers and wait for them to finish.
   Compute prodata_md5, chksum packets, and fec packets concurrently. */
bool write_fec_mt( const uint8_t * const prodata,
                   const uint8_t * const lastbuf,
                   const unsigned long prodata_size,
                   md5_type & prodata_md5, const unsigned fec_blocks,
                   const unsigned k, const unsigned num_workers,
                   const Coded_fbs coded_fbs, const bool chksum2,
                   const char debug_level, const bool gf16 )
  {
  if( debug_level & 2 ) std::fputs( "executing write_fec_mt\n", stderr );
  deliver_id = num_workers;			// id of md5 worker
  check_counter = 0;
  wait_counter = 0;
  xinit_mutex( &omutex );
  const unsigned num_threads = num_workers + 2 + chksum2;
  may_deliver.resize( num_threads );		// fec + mw + cw1 + cw2
  for( unsigned i = 0; i < may_deliver.size(); ++i )
    xinit_cond( &may_deliver[i] );
  std::vector< pthread_t > worker_threads( num_workers );
  pthread_t mworker_thread, cworker_thread1, cworker_thread2;

  // start md5 worker
  Mworker_arg mworker_arg = { prodata, prodata_size, &prodata_md5, num_workers };
  int errcode = pthread_create( &mworker_thread, 0, mworker, &mworker_arg );
  if( errcode ) { show_error( "Can't create md5sum worker thread", errcode );
                  cleanup_and_fail( 1 ); }

  // start first chksum worker
  Cworker_arg cworker_arg1 = { prodata, prodata_size, &prodata_md5,
                               num_workers + 1, coded_fbs, gf16, true };
  errcode = pthread_create( &cworker_thread1, 0, cworker, &cworker_arg1 );
  if( errcode ) { show_error( "Can't create first chksum worker thread",
                  errcode ); cleanup_and_fail( 1 ); }

  std::vector< Worker_arg > worker_args( num_workers );
  for( unsigned i = 0; i < num_workers; ++i )	// start fec workers
    {
    worker_args[i].prodata = prodata;
    worker_args[i].lastbuf = lastbuf;
    worker_args[i].fec_blocks = fec_blocks;
    worker_args[i].k = k;
    worker_args[i].num_workers = num_workers;
    worker_args[i].worker_id = i;
    worker_args[i].coded_fbs = coded_fbs;
    worker_args[i].gf16 = gf16;
    errcode = pthread_create( &worker_threads[i], 0, worker, &worker_args[i] );
    if( errcode ) { show_error( "Can't create worker threads", errcode );
                    cleanup_and_fail( 1 ); }
    }

  Cworker_arg cworker_arg2 = { prodata, prodata_size, &prodata_md5,
                               num_workers + 2, coded_fbs, gf16, false };
  if( chksum2 )				// start second chksum worker
    { errcode = pthread_create( &cworker_thread2, 0, cworker, &cworker_arg2 );
      if( errcode ) { show_error( "Can't create second chksum worker thread",
                      errcode ); cleanup_and_fail( 1 ); } }

  // wait for md5sum worker
  errcode = pthread_join( mworker_thread, 0 );
  if( errcode ) { show_error( "Can't join md5sum worker thread", errcode );
                  cleanup_and_fail( 1 ); }

  // wait for first chksum worker
  errcode = pthread_join( cworker_thread1, 0 );
  if( errcode ) { show_error( "Can't join first chksum worker thread",
                  errcode ); cleanup_and_fail( 1 ); }

  for( unsigned i = 0; i < num_workers; ++i )	// wait for fec workers
    {
    errcode = pthread_join( worker_threads[i], 0 );
    if( errcode ) { show_error( "Can't join worker threads", errcode );
                    cleanup_and_fail( 1 ); }
    }

  if( chksum2 )				// wait for second chksum worker
    {
    xlock( &omutex );			// allow second chksum worker to write
    deliver_id = num_workers + 2; xsignal( &may_deliver[deliver_id] );
    xunlock( &omutex );
    errcode = pthread_join( cworker_thread2, 0 );
    if( errcode ) { show_error( "Can't join second chksum worker thread",
                    errcode ); cleanup_and_fail( 1 ); }
    }

  for( unsigned i = 0; i < may_deliver.size(); ++i )
    xdestroy_cond( &may_deliver[i] );
  xdestroy_mutex( &omutex );

  if( debug_level & 1 )
    std::fprintf( stderr,
      "workers started                    %8u\n"
      "any worker tried to write a packet %8u times\n"
      "any worker had to wait             %8u times\n",
      num_threads, check_counter, wait_counter );

  return true;
  }


inline void set_le( uint8_t * const buf, const int size, unsigned long n )
  { for( int i = 0; i < size; ++i ) { buf[i] = (uint8_t)n; n >>= 8; } }


unsigned compute_unit_fbs( const unsigned long prodata_size )
  {
  unsigned bs = min_fbs;
  while( bs < 65536 && 4ULL * bs * bs < prodata_size ) bs <<= 1;
  return bs;
  }

unsigned long divide_fbs( const unsigned long size, const unsigned blocks,
                          const unsigned unit_fbs )
  {
  unsigned long long fbs = ceil_divide( size, blocks );	// ULL as max_fbs
  if( fbs < min_fbs ) fbs = min_fbs;
  else if( fbs > max_fbs ) fbs = max_fbs;
  return ceil_divide( fbs, unit_fbs );
  }


Coded_fbs compute_fbs( const unsigned long prodata_size,
                       const unsigned cl_block_size, const char fec_level )
  {
  const unsigned unit_fbs = isvalid_fbs( cl_block_size ) ? cl_block_size :
                            compute_unit_fbs( prodata_size );
  const unsigned long max_k = (fec_level == 0) ? max_k8 : max_k16;
  const unsigned k9 = std::min( ceil_divide( prodata_size, unit_fbs ), max_k );
  const unsigned long fbsu9 = divide_fbs( prodata_size, k9, unit_fbs );
  const unsigned long fbsu0 = divide_fbs( prodata_size, max_k8, unit_fbs );
  const unsigned long a = std::min( (10 - fec_level) * fbsu9, fbsu0 );	// lin
  const unsigned long b = fbsu0 >> fec_level;	// exp
  const unsigned long fbsu = std::max( a, b );	// join linear and exponential
  return Coded_fbs( fbsu * unit_fbs, unit_fbs );
  }


unsigned compute_fec_blocks( const unsigned long prodata_size,
                             const unsigned long fb_or_pct, const char fctype,
                             const char fec_level, const Coded_fbs coded_fbs )
  {
  const unsigned long fbs = coded_fbs.val();
  const unsigned prodata_blocks = ceil_divide( prodata_size, fbs );
  const unsigned long max_nk = (fec_level == 0) ? max_k8 : max_nk16;
  unsigned fec_blocks;
  if( fctype == fc_blocks ) fec_blocks = std::min( max_nk, fb_or_pct );
  else
    {
    unsigned long fec_bytes = 0;
    if( fctype == fc_percent )
      { const double pct = std::min( 100000UL, fb_or_pct );
        fec_bytes = (unsigned long)std::ceil( prodata_size * pct / 100000 ); }
    else if( fctype == fc_bytes )
      fec_bytes = std::min( fb_or_pct, prodata_size );
    else internal_error( "unknown fctype." );
    fec_blocks = std::min( ceil_divide( fec_bytes, fbs ), max_nk );
    }
  if( fec_blocks > prodata_blocks ) fec_blocks = prodata_blocks;
  return fec_blocks;
  }


unsigned my_rand( unsigned long & state )
  {
  state = state * 1103515245 + 12345;
  return ( state / 65536 ) % 32768;	// random number from 0 to 32767
  }

void random_fbn_vector( const unsigned fec_blocks, const bool gf16,
                        std::vector< unsigned > & fbn_vector )
  {
  struct timespec ts;
  clock_gettime( CLOCK_REALTIME, &ts );
  unsigned long state = ts.tv_nsec;
  while( state != 0 && ( state & 1 ) == 0 ) state >>= 1;
  if( state != 0 ) state *= ts.tv_sec; else state = ts.tv_sec;
  for( unsigned i = 0; i < fec_blocks; ++i )
    {
    again: const unsigned fbn =
      gf16 ? my_rand( state ) % max_k16 : my_rand( state ) % max_k8;
    for( unsigned j = 0; j < fbn_vector.size(); ++j )
      if( fbn == fbn_vector[j] ) goto again;
    fbn_vector.push_back( fbn );
    }
  }


bool write_fec( const uint8_t * const prodata, const unsigned long prodata_size,
                const unsigned long fb_or_pct, const unsigned cl_block_size,
                unsigned num_workers, const char debug_level, const char fctype,
                const char fec_level, const bool cl_gf16, const bool fec_random )
  {
  const Coded_fbs coded_fbs =
    compute_fbs( prodata_size, cl_block_size, fec_level );
  const unsigned fec_blocks =
    compute_fec_blocks( prodata_size, fb_or_pct, fctype, fec_level, coded_fbs );
  if( fec_random ) num_workers = 1;
  else
    {
    const long page_size = sysconf( _SC_PAGESIZE );
    const long pages = sysconf( _SC_PHYS_PAGES );
    const unsigned long ram_size =
      ( page_size > 1 && pages > 1 && LONG_MAX / page_size >= pages ) ?
        page_size * pages : ULONG_MAX;
    if( prodata_size > ram_size / 2 || num_workers > fec_blocks )
      num_workers = fec_blocks;
    }
  const unsigned long fbs = coded_fbs.val();
  const unsigned chksum_packet_size =
    Chksum_packet::packet_size( prodata_size, fbs );
  unsigned long fecdata_size =
    fec_blocks * Fec_packet::packet_size( fbs ) + chksum_packet_size;
  const bool chksum2 = fec_blocks > 1 &&
    ( fecdata_size + chksum_packet_size ) / 2 <= fec_blocks * fbs;
  if( chksum2 ) fecdata_size += chksum_packet_size;
  const unsigned prodata_blocks = ceil_divide( prodata_size, fbs );
  const bool gf16 = cl_gf16 || prodata_blocks > max_k8 || fec_blocks > max_k8;
  md5_type prodata_md5;
  out_size = 0;
  if( num_workers <= 1 )
    {
    compute_md5( prodata, prodata_size, prodata_md5 );
    const Chksum_packet chksum_packet( prodata, prodata_size, prodata_md5,
      coded_fbs, gf16, false );				// CRC32 array
    const long packet_size = chksum_packet.packet_size();
    if( writeblock( outfd, chksum_packet.image(), packet_size ) != packet_size )
      goto fail;
    out_size += packet_size;
    if( chksum_packet_size != (unsigned)packet_size )
      internal_error( "wrong first chksum_packet_size." );
    }
  {
  const uint8_t * const lastbuf = set_lastbuf( prodata, prodata_size, fbs );
  gf16 ? gf16_init() : gf8_init();		// initialize Galois tables
  if( fec_random )
    {
    std::vector< unsigned > fbn_vector;
    random_fbn_vector( fec_blocks, gf16, fbn_vector );
    for( unsigned i = 0; i < fbn_vector.size(); ++i )
      {
      const unsigned fbn = fbn_vector[i];
      const Fec_packet
        fec_packet( prodata, lastbuf, fbn, prodata_blocks, coded_fbs, gf16 );
      const long packet_size = fec_packet.packet_size();
      if( writeblock( outfd, fec_packet.image(), packet_size ) != packet_size )
        { delete[] lastbuf; goto fail; }
      out_size += packet_size;
      }
    }
  else if( num_workers > 1 )
    {
    if( !write_fec_mt( prodata, lastbuf, prodata_size, prodata_md5, fec_blocks,
                       prodata_blocks, num_workers, coded_fbs, chksum2,
                       debug_level, gf16 ) ) { delete[] lastbuf; goto fail; }
    }
  else for( unsigned fbn = 0; fbn < fec_blocks; ++fbn )
    {
    const Fec_packet
      fec_packet( prodata, lastbuf, fbn, prodata_blocks, coded_fbs, gf16 );
    const long packet_size = fec_packet.packet_size();
    if( writeblock( outfd, fec_packet.image(), packet_size ) != packet_size )
      { delete[] lastbuf; goto fail; }
    out_size += packet_size;
    }
  delete[] lastbuf;
  if( chksum2 && num_workers <= 1 )	// write the second chksum packet
    {
    const Chksum_packet chksum_packet( prodata, prodata_size, prodata_md5,
      coded_fbs, gf16, true );				// CRC32-C array
    const long packet_size = chksum_packet.packet_size();
    if( writeblock( outfd, chksum_packet.image(), packet_size ) != packet_size )
      goto fail;
    out_size += packet_size;
    if( chksum_packet_size != (unsigned)packet_size )
      internal_error( "wrong second chksum_packet_size." );
    }
  if( verbosity >= 1 )
    std::fprintf( stderr, "  %s: %s bytes, %s fec bytes, %u %s\n",
                  printable_name( output_filename, false ),
                  format_num3( fecdata_size ),
                  format_num3( fec_blocks * fbs ), fec_blocks,
                  (fec_blocks == 1) ? "block" : "blocks" );
  if( fecdata_size % 4 != 0 ) internal_error( "fecdata_size % 4 != 0" );
  if( fecdata_size != out_size ) internal_error( "fecdata_size != out_size" );
  return true;
  }
fail:
  show_file_error( printable_name( output_filename, false ), wr_err_msg, errno );
  return false;
  }


int open_instream2( const std::string & name, struct stat * const in_statsp,
                    const bool force )
  {
  if( !has_fec_extension( name ) )
    return open_instream( name.c_str(), in_statsp, false, !force );
  if( verbosity >= 0 )
    std::fprintf( stderr, "%s: %s: Input file already has '%s' suffix, ignored.\n",
                  program_name, name.c_str(), fec_extension );
  return -1;
  }

} // end namespace


Chksum_packet::Chksum_packet( const uint8_t * const prodata,
                 const unsigned long prodata_size,
                 const md5_type & prodata_md5, const Coded_fbs coded_fbs,
                 const bool gf16_, const bool is_crc_c_ )
  {
//const long t0 = std::time( 0 );
//std::fprintf( stderr, "chk %u in (%lds)\n", is_crc_c_, std::time( 0 ) - t0 );
  const unsigned long fbs = coded_fbs.val();
  const unsigned prodata_blocks = ceil_divide( prodata_size, fbs );
  if( prodata_blocks * fbs < prodata_size )
    internal_error( "prodata_blocks * fec_block_size < prodata_size" );
  const unsigned paysize = prodata_blocks * sizeof crc_array()[0];
  const unsigned packet_size = header_size + paysize + trailer_size;
  if( paysize <= prodata_blocks || packet_size <= paysize )
    throw std::bad_alloc();
  uint8_t * const ip = new uint8_t[packet_size];	// writable image ptr
  image_ = ip;

  std::memcpy( ip, fec_magic, fec_magic_l );
  ip[version_o] = current_version;
  ip[flags_o] = ( gf16_ << 1 ) | is_crc_c_;
  set_le( ip + prodata_size_o, prodata_size_l, prodata_size );
  *(md5_type *)(ip + prodata_md5_o) = prodata_md5;
  coded_fbs.copy( ip + fbs_o );
  set_le( ip + header_crc_o, crc32_l, compute_header_crc( image_ ) );

  le32 * const crc_arr = (le32 *)(ip + crc_array_o);	// fill crc array
  unsigned i = 0;
  if( !is_crc_c_ )					// CRC32
    for( unsigned long pos = 0; pos < prodata_size; pos += fbs, ++i )
      crc_arr[i] =
        crc32.compute_crc( prodata + pos, std::min( fbs, prodata_size - pos ) );
  else
    {							// CRC32-C
    const CRC32 crc32c( true );
    for( unsigned long pos = 0; pos < prodata_size; pos += fbs, ++i )
      crc_arr[i] =
        crc32c.compute_crc( prodata + pos, std::min( fbs, prodata_size - pos ) );
    }
  if( i != prodata_blocks )
    internal_error( "wrong fec_block_size or number of prodata_blocks." );

  // compute CRC32 of payload (crc array)
  set_le( ip + crc_array_o + paysize, crc32_l,
          crc32.compute_crc( image_ + crc_array_o, paysize ) );
//std::fprintf( stderr, "chk %u out (%lds)\n", is_crc_c_, std::time( 0 ) - t0 );
  }

bool Chksum_packet::update_prodata_md5( const md5_type & prodata_md5 )
  {
  if( image_is_external ) return false;
  uint8_t * const ip = (uint8_t *)image_;		// writable image ptr
  *(md5_type *)(ip + prodata_md5_o) = prodata_md5;
  set_le( ip + header_crc_o, crc32_l, compute_header_crc( image_ ) );
  return true;
  }


Fec_packet::Fec_packet( const uint8_t * const prodata,
                        const uint8_t * const lastbuf,
                        const unsigned fbn, const unsigned k,
                        const Coded_fbs coded_fbs, const bool gf16 )
  {
//const long t0 = std::time( 0 );
//std::fprintf( stderr, "fec %u in (%lds)\n", fbn, std::time( 0 ) - t0 );
  const unsigned long fbs = coded_fbs.val();
  const unsigned long packet_size = header_size + fbs + trailer_size;
  if( packet_size <= fbs || !fits_in_size_t( packet_size ) )
    throw std::bad_alloc();
  uint8_t * const ip = new uint8_t[packet_size];	// writable image ptr
  image_ = ip;

  std::memcpy( ip, fec_packet_magic, fec_magic_l );
  set_le( ip + fbn_o, fbn_l, fbn );
  coded_fbs.copy( ip + fbs_o );
  set_le( ip + header_crc_o, crc32_l, compute_header_crc( image_ ) );

  // fill fec array
  gf16 ? rs16_encode( prodata, lastbuf, ip + fec_block_o, fbs, fbn, k ) :
         rs8_encode( prodata, lastbuf, ip + fec_block_o, fbs, fbn, k );

  // compute CRC32 of payload (fec array)
  set_le( ip + fec_block_o + fbs, crc32_l,
          crc32.compute_crc( image_ + fec_block_o, fbs ) );
//std::fprintf( stderr, "fec %u out (%lds)\n", fbn, std::time( 0 ) - t0 );
  }


void cleanup_mutex_lock()		// make cleanup_and_fail thread-safe
  { pthread_mutex_lock( &cmutex ); }	// ignore errors to avoid loop

int gf_check( const unsigned k, const bool cl_gf16, const bool fec_random )
  {
  std::vector< unsigned > fbn_vector;
  const bool gf16 = cl_gf16 || k > max_k8;
  if( fec_random ) random_fbn_vector( k, gf16, fbn_vector );
  return gf16 ? !gf16_check( fbn_vector, k ) : !gf8_check( fbn_vector, k );
  }


/* if name contains slash(es), copy name into srcdir up to the last slash,
   removing a leading dot followed by slash(es) */
void extract_dirname( const std::string & name, std::string & srcdir )
  {
  unsigned i = 0;
  unsigned j = name.size();
  if( j >= 2 && name[0] == '.' && name[1] == '/' )	// remove leading "./"
    for( i = 2; i < j && name[i] == '/'; ) ++i;
  while( j > i && name[j-1] != '/' ) --j;	// remove last component if any
  if( j > i ) srcdir.assign( name, i, j - i );
  }


// replace prefix srcdir with destdir in name and write result to outname
void replace_dirname( const std::string & name, const std::string & srcdir,
                      const std::string & destdir, std::string & outname )
  {
  if( srcdir.size() && name.compare( 0, srcdir.size(), srcdir ) != 0 )
    { if( verbosity >= 0 ) std::fprintf( stderr,
        "dirname '%s' != '%s'\n", name.c_str(), srcdir.c_str() );
      internal_error( "srcdir mismatch." ); }
  outname = destdir;
  outname.append( name, srcdir.size(), name.size() - srcdir.size() );
  }


bool has_fec_extension( const std::string & name )
  {
  const unsigned ext_len = std::strlen( fec_extension );
  return name.size() > ext_len &&
         name.compare( name.size() - ext_len, ext_len, fec_extension ) == 0;
  }


int fec_create( const std::vector< std::string > & filenames,
                const std::string & default_output_filename,
                const unsigned long fb_or_pct, const unsigned cl_block_size,
                const unsigned num_workers, const char debug_level,
                const char fctype, const char fec_level, const char recursive,
                const bool cl_gf16, const bool fec_random, const bool force,
                const bool to_stdout )
  {
  const bool to_dir = !to_stdout && default_output_filename.size() &&
                      default_output_filename.end()[-1] == '/';
  const bool to_file = !to_stdout && !to_dir && default_output_filename.size();
  if( ( to_stdout || to_file ) && filenames.size() != 1 )
    { show_error( "You must specify exactly 1 file when redirecting fec data." );
      return 1; }
  if( ( to_stdout || to_file ) && recursive )
    { show_error( "Can't redirect fec data in recursive mode." ); return 1; }
  if( to_stdout ) { outfd = STDOUT_FILENO; if( !check_tty_out() ) return 1; }
  else outfd = -1;

  int retval = 0;
  const bool one_to_one = !to_stdout && !to_file;
  for( unsigned i = 0; i < filenames.size(); ++i )
    {
    if( filenames[i] == "-" )
      { prot_stdin(); set_retval( retval, 1 ); continue; }
    std::string srcdir;			// dirname to be replaced by '-o dir/'
    if( to_dir ) extract_dirname( filenames[i], srcdir );
    std::list< std::string > filelist( 1U, filenames[i] );
    std::string input_filename;
    while( next_filename( filelist, input_filename, retval, recursive ) )
      {
      struct stat in_stats;
      const int infd = open_instream2( input_filename, &in_stats, force );
      if( infd < 0 ) { set_retval( retval, 1 ); continue; }

      const char * const input_filenamep = input_filename.c_str();
      const long long file_size = lseek( infd, 0, SEEK_END );
      if( file_size <= 0 )
        { if( file_size < 0 )
            show_file_error( input_filenamep, seek_msg, errno );
          else show_file_error( input_filenamep, empty_file_msg );
          set_retval( retval, 2 ); close( infd ); continue; }
      if( !fits_in_size_t( file_size ) )
        { show_file_error( input_filenamep, large_file_msg );
          set_retval( retval, 1 ); close( infd ); continue; }
      if( (unsigned long long)file_size > max_prodata_size8 && fec_level == 0 )
        { show_file_error( input_filenamep,
            "Input file is too large for fec protection at fec level 0." );
          set_retval( retval, 1 ); close( infd ); continue; }
      if( (unsigned long long)file_size > max_prodata_size )
        { show_file_error( input_filenamep,
            "Input file is too large for fec protection." );
          set_retval( retval, 1 ); close( infd ); continue; }
      const unsigned long prodata_size = file_size;
      const uint8_t * const prodata =
        (const uint8_t *)mmap( 0, prodata_size, PROT_READ, MAP_PRIVATE, infd, 0 );
      close( infd );
      if( prodata == MAP_FAILED )
        { show_file_error( input_filenamep, mmap_msg, errno );
          set_retval( retval, 1 ); continue; }

      if( one_to_one )
        {
        if( to_dir ) replace_dirname( input_filename, srcdir,
                       default_output_filename, output_filename );
        else output_filename = input_filename;
        output_filename += fec_extension; set_signal_handler();
        if( !open_outstream( force, true, false, true, to_dir ) )
          { munmap( (void *)prodata, prodata_size );
            set_retval( retval, 1 ); continue; }
        if( !check_tty_out() )
          { set_retval( retval, 1 ); return retval; }	// don't delete a tty
        }
      else if( to_file && outfd < 0 )	// open outfd after checking infd
        {
        output_filename = default_output_filename; set_signal_handler();
        if( !open_outstream( force, false ) || !check_tty_out() )
          return 1;	// check tty only once and don't try to delete a tty
        }

      // write fec data to output file
      if( !write_fec( prodata, prodata_size, fb_or_pct, cl_block_size,
                      num_workers, debug_level, fctype, fec_level, cl_gf16,
                      fec_random ) )
        { munmap( (void *)prodata, prodata_size ); cleanup_and_fail( 1 ); }
      /* To avoid '-Fc | -Ft' running out of address space, munmap before
         closing outfd and mmap after reading fec data from stdin */
      munmap( (void *)prodata, prodata_size );
      if( !close_outstream( &in_stats ) ) cleanup_and_fail( 1 );
      }
    }
  return retval;
  }
