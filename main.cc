/* Lziprecover - Data recovery tool
   Copyright (C) 2009-2026 Antonio Diaz Diaz.

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
/*
   Exit status: 0 for a normal exit, 1 for environmental problems
   (file not found, invalid command-line options, I/O errors, etc), 2 to
   indicate a corrupt or invalid input file, 3 for an internal consistency
   error (e.g., bug) which caused lziprecover to panic.
*/

#define _FILE_OFFSET_BITS 64

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <climits>		// CHAR_BIT, SSIZE_MAX
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <list>
#include <string>
#include <vector>
#include <fcntl.h>
#include <pthread.h>		// pthread_t
#include <stdint.h>		// SIZE_MAX
#include <unistd.h>
#include <utime.h>
#include <sys/stat.h>
#if defined __MSVCRT__ || defined __OS2__ || defined __DJGPP__
#include <io.h>
#if defined __MSVCRT__
#include <direct.h>
#define fchmod(x,y) 0
#define fchown(x,y,z) 0
#define mkdir(name,mode) _mkdir(name)
#define SIGHUP SIGTERM
#define S_ISSOCK(x) 0
#ifndef S_IRGRP
#define S_IRGRP 0
#define S_IWGRP 0
#define S_IROTH 0
#define S_IWOTH 0
#endif
#endif
#if defined __DJGPP__
#define S_ISSOCK(x) 0
#define S_ISVTX 0
#endif
#endif

#include "arg_parser.h"
#include "lzip.h"
#include "decoder.h"
#include "md5.h"
#include "fec.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

#if CHAR_BIT != 8
#error "Environments where CHAR_BIT != 8 are not supported."
#endif

#if ( defined  SIZE_MAX &&  SIZE_MAX < ULONG_MAX ) || \
    ( defined SSIZE_MAX && SSIZE_MAX <  LONG_MAX )
#error "Environments where 'size_t' is narrower than 'long' are not supported."
#endif

bool fits_in_size_t( const unsigned long long size )	// fits also in long
  { return sizeof (long) <= sizeof (size_t) && size <= LONG_MAX; }

const char * const program_name = "lziprecover";
std::string output_filename;	// global vars for output file
int outfd = -1;			// see 'delete_output_on_interrupt' below

namespace {

const char * invocation_name = program_name;		// default value

const struct { const char * from; const char * to; } known_extensions[] = {
  { ".lz",  ""     },
  { ".tlz", ".tar" },
  { 0,      0      } };

enum Mode { m_none, m_alone_to_lz, m_append, m_byte_repair, m_check,
            m_debug_byte_repair, m_debug_decompress, m_debug_delay,
            m_decompress, m_dump, m_fec_create, m_fec_repair, m_fec_test,
            m_fec_list, m_fec_dc, m_fec_df, m_fec_dz, m_fec_dZ, m_list,
            m_md5sum, m_merge, m_nonzero_repair, m_nrep_stats, m_range_dec,
            m_remove, m_reproduce, m_show_packets, m_split, m_strip, m_test,
            m_unzcrash_bit, m_unzcrash_block };

/* Variables used in signal handler context.
   They are not declared volatile because the handler never returns. */
bool delete_output_on_interrupt = false;


void show_help( const long num_online )
  {
  std::fputs(
    "Lziprecover is a data recovery tool and decompressor for files in the lzip\n"
    "compressed data format (.lz). Lziprecover also provides Forward Error\n"
    "Correction files (.fec) that can be used to repair any kind of file, not\n"
    "only lzip files. A fec file can be used as recovery record for a tar.lz\n"
    "archive.\n"
    "\nLziprecover can remove the damaged members from multimember files, for\n"
    "example multimember tar.lz archives.\n"
    "\nLziprecover provides random access to the data in multimember files; it only\n"
    "decompresses the members containing the desired data.\n", stdout );
  std::printf( "\nUsage: %s [options] [files]\n", invocation_name );
  std::printf( "\nOptions:\n"
    "  -h, --help                    display this help and exit\n"
    "  -V, --version                 output version information and exit\n"
    "  -a, --trailing-error          exit with error status if trailing data\n"
    "  -A, --alone-to-lz             convert lzma-alone files to lzip format\n"
    "  -b, --block-size=<bytes>      make FEC block size a multiple of <bytes>\n"
    "  -B, --byte-repair             try to repair a corrupt byte in file\n"
    "  -c, --stdout                  write to standard output, keep input files\n"
    "  -d, --decompress              decompress, test compressed file integrity\n"
    "  -D, --range-decompress=<n-m>  decompress a range of bytes to stdout\n"
    "  -e, --reproduce               try to reproduce a zeroed sector in file\n"
    "      --lzip-level=N|a|m[N]     reproduce one level, all, or match length\n"
    "      --lzip-name=<name>        name of lzip executable for --reproduce\n"
    "      --reference-file=<file>   reference file for --reproduce\n"
    "  -f, --force                   overwrite existing output files\n"
    "  -F, --fec=c[N]|r|t|l          create, repair, test, list (using) fec file\n"
    "  -0 .. -9                      set FEC fragmentation level [default 9]\n"
    "      --fec-file=<file>[/]      read fec file from <file> or directory\n"
    "  -i, --ignore-errors           ignore non-fatal errors\n"
    "  -k, --keep                    keep (don't delete) input files\n"
    "  -l, --list                    print (un)compressed file sizes\n"
    "  -m, --merge                   repair errors in file using several copies\n"
    "  -n, --threads=<n>             set number of threads for fec create [%ld]\n"
    "  -o, --output=<file>[/]        place the output into <file> or directory\n"
    "  -q, --quiet                   suppress all messages\n"
    "  -r, --recursive               (fec) operate recursively on directories\n"
    "  -R, --dereference-recursive   (fec) recursively follow symbolic links\n"
    "  -s, --split                   split multimember file in single-member files\n"
    "  -t, --test                    test compressed file integrity\n"
    "  -v, --verbose                 be verbose (a 2nd -v gives more)\n"
    "      --append=<file>           append <file> as trailing data\n"
    "      --dump=<list>:d:e:t       dump members, damaged, empty, tdata to stdout\n"
    "      --remove=<list>:d:e:t     remove members, tdata from files in place\n"
    "      --strip=<list>:d:e:t      copy files to stdout stripping members given\n"
    "      --loose-trailing          allow trailing data seeming corrupt header\n"
    "      --nonzero-repair          repair in place a nonzero first LZMA byte\n", num_online );
  if( verbosity >= 1 ) std::fputs( "\nDebug options for experts:\n"
    "  -E, --debug-reproduce=<range>[,ss]  set range to 0 and try to reproduce file\n"
    "  -F, --fec=dc<n>                   test repair combinations of n zeroed blocks\n"
    "  -F, --fec=dz<range>[:<range>]...  test repair zeroed block(s) at range(s)\n"
    "  -F, --fec=dZ<size>[,<delta>]      test repair zeroed blocks of size <size>\n"
    "  -M, --md5sum                      print the MD5 digests of the input files\n"
    "  -S, --nrep-stats[=<val>]          print stats of N-byte repeated sequences\n"
    "  -U, --unzcrash=1|B<size>          test 1-bit or block errors in input file\n"
    "  -W, --debug-decompress=<pos>,<val>  set pos to val and decompress to stdout\n"
    "  -X, --show-packets[=<pos>,<val>]  show in stdout the decoded LZMA packets\n"
    "  -Y, --debug-delay=<range>         find max error detection delay in <range>\n"
    "  -Z, --debug-byte-repair=<pos>,<val>  test repair one-byte error at <pos>\n"
    "      --check=<size>                check creation of FEC decode matrix\n"
    "      --debug=<level>               print parallel FEC statistics to stderr\n"
    "      --gf16                        use GF(2^16) to create fec files\n"
    "      --random                      create fec files with random block numbers\n", stdout );
  std::fputs(
    "\nIf no file names are given, or if a file is '-', lziprecover decompresses\n"
    "from standard input to standard output.\n"
    "Numbers may contain underscore separators between groups of digits and\n"
    "may be followed by a SI or binary multiplier: 1_234_567kB, 4KiB.\n"
    "The argument to --fec=create may be a number of blocks (-Fc20), a\n"
    "percentage (-Fc5%), or a size in bytes (-Fc10KiB).\n"
    "\nTo extract all the files from archive 'foo.tar.lz', use the commands\n"
    "'tar -xf foo.tar.lz' or 'lziprecover -cd foo.tar.lz | tar -xf -'.\n"
    "\n*Exit status*\n"
    "0 for a normal exit, 1 for environmental problems(file not found, invalid\n"
    "command-line options, I/O errors, etc), 2 to indicate a corrupt or invalid\n"
    "input file, 3 for an internal consistency error (e.g., bug) which caused\n"
    "lziprecover to panic.\n"
    "\nReport bugs to lzip-bug@nongnu.org\n"
    "Lziprecover home page: http://www.nongnu.org/lzip/lziprecover.html\n", stdout );
  }

} // end namespace

void Pretty_print::operator()( const char * const msg, FILE * const f ) const
  {
  if( verbosity < 0 ) return;
  if( first_post )
    {
    first_post = false;
    std::fputs( padded_name.c_str(), f );
    if( !msg ) std::fflush( f );
    }
  if( msg ) std::fprintf( f, "%s\n", msg );
  }


const char * bad_version( const unsigned version )
  {
  static char buf[80];
  snprintf( buf, sizeof buf, "Version %u member format not supported.",
            version );
  return buf;
  }


const char * format_ds( const unsigned dictionary_size )
  {
  enum { bufsize = 16, factor = 1024, n = 3 };
  static char buf[bufsize];
  const char * const prefix[n] = { "Ki", "Mi", "Gi" };
  const char * p = "";
  const char * np = "  ";
  unsigned num = dictionary_size;
  bool exact = num % factor == 0;

  for( int i = 0; i < n && ( num > 9999 || ( exact && num >= factor ) ); ++i )
    { num /= factor; if( num % factor != 0 ) exact = false;
      p = prefix[i]; np = ""; }
  snprintf( buf, bufsize, "%s%4u %sB", np, num, p );
  return buf;
  }


void show_header( const unsigned dictionary_size )
  {
  std::fprintf( stderr, "dict %s, ", format_ds( dictionary_size ) );
  }


#include "main_common.cc"


// Colon-separated list of "damaged", "empty", "tdata", [r][^]<list> (1 1,3-5)
void Member_list::parse_ml( const char * const arg,
                            const char * const option_name,
                            Cl_options & cl_opts )
  {
  const char * p = arg;			// points to current char
  while( true )
    {
    const char * tp = p;		// points to terminator (':' or '\0')
    while( *tp && *tp != ':' ) ++tp;
    const unsigned len = tp - p;
    if( std::islower( *(const unsigned char *)p ) )
      {
      if( len <= 7 && std::strncmp( "damaged", p, len ) == 0 )
        { damaged = true; cl_opts.ignore_errors = true; goto next; }
      if( len <= 5 && std::strncmp( "empty", p, len ) == 0 )
        { empty = true; goto next; }
      if( len <= 5 && std::strncmp( "tdata", p, len ) == 0 )
        { tdata = true; cl_opts.ignore_trailing = true; goto next; }
      }
    {
    const bool reverse = *p == 'r';
    if( reverse ) ++p;
    if( *p == '^' ) { ++p; if( reverse ) rin = false; else in = false; }
    std::vector< Block > * rvp = reverse ? &rrange_vector : &range_vector;
    while( std::isdigit( *(const unsigned char *)p ) )
      {
      const char * tail;
      const long pos = getnum( p, option_name, 0, 1, LONG_MAX, &tail ) - 1;
      if( rvp->size() && pos < rvp->back().end() ) break;
      const long size = (*tail == '-') ?
        getnum( tail + 1, option_name, 0, pos + 1, LONG_MAX, &tail ) - pos : 1;
      rvp->push_back( Block( pos, size ) );
      if( tail == tp ) goto next;
      if( *tail == ',' ) p = tail + 1; else break;
      }
    }
    show_option_error( arg, "Invalid list of members in", option_name );
    std::exit( 1 );
next:
    if( *(p = tp) != 0 ) ++p; else return;
    }
  }


namespace {

const char * const inv_arg_msg = "Invalid argument in";

// Recognized formats: <digit> 'a' m[<match_length>]
int parse_lzip_level( const char * const arg, const char * const option_name )
  {
  if( *arg == 'a' || std::isdigit( *(const unsigned char *)arg ) ) return *arg;
  if( *arg != 'm' )
    { show_option_error( arg, inv_arg_msg, option_name ); std::exit( 1 ); }
  if( arg[1] == 0 ) return -1;
  return -getnum( arg + 1, option_name, 0, min_match_len_limit, max_match_len );
  }


/* Recognized format: <range>[,<sector_size>]
   range formats: <begin> <begin>-<end> <begin>,<size> ,<size>
   Return a pointer to the byte following the bytes parsed.
*/
const char * parse_range( const char * const arg, const char * const pn,
                          Block & range, int * const sector_sizep = 0 )
  {
  const char * tail = arg;
  long long value =
    ( *arg == ',' ) ? 0 : getnum( arg, pn, 0, 0, INT64_MAX - 1, &tail );
  if( *tail == 0 || *tail == ',' || *tail == '-' || *tail == ':' )
    {
    range.pos( value );
    if( *tail == 0 || *tail == ':' )
      { range.size( INT64_MAX - value ); return tail; }
    const bool is_size = *tail == ',';
    if( sector_sizep && tail[1] == ',' ) { value = INT64_MAX - value; ++tail; }
    else value = getnum( tail + 1, pn, 0, 1, INT64_MAX, &tail );	// size
    if( !is_size && value <= range.pos() )
      { show_option_error( arg, "Begin must be < end in", pn ); std::exit( 1 ); }
    if( !is_size ) value -= range.pos();		// size = end - pos
    if( INT64_MAX - value >= range.pos() )
      {
      range.size( value );
      if( sector_sizep && *tail == ',' )
        *sector_sizep = getnum( tail + 1, pn, 0, 8, INT_MAX, &tail );
      return tail;
      }
    }
  show_option_error( arg, "Invalid decompression range in", pn );
  std::exit( 1 );
  }


// Insert b in its place or merge it with contiguous or overlapping blocks.
void insert_block_sorted( std::vector< Block > & block_vector, const Block & b )
  {
  if( block_vector.empty() || b.pos() > block_vector.back().end() )
    { block_vector.push_back( b ); return; }	// append at the end
  const long long pos = b.pos();
  const long long end = b.end();
  for( unsigned long i = 0; i < block_vector.size(); ++i )
    if( end <= block_vector[i].pos() )		// maybe insert b before i
      {
      if( end < block_vector[i].pos() &&
          ( i == 0 || pos > block_vector[i-1].end() ) )
        { block_vector.insert( block_vector.begin() + i, b ); return; }
      break;
      }
  for( unsigned long i = 0; i < block_vector.size(); ++i )
    if( block_vector[i].touches( b ) )	// merge b with blocks touching it
      {
      unsigned long j = i;	// indexes of first/last mergeable blocks
      while( j + 1 < block_vector.size() && block_vector[j+1].touches( b ) )
        ++j;
      const long long new_pos = std::min( pos, block_vector[i].pos() );
      const long long new_end = std::max( end, block_vector[j].end() );
      block_vector[i].assign( new_pos, new_end - new_pos );
      if( i < j ) block_vector.erase( block_vector.begin() + i + 1,
                                      block_vector.begin() + j + 1 );
      break;
      }
  }

/* Recognized format: <range>[:<range>]...
   Allow unordered, overlapping ranges. Return ranges sorted and merged. */
void parse_range_vector( const char * const arg, const char * const pn,
                         std::vector< Block > & range_vector )
  {
  Block range( 0, 0 );
  const char * p = arg;
  while( true )
    {
    p = parse_range( p, pn, range );
    insert_block_sorted( range_vector, range );
    if( *p == 0 ) return;
    if( *p == ':' ) { ++p; if( *p == 0 ) return; else continue; }
    show_option_error( p, "Extra characters in", pn );
    std::exit( 1 );
    }
  }


void no_to_stdout( const bool to_stdout )
  {
  if( to_stdout )
    { show_error( "'--stdout' not allowed." ); std::exit( 1 ); }
  }

void one_file( const int files )
  {
  if( files == 1 ) return;
  show_error( "You must specify exactly 1 file.", 0, true );
  std::exit( 1 );
  }

void at_least_one_file( const int files )
  {
  if( files >= 1 ) return;
  show_error( "You must specify at least 1 file.", 0, true );
  std::exit( 1 );
  }


void set_mode( Mode & program_mode, const Mode new_mode )
  {
  if( program_mode != m_none && program_mode != new_mode )
    {
    show_error( "Only one operation can be specified.", 0, true );
    std::exit( 1 );
    }
  program_mode = new_mode;
  }


// return true if arg is a non-empty prefix of target
bool compare_prefix( const char * const arg, const char * const target,
                     const char * const option_name = 0,
                     unsigned long * const fb_or_pctp = 0, char * fctypep = 0 )
  {
  if( *arg && *arg == *target )
    for( int i = 1; i < INT_MAX; ++i )
      {
      if( arg[i] == 0 ) return true;
      if( fb_or_pctp && std::isdigit( arg[i] ) )
        {
        const char * tail = arg + i;
        *fb_or_pctp = getnum( tail, option_name, 0, 0, LONG_MAX, &tail );
        if( *tail == 0 )
          { if( tail[-1] == 'B' ) { *fctypep = fc_bytes; return true; }
            if( std::isdigit( tail[-1] ) )
              { if( *fb_or_pctp <= max_nk16 )			// else error
                  { *fctypep = fc_blocks; return true; }
                getnum( arg + 1, option_name, 0, 0, max_nk16 ); } }
        else if( *fb_or_pctp <= 100 && std::isdigit( tail[-1] ) )
          { if( *tail == '%' && tail[1] == 0 )
              { *fb_or_pctp *= 1000; *fctypep = fc_percent; return true; }
            if( *tail == '.' && std::isdigit( *++tail ) )
              { for( int j = 0; j < 3; ++j ) { *fb_or_pctp *= 10;
                  if( std::isdigit( *tail ) ) *fb_or_pctp += *tail++ - '0'; }
                if( *tail >= '5' && *tail <= '9' ) { ++tail; ++*fb_or_pctp; }
                while( std::isdigit( *tail ) ) { ++tail;
                  if( *fb_or_pctp == 0 && tail[-1] > '0' ) *fb_or_pctp = 1; }
                if( *tail == '%' && tail[1] == 0 && *fb_or_pctp <= 100000 )
                  { *fctypep = fc_percent; return true; } } }
        return false;
        }
      if( arg[i] != target[i] ) break;
      }
  return false;
  }


void parse_fec( const char * const arg, const char * const option_name,
                Mode & program_mode, unsigned long & fb_or_pct,
                unsigned & cblocks, unsigned & delta, int & sector_size,
                std::vector< Block > & range_vector, char & fctype )
  {
  if( compare_prefix( arg, "create", option_name, &fb_or_pct, &fctype ) )
    set_mode( program_mode, m_fec_create );
  else if( compare_prefix( arg, "repair" ) )
    set_mode( program_mode, m_fec_repair );
  else if( compare_prefix( arg, "test" ) )
    set_mode( program_mode, m_fec_test );
  else if( compare_prefix( arg, "list" ) )
    set_mode( program_mode, m_fec_list );
  else if( *arg == 'd' && arg[1] == 'c' )
    { const char * tail = arg + 2;
      cblocks = getnum( tail, option_name, 0, 1, max_nk16, &tail );
      if( *tail != 0 )
        { show_option_error( arg, inv_arg_msg, option_name ); std::exit( 1 ); }
      set_mode( program_mode, m_fec_dc ); }
  else if( *arg == 'd' && arg[1] == 'f' )
    set_mode( program_mode, m_fec_df );
  else if( *arg == 'd' && arg[1] == 'z' )
    { parse_range_vector( arg + 2, option_name, range_vector );
      set_mode( program_mode, m_fec_dz ); }
  else if( *arg == 'd' && arg[1] == 'Z' )
    { const char * tail = arg + 2;
      sector_size = getnum( tail, option_name, 0, 1, INT_MAX, &tail );
      if( *tail == 0 ) delta = sector_size;
      else if( *tail == ',' )
        delta = getnum( tail + 1, option_name, 0, 1, INT_MAX );
      else { show_option_error( arg, "Comma expected before delta in",
                                option_name ); std::exit( 1 ); }
      set_mode( program_mode, m_fec_dZ ); }
  else
    { show_option_error( arg, inv_arg_msg, option_name ); std::exit( 1 ); }
  }


void parse_u( const char * const arg, const char * const option_name,
              Mode & program_mode, int & sector_size )
  {
  if( *arg == '1' ) set_mode( program_mode, m_unzcrash_bit );
  else if( *arg == 'B' )
    { set_mode( program_mode, m_unzcrash_block );
      sector_size = getnum( arg + 1, option_name, 0, 1, INT_MAX ); }
  else
    { show_option_error( arg, inv_arg_msg, option_name ); std::exit( 1 ); }
  }


int extension_index( const std::string & name )
  {
  for( int eindex = 0; known_extensions[eindex].from; ++eindex )
    {
    const std::string ext( known_extensions[eindex].from );
    if( name.size() > ext.size() &&
        name.compare( name.size() - ext.size(), ext.size(), ext ) == 0 )
      return eindex;
    }
  return -1;
  }


void set_a_outname( const std::string & name )
  {
  output_filename = name;
  if( name.size() > 5 && name.compare( name.size() - 5, 5, ".lzma" ) == 0 )
    output_filename.erase( name.size() - 2 );
  else if( name.size() > 4 && name.compare( name.size() - 4, 4, ".tlz" ) == 0 )
    output_filename.insert( name.size() - 2, "ar." );
  else if( name.size() <= 3 || name.compare( name.size() - 3, 3, ".lz" ) != 0 )
    output_filename += known_extensions[0].from;
  }


void set_d_outname( const std::string & name, const int eindex )
  {
  if( eindex >= 0 )
    {
    const std::string from( known_extensions[eindex].from );
    if( name.size() > from.size() )
      {
      output_filename.assign( name, 0, name.size() - from.size() );
      output_filename += known_extensions[eindex].to;
      return;
      }
    }
  output_filename = name; output_filename += ".out";
  if( verbosity >= 1 )
    std::fprintf( stderr, "%s: %s: Can't guess original name -- using '%s'\n",
                  program_name, name.c_str(), output_filename.c_str() );
  }

} // end namespace

int open_instream( const char * const name, struct stat * const in_statsp,
                   const bool one_to_one, const bool reg_only )
  {
  int infd = open( name, O_RDONLY | O_BINARY );
  if( infd < 0 )
    show_file_error( name, "Can't open input file", errno );
  else
    {
    const int i = fstat( infd, in_statsp );
    const mode_t mode = in_statsp->st_mode;
    const bool can_read = i == 0 && !reg_only &&
                          ( S_ISBLK( mode ) || S_ISCHR( mode ) ||
                            S_ISFIFO( mode ) || S_ISSOCK( mode ) );
    if( i != 0 || ( !S_ISREG( mode ) && ( !can_read || one_to_one ) ) )
      {
      if( verbosity >= 0 )
        std::fprintf( stderr, "%s: %s: Input file is not a regular file%s.\n",
                      program_name, name, ( can_read && one_to_one ) ?
                      ",\n  and neither '-c' nor '-o' were specified" : "" );
      close( infd );
      infd = -1;
      }
    }
  return infd;
  }


int open_truncable_stream( const char * const name,
                           struct stat * const in_statsp )
  {
  int fd = open( name, O_RDWR | O_BINARY );
  if( fd < 0 )
    show_file_error( name, "Can't open file in R/W mode", errno );
  else
    {
    const int i = fstat( fd, in_statsp );
    const mode_t mode = in_statsp->st_mode;
    if( i != 0 || !S_ISREG( mode ) )
      { show_file_error( name, "Not a regular file." ); close( fd ); fd = -1; }
    }
  return fd;
  }

namespace {

bool make_dirs( const std::string & name )
  {
  int i = name.size();
  while( i > 0 && name[i-1] != '/' ) --i;	// remove last component
  while( i > 0 && name[i-1] == '/' ) --i;	// remove slash(es)
  const int dirsize = i;	// size of dirname without trailing slash(es)

  for( i = 0; i < dirsize; )	// if dirsize == 0, dirname is '/' or empty
    {
    while( i < dirsize && name[i] == '/' ) ++i;
    const int first = i;
    while( i < dirsize && name[i] != '/' ) ++i;
    if( first < i )
      {
      const std::string partial( name, 0, i );
      const mode_t mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
      struct stat st;
      if( stat( partial.c_str(), &st ) == 0 )
        { if( !S_ISDIR( st.st_mode ) ) { errno = ENOTDIR; return false; } }
      else if( mkdir( partial.c_str(), mode ) != 0 && errno != EEXIST )
        return false;		// if EEXIST, another process created the dir
      }
    }
  return true;
  }

const char * const force_msg =
  "Output file already exists. Use '--force' to overwrite it.";

unsigned char xdigit( const unsigned value )	// hex digit for 'value'
  { return (value <= 9) ? '0' + value : (value <= 15) ? 'A' + value - 10 : 0; }

} // end namespace

bool open_outstream( const bool force, const bool protect,
                     const bool rw, const bool skipping, const bool to_file )
  {
  const mode_t usr_rw = S_IRUSR | S_IWUSR;
  const mode_t all_rw = usr_rw | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
  const mode_t outfd_mode = protect ? usr_rw : all_rw;
  int flags = O_CREAT | ( rw ? O_RDWR : O_WRONLY ) | O_BINARY;
  if( force ) flags |= O_TRUNC; else flags |= O_EXCL;

  outfd = -1;
  if( output_filename.size() && output_filename.end()[-1] == '/' )
    errno = EISDIR;
  else {
    if( ( !protect || to_file ) && !make_dirs( output_filename ) )
      { show_file_error( output_filename.c_str(),
          "Error creating intermediate directory", errno ); return false; }
    outfd = open( output_filename.c_str(), flags, outfd_mode );
    if( outfd >= 0 ) { delete_output_on_interrupt = true; return true; }
    if( errno == EEXIST )
      { show_file_error( output_filename.c_str(), skipping ?
        "Output file already exists, skipping." : force_msg ); return false; }
    }
  show_file_error( output_filename.c_str(), "Can't create output file", errno );
  return false;
  }


bool output_file_exists()
  {
  struct stat st;
  if( stat( output_filename.c_str(), &st ) == 0 )
    { show_file_error( output_filename.c_str(), force_msg ); return true; }
  return false;
  }


void set_signals( void (*action)(int) )
  {
  std::signal( SIGHUP, action );
  std::signal( SIGINT, action );
  std::signal( SIGTERM, action );
  }


void cleanup_and_fail( const int retval )
  {
  set_signals( SIG_IGN );			// ignore signals
  cleanup_mutex_lock();		// only one thread can delete and exit
  if( delete_output_on_interrupt )
    {
    delete_output_on_interrupt = false;
    show_file_error( output_filename.c_str(),
                     "Deleting output file, if it exists." );
    if( outfd >= 0 ) { close( outfd ); outfd = -1; }
    if( std::remove( output_filename.c_str() ) != 0 && errno != ENOENT )
      show_error( "warning: deletion of output file failed", errno );
    }
  std::exit( retval );
  }


bool check_tty_out()
  {
  if( isatty( outfd ) )
    { show_file_error( output_filename.size() ?
                       output_filename.c_str() : "(stdout)",
                       "I won't write compressed data to a terminal." );
      return false; }
  return true;
  }


void format_trailing_bytes( const uint8_t * const data, const int size,
                            std::string & msg )
  {
  for( int i = 0; i < size; ++i )
    {
    msg += xdigit( data[i] >> 4 );
    msg += xdigit( data[i] & 0x0F );
    msg += ' ';
    }
  msg += '\'';
  for( int i = 0; i < size; ++i )
    msg += std::isprint( data[i] ) ? data[i] : '.';
  msg += '\'';
  }

namespace {

extern "C" void signal_handler( int )
  {
  show_error( "Control-C or similar caught, quitting." );
  cleanup_and_fail( 1 );
  }


bool check_tty_in( const char * const input_filename, const int infd,
                   const Mode program_mode, int & retval )
  {
  if( isatty( infd ) )			// all modes read compressed data
    { show_file_error( input_filename,
                       "I won't read compressed data from a terminal." );
      close( infd ); set_retval( retval, 2 );
      if( program_mode != m_test ) cleanup_and_fail( retval );
      return false; }
  return true;
  }

bool check_tty_out( const Mode program_mode )
  { return program_mode != m_alone_to_lz || ::check_tty_out(); }


// Set permissions, owner, and times.
void close_and_set_permissions( const struct stat * const in_statsp )
  {
  bool warning = false;
  if( in_statsp )
    {
    const mode_t mode = in_statsp->st_mode;
    // fchown in many cases returns with EPERM, which can be safely ignored.
    if( fchown( outfd, in_statsp->st_uid, in_statsp->st_gid ) == 0 )
      { if( fchmod( outfd, mode ) != 0 ) warning = true; }
    else
      if( errno != EPERM ||
          fchmod( outfd, mode & ~( S_ISUID | S_ISGID | S_ISVTX ) ) != 0 )
        warning = true;
    }
  if( close( outfd ) != 0 )
    { show_file_error( output_filename.c_str(), "Error closing output file",
                       errno ); cleanup_and_fail( 1 ); }
  outfd = -1;
  delete_output_on_interrupt = false;
  if( in_statsp )
    {
    struct utimbuf t;
    t.actime = in_statsp->st_atime;
    t.modtime = in_statsp->st_mtime;
    if( utime( output_filename.c_str(), &t ) != 0 ) warning = true;
    }
  if( warning && verbosity >= 1 )
    show_file_error( output_filename.c_str(),
                     "warning: can't change output file attributes", errno );
  }


bool show_trailing_data( const uint8_t * const data, const int size,
                         const Pretty_print & pp, const bool all,
                         const int ignore_trailing )	// -1 = show
  {
  if( verbosity >= 4 || ignore_trailing <= 0 )
    {
    std::string msg;
    if( !all ) msg = "first bytes of ";
    msg += "trailing data = ";
    format_trailing_bytes( data, size, msg );
    pp( msg.c_str() );
    if( ignore_trailing == 0 ) show_file_error( pp.name(), trailing_msg );
    }
  return ignore_trailing > 0;
  }


int decompress( const unsigned long long cfile_size, const int infd,
                const Cl_options & cl_opts, const Pretty_print & pp,
                const bool from_stdin, const bool testing )
  {
  unsigned long long partial_file_pos = 0;
  Range_decoder rdec( infd );
  int retval = 0;
  bool empty = false, multi = false;

  for( bool first_member = true; ; first_member = false )
    {
    Lzip_header header;
    rdec.reset_member_position();
    const int size = rdec.read_header_carefully( header, cl_opts.ignore_errors );
    if( rdec.finished() ||			// End Of File
        ( size < header.size && !rdec.find_header( header ) ) )
      {
      if( first_member )
        { show_file_error( pp.name(), "File ends unexpectedly at member header." );
          retval = 2; }
      else if( header.check_prefix( size ) )
        { pp( "Truncated header in multimember file." );
          show_trailing_data( header.data, size, pp, true, -1 ); retval = 2; }
      else if( size > 0 && !show_trailing_data( header.data, size, pp, true,
                                 cl_opts.ignore_trailing ) ) retval = 2;
      break;
      }
    if( !header.check_magic() )
      {
      if( first_member )
        { show_file_error( pp.name(), bad_magic_msg ); retval = 2; }
      else if( !cl_opts.loose_trailing && header.check_corrupt() )
        { pp( corrupt_mm_msg );
          show_trailing_data( header.data, size, pp, false, -1 ); retval = 2; }
      else if( !show_trailing_data( header.data, size, pp, false,
                                    cl_opts.ignore_trailing ) ) retval = 2;
      if( cl_opts.ignore_errors ) { pp.reset(); continue; } else break;
      }
    if( !header.check_version() )
      { pp( bad_version( header.version() ) ); retval = 2;
        if( cl_opts.ignore_errors ) { pp.reset(); continue; } else break; }
    const unsigned dictionary_size = header.dictionary_size();
    if( !isvalid_ds( dictionary_size ) )
      { pp( bad_dict_msg ); retval = 2;
        if( cl_opts.ignore_errors ) { pp.reset(); continue; } else break; }

    if( verbosity >= 2 || ( verbosity == 1 && first_member ) ) pp();

    LZ_decoder decoder( rdec, dictionary_size, outfd );
    show_dprogress( cfile_size, partial_file_pos, &rdec, &pp );	// init
    const int result = decoder.decode_member( pp, cl_opts.ignore_errors );
    partial_file_pos += rdec.member_position();
    if( result != 0 )
      {
      if( verbosity >= 0 && result <= 2 )
        {
        pp();
        std::fprintf( stderr, "%s at pos %s\n", ( result == 2 ) ?
                      "File ends unexpectedly" : "Decoder error",
                      format_num3( partial_file_pos ) );
        }
      else if( result == 5 ) pp( nonzero_msg );
      retval = 2;
      if( cl_opts.ignore_errors ) { pp.reset(); continue; } else break;
      }
    if( !from_stdin && !cl_opts.ignore_errors ) { multi = !first_member;
      if( decoder.data_position() == 0 ) empty = true; }
    if( verbosity >= 2 )
      { std::fputs( testing ? "ok\n" : "done\n", stderr ); pp.reset(); }
    }
  if( verbosity == 1 && retval == 0 )
    std::fputs( testing ? "ok\n" : "done\n", stderr );
  if( empty && multi && retval == 0 )
    { show_file_error( pp.name(), empty_member_msg ); retval = 2; }
  if( retval == 2 && cl_opts.ignore_errors ) retval = 0;
  return retval;
  }

} // end namespace

void set_signal_handler() { set_signals( signal_handler ); }

bool close_outstream( const struct stat * const in_statsp )
  {
  if( delete_output_on_interrupt ) close_and_set_permissions( in_statsp );
  if( outfd >= 0 && close( outfd ) != 0 )
    { show_error( "Error closing stdout", errno ); return false; }
  outfd = -1;
  return true;
  }


std::string insert_fixed( std::string name, const bool append_lz )
  {
  if( name.size() > 7 && name.compare( name.size() - 7, 7, ".tar.lz" ) == 0 )
    name.insert( name.size() - 7, "_fixed" );
  else if( name.size() > 3 && name.compare( name.size() - 3, 3, ".lz" ) == 0 )
    name.insert( name.size() - 3, "_fixed" );
  else if( name.size() > 4 && name.compare( name.size() - 4, 4, ".tlz" ) == 0 )
    name.insert( name.size() - 4, "_fixed" );
  else if( name.size() > 4 && !append_lz &&
           name.compare( name.size() - 4, 4, ".tar" ) == 0 )
    name.insert( name.size() - 4, "_fixed" );
  else if( append_lz ) name += "_fixed.lz";
  else name += "_fixed";
  return name;
  }


void show_2file_error( const char * const msg1, const char * const name1,
                       const char * const name2, const char * const msg2 )
  {
  if( verbosity >= 0 )
    std::fprintf( stderr, "%s: %s '%s' and '%s' %s\n",
                  program_name, msg1, name1, name2, msg2 );
  }


void show_dprogress( const unsigned long long cfile_size,
                     const unsigned long long partial_size,
                     const Range_decoder * const d,
                     const Pretty_print * const p )
  {
  static unsigned long long csize = 0;		// file_size / 100
  static unsigned long long psize = 0;
  static const Range_decoder * rdec = 0;
  static const Pretty_print * pp = 0;
  static int counter = 0;
  static bool enabled = true;

  if( !enabled ) return;
  if( p )					// initialize static vars
    {
    if( verbosity < 2 || !isatty( STDERR_FILENO ) ) { enabled = false; return; }
    csize = cfile_size; psize = partial_size; rdec = d; pp = p; counter = 0;
    }
  if( rdec && pp && --counter <= 0 )
    {
    const unsigned long long pos = psize + rdec->member_position();
    counter = 7;		// update display every 114688 bytes
    if( csize > 0 )
      std::fprintf( stderr, "%4llu%%  %.1f MB\r", pos / csize, pos / 1000000.0 );
    else
      std::fprintf( stderr, "  %.1f MB\r", pos / 1000000.0 );
    pp->reset(); (*pp)();			// restore cursor position
    }
  }


int main( const int argc, const char * const argv[] )
  {
  std::vector< Block > range_vector;
  Block range( 0, 0 );
  int sector_size = INT_MAX;		// default larger than practical range
  Bad_byte bad_byte;
  Member_list member_list;
  std::string append_filename;
  std::string cl_fec_filename;
  std::string default_output_filename;
  const char * lzip_name = "lzip";		// default is lzip
  const char * reference_filename = 0;
  unsigned long fb_or_pct = 8;	// fec blocks, bytes (B), or 0.001% to 100%
  unsigned cblocks = 0;		// blocks per combination in fec_dc
  unsigned cl_block_size = 0;	// make fbs a multiple of this
  unsigned num_workers = 0;	// start this many worker threads
  unsigned delta = 0;		// set to 0 to keep gcc 6.1.0 quiet
  Mode program_mode = m_none;
  int lzip_level = 0;		//  0 = test all levels and match lengths
				// '0'..'9' = level, 'a' = all levels
				// -5..-273 = match length, -1 = all lengths
  int repeated_byte = -1;	// 0 to 255, or -1 for all values
  Cl_options cl_opts;		// command-line options
  char debug_level = 0;
  char fctype = fc_blocks;	// type of value in fb_or_pct
  char fec_level = 9;		// fec fragmentation level, default = "-9"
  char recursive = 0;		// 1 = '-r', 2 = '-R'
  bool cl_gf16 = false;
  bool fec_random = false;
  bool force = false;
  bool keep_input_files = false;
  bool to_stdout = false;
  if( argc > 0 ) invocation_name = argv[0];

  enum { opt_app = 256, opt_chk, opt_dbg, opt_du, opt_ff, opt_g16, opt_lt,
         opt_lzl, opt_lzn, opt_nzr, opt_ref, opt_rem, opt_rnd, opt_st };
  const Arg_parser::Option options[] =
    {
    { '0', 0,                       Arg_parser::no  },
    { '1', 0,                       Arg_parser::no  },
    { '2', 0,                       Arg_parser::no  },
    { '3', 0,                       Arg_parser::no  },
    { '4', 0,                       Arg_parser::no  },
    { '5', 0,                       Arg_parser::no  },
    { '6', 0,                       Arg_parser::no  },
    { '7', 0,                       Arg_parser::no  },
    { '8', 0,                       Arg_parser::no  },
    { '9', 0,                       Arg_parser::no  },
    { 'a', "trailing-error",        Arg_parser::no  },
    { 'A', "alone-to-lz",           Arg_parser::no  },
    { 'b', "block-size",            Arg_parser::yes },
    { 'B', "byte-repair",           Arg_parser::no  },
    { 'B', "repair",                Arg_parser::no  },
    { 'c', "stdout",                Arg_parser::no  },
    { 'd', "decompress",            Arg_parser::no  },
    { 'D', "range-decompress",      Arg_parser::yes },
    { 'e', "reproduce",             Arg_parser::no  },
    { 'E', "debug-reproduce",       Arg_parser::yes },
    { 'f', "force",                 Arg_parser::no  },
    { 'F', "fec",                   Arg_parser::yes },
    { 'h', "help",                  Arg_parser::no  },
    { 'i', "ignore-errors",         Arg_parser::no  },
    { 'k', "keep",                  Arg_parser::no  },
    { 'l', "list",                  Arg_parser::no  },
    { 'm', "merge",                 Arg_parser::no  },
    { 'M', "md5sum",                Arg_parser::no  },
    { 'n', "threads",               Arg_parser::yes },
    { 'o', "output",                Arg_parser::yes },
    { 'q', "quiet",                 Arg_parser::no  },
    { 'r', "recursive",             Arg_parser::no  },
    { 'R', "dereference-recursive", Arg_parser::no  },
    { 's', "split",                 Arg_parser::no  },
    { 'S', "nrep-stats",            Arg_parser::maybe },
    { 't', "test",                  Arg_parser::no  },
    { 'U', "unzcrash",              Arg_parser::yes },
    { 'v', "verbose",               Arg_parser::no  },
    { 'V', "version",               Arg_parser::no  },
    { 'W', "debug-decompress",      Arg_parser::yes },
    { 'X', "show-packets",          Arg_parser::maybe },
    { 'Y', "debug-delay",           Arg_parser::yes },
    { 'Z', "debug-byte-repair",     Arg_parser::yes },
    { opt_app, "append",            Arg_parser::yes },
    { opt_chk, "check",             Arg_parser::yes },
    { opt_dbg, "debug",             Arg_parser::yes },
    { opt_du,  "dump",              Arg_parser::yes },
    { opt_ff,  "fec-file",          Arg_parser::yes },
    { opt_g16, "gf16",              Arg_parser::no  },
    { opt_lt,  "loose-trailing",    Arg_parser::no  },
    { opt_lzl, "lzip-level",        Arg_parser::yes },
    { opt_lzn, "lzip-name",         Arg_parser::yes },
    { opt_nzr, "nonzero-repair",    Arg_parser::no  },
    { opt_ref, "reference-file",    Arg_parser::yes },
    { opt_rem, "remove",            Arg_parser::yes },
    { opt_rnd, "random",            Arg_parser::no  },
    { opt_st,  "strip",             Arg_parser::yes },
    { 0, 0,                         Arg_parser::no  } };

  const Arg_parser parser( argc, argv, options );
  if( parser.error().size() )				// bad option
    { show_error( parser.error().c_str(), 0, true ); return 1; }

  const long num_online = std::max( 1L, sysconf( _SC_NPROCESSORS_ONLN ) );
  long max_workers = sysconf( _SC_THREAD_THREADS_MAX );
  if( max_workers < 1 || max_workers > INT_MAX / (int)sizeof (pthread_t) )
    max_workers = INT_MAX / sizeof (pthread_t);

  int argind = 0;
  for( ; argind < parser.arguments(); ++argind )
    {
    const int code = parser.code( argind );
    if( !code ) break;					// no more options
    const char * const pn = parser.parsed_name( argind ).c_str();
    const std::string & sarg = parser.argument( argind );
    const char * const arg = sarg.c_str();
    switch( code )
      {
      case '0': case '1': case '2': case '3': case '4': case '5':
      case '6': case '7': case '8': case '9': fec_level = code - '0'; break;
      case 'a': cl_opts.ignore_trailing = false; break;
      case 'A': set_mode( program_mode, m_alone_to_lz ); break;
      case 'b': cl_block_size = getnum( arg, pn, 0, min_fbs, max_unit_fbs ) &
                ( max_unit_fbs - min_fbs ); break;
      case 'B': set_mode( program_mode, m_byte_repair ); break;
      case 'c': to_stdout = true; break;
      case 'd': set_mode( program_mode, m_decompress ); break;
      case 'D': set_mode( program_mode, m_range_dec );
                parse_range( arg, pn, range ); break;
      case 'e': set_mode( program_mode, m_reproduce ); break;
      case 'E': set_mode( program_mode, m_reproduce );
                parse_range( arg, pn, range, &sector_size ); break;
      case 'f': force = true; break;
      case 'F': parse_fec( arg, pn, program_mode, fb_or_pct, cblocks, delta,
                           sector_size, range_vector, fctype ); break;
      case 'h': show_help( num_online ); return 0;
      case 'i': cl_opts.ignore_errors = true; break;
      case 'k': keep_input_files = true; break;
      case 'l': set_mode( program_mode, m_list ); break;
      case 'm': set_mode( program_mode, m_merge ); break;
      case 'M': set_mode( program_mode, m_md5sum ); break;
      case 'n': num_workers = getnum( arg, pn, 0, 1, max_workers ); break;
      case 'o': if( sarg == "-" ) to_stdout = true;
                else { default_output_filename = sarg; } break;
      case 'q': cl_verbosity = verbosity = -1; break;
      case 'r': recursive = 1; break;
      case 'R': recursive = 2; break;
      case 's': set_mode( program_mode, m_split ); break;
      case 'S': if( *arg ) repeated_byte = getnum( arg, pn, 0, 0, 255 );
                set_mode( program_mode, m_nrep_stats ); break;
      case 't': set_mode( program_mode, m_test ); break;
      case 'U': parse_u( arg, pn, program_mode, sector_size ); break;
      case 'v': if( verbosity < 4 ) ++verbosity; break;
      case 'V': show_version(); return 0;
      case 'W': set_mode( program_mode, m_debug_decompress );
                bad_byte.parse_bb( arg, pn ); break;
      case 'X': set_mode( program_mode, m_show_packets );
                if( *arg ) { bad_byte.parse_bb( arg, pn ); } break;
      case 'Y': set_mode( program_mode, m_debug_delay );
                parse_range( arg, pn, range ); break;
      case 'Z': set_mode( program_mode, m_debug_byte_repair );
                bad_byte.parse_bb( arg, pn ); break;
      case opt_app: set_mode( program_mode, m_append );
                    append_filename = sarg; break;
      case opt_chk: set_mode( program_mode, m_check );
                    cblocks = getnum( arg, pn, 0, 1, max_k16 ); break;
      case opt_dbg: debug_level = getnum( arg, pn, 0, 0, 3 ); break;
      case opt_du:  set_mode( program_mode, m_dump );
                    member_list.parse_ml( arg, pn, cl_opts ); break;
      case opt_ff:  cl_fec_filename = sarg; break;
      case opt_g16: cl_gf16 = true; break;
      case opt_lt:  cl_opts.loose_trailing = true; break;
      case opt_lzl: lzip_level = parse_lzip_level( arg, pn ); break;
      case opt_lzn: lzip_name = arg; break;
      case opt_nzr: set_mode( program_mode, m_nonzero_repair ); break;
      case opt_ref: reference_filename = arg; break;
      case opt_rem: set_mode( program_mode, m_remove );
                    member_list.parse_ml( arg, pn, cl_opts ); break;
      case opt_rnd: fec_random = true; break;
      case opt_st:  set_mode( program_mode, m_strip );
                    member_list.parse_ml( arg, pn, cl_opts ); break;
      default: internal_error( "uncaught option." );
      }
    } // end process options

#if defined __MSVCRT__ || defined __OS2__ || defined __DJGPP__
  setmode( STDIN_FILENO, O_BINARY );
  setmode( STDOUT_FILENO, O_BINARY );
#endif

  if( program_mode == m_none )
    {
    show_error( "You must specify the operation to be performed.", 0, true );
    return 1;
    }

  std::vector< std::string > filenames;
  bool filenames_given = false;
  for( ; argind < parser.arguments(); ++argind )
    {
    filenames.push_back( parser.argument( argind ) );
    if( filenames.back() != "-" ) filenames_given = true;
    }

  const char terminator = isatty( STDOUT_FILENO ) ? '\r' : '\n';
  try {
  switch( program_mode )
    {
    case m_none: internal_error( "invalid operation." ); break;
    case m_alone_to_lz: break;
    case m_append:
      at_least_one_file( filenames.size() );
      return append_tdata( filenames, append_filename, cl_opts, force );
    case m_byte_repair:
      one_file( filenames.size() ); no_to_stdout( to_stdout );
      return byte_repair( filenames[0], default_output_filename, cl_opts,
                          terminator, force );
    case m_check: return gf_check( cblocks, cl_gf16, fec_random );
    case m_debug_byte_repair:
      one_file( filenames.size() );
      return debug_byte_repair( filenames[0], cl_opts, bad_byte, terminator );
    case m_debug_decompress:
      one_file( filenames.size() );
      return debug_decompress( filenames[0], cl_opts, bad_byte, false );
    case m_debug_delay:
      one_file( filenames.size() );
      return debug_delay( filenames[0], cl_opts, range, terminator );
    case m_decompress: break;
    case m_dump:
    case m_strip:
      at_least_one_file( filenames.size() );
      return dump_members( filenames, default_output_filename, cl_opts,
                      member_list, force, program_mode == m_strip, to_stdout );
    case m_fec_create:
      at_least_one_file( filenames.size() );
      if( num_workers <= 0 ) num_workers = std::min( num_online, max_workers );
      return fec_create( filenames, default_output_filename, fb_or_pct,
                    cl_block_size, num_workers, debug_level, fctype, fec_level,
                    recursive, cl_gf16, fec_random, force, to_stdout );
    case m_fec_repair:
    case m_fec_test:
      at_least_one_file( filenames.size() );
      return fec_test( filenames, cl_fec_filename, default_output_filename,
                       recursive, force, cl_opts.ignore_errors,
                       program_mode == m_fec_repair, to_stdout );
    case m_fec_list:
      if( filenames.empty() ) filenames.push_back("-");
      return fec_list( filenames, cl_opts.ignore_errors );
    case m_fec_dc:
      one_file( filenames.size() );
      return fec_dc( filenames[0], cl_fec_filename, cblocks );
    case m_fec_df:
      if( filenames.empty() ) filenames.push_back("-");
      return fec_df( filenames );
    case m_fec_dz:
      one_file( filenames.size() );
      return fec_dz( filenames[0], cl_fec_filename, range_vector );
    case m_fec_dZ:
      one_file( filenames.size() );
      return fec_dZ( filenames[0], cl_fec_filename, delta, sector_size );
    case m_list: break;
    case m_md5sum: break;
    case m_merge: no_to_stdout( to_stdout );
      if( filenames.size() < 2 )
        { show_error( "You must specify at least 2 files.", 0, true ); return 1; }
      return merge_files( filenames, default_output_filename, cl_opts,
                          terminator, force );
    case m_nonzero_repair:
      at_least_one_file( filenames.size() );
      return nonzero_repair( filenames, cl_opts );
    case m_nrep_stats:
      return print_nrep_stats( filenames, cl_opts, repeated_byte );
    case m_range_dec:
      one_file( filenames.size() );
      return range_decompress( filenames[0], default_output_filename,
                               cl_opts, range, force, to_stdout );
    case m_remove:
      at_least_one_file( filenames.size() );
      return remove_members( filenames, cl_opts, member_list );
    case m_reproduce:
      one_file( filenames.size() ); no_to_stdout( to_stdout );
      if( !reference_filename || !reference_filename[0] )
        { show_error( "You must specify a reference file.", 0, true ); return 1; }
      if( range.size() > 0 )
        return debug_reproduce_file( filenames[0], lzip_name,
                 reference_filename, cl_opts, range, sector_size, lzip_level );
      else
        return reproduce_file( filenames[0], default_output_filename, lzip_name,
                 reference_filename, cl_opts, lzip_level, terminator, force );
    case m_show_packets:
      one_file( filenames.size() );
      return debug_decompress( filenames[0], cl_opts, bad_byte, true );
    case m_split:
      one_file( filenames.size() ); no_to_stdout( to_stdout );
      return split_file( filenames[0], default_output_filename, cl_opts, force );
    case m_test: break;
    case m_unzcrash_bit:
      one_file( filenames.size() );
      return lunzcrash_bit( filenames[0], cl_opts );
    case m_unzcrash_block:
      one_file( filenames.size() );
      return lunzcrash_block( filenames[0], cl_opts, sector_size );
    }
    }
  catch( std::bad_alloc & ) { show_error( mem_msg ); cleanup_and_fail( 1 ); }
  catch( Error & e ) { show_error( e.msg, errno ); cleanup_and_fail( 1 ); }

  if( filenames.empty() ) filenames.push_back("-");

  if( program_mode == m_list ) return list_files( filenames, cl_opts );
  if( program_mode == m_md5sum ) return md5sum_files( filenames );

  if( program_mode != m_alone_to_lz && program_mode != m_decompress &&
      program_mode != m_test )
    internal_error( "invalid decompressor operation." );

  if( program_mode == m_test ) to_stdout = false;	// apply overrides
  if( program_mode == m_test || to_stdout ) default_output_filename.clear();

  if( to_stdout && program_mode != m_test )	// check tty only once
    { outfd = STDOUT_FILENO; if( !check_tty_out( program_mode ) ) return 1; }
  else outfd = -1;

  const bool to_file = !to_stdout && program_mode != m_test &&
                       default_output_filename.size();
  if( !to_stdout && program_mode != m_test && ( filenames_given || to_file ) )
    set_signals( signal_handler );

  Pretty_print pp( filenames );

  unsigned failed_tests = 0;
  int retval = 0;
  const bool one_to_one = !to_stdout && program_mode != m_test && !to_file;
  bool stdin_used = false;
  struct stat in_stats;
  for( unsigned i = 0; i < filenames.size(); ++i )
    {
    std::string input_filename;
    int infd;
    const bool from_stdin = filenames[i] == "-";

    pp.set_name( filenames[i] );
    if( from_stdin )
      {
      if( stdin_used ) continue; else stdin_used = true;
      infd = STDIN_FILENO;
      if( !check_tty_in( pp.name(), infd, program_mode, retval ) ) continue;
      if( one_to_one ) { outfd = STDOUT_FILENO; output_filename.clear(); }
      }
    else
      {
      input_filename = filenames[i];
      infd = open_instream( input_filename.c_str(), &in_stats, one_to_one );
      if( infd < 0 ) { set_retval( retval, 1 ); continue; }
      if( !check_tty_in( pp.name(), infd, program_mode, retval ) ) continue;
      if( one_to_one )			// open outfd after checking infd
        {
        if( program_mode == m_alone_to_lz ) set_a_outname( input_filename );
        else set_d_outname( input_filename, extension_index( input_filename ) );
        if( !open_outstream( force, true ) )
          { close( infd ); set_retval( retval, 1 ); continue; }
        }
      }

    if( one_to_one && !check_tty_out( program_mode ) )
      { set_retval( retval, 1 ); return retval; }	// don't delete a tty

    if( to_file && outfd < 0 )		// open outfd after checking infd
      {
      output_filename = default_output_filename;
      if( !open_outstream( force, false ) || !check_tty_out( program_mode ) )
        return 1;	// check tty only once and don't try to delete a tty
      }

    const struct stat * const in_statsp =
      ( input_filename.size() && one_to_one ) ? &in_stats : 0;
    const unsigned long long cfile_size =
      ( input_filename.size() && S_ISREG( in_stats.st_mode ) ) ?
        ( in_stats.st_size + 99 ) / 100 : 0;
    int tmp;
    try {
      if( program_mode == m_alone_to_lz )
        tmp = alone_to_lz( infd, pp );
      else
        tmp = decompress( cfile_size, infd, cl_opts, pp, from_stdin,
                          program_mode == m_test );
      }
    catch( std::bad_alloc & ) { pp( mem_msg ); tmp = 1; }
    catch( Error & e ) { pp(); show_error( e.msg, errno ); tmp = 1; }
    if( close( infd ) != 0 )
      { show_file_error( pp.name(), "Error closing input file", errno );
        set_retval( tmp, 1 ); }
    set_retval( retval, tmp );
    if( tmp )
      { if( program_mode != m_test ) cleanup_and_fail( retval );
        else ++failed_tests; }

    if( delete_output_on_interrupt && one_to_one )
      close_and_set_permissions( in_statsp );
    if( input_filename.size() && !keep_input_files && one_to_one &&
        ( program_mode != m_decompress || !cl_opts.ignore_errors ) )
      std::remove( input_filename.c_str() );
    }
  if( delete_output_on_interrupt )					// -o
    close_and_set_permissions( ( retval == 0 && !stdin_used &&
      filenames_given && filenames.size() == 1 ) ? &in_stats : 0 );
  else if( outfd >= 0 && close( outfd ) != 0 )				// -c
    {
    show_error( "Error closing stdout", errno );
    set_retval( retval, 1 );
    }
  if( failed_tests > 0 && verbosity >= 1 && filenames.size() > 1 )
    std::fprintf( stderr, "%s: warning: %u %s failed the test.\n",
                  program_name, failed_tests,
                  ( failed_tests == 1 ) ? "file" : "files" );
  return retval;
  }
