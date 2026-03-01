/* Unzcrash - Tests robustness of decompressors to corrupted data.
   Inspired by unzcrash.c from Julian Seward's bzip2.
   Copyright (C) 2008-2026 Antonio Diaz Diaz.

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
   error (e.g., bug) which caused unzcrash to panic.
*/

#define _FILE_OFFSET_BITS 64

#include <algorithm>
#include <cerrno>
#include <climits>		// CHAR_BIT, SSIZE_MAX
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <stdint.h>		// SIZE_MAX
#include <unistd.h>
#include <sys/wait.h>

#include "arg_parser.h"
#include "common.h"

#if CHAR_BIT != 8
#error "Environments where CHAR_BIT != 8 are not supported."
#endif

#if ( defined  SIZE_MAX &&  SIZE_MAX < ULONG_MAX ) || \
    ( defined SSIZE_MAX && SSIZE_MAX <  LONG_MAX )
#error "Environments where 'size_t' is narrower than 'long' are not supported."
#endif

namespace {

const char * const program_name = "unzcrash";
const char * invocation_name = program_name;		// default value


void show_help()
  {
  std::fputs(
    "Unzcrash tests the robustness of decompressors to corrupted data.\n"
    "\nBy default, unzcrash reads the file specified and then repeatedly\n"
    "decompresses it, increasing 256 times each byte of the compressed data, so\n"
    "as to test all possible one-byte errors. Note that it may take years or even\n"
    "centuries to test all possible one-byte errors in a large file (tens of MB).\n"
    "\nIf the option '--block' is given, unzcrash reads the file specified and\n"
    "then repeatedly decompresses it, setting all bytes in each successive block\n"
    "to the value given, so as to test all possible full sector errors.\n"
    "\nIf the option '--truncate' is given, unzcrash reads the file specified\n"
    "and then repeatedly decompresses it, truncating the file to increasing\n"
    "lengths, so as to test all possible truncation points.\n"
    "\nNone of the three test modes described above should cause any invalid memory\n"
    "accesses. If any of them does, please, report it as a bug to the maintainers\n"
    "of the decompressor being tested.\n"
    "\nIf the decompressor returns with zero status, unzcrash compares the output\n"
    "of the decompressor for the original and corrupt files. If the outputs\n"
    "differ, it means that the decompressor returned a false negative; it failed\n"
    "to recognize the corruption and produced garbage output. The only exception\n"
    "is when a multimember file is truncated just after the last byte of a\n"
    "member, producing a shorter but valid compressed file. Except in this latter\n"
    "case, please, report any false negative as a bug.\n"
    "\nIn order to compare the outputs, unzcrash needs a 'zcmp' program able to\n"
    "understand the format being tested. For example the zcmp provided by zutils.\n"
    "Use '--zcmp=false' to disable comparisons.\n", stdout );
  std::printf( "\nUsage: %s [options] 'lzip -t' file.lz\n", invocation_name );
  std::fputs(
    "\nOptions:\n"
    "  -h, --help                    display this help and exit\n"
    "  -V, --version                 output version information and exit\n"
    "  -b, --bits=<range>            test N-bit errors instead of full byte\n"
    "  -B, --block[=<size>][,<val>]  test blocks of given size [512,0]\n"
    "  -d, --delta=<n>               test one byte/block/truncation every n bytes\n"
    "  -e, --set-byte=<pos>,<val>    set byte at position <pos> to value <val>\n"
    "  -n, --no-check                skip initial test of file.lz and zcmp\n"
    "  -p, --position=<bytes>        first byte position to test [default 0]\n"
    "  -q, --quiet                   suppress all messages\n"
    "  -s, --size=<bytes>            number of byte positions to test [all]\n"
    "  -t, --truncate                test decompression of truncated file\n"
    "  -v, --verbose                 be verbose (a 2nd -v gives more)\n"
    "  -z, --zcmp=<command>          set zcmp command name and options [zcmp]\n"
    "Examples of <range>:  1  1,2,3  1-4  1,3-5,8  1-3,5-8\n"
    "A negative position is relative to the end of file.\n"
    "A negative size is relative to the rest of the file.\n"
    "\n*Exit status*\n"
    "0 for a normal exit, 1 for environmental problems (file not found, invalid\n"
    "command-line options, I/O errors, etc), 2 to indicate a corrupt or invalid\n"
    "input file, 3 for an internal consistency error (e.g., bug) which caused\n"
    "unzcrash to panic.\n"
    "\nReport bugs to lzip-bug@nongnu.org\n"
    "Lziprecover home page: http://www.nongnu.org/lzip/lziprecover.html\n", stdout );
  }

} // end namespace

#include "main_common.cc"

namespace {

void parse_block( const char * const arg, const char * const option_name,
                  long & size, uint8_t & value )
  {
  const char * tail = arg;

  if( *tail != ',' ) size = getnum( arg, option_name, 0, 1, INT_MAX, &tail );
  if( *tail == ',' ) value = getnum( tail + 1, option_name, 0, 0, 255 );
  else if( *tail )
    { show_option_error( arg, "Missing comma between <size> and <value> in",
                         option_name ); std::exit( 1 ); }
  }


/* Return the address of a malloc'd buffer containing the file data and
   the file size in '*file_sizep'.
   In case of error, return 0 and do not modify '*file_sizep'.
*/
uint8_t * read_file( const char * const filename, long * const file_sizep )
  {
  FILE * const f = std::fopen( filename, "rb" );
  if( !f )
    { show_file_error( filename, "Can't open input file", errno ); return 0; }

  long buffer_size = 65536;
  uint8_t * buffer = (uint8_t *)std::malloc( buffer_size );
  if( !buffer )
    { show_file_error( filename, mem_msg ); std::fclose( f ); return 0; }
  long file_size = std::fread( buffer, 1, buffer_size, f );
  while( file_size >= buffer_size || ( !std::ferror( f ) && !std::feof( f ) ) )
    {
    if( file_size >= buffer_size )	// may be false because of EINTR
      {
      if( buffer_size >= LONG_MAX )
        { show_file_error( filename, large_file_msg );
          std::free( buffer ); std::fclose( f ); return 0; }
      buffer_size = (buffer_size <= LONG_MAX / 2) ? 2 * buffer_size : LONG_MAX;
      uint8_t * const tmp = (uint8_t *)std::realloc( buffer, buffer_size );
      if( !tmp ) { show_file_error( filename, mem_msg ); std::free( buffer );
                   std::fclose( f ); return 0; }
      buffer = tmp;
      }
    file_size += std::fread( buffer + file_size, 1, buffer_size - file_size, f );
    }
  if( std::ferror( f ) || !std::feof( f ) )
    { show_file_error( filename, rd_err_msg, errno );
      std::free( buffer ); std::fclose( f ); return 0; }
  if( std::fclose( f ) != 0 )
    { show_file_error( filename, "Error closing input file", errno );
      std::free( buffer ); return 0; }
  *file_sizep = file_size;
  return buffer;
  }


class Bitset8			// 8 value bitset (1 to 8)
  {
  bool data[8];
  static bool valid_digit( const unsigned char ch )
    { return ch >= '1' && ch <= '8'; }

public:
  Bitset8() { for( int i = 0; i < 8; ++i ) data[i] = true; }

  bool includes( const int i ) const
    { return i >= 1 && i <= 8 && data[i-1]; }

  // Recognized formats: 1 1,2,3 1-4 1,3-5,8 1-3,5-8
  void parse_bs( const char * const arg, const char * const option_name )
    {
    const char * p = arg;
    for( int i = 0; i < 8; ++i ) data[i] = false;
    while( true )
      {
      const unsigned char ch1 = *p++;
      if( !valid_digit( ch1 ) ) break;
      if( *p != '-' ) data[ch1-'1'] = true;
      else
        {
        ++p;
        if( !valid_digit( *p ) || ch1 > *p ) break;
        for( int c = ch1; c <= *p; ++c ) data[c-'1'] = true;
        ++p;
        }
      if( *p == 0 ) return;
      if( *p == ',' ) ++p; else break;
      }
    show_option_error( arg, "Invalid bit position or range in", option_name );
    std::exit( 1 );
    }

  // number of N-bit errors per byte (N=0 to 8): 1 8 28 56 70 56 28 8 1
  void print() const
    {
    std::fflush( stderr );
    int c = 0;
    for( int i = 0; i < 8; ++i ) if( data[i] ) ++c;
    if( c == 8 ) std::fputs( "Testing full byte.\n", stdout );
    else if( c == 0 ) std::fputs( "Nothing to test.\n", stdout );
    else
      {
      std::fputs( "Testing ", stdout );
      for( int i = 0; i < 8; ++i )
        if( data[i] )
          {
          std::printf( "%d", i + 1 );
          if( --c ) std::fputc( ',', stdout );
          }
      std::fputs( " bit errors.\n", stdout );
      }
    std::fflush( stdout );
    }
  };


int differing_bits( const uint8_t byte1, const uint8_t byte2 )
  {
  int count = 0;
  uint8_t dif = byte1 ^ byte2;
  while( dif )
    { count += ( dif & 1 ); dif >>= 1; }
  return count;
  }


/* Return the number of bytes really written.
   If (value returned < size), it is always an error.
*/
long writeblock( const int fd, const uint8_t * const buf, const long size )
  {
  long sz = 0;
  errno = 0;
  while( sz < size )
    {
    const long n = write( fd, buf + sz, size - sz );
    if( n > 0 ) sz += n;
    else if( n < 0 && errno != EINTR ) break;
    errno = 0;
    }
  return sz;
  }


void show_exec_error( const char * const prog_name )
  {
  if( verbosity >= 0 )
    std::fprintf( stderr, "%s: Can't exec '%s': %s\n",
                  program_name, prog_name, std::strerror( errno ) );
  }


void show_fork_error( const char * const prog_name )
  {
  if( verbosity >= 0 )
    std::fprintf( stderr, "%s: Can't fork '%s': %s\n",
                  program_name, prog_name, std::strerror( errno ) );
  }


int wait_for_child( const pid_t pid, const char * const name )
  {
  int status;
  while( waitpid( pid, &status, 0 ) == -1 )
    {
    if( errno != EINTR )
      {
      if( verbosity >= 0 )
        std::fprintf( stderr, "%s: Error waiting termination of '%s': %s\n",
                      program_name, name, std::strerror( errno ) );
      return -1;
      }
    }
  if( WIFEXITED( status ) )
    { const int ret = WEXITSTATUS( status ); if( ret != 255 ) return ret; }
  return -1;
  }


bool word_split( const char * const command, std::vector< std::string > & args )
  {
  const unsigned long old_size = args.size();
  for( const char * p = command; *p; )
    {
    while( *p && std::isspace( *p ) ) ++p;	// strip leading space
    if( !*p ) break;
    if( *p == '\'' || *p == '"' )		// quoted name
      {
      const char quote = *p;
      const char * const begin = ++p;		// skip leading quote
      while( *p && *p != quote ) ++p;
      if( !*p || begin == p ) return false;	// umbalanced or empty
      args.push_back( std::string( begin, p - begin ) );
      ++p; continue;				// skip trailing quote
      }
    const char * const begin = p++;
    while( *p && !std::isspace( *p ) ) ++p;
    args.push_back( std::string( begin, p - begin ) );
    }
  return args.size() > old_size;
  }


// return -1 if fatal error, 0 if OK, > 0 if error
int fork_and_feed( const uint8_t * const buffer, const long buffer_size,
                   const char ** const argv, const bool check = false )
  {
  int fda[2];				// pipe to child
  if( pipe( fda ) < 0 )
    { show_error( "Can't create pipe", errno ); return -1; }

  const pid_t pid = vfork();
  if( pid < 0 )				// parent
    { show_fork_error( argv[0] ); return -1; }
  else if( pid > 0 )			// parent (feed data to child)
    {
    if( close( fda[0] ) != 0 )
      { show_error( "Error closing unused pipe", errno ); return -1; }
    if( writeblock( fda[1], buffer, buffer_size ) != buffer_size && check )
      { show_error( "Can't write to child process", errno ); return -1; }
    if( close( fda[1] ) != 0 )
      { show_error( "Error closing pipe", errno ); return -1; }
    }
  else if( pid == 0 )			// child
    {
    if( dup2( fda[0], STDIN_FILENO ) >= 0 &&
        close( fda[0] ) == 0 && close( fda[1] ) == 0 )
      execvp( argv[0], (char **)argv );
    show_exec_error( argv[0] );
    _exit( 255 );		// 255 means fatal error in wait_for_child
    }

  return wait_for_child( pid, argv[0] );
  }

} // end namespace


int main( const int argc, const char * const argv[] )
  {
  enum Mode { m_block, m_byte, m_truncate };
  const char * mode_str[3] = { "block", "byte", "size" };
  Bitset8 bits;		// if Bitset8::parse_bs not called, test full byte
  Bad_byte bad_byte;
  const char * zcmp_program = "zcmp";
  long pos = 0;
  long max_size = LONG_MAX;
  long delta = 0;		// to be set later
  long block_size = 512;
  Mode program_mode = m_byte;
  uint8_t block_value = 0;
  bool check = true;
  if( argc > 0 ) invocation_name = argv[0];

  const Arg_parser::Option options[] =
    {
    { 'h', "help",      Arg_parser::no  },
    { 'b', "bits",      Arg_parser::yes },
    { 'B', "block",     Arg_parser::maybe },
    { 'd', "delta",     Arg_parser::yes },
    { 'e', "set-byte",  Arg_parser::yes },
    { 'n', "no-check",  Arg_parser::no  },
    { 'n', "no-verify", Arg_parser::no  },
    { 'p', "position",  Arg_parser::yes },
    { 'q', "quiet",     Arg_parser::no  },
    { 's', "size",      Arg_parser::yes },
    { 't', "truncate",  Arg_parser::no  },
    { 'v', "verbose",   Arg_parser::no  },
    { 'V', "version",   Arg_parser::no  },
    { 'z', "zcmp",      Arg_parser::yes },
    { 0, 0,             Arg_parser::no  } };

  const Arg_parser parser( argc, argv, options );
  if( parser.error().size() )				// bad option
    { show_error( parser.error().c_str(), 0, true ); return 1; }

  int argind = 0;
  for( ; argind < parser.arguments(); ++argind )
    {
    const int code = parser.code( argind );
    if( !code ) break;					// no more options
    const char * const pn = parser.parsed_name( argind ).c_str();
    const char * const arg = parser.argument( argind ).c_str();
    switch( code )
      {
      case 'b': bits.parse_bs( arg, pn ); program_mode = m_byte; break;
      case 'B': if( *arg ) parse_block( arg, pn, block_size, block_value );
                program_mode = m_block; break;
      case 'd': delta = getnum( arg, pn, block_size, 1, INT_MAX ); break;
      case 'e': bad_byte.parse_bb( arg, pn ); break;
      case 'h': show_help(); return 0;
      case 'n': check = false; break;
      case 'p': pos = getnum( arg, pn, block_size, -LONG_MAX, LONG_MAX ); break;
      case 'q': cl_verbosity = verbosity = -1; break;
      case 's': max_size = getnum( arg, pn, block_size, -LONG_MAX, LONG_MAX ); break;
      case 't': program_mode = m_truncate; break;
      case 'v': if( verbosity < 4 ) ++verbosity; break;
      case 'V': show_version(); return 0;
      case 'z': zcmp_program = arg; break;
      default: internal_error( "uncaught option." );
      }
    } // end process options

  if( parser.arguments() - argind != 2 )
    {
    if( verbosity >= 0 )
      std::fprintf( stderr, "Usage: %s [options] 'lzip -t' file.lz\n",
                    invocation_name );
    return 1;
    }

  if( delta <= 0 ) delta = (program_mode == m_block) ? block_size : 1;

  const char * const command = parser.argument( argind ).c_str();
  std::vector< std::string > command_args;
  if( !word_split( command, command_args ) )
    { show_file_error( command, "Invalid command." ); return 1; }
  const char ** const command_argv = new const char *[command_args.size()+1];
  for( unsigned i = 0; i < command_args.size(); ++i )
    command_argv[i] = command_args[i].c_str();
  command_argv[command_args.size()] = 0;

  const char * const filename = parser.argument( argind + 1 ).c_str();
  long file_size = 0;
  uint8_t * const buffer = read_file( filename, &file_size );
  if( !buffer ) return 1;
  std::string zcmp_command;
  std::vector< std::string > zcmp_args;
  const char ** zcmp_argv = 0;
  if( std::strcmp( zcmp_program, "false" ) != 0 )
    {
    zcmp_command = zcmp_program;
    zcmp_command += " '"; zcmp_command += filename; zcmp_command += "' -";
    if( !word_split( zcmp_command.c_str(), zcmp_args ) )
      { show_file_error( zcmp_command.c_str(), "Invalid zcmp command." );
        return 1; }
    zcmp_argv = new const char *[zcmp_args.size()+1];
    for( unsigned i = 0; i < zcmp_args.size(); ++i )
      zcmp_argv[i] = zcmp_args[i].c_str();
    zcmp_argv[zcmp_args.size()] = 0;
    }

  // check original file
  if( verbosity >= 1 ) fprintf( stderr, "Testing file '%s'\n", filename );
  if( check )
    {
    const int ret = fork_and_feed( buffer, file_size, command_argv, true );
    if( ret != 0 )
      {
      if( verbosity >= 0 )
        {
        if( ret < 0 )
          std::fprintf( stderr, "%s: Can't run '%s'.\n", program_name, command );
        else
          std::fprintf( stderr, "%s: \"%s\" failed (%d).\n",
                        program_name, command, ret );
        }
      return 1;
      }
    if( zcmp_command.size() )
      {
      const int ret = fork_and_feed( buffer, file_size, zcmp_argv, true );
      if( ret != 0 )
        {
        if( verbosity >= 0 )
          {
          if( ret < 0 )
            std::fprintf( stderr, "%s: Can't run '%s'.\n",
                          program_name, zcmp_command.c_str() );
          else
            std::fprintf( stderr, "%s: \"%s\" failed (%d). Disabling comparisons.\n",
                          program_name, zcmp_command.c_str(), ret );
          }
        if( ret < 0 ) return 1;
        zcmp_command.clear();
        }
      }
    }

  std::signal( SIGPIPE, SIG_IGN );

  if( pos < 0 ) pos = std::max( 0L, file_size + pos );
  if( pos >= file_size || max_size == 0 ||
      ( max_size < 0 && -max_size >= file_size - pos ) )
    { show_error( "Nothing to do; domain is empty." ); return 0; }
  if( max_size < 0 ) max_size += file_size - pos;
  const long end = (max_size < file_size - pos) ? pos + max_size : file_size;
  if( bad_byte.pos >= file_size )
    { show_option_error( bad_byte.argument, "Position is beyond end of file in",
                         bad_byte.option_name ); return 1; }
  if( bad_byte.pos >= 0 )
    buffer[bad_byte.pos] = bad_byte( buffer[bad_byte.pos] );
  unsigned long positions = 0, decompressions = 0, successes = 0,
                failed_comparisons = 0;
  if( program_mode == m_truncate )
    for( long i = pos; i < end; i += std::min( delta, end - i ) )
      {
      if( verbosity >= 1 )
        std::fprintf( stderr, "length %s\n", format_num3( i ) );
      ++positions; ++decompressions;
      const int ret = fork_and_feed( buffer, i, command_argv );
      if( ret < 0 ) return 1;
      if( ret == 0 )
        {
        ++successes;
        if( verbosity >= 0 )
          std::fprintf( stderr, "length %s passed the test\n", format_num3( i ) );
        if( zcmp_command.size() )
          {
          const int ret = fork_and_feed( buffer, i, zcmp_argv );
          if( ret < 0 ) return 1;
          if( ret > 0 )
            {
            ++failed_comparisons;
            if( verbosity >= 0 ) std::fprintf( stderr,
              "length %s comparison failed\n", format_num3( i ) );
            }
          }
        }
      }
  else if( program_mode == m_block )
    {
    uint8_t * const block = (uint8_t *)std::malloc( block_size );
    if( !block ) { show_error( mem_msg ); return 1; }
    for( long i = pos; i < end; i += std::min( delta, end - i ) )
      {
      const long size = std::min( block_size, file_size - i );
      if( verbosity >= 1 ) std::fprintf( stderr, "block %s,%s\n",
                           format_num3( i ), format_num3( size ) );
      ++positions; ++decompressions;
      std::memcpy( block, buffer + i, size );
      std::memset( buffer + i, block_value, size );
      const int ret = fork_and_feed( buffer, file_size, command_argv );
      if( ret < 0 ) return 1;
      if( ret == 0 )
        {
        ++successes;
        if( verbosity >= 0 )
          std::fprintf( stderr, "block %s,%s passed the test\n",
                        format_num3( i ), format_num3( size ) );
        if( zcmp_command.size() )
          {
          const int ret = fork_and_feed( buffer, file_size, zcmp_argv );
          if( ret < 0 ) return 1;
          if( ret > 0 )
            {
            ++failed_comparisons;
            if( verbosity >= 0 )
              std::fprintf( stderr, "block %s,%s comparison failed\n",
                            format_num3( i ), format_num3( size ) );
            }
          }
        }
      std::memcpy( buffer + i, block, size );
      }
    std::free( block );
    }
  else
    {
    if( verbosity >= 1 ) bits.print();
    for( long i = pos; i < end; i += std::min( delta, end - i ) )
      {
      if( verbosity >= 1 )
        std::fprintf( stderr, "byte %s\n", format_num3( i ) );
      ++positions;
      const uint8_t byte = buffer[i];
      for( int j = 1; j < 256; ++j )
        {
        ++buffer[i];
        if( bits.includes( differing_bits( byte, buffer[i] ) ) )
          {
          ++decompressions;
          if( verbosity >= 2 )
            std::fprintf( stderr, "0x%02X (0x%02X+0x%02X) ",
                          buffer[i], byte, j );
          const int ret = fork_and_feed( buffer, file_size, command_argv );
          if( ret < 0 ) return 1;
          if( ret == 0 )
            {
            ++successes;
            if( verbosity >= 0 )
              { if( verbosity < 2 )	// else already printed above
                  std::fprintf( stderr, "0x%02X (0x%02X+0x%02X) ",
                                buffer[i], byte, j );
                std::fprintf( stderr, "byte %s passed the test\n",
                              format_num3( i ) ); }
            if( zcmp_command.size() )
              {
              const int ret = fork_and_feed( buffer, file_size, zcmp_argv );
              if( ret < 0 ) return 1;
              if( ret > 0 )
                {
                ++failed_comparisons;
                if( verbosity >= 0 ) std::fprintf( stderr,
                  "byte %s comparison failed\n", format_num3( i ) );
                }
              }
            }
          }
        }
      buffer[i] = byte;
      }
    }

  if( verbosity >= 0 )
    {
    std::fprintf( stderr, "\n%11s %ss tested\n%11s total decompressions"
                          "\n%11s decompressions returned with zero status",
                  format_num3( positions ), mode_str[program_mode],
                  format_num3( decompressions ), format_num3( successes ) );
    if( successes > 0 )
      {
      if( zcmp_command.empty() )
        std::fputs( "\n            comparisons disabled\n", stderr );
      else if( failed_comparisons > 0 )
        std::fprintf( stderr, ", of which\n%11s comparisons failed\n",
                      format_num3( failed_comparisons ) );
      else std::fputs( "\n            all comparisons passed\n", stderr );
      }
    else std::fputc( '\n', stderr );
    }

  std::free( buffer );
  return 0;
  }
