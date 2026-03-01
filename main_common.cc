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

int cl_verbosity = 0;		// used to silence internal_error if '-q'
int verbosity = 0;

namespace {

const char * const program_year = "2026";

void show_version()
  {
  std::printf( "%s %s\n", program_name, PROGVERSION );
  std::printf( "Copyright (C) %s Antonio Diaz Diaz.\n", program_year );
  std::fputs( "License GPLv2+: GNU GPL version 2 or later <http://gnu.org/licenses/gpl.html>\n"
              "This is free software: you are free to change and redistribute it.\n"
              "There is NO WARRANTY, to the extent permitted by law.\n", stdout );
  }


int chvalue( const unsigned char ch )
  {
  if( ch >= '0' && ch <= '9' ) return ch - '0';
  if( ch >= 'A' && ch <= 'Z' ) return ch - 'A' + 10;
  if( ch >= 'a' && ch <= 'z' ) return ch - 'a' + 10;
  return 255;
  }

long long strtoll_( const char * const ptr, const char ** tail, int base )
  {
  if( tail ) *tail = ptr;				// error value
  int i = 0;
  while( std::isspace( ptr[i] ) || (unsigned char)ptr[i] == 0xA0 ) ++i;
  const bool minus = ptr[i] == '-';
  if( minus || ptr[i] == '+' ) ++i;
  if( base < 0 || base > 36 || base == 1 ||
      ( base == 0 && !std::isdigit( ptr[i] ) ) ||
      ( base != 0 && chvalue( ptr[i] ) >= base ) )
    { errno = EINVAL; return 0; }

  if( base == 0 )
    {
    if( ptr[i] != '0' ) base = 10;			// decimal
    else if( ptr[i+1] == 'x' || ptr[i+1] == 'X' ) { base = 16; i += 2; }
    else base = 8;					// octal or 0
    }
  const int dpg = ( base != 16 ) ? 3 : 2;	// min digits per group
  int dig = dpg - 1;	// digits in current group, first may have 1 digit
  const unsigned long long limit = minus ? LLONG_MAX + 1ULL : LLONG_MAX;
  unsigned long long result = 0;
  bool erange = false;
  for( ; ptr[i]; ++i )
    {
    if( ptr[i] == '_' ) { if( dig < dpg ) break; else { dig = 0; continue; } }
    const int val = chvalue( ptr[i] ); if( val >= base ) break; else ++dig;
    if( !erange && ( limit - val ) / base >= result )
      result = result * base + val;
    else erange = true;
    }
  if( dig < dpg ) { errno = EINVAL; return 0; }
  if( tail ) *tail = ptr + i;
  if( erange ) { errno = ERANGE; return minus ? LLONG_MIN : LLONG_MAX; }
  return minus ? 0LL - result : result;
  }


// separate numbers of 5 or more digits in groups of 3 digits using '_'
const char * format_num3p( long long num )
  {
  enum { buffers = 8, bufsize = 4 * sizeof num };
  const char * const si_prefix = "kMGTPEZYRQ";
  const char * const binary_prefix = "KMGTPEZYRQ";
  static char buffer[buffers][bufsize];	// circle of buffers for printf
  static int current = 0;

  char * const buf = buffer[current++]; current %= buffers;
  char * p = buf + bufsize - 1;		// fill the buffer backwards
  *p = 0;				// terminator
  const bool negative = num < 0;
  if( num >= 10000 || num <= -10000 )
    {
    char prefix = 0;			// try binary first, then si
    for( int i = 0; num != 0 && num % 1024 == 0 && binary_prefix[i]; ++i )
      { num /= 1024; prefix = binary_prefix[i]; }
    if( prefix ) *(--p) = 'i';
    else
      for( int i = 0; num != 0 && num % 1000 == 0 && si_prefix[i]; ++i )
        { num /= 1000; prefix = si_prefix[i]; }
    if( prefix ) *(--p) = prefix;
    }
  const bool split = num >= 10000 || num <= -10000;

  for( int i = 0; ; )
    {
    const long long onum = num; num /= 10;
    *(--p) = llabs( onum - ( 10 * num ) ) + '0'; if( num == 0 ) break;
    if( split && ++i >= 3 ) { i = 0; *(--p) = '_'; }
    }
  if( negative ) *(--p) = '-';
  return p;
  }


void show_option_error( const char * const arg, const char * const msg,
                        const char * const option_name )
  {
  if( verbosity >= 0 )
    std::fprintf( stderr, "%s: '%s': %s option '%s'.\n",
                  program_name, arg, msg, option_name );
  }


// Recognized formats: <num>k[Bs], <num>Ki[Bs], <num>[MGTPEZYRQ][i][Bs]
long long getnum( const char * const arg, const char * const option_name,
                  const int hardbs, const long long llimit = LLONG_MIN,
                  const long long ulimit = LLONG_MAX,
                  const char ** const tailp = 0 )
  {
  const char * tail;
  errno = 0;
  long long result = strtoll_( arg, &tail, 0 );
  if( tail == arg )
    { show_option_error( arg, "Bad or missing numerical argument in",
                         option_name ); std::exit( 1 ); }

  if( !errno && *tail )
    {
    const char * const p = tail++;
    int factor = 1000;				// default factor
    int exponent = -1;				// -1 = bad multiplier
    char usuf = 0;			// 'B' or 's' unit suffix is present
    switch( *p )
      {
      case 'Q': exponent = 10; break;
      case 'R': exponent = 9; break;
      case 'Y': exponent = 8; break;
      case 'Z': exponent = 7; break;
      case 'E': exponent = 6; break;
      case 'P': exponent = 5; break;
      case 'T': exponent = 4; break;
      case 'G': exponent = 3; break;
      case 'M': exponent = 2; break;
      case 'K': if( *tail == 'i' ) { ++tail; factor = 1024; exponent = 1; } break;
      case 'k': if( *tail != 'i' ) exponent = 1; break;
      case 'B':
      case 's': usuf = *p; exponent = 0; break;
      default: if( tailp ) { tail = p; exponent = 0; }
      }
    if( exponent > 1 && *tail == 'i' ) { ++tail; factor = 1024; }
    if( exponent > 0 && usuf == 0 && ( *tail == 'B' || *tail == 's' ) )
      { usuf = *tail; ++tail; }
    if( exponent < 0 || ( usuf == 's' && hardbs <= 0 ) ||
        ( !tailp && *tail != 0 ) )
      { show_option_error( arg, "Bad multiplier in numerical argument of",
                           option_name ); std::exit( 1 ); }
    for( int i = 0; i < exponent; ++i )
      {
      if( ( result >= 0 && LLONG_MAX / factor >= result ) ||
          ( result < 0 && LLONG_MIN / factor <= result ) ) result *= factor;
      else { errno = ERANGE; break; }
      }
    if( usuf == 's' )
      {
      if( ( result >= 0 && LLONG_MAX / hardbs >= result ) ||
          ( result < 0 && LLONG_MIN / hardbs <= result ) ) result *= hardbs;
      else errno = ERANGE;
      }
    }
  if( !errno && ( result < llimit || result > ulimit ) ) errno = ERANGE;
  if( errno )
    {
    if( verbosity >= 0 )
      std::fprintf( stderr, "%s: '%s': Value out of limits [%s,%s] in "
                    "option '%s'.\n", program_name, arg, format_num3p( llimit ),
                    format_num3p( ulimit ), option_name );
    std::exit( 1 );
    }
  if( tailp ) *tailp = tail;
  return result;
  }

} // end namespace


// Recognized formats: <pos>,<value> <pos>,+<value> <pos>,f<value>
void Bad_byte::parse_bb( const char * const arg, const char * const pn )
  {
  argument = arg;
  option_name = pn;
  const char * tail;
  pos = getnum( arg, option_name, 0, 0, LLONG_MAX, &tail );
  if( *tail != ',' )
    { show_option_error( arg, ( *tail == 0 ) ? "Missing <val> in" :
                         "Missing comma between <pos> and <val> in",
                         option_name ); std::exit( 1 ); }
  if( tail[1] == '+' ) { ++tail; mode = delta; }
  else if( tail[1] == 'f' ) { ++tail; mode = flip; }
  else mode = literal;
  value = getnum( tail + 1, option_name, 0, 0, 255 );
  }


// separate numbers of 5 or more digits in groups of 3 digits using '_'
const char * format_num3( const unsigned long long pos,
                          const unsigned long long neg )
  {
  enum { buffers = 8, bufsize = 4 * sizeof pos };
  static char buffer[buffers][bufsize];	// circle of buffers for printf
  static int current = 0;

  char * const buf = buffer[current++]; current %= buffers;
  char * p = buf + bufsize - 1;		// fill the buffer backwards
  *p = 0;				// terminator
  const bool negative = pos < neg;
  unsigned long long num = negative ? neg - pos : pos - neg;
  const bool split = num >= 10000;

  for( int i = 0; ; )
    {
    *(--p) = num % 10 + '0'; num /= 10; if( num == 0 ) break;
    if( split && ++i >= 3 ) { i = 0; *(--p) = '_'; }
    }
  if( negative ) *(--p) = '-';
  return p;
  }


void show_error( const char * const msg, const int errcode, const bool help )
  {
  if( verbosity < 0 ) return;
  if( msg && msg[0] )
    std::fprintf( stderr, "%s: %s%s%s\n", program_name, msg,
                  ( errcode > 0 ) ? ": " : "",
                  ( errcode > 0 ) ? std::strerror( errcode ) : "" );
  if( help )
    std::fprintf( stderr, "Try '%s --help' for more information.\n",
                  invocation_name );
  }


void show_file_error( const char * const filename, const char * const msg,
                      const int errcode )
  {
  if( verbosity >= 0 )
    std::fprintf( stderr, "%s: %s: %s%s%s\n", program_name, filename, msg,
                  ( errcode > 0 ) ? ": " : "",
                  ( errcode > 0 ) ? std::strerror( errcode ) : "" );
  }


void internal_error( const char * const msg )
  {
  if( cl_verbosity >= 0 )
    std::fprintf( stderr, "%s: internal error: %s\n", program_name, msg );
  std::exit( 3 );
  }
