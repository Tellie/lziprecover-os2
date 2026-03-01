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

struct Bad_byte
  {
  enum Mode { literal, delta, flip };
  long long pos;
  const char * argument;
  const char * option_name;
  Mode mode;
  uint8_t value;

  Bad_byte() :
    pos( -1 ), argument( 0 ), option_name( 0 ), mode( literal ), value( 0 ) {}

  uint8_t operator()( const uint8_t old_value ) const
    {
    if( mode == delta ) return old_value + value;
    if( mode == flip ) return old_value ^ value;
    return value;
    }

  void parse_bb( const char * const arg, const char * const pn );
  };


const char * const large_file_msg = "Input file is too large for this computer.";
const char * const mem_msg = "Not enough memory.";
const char * const rd_err_msg = "Read error";

// defined in main_common.cc
extern int verbosity;

const char * format_num3( const unsigned long long pos,
                          const unsigned long long neg = 0 );
void show_error( const char * const msg, const int errcode = 0,
                 const bool help = false );
void show_file_error( const char * const filename, const char * const msg,
                      const int errcode = 0 );
void internal_error( const char * const msg );
