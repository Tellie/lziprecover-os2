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

class Range_mtester
  {
  const uint8_t * const buffer;		// input buffer
  const long buffer_size;
  long pos;				// current pos in buffer
  uint32_t code;
  uint32_t range;
  bool at_stream_end;

public:
  Range_mtester( const uint8_t * const buf, const long buf_size )
    :
    buffer( buf ),
    buffer_size( buf_size ),
    pos( Lzip_header::size ),
    code( 0 ),
    range( 0xFFFFFFFFU ),
    at_stream_end( false )
    {}

  bool finished() { return pos >= buffer_size; }
  unsigned long member_position() const { return pos; }

  uint8_t get_byte()
    {
    // 0xFF avoids decoder error if member is truncated at EOS marker
    if( finished() ) return 0xFF;
    return buffer[pos++];
    }

  const Lzip_trailer * get_trailer()
    {
    if( buffer_size - pos < Lzip_trailer::size ) return 0;
    const Lzip_trailer * const p = (const Lzip_trailer *)( buffer + pos );
    pos += Lzip_trailer::size;
    return p;
    }

  bool load()
    {
    code = 0;
    range = 0xFFFFFFFFU;
    // check first byte of the LZMA stream without reading it
    if( buffer[pos] != 0 ) return false;
    get_byte();			// discard first byte of the LZMA stream
    for( int i = 0; i < 4; ++i ) code = ( code << 8 ) | get_byte();
    return true;
    }

  void normalize()
    {
    if( range <= 0x00FFFFFFU )
      { range <<= 8; code = ( code << 8 ) | get_byte(); }
    }

  unsigned decode( const int num_bits )
    {
    unsigned symbol = 0;
    for( int i = num_bits; i > 0; --i )
      {
      normalize();
      range >>= 1;
//      symbol <<= 1;
//      if( code >= range ) { code -= range; symbol |= 1; }
      const bool bit = code >= range;
      symbol <<= 1; symbol += bit;
      code -= range & ( 0U - bit );
      }
    return symbol;
    }

  bool decode_bit( Bit_model & bm )
    {
    normalize();
    const uint32_t bound = ( range >> bit_model_total_bits ) * bm.probability;
    if( code < bound )
      {
      range = bound;
      bm.probability +=
        ( bit_model_total - bm.probability ) >> bit_model_move_bits;
      return 0;
      }
    else
      {
      code -= bound;
      range -= bound;
      bm.probability -= bm.probability >> bit_model_move_bits;
      return 1;
      }
    }

  void decode_symbol_bit( Bit_model & bm, unsigned & symbol )
    {
    normalize();
    symbol <<= 1;
    const uint32_t bound = ( range >> bit_model_total_bits ) * bm.probability;
    if( code < bound )
      {
      range = bound;
      bm.probability +=
        ( bit_model_total - bm.probability ) >> bit_model_move_bits;
      }
    else
      {
      code -= bound;
      range -= bound;
      bm.probability -= bm.probability >> bit_model_move_bits;
      symbol |= 1;
      }
    }

  void decode_symbol_bit_reversed( Bit_model & bm, unsigned & model,
                                   unsigned & symbol, const int i )
    {
    normalize();
    model <<= 1;
    const uint32_t bound = ( range >> bit_model_total_bits ) * bm.probability;
    if( code < bound )
      {
      range = bound;
      bm.probability +=
        ( bit_model_total - bm.probability ) >> bit_model_move_bits;
      }
    else
      {
      code -= bound;
      range -= bound;
      bm.probability -= bm.probability >> bit_model_move_bits;
      model |= 1;
      symbol |= 1 << i;
      }
    }

  unsigned decode_tree6( Bit_model bm[] )
    {
    unsigned symbol = 1;
    decode_symbol_bit( bm[symbol], symbol );
    decode_symbol_bit( bm[symbol], symbol );
    decode_symbol_bit( bm[symbol], symbol );
    decode_symbol_bit( bm[symbol], symbol );
    decode_symbol_bit( bm[symbol], symbol );
    decode_symbol_bit( bm[symbol], symbol );
    return symbol & 0x3F;
    }

  unsigned decode_tree8( Bit_model bm[] )
    {
    unsigned symbol = 1;
    decode_symbol_bit( bm[symbol], symbol );
    decode_symbol_bit( bm[symbol], symbol );
    decode_symbol_bit( bm[symbol], symbol );
    decode_symbol_bit( bm[symbol], symbol );
    decode_symbol_bit( bm[symbol], symbol );
    decode_symbol_bit( bm[symbol], symbol );
    decode_symbol_bit( bm[symbol], symbol );
    decode_symbol_bit( bm[symbol], symbol );
    return symbol & 0xFF;
    }

  unsigned decode_tree_reversed( Bit_model bm[], const int num_bits )
    {
    unsigned model = 1;
    unsigned symbol = 0;
    for( int i = 0; i < num_bits; ++i )
      decode_symbol_bit_reversed( bm[model], model, symbol, i );
    return symbol;
    }

  unsigned decode_tree_reversed4( Bit_model bm[] )
    {
    unsigned model = 1;
    unsigned symbol = 0;
    decode_symbol_bit_reversed( bm[model], model, symbol, 0 );
    decode_symbol_bit_reversed( bm[model], model, symbol, 1 );
    decode_symbol_bit_reversed( bm[model], model, symbol, 2 );
    decode_symbol_bit_reversed( bm[model], model, symbol, 3 );
    return symbol;
    }

  unsigned decode_matched( Bit_model bm[], unsigned match_byte )
    {
    Bit_model * const bm1 = bm + 0x100;
    unsigned symbol = 1;
    while( symbol < 0x100 )
      {
      const unsigned match_bit = ( match_byte <<= 1 ) & 0x100;
      const bool bit = decode_bit( bm1[symbol+match_bit] );
      symbol <<= 1; symbol |= bit;
      if( match_bit >> 8 != bit )
        {
        while( symbol < 0x100 ) decode_symbol_bit( bm[symbol], symbol );
        break;
        }
      }
    return symbol & 0xFF;
    }

  unsigned decode_len( Len_model & lm, const int pos_state )
    {
    Bit_model * bm;
    unsigned mask, offset, symbol = 1;

    if( decode_bit( lm.choice1 ) == 0 )
      { bm = lm.bm_low[pos_state]; mask = 7; offset = 0; goto len3; }
    if( decode_bit( lm.choice2 ) == 0 )
      { bm = lm.bm_mid[pos_state]; mask = 7; offset = len_low_symbols; goto len3; }
    bm = lm.bm_high; mask = 0xFF; offset = len_low_symbols + len_mid_symbols;
    decode_symbol_bit( bm[symbol], symbol );
    decode_symbol_bit( bm[symbol], symbol );
    decode_symbol_bit( bm[symbol], symbol );
    decode_symbol_bit( bm[symbol], symbol );
    decode_symbol_bit( bm[symbol], symbol );
len3:
    decode_symbol_bit( bm[symbol], symbol );
    decode_symbol_bit( bm[symbol], symbol );
    decode_symbol_bit( bm[symbol], symbol );
    return ( symbol & mask ) + min_match_len + offset;
    }
  };

class MD5SUM;		// forward declaration

class LZ_mtester
  {
  unsigned long long partial_data_pos;
  Range_mtester rdec;
  const unsigned dictionary_size;
  uint8_t * buffer;		// output buffer
  unsigned pos;			// current pos in buffer
  unsigned stream_pos;		// first byte not yet written to file
  uint32_t crc_;
  const int outfd;		// output file descriptor
  unsigned dis0;		// dis[0-3] latest four distances
  unsigned dis1;		// used for efficient coding of
  unsigned dis2;		// repeated distances
  unsigned dis3;
  State state;
  MD5SUM * const md5sum;
  unsigned long long total_packets_;	// total number of packets in member
  unsigned long long max_dis0_pos;	// member position of maximum distance
  unsigned max_dis0;			// maximum distance found
  std::vector< unsigned long long > max_packet_posv_;	// member pos of large packets
  unsigned max_packet_size_;		// maximum packet size found
  unsigned max_marker_size_;		// maximum marker size found
  bool pos_wrapped;
  bool buffer_is_external;

  Bit_model bm_literal[1<<literal_context_bits][0x300];
  Bit_model bm_match[State::states][pos_states];
  Bit_model bm_rep[State::states];
  Bit_model bm_rep0[State::states];
  Bit_model bm_rep1[State::states];
  Bit_model bm_rep2[State::states];
  Bit_model bm_len[State::states][pos_states];
  Bit_model bm_dis_slot[len_states][1<<dis_slot_bits];
  Bit_model bm_dis[modeled_distances-end_dis_model+1];
  Bit_model bm_align[dis_align_size];

  Len_model match_len_model;
  Len_model rep_len_model;

  void print_block( const int len );
  void flush_data();
  bool check_trailer( FILE * const f = 0, unsigned long long byte_pos = 0 );

  uint8_t peek_prev() const
    { return buffer[((pos > 0) ? pos : dictionary_size)-1]; }

  uint8_t peek( const unsigned distance ) const
    {
    const unsigned i = ( ( pos > distance ) ? 0 : dictionary_size ) +
                       pos - distance - 1;
    return buffer[i];
    }

  void put_byte( const uint8_t b )
    {
    buffer[pos] = b;
    if( ++pos >= dictionary_size ) flush_data();
    }

  void copy_block( const unsigned distance, unsigned len )
    {
    unsigned lpos = pos, i = lpos - distance - 1;
    bool fast, fast2;
    if( lpos > distance )
      {
      fast = len < dictionary_size - lpos;
      fast2 = fast && len <= lpos - i;
      }
    else
      {
      i += dictionary_size;
      fast = len < dictionary_size - i;		// (i == pos) may happen
      fast2 = fast && len <= i - lpos;
      }
    if( fast )					// no wrap
      {
      pos += len;
      if( fast2 )				// no wrap, no overlap
        std::memcpy( buffer + lpos, buffer + i, len );
      else
        for( ; len > 0; --len ) buffer[lpos++] = buffer[i++];
      }
    else for( ; len > 0; --len )
      {
      buffer[pos] = buffer[i];
      if( ++pos >= dictionary_size ) flush_data();
      if( ++i >= dictionary_size ) i = 0;
      }
    }

void set_max_packet( const unsigned new_size, const unsigned long long pos )
  {
  if( max_packet_size_ > new_size || new_size == 0 ) return;
  if( max_packet_size_ < new_size )			// new max size
    { max_packet_size_ = new_size; max_packet_posv_.clear(); }
  max_packet_posv_.push_back( pos - new_size );		// pos of first byte
  }

void set_max_marker( const unsigned new_size )
  { if( max_marker_size_ < new_size ) max_marker_size_ = new_size; }

public:
  LZ_mtester( const uint8_t * const ibuf, const long ibuf_size,
              const unsigned dict_size, const int ofd = -1,
              MD5SUM * const md5sum_ = 0 )
    :
    partial_data_pos( 0 ),
    rdec( ibuf, ibuf_size ),
    dictionary_size( dict_size ),
    buffer( new uint8_t[dictionary_size] ),
    pos( 0 ),
    stream_pos( 0 ),
    crc_( 0xFFFFFFFFU ),
    outfd( ofd ),
    dis0( 0 ),
    dis1( 0 ),
    dis2( 0 ),
    dis3( 0 ),
    md5sum( md5sum_ ),
    total_packets_( -1ULL ),		// don't count EOS marker
    max_dis0_pos( 0 ),
    max_dis0( 0 ),
    max_packet_size_( 0 ),
    max_marker_size_( 0 ),
    pos_wrapped( false ), buffer_is_external( false )
    { buffer[dictionary_size-1] = 0; }		// prev_byte of first byte

  ~LZ_mtester() { if( !buffer_is_external ) delete[] buffer; }

  unsigned crc() const { return crc_ ^ 0xFFFFFFFFU; }
  unsigned long long data_position() const { return partial_data_pos + pos; }
  bool finished() { return rdec.finished(); }
  unsigned long member_position() const { return rdec.member_position(); }
  unsigned long long total_packets() const { return total_packets_; }
  unsigned long long max_distance_pos() const { return max_dis0_pos; }
  unsigned max_distance() const { return max_dis0 + 1; }
  const std::vector< unsigned long long > & max_packet_posv() const
    { return max_packet_posv_; }
  unsigned max_packet_size() const { return max_packet_size_; }
  unsigned max_marker_size() const { return max_marker_size_; }

  const uint8_t * get_buffers( const uint8_t ** const prev_bufferp,
                               int * const sizep, int * const prev_sizep ) const
    { *sizep = (pos_wrapped && pos == 0) ? dictionary_size : pos;
      *prev_sizep = (pos_wrapped && pos > 0) ? dictionary_size - pos : 0;
      *prev_bufferp = buffer + pos; return buffer; }

  void duplicate_buffer( uint8_t * const buffer2 );

  // these two functions set max_dis0
  int test_member( const unsigned long mpos_limit = LONG_MAX,
                   const unsigned long long dpos_limit = LLONG_MAX,
                   FILE * const f = 0, const unsigned long long byte_pos = 0 );
  /* this function also sets max_dis0_pos, total_packets_, max_packet_size_,
                             max_packet_posv_, and max_marker_size_ */
  int debug_decode_member( const bool show_packets );
  };
