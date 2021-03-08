#ifndef JSON_SPIRIT_READER_TEMPLATE
#define JSON_SPIRIT_READER_TEMPLATE

//          Copyright John W. Wilkinson 2007 - 2009.
// Distributed under the MIT License, see accompanying file LICENSE.txt

// json spirit version 4.03

#include "json_spirit_value.h"
#include "json_spirit_error_position.h"

//#define BOOST_SPIRIT_THREADSAFE  // uncomment for multithreaded use, requires linking to boost.thread

#include <boost/bind.hpp>
#include <boost/function.hpp>
#include <boost/version.hpp>

#if BOOST_VERSION >= 103800
    #include <boost/spirit/include/classic_core.hpp>
    #include <boost/spirit/include/classic_confix.hpp>
    #include <boost/spirit/include/classic_escape_char.hpp>
    #include <boost/spirit/include/classic_multi_pass.hpp>
    #include <boost/spirit/include/classic_position_iterator.hpp>
    #define spirit_namespace boost::spirit::classic
#else
    #include <boost/spirit/core.hpp>
    #include <boost/spirit/utility/confix.hpp>
    #include <boost/spirit/utility/escape_char.hpp>
    #include <boost/spirit/iterator/multi_pass.hpp>
    #include <boost/spirit/iterator/position_iterator.hpp>
    #define spirit_namespace boost::spirit
#endif

namespace json_spirit
{
    const spirit_namespace::int_parser < boost::int64_t >  int64_p  = spirit_namespace::int_parser < boost::int64_t  >();
    const spirit_namespace::uint_parser< boost::uint64_t > uint64_p = spirit_namespace::uint_parser< boost::uint64_t >();

    template< class Iter_type >
    bool is_eq( Iter_type first, Iter_type last, const char* c_str )
    {
        for( Iter_type i = first; i != last; ++i, ++c_str )
        {
            if( *c_str == 0 ) return false;

            if( *i != *c_str ) return false;
        }

        return true;
    }

    template< class Char_type >
    Char_type hex_to_num( const Char_type c )
    {
        if( ( c >= '0' ) && ( c <= '9' ) ) return c - '0';
        if( ( c >= 'a' ) && ( c <= 'f' ) ) return c - 'a' + 10;
        if( ( c >= 'A' ) && ( c <= 'F' ) ) return c - 'A' + 10;
        return 0;
    }

    template< class Char_type, class Iter_type >
    Char_type hex_str_to_char( Iter_type& begin )
    {
        const Char_type c1( *( ++begin ) );
        const Char_type c2( *( ++begin ) );

        return ( hex_to_num( c1 ) << 4 ) + hex_to_num(