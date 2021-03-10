#ifndef JSON_SPIRIT_UTILS
#define JSON_SPIRIT_UTILS

//          Copyright John W. Wilkinson 2007 - 2009.
// Distributed under the MIT License, see accompanying file LICENSE.txt

// json spirit version 4.03

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
# pragma once
#endif

#include "json_spirit_value.h"
#include <map>

namespace json_spirit
{ 
    template< class Obj_t, class Map_t >
    void obj_to_map( const Obj_t& obj, Map_t& mp_obj )
  