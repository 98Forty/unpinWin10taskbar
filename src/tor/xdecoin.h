
/* Copyright (c) 2014, XDECoin 3.0 Developers */
/* See LICENSE for licensing information */

/**
 * \file xdecoin.h
 * \brief Headers for xdecoin.cpp
 **/

#ifndef TOR_XDECOIN_H
#define TOR_XDECOIN_H

#ifdef __cplusplus
extern "C" {
#endif

    char const* xdecoin_tor_data_directory(
    );

    char const* xdecoin_service_directory(
    );

    int check_interrupted(
    );

    void set_initialized(
    );

    void wait_initialized(
    );

#ifdef __cplusplus
}
#endif

#endif
