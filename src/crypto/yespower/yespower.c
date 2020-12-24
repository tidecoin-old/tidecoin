/*-
 * Copyright 2019 Yenten team
 * Copyright 2018 Cryply team
 * Copyright 2009 Colin Percival
 * Copyright 2013-2018 Alexander Peslyak
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "yespower.h"
#include "sysendian.h"

// for standard yespower (Cryply/CranePay, Bellcoin, Veco)
void yespower_hash(const char *input, char *output)
{
        yespower_params_t params = {
                .version = YESPOWER_1_0,
                .N = 2048,
                .r = 8,
                .pers = (const uint8_t *)"Tidecoin: Post Quantum Security.",
                .perslen = 32
        };
        yespower_tls((const uint8_t *) input, 80, &params, (yespower_binary_t *) output);
}

// for yespowerR16 (Yenten on and after 30 March 2019)
void yespowerR16_hash(const char *input, char *output)
{
        yespower_params_t params = {
                .version = YESPOWER_1_0,
                .N = 4096,
                .r = 16,
                .pers = NULL,
                .perslen = 0
        };
        yespower_tls((const uint8_t *) input, 80, &params, (yespower_binary_t *) output);
}

// for yespowerYTN (Yenten automatic algorithm change)
void yespowerYTN_hash(const char *input, char *output)
{
        yespower_params_t old_params = {
                .version = YESPOWER_0_5,
                .N = 4096,
                .r = 16,
                .pers = "Client Key",
                .perslen = 10
        };
        yespower_params_t new_params = {
                .version = YESPOWER_1_0,
                .N = 4096,
                .r = 16,
                .pers = NULL,
                .perslen = 0
        };
        uint32_t time = le32dec(&input[68]);
        if (time > 1553904000) {
            yespower_tls((const uint8_t *) input, 80, &new_params, (yespower_binary_t *) output);
        } else {
            yespower_tls((const uint8_t *) input, 80, &old_params, (yespower_binary_t *) output);
        }
}

// for yescryptR8, yespower-0.5_R8 (BitZeny, BitZeny-Plus)
void yespower_0_5_R8_hash(const char *input, char *output)
{
        yespower_params_t params = {
                .version = YESPOWER_0_5,
                .N = 2048,
                .r = 8,
                .pers = "Client Key",
                .perslen = 10
        };
        yespower_tls((const uint8_t *) input, 80, &params, (yespower_binary_t *) output);
}

// for yescryptR8G, yespower-0.5_R8G (Koto before Sapling)
void yespower_0_5_R8G_hash(const char *input, char *output)
{
        yespower_params_t params = {
                .version = YESPOWER_0_5,
                .N = 2048,
                .r = 8,
                .pers = (const uint8_t *)input,
                .perslen = 80
        };
        yespower_tls((const uint8_t *) input, 80, &params, (yespower_binary_t *) output);
}

// for yescryptR16, yespower-0.5_R16 (Yenten up to 3.0.2)
void yespower_0_5_R16_hash(const char *input, char *output)
{
        yespower_params_t params = {
                .version = YESPOWER_0_5,
                .N = 4096,
                .r = 16,
                .pers = "Client Key",
                .perslen = 10
        };
        yespower_tls((const uint8_t *) input, 80, &params, (yespower_binary_t *) output);
}

// for yescryptR24, yespower-0.5_R24 (Jagaricoin-R)
void yespower_0_5_R24_hash(const char *input, char *output)
{
        yespower_params_t params = {
                .version = YESPOWER_0_5,
                .N = 4096,
                .r = 24,
                .pers = "Jagaricoin",
                .perslen = 10
        };
        yespower_tls((const uint8_t *) input, 80, &params, (yespower_binary_t *) output);
}

// for yescryptR32, yespower-0.5_R32 (Wavi)
void yespower_0_5_R32_hash(const char *input, char *output)
{
        yespower_params_t params = {
                .version = YESPOWER_0_5,
                .N = 4096,
                .r = 32,
                .pers = "WaviBanana",
                .perslen = 10
        };
        yespower_tls((const uint8_t *) input, 80, &params, (yespower_binary_t *) output);
}

