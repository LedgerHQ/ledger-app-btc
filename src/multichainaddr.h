/* Copyright (c) 2017 Pieter Wuille
 * Modified work Copyright (c) 2018 Jonas Karlsson
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef _MULTICHAINADDR_H_
#define _MULTICHAINADDR_H_

#include <stdint.h>

/** Encode a Multichain address
 *
 *  In:      in:           Pointer to the public key
 *           inlen:        Length of public key (bytes)
 *           outlen:       Maximum length of encoded address
 *           version:      address-pubkeyhash-version
 *           checksum:     address-checksum-value
 *
 *  Out:     out:          Pointer to a buffer with encoded address. The encoded
 * address end with a '\0'.
 *
 *  Returns the length of the address if successful, 0 if unsuccessful.
 */

int multichainaddr_encode(unsigned char *in, unsigned short inlen, unsigned char *out,
                          unsigned short outlen, unsigned int version, unsigned int checksum, unsigned char alreadyHashed);

#endif /* _MULTICHAINADDR_H_ */
