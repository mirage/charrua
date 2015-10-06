(*
 * Copyright (c) 2015 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

cstruct dhcp {
  uint8_t      op;
  uint8_t      htype;
  uint8_t      hlen;
  uint8_t      hops;
  uint32_t     xid;
  uint16_t     secs;
  uint16_t     flags;
  uint32_t     ciaddr;
  uint32_t     yiaddr;
  uint32_t     siaddr;
  uint32_t     giaddr;
  uint8_t      chaddr[16];
  uint8_t      sname[64];
  uint8_t      file[128];
} as big_endian
