(* This is a placeholder for the cpkt structure, merlin has no support for
   cstructs syntax extensions yet, so I split it in another module so that we
   don't get syntax errors while doing the real work in Dhcp. *)
cstruct cpkt {
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

cstruct ethernet {
  uint8_t        dst[6];
  uint8_t        src[6];
  uint16_t       ethertype;
} as big_endian

cstruct ipv4 {
  uint8_t        hlen_version;
  uint8_t        tos;
  uint16_t       len;
  uint16_t       id;
  uint16_t       off;
  uint8_t        ttl;
  uint8_t        proto;
  uint16_t       csum;
  uint32_t       src;
  uint32_t       dst;
} as big_endian

cstruct udp {
  uint16_t       src;
  uint16_t       dst;
  uint16_t       len;
  uint16_t       csum;
} as big_endian
