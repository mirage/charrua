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

