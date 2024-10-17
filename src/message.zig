const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const alignment = 4;

pub const attribute = struct {
    len: u16,
    type: @"type",
    payload: []u8,
    const @"type" = enum(u16) {
        invalid,
        flag,
        u8,
        u16,
        u32,
        u64,
        s8,
        s16,
        s32,
        s64,
        binary,
        string,
        nul_string,
        nested,
        nested_array,
        bitfield32,
    };
    pub fn convert_to_message(self: *attribute) []u8 {
        var header: [32]u8 = undefined;
        @memcpy(header[0..16], self.len);
        @memcpy(header[16..32], self.type);
        return header ++ self.payload ++ @as(u1, 0x0) ** (header.len + self.payload.len) % 4;
    }
};

//   nla_type (16 bits)
//   +---+---+-------------------------------+
//   | N | O | Attribute Type                |
//   +---+---+-------------------------------+
//   N := Carries nested attributes
//   O := Payload stored in network byte order
//
//   Note: The N and O flag are mutually exclusive.
//
// #define NLA_F_NESTED		(1 << 15)
// #define NLA_F_NET_BYTEORDER	(1 << 14)
// #define NLA_TYPE_MASK		~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)

pub const error_attributes = enum {
    unused,
    msg,
    offs,
    policy,
    miss_type,
    miss_nest,
    max_err_attr,

    ///   nla_type (16 bits)
    ///   +---+---+-------------------------------+
    ///   | N | O | Attribute Type                |
    ///   +---+---+-------------------------------+
    ///   N := Carries nested attributes
    ///   O := Payload stored in network byte order
    const msg_type = enum(i32) {
        noop = 0x1,
        @"error" = 0x2,
        done = 0x3,
        overrun = 0x4,
    };

    pub fn set_nested(self: *error_attributes.msg_type) void {
        assert(self & 1 << 15);
        self &= 1 << 15;
    }

    pub fn set_byteorder_net(self: *error_attributes.msg_type) void {
        assert(self & 1 << 14);
        self &= 1 << 14;
    }

    pub fn mask_type(self: *error_attributes.msg_type) void {
        self &= 1 << 14;
        self &= 1 << 15;
    }
};

// #define NLMSG_ALIGNTO	4U
// #define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
// #define NLMSG_HDRLEN	 ((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))
// #define NLMSG_LENGTH(len) ((len) + NLMSG_HDRLEN)
// #define NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))
// #define NLMSG_DATA(nlh)  ((void *)(((char *)nlh) + NLMSG_HDRLEN))
// #define NLMSG_NEXT(nlh,len)	 ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
// 				  (struct nlmsghdr *)(((char *)(nlh)) + \
// 				  NLMSG_ALIGN((nlh)->nlmsg_len)))
// #define NLMSG_OK(nlh,len) ((len) >= (int)sizeof(struct nlmsghdr) && \
// 			   (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
// 			   (nlh)->nlmsg_len <= (len))
// #define NLMSG_PAYLOAD(nlh,len) ((nlh)->nlmsg_len - NLMSG_SPACE((len)))

// #define NLMSG_MIN_TYPE		0x10	/* < 0x10: reserved control messages */

const message = struct {
    flags: []msg_flags,
    type: msg_types,
    pub const msg_flags = enum(u32) {
        request = 1,
        mutlipart = 2,
        ack = 4,
        echo = 8,
        // Get Request
        root = 0x100,
        match = 0x200,
        atomic = 0x400,
        dump = message.flags.root | message.flags.match,
        // New Request
        replace = 0x100,
        excl = 0x200,
        create = 0x400,
        append = 0x800,
        // Delete request
        nonrec = 0x100,
        bulk = 0x200,
        // Ack request
        capped = 0x100,
        ack_tlvs = 0x200,
        pub fn mflags_to_int(self: *message) i32 {
            var flag: i32 = 0;
            for (self) |f| {
                flag |= f;
            }
            return flag;
        }
    };

    pub const msg_types = enum(u32) {
        noop = 0x1,
        @"error" = 0x2,
        done = 0x3,
        overrun = 0x4,
        min_type = 0x10,
    };
};

const MSG_SETCFG = 0x11;
const MSG_GETCFG = 0x12;
