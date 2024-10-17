const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const libnl = @cImport({
    @cInclude("netlink/netlink.h");
});

const alignment = 4;

const attribute = struct {
    len: u16,
    type: u16,
    const @"type" = enum {
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

const message = struct {};

const error_attributes = enum {
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

const callback = struct {
    const receiver_callback_t = *const fn (*message, *anyopaque) i32;
    const receiver_error_callback_t = *const fn (*socket_addr, nl_error, *anyopaque) i32;
    callback_set: []receiver_callback_t,
    arguments: []*anyopaque,
    error_callback: receiver_error_callback_t,
    error_argument: ?*anyopaque = null,
    receive_messages: ?*const fn (*socket, *callback) i32 = null, // won't be implemented soon
    receiver: ?*const fn (*socket, *socket_addr, *[*:0]u8, *anyopaque) i32 = null, // won't be implemented soon
    sender: ?*const fn (*socket, *anyopaque) i32 = null,
    reference_count: i32,
    active: undefined,
};

const socket_addr = struct {
    family: u16,
    pad: u16,
    pid: u32,
    groups: u32,
};

const socket = struct {
    fd: i32,
    proto: i32,
    cb: *anyopaque,
    local: socket_addr,
    peer: socket_addr,
    sequence_next: u32,
    sequence_expect: u32,
    flags: i32,
    buffer_size: u64,

    //  sk->s_fd = -1;
    //   124         sk->s_cb = nl_cb_get(cb);
    //   125         sk->s_local.nl_family = AF_NETLINK;
    //   126         sk->s_peer.nl_family = AF_NETLINK;
    //   127         sk->s_seq_expect = sk->s_seq_next = time(0);
    //   128         sk->s_local.nl_pid = generate_local_port();
    //   129         if (sk->s_local.nl_pid == UINT_MAX) {
    //   130                 nl_socket_free(sk);
    //   131                 return NULL;
    //   132         }

    pub fn init(allocator: Allocator) !*socket {
        const self = try allocator.create(socket);
        self.* = .{
            .fd = -1,
            .s_seq_expect = std.time.timestamp(),
        };
        return self;
    }
};

const message_flags = enum(u32) {
    request = 1,
    mutlipart = 2,
    ack = 4,
    echo = 8,
    // Get Request
    root = 0x100,
    match = 0x200,
    atomic = 0x400,
    dump = message_flags.root | message_flags.match,
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
};

pub fn mflags_to_int(flags: []message_flags) i32 {
    var flag: i32 = 0;
    for (flags) |f| {
        flag |= f;
    }
    return flag;
}

const MSG_SETCFG = 0x11;
const MSG_GETCFG = 0x12;

const nl_header = struct {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,

    const Self = @This();

    pub fn convert_to_message(self: *Self) []u8 {
        var buffer: []u8 = undefined;
        @memcpy(buffer[0..32], self.nlmsg_len);
        @memcpy(buffer[32..48], self.nlmsg_type);
        @memcpy(buffer[48..64], self.nlmsg_flags);
        @memcpy(buffer[64..128], self.nlmsg_seq);
        @memcpy(buffer[128..256], self.nlmsg_pid);
    }
};

const nl_error = struct { header: nl_header, errorcode: u32 };
