const std = @import("std");
const Allocator = std.mem.Allocator;
const unix_socket = std.os.linux.socket;

const core = @import("./message.zig");

const nl_error = struct { header: nl_header, errorcode: u32 };

const nl_header = struct {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,

    pub fn convert_to_message(self: *nl_header) []u8 {
        var buffer: []u8 = undefined;
        @memcpy(buffer[0..32], self.nlmsg_len);
        @memcpy(buffer[32..48], self.nlmsg_type);
        @memcpy(buffer[48..64], self.nlmsg_flags);
        @memcpy(buffer[64..128], self.nlmsg_seq);
        @memcpy(buffer[128..256], self.nlmsg_pid);
    }
};

const socket_addr = struct {
    family: u16,
    pad: u16,
    pid: u32,
    groups: u32,
};

const callback = struct {
    const receiver_callback_t = *const fn (*core.message, *anyopaque) i32;
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

const socket = struct {
    fd: i32,
    proto: i32,
    callback: *callback,
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

fn generate_local_port() u32 {
    const pid = std.os.linux.getpid() & 0x3FFFFF;
    // write lock
    _ = pid;
}
