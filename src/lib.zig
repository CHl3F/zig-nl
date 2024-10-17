const std = @import("std");

const nl_socket = @import("./socket.zig");
const nl_msg = @import("./message.zig");

pub const socket = nl_socket.socket;
pub const message = nl_msg.message;

pub const link = struct {
    pub fn create(self: *link, allocator: std.mem.Allocator, diagnose: ?diagnostics) !void {
        _ = self;
        _ = allocator;
        _ = diagnose;
    }
    pub fn delete(self: *link, allocator: std.mem.Allocator, diagnose: ?diagnostics) !void {
        _ = self;
        _ = allocator;
        _ = diagnose;
    }
    pub fn modify(self: *link, allocator: std.mem.Allocator, diagnose: ?diagnostics) !void {
        _ = self;
        _ = allocator;
        _ = diagnose;
    }
};
pub const route = struct {
    pub fn create(self: *link, allocator: std.mem.Allocator, diagnose: ?diagnostics) !void {
        _ = self;
        _ = allocator;
        _ = diagnose;
    }
    pub fn delete(self: *link, allocator: std.mem.Allocator, diagnose: ?diagnostics) !void {
        _ = self;
        _ = allocator;
        _ = diagnose;
    }
    pub fn modify(self: *link, allocator: std.mem.Allocator, diagnose: ?diagnostics) !void {
        _ = self;
        _ = allocator;
        _ = diagnose;
    }
};
pub const diagnostics = struct {
    msg: []u8,
    code: usize,
};
