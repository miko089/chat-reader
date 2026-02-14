const std = @import("std");

const TlsClient = std.crypto.tls.Client;

pub const WSClient = struct {
    const Self = @This();
    reader_buf_tcp: [std.crypto.tls.max_ciphertext_record_len]u8 = undefined,
    writer_buf_tcp: [std.crypto.tls.max_ciphertext_record_len]u8 = undefined,
    reader_buf_tls: [std.crypto.tls.max_ciphertext_record_len]u8 = undefined,
    writer_buf_tls: [std.crypto.tls.max_ciphertext_record_len]u8 = undefined,
    reader_tcp_: std.net.Stream.Reader,
    writer_tcp_: std.net.Stream.Writer,
    reader_tcp: *std.Io.Reader,
    writer_tcp: *std.Io.Writer,
    reader_tls: *std.Io.Reader,
    writer_tls: *std.Io.Writer,
    tcp_conn: std.net.Stream,
    tls_client: std.crypto.tls.Client,
    allocator: std.mem.Allocator,
    hostname: []const u8,
    resource: []const u8,
    port: u16,
    bundle: std.crypto.Certificate.Bundle,

    pub fn init(self: *Self, allocator: std.mem.Allocator, comptime hostname: []const u8, comptime resource: []const u8, comptime port: u16) !void {
        self.hostname = hostname;
        self.resource = resource;
        self.port = port;
        self.allocator = allocator;

        try tcpClientInit(self);
        self.bundle = std.crypto.Certificate.Bundle{};
        try self.bundle.rescan(self.allocator);
        try self.tlsClientInit();

        try websocketUpgrade(self);
    }

    fn tcpClientInit(self: *Self) !void {
        self.tcp_conn = try std.net.tcpConnectToHost(self.allocator, self.hostname, self.port);
        self.reader_tcp_ = self.tcp_conn.reader(&self.reader_buf_tcp);
        self.reader_tcp = self.reader_tcp_.interface();
        self.writer_tcp_ = self.tcp_conn.writer(&self.writer_buf_tcp);
        self.writer_tcp = &self.writer_tcp_.interface;
    }

    fn tlsClientInit(self: *Self) !void {
        self.tls_client = try .init(self.reader_tcp, self.writer_tcp, .{
            .host = .{ .explicit = self.hostname },
            .ca = .{ .bundle = self.bundle },
            .write_buffer = &self.writer_buf_tls,
            .read_buffer = &self.reader_buf_tls,
        });

        self.reader_tls = &self.tls_client.reader;
        self.writer_tls = &self.tls_client.writer;
    }

    inline fn flush(self: *Self) !void {
        try self.writer_tls.flush();
        try self.writer_tcp.flush();
    }

    fn websocketUpgrade(self: *Self) !void {
        var websockey: [16]u8 = undefined;
        std.crypto.random.bytes(&websockey);

        const base64_encoder: std.base64.Base64Encoder = .init(std.base64.standard_alphabet_chars, '=');
        var base64_buf: [24]u8 = undefined;
        _ = base64_encoder.encode(&base64_buf, &websockey);

        var request: [1024 * 4]u8 = undefined;
        const request_fmt = "GET {s} HTTP/1.1\r\n" ++
            "Host: {s}\r\n" ++
            "Request-URI: https://{s}{s}\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: upgrade\r\n" ++
            "Sec-WebSocket-Key: {s}\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++ "\r\n";
        _ = try std.fmt.bufPrint(&request, request_fmt, .{ self.resource, self.hostname, self.hostname, self.resource, base64_buf });
        _ = try self.writer_tls.write(&request);
        try self.flush();
        _ = try self.reader_tls.discardDelimiterInclusive(' ');
        const resp = try self.reader_tls.take(3);
        const code = try std.fmt.parseInt(u32, resp, 10);
        if (code != 101) {
            std.log.err("Wrong HTTP code: expected 101, got {d}", .{code});
            return error.WrongHTTPCode;
        }
        while (true) {
            _ = try self.reader_tls.discardDelimiterInclusive('\n');
            const bytes = try self.reader_tls.peek(2);
            if (bytes[0] == '\r' and bytes[1] == '\n') {
                _ = try self.reader_tls.discard(.limited(2));
                break;
            }
        }
        // const resp2 = try self.reader_tls.take(4);
        // std.debug.print("{any}", .{resp2});
    }

    const Flags = packed struct {
        fin: u1,
        rsv: u3,
        opcode: u4,
        mask: u1,
        payload_length: u7,
    };

    /// it should return ![]const u8
    pub fn readFrame(self: *Self) !void {
        const flags_raw = (try self.reader_tls.takeInt(u16, .big));
        const flags: Flags = @bitCast(flags_raw);
        std.debug.print("{any}", .{flags});
        return error.somenonsense;
    }

    pub fn deinit(self: *Self) void {
        defer self.tcp_conn.close();
        defer self.bundle.deinit(self.allocator);
        defer self.tls_client.end() catch {};
    }
};

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    const allocator: std.mem.Allocator = gpa.allocator();

    var ws: WSClient = undefined;
    try ws.init(allocator, "eventsub.wss.twitch.tv", "/ws", 443);
    defer ws.deinit();

    _ = ws.readFrame() catch {};
}
