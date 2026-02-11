const std = @import("std");

const TlsClient = std.crypto.tls.Client;

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    const allocator: std.mem.Allocator = gpa.allocator();

    var reader_buf_tcp: [std.crypto.tls.max_ciphertext_record_len]u8 = undefined;
    var writer_buf_tcp: [std.crypto.tls.max_ciphertext_record_len]u8 = undefined;

    var writer_buf_tls: [std.crypto.tls.max_ciphertext_record_len]u8 = undefined;
    var reader_buf_tls: [std.crypto.tls.max_ciphertext_record_len]u8 = undefined;

    const hostname = "eventsub.wss.twitch.tv";
    const resource = "/ws";
    const port = 443;

    const conn = try std.net.tcpConnectToHost(allocator, hostname, port);
    defer conn.close();

    var reader_tcp_ = conn.reader(&reader_buf_tcp);
    const reader_tcp = reader_tcp_.interface();

    var writer_tcp_ = conn.writer(&writer_buf_tcp);
    const writer_tcp = &writer_tcp_.interface;

    var bundle: std.crypto.Certificate.Bundle = std.crypto.Certificate.Bundle{};
    try bundle.rescan(allocator);
    defer bundle.deinit(allocator);

    var client: TlsClient = try .init(reader_tcp, writer_tcp, .{
        .host = .{ .explicit = hostname },
        .ca = .{ .bundle = bundle },
        .write_buffer = &writer_buf_tls,
        .read_buffer = &reader_buf_tls,
    });
    defer client.end() catch {};

    var writer = &client.writer;
    var reader = &client.reader;

    var websockey: [16]u8 = undefined;

    std.crypto.random.bytes(&websockey);

    std.debug.print("{any}\n", .{websockey});

    const base64_encoder: std.base64.Base64Encoder = .init(std.base64.standard_alphabet_chars, '=');
    var base64_buf: [24]u8 = undefined;
    _ = base64_encoder.encode(&base64_buf, &websockey);
    std.debug.print("base64_encoded_key: {s}\n", .{base64_buf});

    const request = "GET " ++ resource ++ " HTTP/1.1\r\n" ++
        "Host: " ++ hostname ++ "\r\n" ++
        "Request-URI: https://" ++ hostname ++ resource ++ "\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: upgrade\r\n" ++
        "Sec-WebSocket-Key: " ++ base64_buf ++ "\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++ "\r\n";

    std.debug.print("{s}\n", .{request});
    _ = try writer.write(request);

    try writer.flush();
    try writer_tcp.flush();
    const data = try reader.readAlloc(allocator, 32);
    std.debug.print("{s}", .{data});
}
