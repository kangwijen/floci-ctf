package io.github.hectorvent.floci.services.docdb.proxy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/**
 * Minimal MongoDB OP_MSG helpers for DocumentDB AuthProxy hello + PLAIN saslStart.
 */
final class DocDbMongoWire {

    private static final int OP_MSG = 2013;

    private DocDbMongoWire() {
    }

    record PlainCredentials(String username, String password) {
    }

    static byte[] readMessage(InputStream in) throws IOException {
        byte[] header = in.readNBytes(4);
        if (header.length < 4) {
            return header;
        }
        int size = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if (size < 16 || size > 16 * 1024 * 1024) {
            return header;
        }
        byte[] rest = in.readNBytes(size - 4);
        byte[] all = new byte[size];
        System.arraycopy(header, 0, all, 0, 4);
        System.arraycopy(rest, 0, all, 4, rest.length);
        return all;
    }

    static int requestId(byte[] message) {
        if (message.length < 12) {
            return 0;
        }
        return ByteBuffer.wrap(message, 4, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    static boolean isHello(byte[] message) {
        String body = bodyAsLatin(message);
        return body.contains("hello") || body.contains("isMaster") || body.contains("ismaster");
    }

    static PlainCredentials parsePlainSaslStart(byte[] message) {
        String body = bodyAsLatin(message);
        if (!body.contains("saslStart") || !body.contains("PLAIN")) {
            return null;
        }
        // PLAIN payload is binary BSON: subtype + bytes "\0user\0pass"
        int payloadKey = indexOf(message, "payload".getBytes(StandardCharsets.UTF_8));
        if (payloadKey < 0) {
            return null;
        }
        // After cstring name comes int32 length, subtype byte, then payload bytes
        int nameEnd = payloadKey + "payload".length() + 1;
        if (nameEnd + 5 > message.length) {
            return null;
        }
        int len = ByteBuffer.wrap(message, nameEnd, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int subtypeIndex = nameEnd + 4;
        int dataStart = subtypeIndex + 1;
        if (len < 3 || dataStart + len > message.length) {
            return null;
        }
        byte[] payload = new byte[len];
        System.arraycopy(message, dataStart, payload, 0, len);
        if (payload[0] != 0) {
            return null;
        }
        int second = -1;
        for (int i = 1; i < payload.length; i++) {
            if (payload[i] == 0) {
                second = i;
                break;
            }
        }
        if (second < 0 || second + 1 >= payload.length) {
            return null;
        }
        String user = new String(payload, 1, second - 1, StandardCharsets.UTF_8);
        String pass = new String(payload, second + 1, payload.length - second - 1, StandardCharsets.UTF_8);
        return new PlainCredentials(user, pass);
    }

    static byte[] helloOkResponse(int responseTo) {
        byte[] body = bsonDocument(
                bsonDouble("ok", 1.0),
                bsonBoolean("isWritablePrimary", true),
                bsonInt32("maxWireVersion", 17),
                bsonInt32("minWireVersion", 0),
                bsonArray("saslSupportedMechs", "PLAIN"));
        return opMsgResponse(responseTo, body);
    }

    static byte[] saslSuccessResponse(int responseTo) {
        byte[] body = bsonDocument(
                bsonInt32("conversationId", 1),
                bsonBoolean("done", true),
                bsonBinary("payload", new byte[0]),
                bsonDouble("ok", 1.0));
        return opMsgResponse(responseTo, body);
    }

    static byte[] authFailureResponse(int responseTo, String errmsg) {
        byte[] body = bsonDocument(
                bsonDouble("ok", 0.0),
                bsonString("errmsg", errmsg),
                bsonInt32("code", 18),
                bsonString("codeName", "AuthenticationFailed"));
        return opMsgResponse(responseTo, body);
    }

    private static String bodyAsLatin(byte[] message) {
        if (message.length <= 16) {
            return "";
        }
        return new String(message, 16, message.length - 16, StandardCharsets.ISO_8859_1);
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static byte[] opMsgResponse(int responseTo, byte[] bsonBody) {
        ByteArrayOutputStream payload = new ByteArrayOutputStream();
        writeInt32(payload, 0);
        payload.write(0);
        payload.writeBytes(bsonBody);
        byte[] payloadBytes = payload.toByteArray();
        int total = 16 + payloadBytes.length;
        ByteBuffer buf = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(total);
        buf.putInt(1);
        buf.putInt(responseTo);
        buf.putInt(OP_MSG);
        buf.put(payloadBytes);
        return buf.array();
    }

    private static byte[] bsonDocument(byte[]... elements) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] el : elements) {
            out.writeBytes(el);
        }
        out.write(0);
        byte[] content = out.toByteArray();
        ByteBuffer buf = ByteBuffer.allocate(4 + content.length).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(4 + content.length);
        buf.put(content);
        return buf.array();
    }

    private static byte[] bsonArray(String name, String value) {
        byte[] elem = bsonString("0", value);
        ByteArrayOutputStream content = new ByteArrayOutputStream();
        content.writeBytes(elem);
        content.write(0);
        byte[] c = content.toByteArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x04);
        writeCString(out, name);
        writeInt32(out, 4 + c.length);
        out.writeBytes(c);
        return out.toByteArray();
    }

    private static byte[] bsonDouble(String name, double value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x01);
        writeCString(out, name);
        ByteBuffer buf = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN);
        buf.putDouble(value);
        out.writeBytes(buf.array());
        return out.toByteArray();
    }

    private static byte[] bsonBoolean(String name, boolean value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x08);
        writeCString(out, name);
        out.write(value ? 1 : 0);
        return out.toByteArray();
    }

    private static byte[] bsonInt32(String name, int value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x10);
        writeCString(out, name);
        writeInt32(out, value);
        return out.toByteArray();
    }

    private static byte[] bsonString(String name, String value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x02);
        writeCString(out, name);
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        writeInt32(out, bytes.length + 1);
        out.writeBytes(bytes);
        out.write(0);
        return out.toByteArray();
    }

    private static byte[] bsonBinary(String name, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x05);
        writeCString(out, name);
        writeInt32(out, value.length);
        out.write(0);
        out.writeBytes(value);
        return out.toByteArray();
    }

    private static void writeCString(ByteArrayOutputStream out, String s) {
        out.writeBytes(s.getBytes(StandardCharsets.UTF_8));
        out.write(0);
    }

    private static void writeInt32(ByteArrayOutputStream out, int value) {
        out.write(value & 0xff);
        out.write((value >> 8) & 0xff);
        out.write((value >> 16) & 0xff);
        out.write((value >> 24) & 0xff);
    }
}
