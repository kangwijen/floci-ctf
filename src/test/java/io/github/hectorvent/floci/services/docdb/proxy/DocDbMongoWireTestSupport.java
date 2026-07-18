package io.github.hectorvent.floci.services.docdb.proxy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Minimal MongoDB wire helpers for DocDB AuthProxy security-regression tests.
 */
final class DocDbMongoWireTestSupport {

    private static final int OP_MSG = 2013;

    private DocDbMongoWireTestSupport() {
    }

    static byte[] helloRequest() {
        byte[] body = bsonDocument(
                bsonInt32("hello", 1),
                bsonString("$db", "admin"));
        return opMsg(body);
    }

    static byte[] plainSaslStart(String username, String password) {
        byte[] payload = ("\0" + username + "\0" + password).getBytes(StandardCharsets.UTF_8);
        byte[] body = bsonDocument(
                bsonInt32("saslStart", 1),
                bsonString("mechanism", "PLAIN"),
                bsonBinary("payload", payload),
                bsonString("$db", "admin"));
        return opMsg(body);
    }

    static byte[] readMessage(InputStream in) throws IOException {
        byte[] header = in.readNBytes(4);
        if (header.length < 4) {
            return header;
        }
        int size = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if (size < 4 || size > 16 * 1024 * 1024) {
            return header;
        }
        byte[] rest = in.readNBytes(size - 4);
        byte[] all = new byte[size];
        System.arraycopy(header, 0, all, 0, 4);
        System.arraycopy(rest, 0, all, 4, rest.length);
        return all;
    }

    static boolean bodyContains(byte[] message, String needle) {
        if (message == null || message.length < 16) {
            return false;
        }
        String asLatin = new String(message, StandardCharsets.ISO_8859_1);
        return asLatin.contains(needle);
    }

    private static byte[] opMsg(byte[] bsonBody) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // flagBits
        writeInt32(out, 0);
        // section kind 0 = body
        out.write(0);
        try {
            out.write(bsonBody);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        byte[] payload = out.toByteArray();
        int total = 16 + payload.length;
        ByteBuffer buf = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(total);
        buf.putInt(1); // requestId
        buf.putInt(0); // responseTo
        buf.putInt(OP_MSG);
        buf.put(payload);
        return buf.array();
    }

    private static byte[] bsonDocument(byte[]... elements) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] el : elements) {
            try {
                out.write(el);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
        out.write(0);
        byte[] content = out.toByteArray();
        ByteBuffer buf = ByteBuffer.allocate(4 + content.length).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(4 + content.length);
        buf.put(content);
        return buf.array();
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
        try {
            out.write(bytes);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        out.write(0);
        return out.toByteArray();
    }

    private static byte[] bsonBinary(String name, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x05);
        writeCString(out, name);
        writeInt32(out, value.length);
        out.write(0); // subtype generic
        try {
            out.write(value);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
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
