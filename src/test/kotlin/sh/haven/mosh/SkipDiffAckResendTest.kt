package sh.haven.mosh

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import sh.haven.mosh.crypto.MoshCrypto
import sh.haven.mosh.network.MoshConnection
import sh.haven.mosh.proto.Transportinstruction.Instruction as TransportInstruction
import sh.haven.mosh.transport.MoshTransport
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.Base64
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.zip.DeflaterOutputStream
import java.util.zip.InflaterInputStream

/**
 * #421: when the server diffs from a state the client has already passed
 * (its ack of that state was lost or not yet acted on), the client used to
 * send nothing until the next 3s keepalive — the server kept retransmitting
 * the unappliable diff ~14/s and the screen froze for the whole window.
 * A skip must trigger a prompt resend of the ack carrying the client's
 * actual state, rate limited so a storm of skips doesn't storm acks.
 */
class SkipDiffAckResendTest {

    private fun randomKey(): String {
        val bytes = ByteArray(16)
        java.security.SecureRandom().nextBytes(bytes)
        return Base64.getEncoder().encodeToString(bytes)
    }

    private fun instruction(oldNum: Long, newNum: Long): TransportInstruction =
        TransportInstruction.newBuilder()
            .setProtocolVersion(MoshTransport.PROTOCOL_VERSION)
            .setOldNum(oldNum)
            .setNewNum(newNum)
            .setAckNum(0)
            .setThrowawayNum(0)
            .build()

    /**
     * Loopback stand-in for mosh-server: decrypts every client packet,
     * records the parsed instruction, and acks the client's most recent
     * state so the transport's own retransmit logic stays quiet and only
     * the behaviour under test moves packets.
     */
    private class FakeServer(crypto: MoshCrypto) {
        val socket = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val received = ConcurrentLinkedQueue<TransportInstruction>()
        private val running = AtomicBoolean(true)
        private val delegate = crypto
        private var ackSeq = 0L
        private var lastSender: java.net.SocketAddress? = null

        fun start() {
            val thread = Thread {
                val buf = ByteArray(2048)
                socket.soTimeout = 50
                while (running.get()) {
                    val p = DatagramPacket(buf, buf.size)
                    try {
                        socket.receive(p)
                    } catch (_: Exception) {
                        continue
                    }
                    lastSender = p.socketAddress
                    val inst = try { parseClientPacket(p.data.copyOf(p.length)) } catch (_: Exception) { null }
                    if (inst != null) received.add(inst)
                    try { sendAck(inst?.newNum ?: 0L) } catch (_: Exception) {}
                }
            }
            thread.isDaemon = true
            thread.start()
        }

        fun stop() {
            running.set(false)
            socket.close()
        }

        /**
         * Client→server wire: [8-byte nonce][OCB(plaintext)] where plaintext
         * is [4-byte timestamps][8-byte frag id][2-byte frag flags][zlib
         * protobuf]. Mirrors the single-fragment path of MoshConnection.
         */
        private fun parseClientPacket(packet: ByteArray): TransportInstruction? {
            val (_, plaintext) = delegate.decrypt(packet)
            require(plaintext.size > MoshConnection.TIMESTAMP_LEN + MoshConnection.FRAG_HEADER_LEN)
            val combined = ((plaintext[MoshConnection.TIMESTAMP_LEN + 8].toInt() and 0xFF) shl 8) or
                (plaintext[MoshConnection.TIMESTAMP_LEN + 9].toInt() and 0xFF)
            val isFinal = (combined and 0x8000) != 0
            val fragmentNum = combined and 0x7FFF
            if (!isFinal || fragmentNum != 0) return null
            val payload = plaintext.copyOfRange(
                MoshConnection.TIMESTAMP_LEN + MoshConnection.FRAG_HEADER_LEN,
                plaintext.size,
            )
            return TransportInstruction.parseFrom(zlib(payload))
        }

        private fun sendAck(ackNum: Long) {
            val sender = lastSender ?: return
            val inst = TransportInstruction.newBuilder()
                .setProtocolVersion(MoshTransport.PROTOCOL_VERSION)
                .setOldNum(0)
                .setNewNum(0)
                .setAckNum(ackNum)
                .setThrowawayNum(0)
                .build()
            val payload = ByteArrayOutputStream().also { bos ->
                DeflaterOutputStream(bos).use { it.write(inst.toByteArray()) }
            }.toByteArray()
            val header = MoshConnection.TIMESTAMP_LEN + MoshConnection.FRAG_HEADER_LEN
            val plaintext = ByteArray(header + payload.size)
            val combined = 1 shl 15 // final, fragment 0
            plaintext[header - 2] = (combined ushr 8).toByte()
            plaintext[header - 1] = combined.toByte()
            System.arraycopy(payload, 0, plaintext, header, payload.size)
            val packet = delegate.encrypt(MoshCrypto.DIRECTION_TO_CLIENT or ackSeq++, plaintext)
            socket.send(DatagramPacket(packet, packet.size, sender))
        }

        private fun zlib(data: ByteArray): ByteArray = InflaterInputStream(data.inputStream()).readBytes()
    }

    private fun awaitContact(fake: FakeServer) {
        val deadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < deadline && fake.received.isEmpty()) Thread.sleep(20)
        assertTrue("client never reached the fake server", fake.received.isNotEmpty())
        // Give the fake ack a moment to settle the transport's retransmit
        // loop so packets recorded below are the behaviour under test.
        Thread.sleep(150)
    }

    @Test
    fun `skipped ahead diff triggers prompt ack resend`() {
        val key = randomKey()
        val fake = FakeServer(MoshCrypto(key))
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val t = MoshTransport(
            serverIp = "127.0.0.1",
            port = fake.socket.localPort,
            key = key,
            onOutput = { _, _, _ -> },
        )
        try {
            fake.start()
            t.start(scope)
            awaitContact(fake)

            // Server ahead on a base the client has passed: client is at
            // state 0, the diff goes 5 → 6 (the #421 shape).
            val before = fake.received.size
            t.processInstruction(instruction(oldNum = 5, newNum = 6))

            val deadline = System.currentTimeMillis() + 600
            while (System.currentTimeMillis() < deadline && fake.received.size == before) Thread.sleep(10)
            assertTrue(
                "no ack resent within 600ms of a skipped diff — the #421 freeze",
                fake.received.size > before,
            )
            // The resent packet must carry the client's actual state (0),
            // not the server's announcement.
            assertEquals(0L, fake.received.toList()[before].ackNum)
        } finally {
            t.close()
            scope.cancel()
            fake.stop()
        }
    }

    @Test
    fun `ack resends are rate limited during a skip storm`() {
        val key = randomKey()
        val fake = FakeServer(MoshCrypto(key))
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val t = MoshTransport(
            serverIp = "127.0.0.1",
            port = fake.socket.localPort,
            key = key,
            onOutput = { _, _, _ -> },
        )
        try {
            fake.start()
            t.start(scope)
            awaitContact(fake)

            // dkoppenh's log showed ~14 skipped diffs per second; hammer far
            // past that and check the ack cadence stays bounded.
            val before = fake.received.size
            repeat(100) { t.processInstruction(instruction(oldNum = 5, newNum = 6)) }
            Thread.sleep(1000)
            val arrived = fake.received.size - before
            assertTrue("skip storm produced no ack resends", arrived > 0)
            assertTrue(
                "skip storm produced $arrived acks in 1s — resend is not rate limited",
                arrived <= 15,
            )
        } finally {
            t.close()
            scope.cancel()
            fake.stop()
        }
    }

    @Test
    fun `resent ack carries the client state, not the server's announced state`() {
        val key = randomKey()
        val fake = FakeServer(MoshCrypto(key))
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val t = MoshTransport(
            serverIp = "127.0.0.1",
            port = fake.socket.localPort,
            key = key,
            onOutput = { _, _, _ -> },
        )
        try {
            fake.start()
            t.start(scope)
            awaitContact(fake)

            // Bring the client to state 2 with base-matching empty diffs.
            t.processInstruction(instruction(oldNum = 0, newNum = 1))
            t.processInstruction(instruction(oldNum = 1, newNum = 2))
            Thread.sleep(100)
            val before = fake.received.size

            // Server now diffs from a base the client has passed.
            t.processInstruction(instruction(oldNum = 0, newNum = 3))

            val deadline = System.currentTimeMillis() + 600
            while (System.currentTimeMillis() < deadline && fake.received.size == before) Thread.sleep(10)
            assertTrue("no ack resent within 600ms of a skipped diff", fake.received.size > before)
            // Acking the server's announcement (3) would tell it to discard
            // the exact state we need — the #73 corruption trap.
            assertEquals(2L, fake.received.toList()[before].ackNum)
            assertEquals(1L, fake.received.toList()[before].oldNum)
        } finally {
            t.close()
            scope.cancel()
            fake.stop()
        }
    }
}