package sh.haven.mosh.network

import sh.haven.mosh.crypto.MoshCrypto
import sh.haven.mosh.crypto.MoshCrypto.Companion.DIRECTION_TO_CLIENT
import sh.haven.mosh.crypto.MoshCrypto.Companion.DIRECTION_TO_SERVER
import sh.haven.mosh.crypto.MoshCrypto.Companion.getBE64
import sh.haven.mosh.crypto.MoshCrypto.Companion.putBE64
import sh.haven.mosh.proto.Transportinstruction.Instruction as TransportInstruction
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.util.zip.Deflater
import java.util.zip.Inflater

/**
 * UDP connection with mosh packet encryption, timestamps, zlib compression,
 * and fragment reassembly.
 *
 * Packet wire format: [8-byte nonce][AES-128-OCB(plaintext) + 16-byte tag]
 * Plaintext: [2-byte timestamp][2-byte timestamp_reply][fragment data]
 * Fragment: [8-byte fragment_id][2-byte (final<<15 | frag_num)][payload]
 *
 * After fragment reassembly, the payload is zlib-decompressed, then parsed
 * as a TransportBuffers::Instruction protobuf.
 */
class MoshConnection(
    serverIp: String,
    port: Int,
    private val crypto: MoshCrypto,
    private val socketProvider: UdpSocketProvider = UdpSocketProvider { AndroidUdpAdapter() },
) : Closeable {

    private val serverHost: String = serverIp
    private val serverPort = port
    // @Volatile so the receive loop sees a rebind performed on another thread
    // without needing its own synchronization, and the rebind itself is
    // serialized under socketLock so a concurrent send never observes a
    // half-closed / half-created socket.
    @Volatile
    private var socket: UdpSocketAdapter = socketProvider.create()
    private val socketLock = Any()
    // Sockets swapped out by rebindSocket, kept open until the receive side is
    // provably out of them (receiveInstruction entry / close) — see there.
    private val retiredSockets = ArrayList<UdpSocketAdapter>()

    private var sendNonceSeq = 0L
    private var fragmentIdCounter = 0

    // Reuse zlib instances — send is single-threaded, receive is single-threaded
    private val deflater = Deflater()
    private val inflater = Inflater()
    // Reuse buffers for zlib work
    private val deflateBuf = ByteArray(1024)
    private val inflateBuf = ByteArray(4096)
    // Reuse receive buffer; the adapter fills it from offset 0 each call
    // and reports the actual datagram length via UdpReceivedPacket.length.
    private val recvBuf = ByteArray(RECV_BUF_SIZE)

    // Timestamp tracking for RTT estimation
    @Volatile var lastReceivedTimestamp: Int = 0
        private set

    // Fragment reassembly buffer
    private val fragmentBuffer = mutableMapOf<Long, FragmentAssembly>()

    private class FragmentAssembly {
        var totalExpected: Int = -1
        val fragments = mutableMapOf<Int, ByteArray>()
    }

    /**
     * Send a TransportInstruction, compressing and fragmenting as needed.
     */
    fun sendInstruction(instruction: TransportInstruction) {
        val serialized = instruction.toByteArray()
        val payload = zlibCompress(serialized)
        val fragId = (fragmentIdCounter++).toLong() and 0xFFFFL

        if (payload.size <= MAX_FRAG_PAYLOAD) {
            sendFragment(fragId, 0, true, payload)
        } else {
            val numFragments = (payload.size + MAX_FRAG_PAYLOAD - 1) / MAX_FRAG_PAYLOAD
            for (i in 0 until numFragments) {
                val start = i * MAX_FRAG_PAYLOAD
                val end = minOf(start + MAX_FRAG_PAYLOAD, payload.size)
                sendFragment(fragId, i, i == numFragments - 1,
                    payload.copyOfRange(start, end))
            }
        }
    }

    private fun sendFragment(
        fragmentId: Long, fragmentNum: Int, isFinal: Boolean, data: ByteArray,
    ) {
        // Build fragment: 8-byte ID + 2-byte combined + payload
        val fragData = ByteArray(FRAG_HEADER_LEN + data.size)
        putBE64(fragData, 0, fragmentId)
        val combined = ((if (isFinal) 1 else 0) shl 15) or (fragmentNum and 0x7FFF)
        fragData[8] = (combined ushr 8).toByte()
        fragData[9] = combined.toByte()
        System.arraycopy(data, 0, fragData, FRAG_HEADER_LEN, data.size)

        // Prepend 4-byte timestamps to the plaintext
        val timestamp = (System.currentTimeMillis() % 65536).toInt()
        val plaintext = ByteArray(TIMESTAMP_LEN + fragData.size)
        plaintext[0] = (timestamp ushr 8).toByte()
        plaintext[1] = timestamp.toByte()
        plaintext[2] = (lastReceivedTimestamp ushr 8).toByte()
        plaintext[3] = lastReceivedTimestamp.toByte()
        System.arraycopy(fragData, 0, plaintext, TIMESTAMP_LEN, fragData.size)

        // Encrypt with client→server direction
        val nonceVal = DIRECTION_TO_SERVER or sendNonceSeq++
        val packet = crypto.encrypt(nonceVal, plaintext)
        // Serialize with rebindSocket so we never send through a socket the
        // rebind path has just closed. The lock is uncontended under normal
        // operation (sends run back to back on one thread; rebinds are rare).
        synchronized(socketLock) {
            socket.send(packet, serverHost, serverPort)
        }
    }

    /**
     * Receive and reassemble a complete TransportInstruction.
     * @return the instruction, or null on timeout
     */
    fun receiveInstruction(timeoutMs: Int): TransportInstruction? {
        // Reclaim sockets retired by a rebind before blocking on the current
        // one: this is the one point where the receive loop is guaranteed
        // outside socket.receive(), so closing them cannot interrupt a read.
        closeRetiredSockets()
        while (true) {
            val received = socket.receive(recvBuf, timeoutMs) ?: return null

            val packet = recvBuf.copyOf(received.length)

            val (nonceVal, plaintext) = try {
                crypto.decrypt(packet)
            } catch (_: Exception) {
                continue // auth failure or malformed
            }

            // Validate direction: must be server→client (high bit set)
            if (nonceVal and DIRECTION_TO_CLIENT == 0L) continue

            // Need at least timestamp (4 bytes) + fragment header (10 bytes)
            if (plaintext.size < TIMESTAMP_LEN + FRAG_HEADER_LEN) continue

            // Extract timestamps
            val timestamp = ((plaintext[0].toInt() and 0xFF) shl 8) or
                (plaintext[1].toInt() and 0xFF)
            lastReceivedTimestamp = timestamp

            // Parse fragment (after timestamp bytes)
            val fragStart = TIMESTAMP_LEN
            val fragmentId = getBE64(plaintext, fragStart)
            val combined = ((plaintext[fragStart + 8].toInt() and 0xFF) shl 8) or
                (plaintext[fragStart + 9].toInt() and 0xFF)
            val isFinal = (combined and 0x8000) != 0
            val fragmentNum = combined and 0x7FFF
            val fragPayload = plaintext.copyOfRange(
                fragStart + FRAG_HEADER_LEN, plaintext.size
            )

            // Single-fragment message (common case)
            if (isFinal && fragmentNum == 0) {
                return try {
                    val decompressed = zlibDecompress(fragPayload)
                    TransportInstruction.parseFrom(decompressed)
                } catch (_: Exception) {
                    continue
                }
            }

            // Multi-fragment reassembly
            val assembly = fragmentBuffer.getOrPut(fragmentId) { FragmentAssembly() }
            assembly.fragments[fragmentNum] = fragPayload
            if (isFinal) {
                assembly.totalExpected = fragmentNum + 1
            }

            if (assembly.totalExpected > 0 &&
                assembly.fragments.size == assembly.totalExpected
            ) {
                val full = ByteArrayOutputStream()
                for (i in 0 until assembly.totalExpected) {
                    full.write(assembly.fragments[i] ?: continue)
                }
                fragmentBuffer.remove(fragmentId)
                // Evict old incomplete assemblies
                if (fragmentBuffer.size > MAX_PENDING_ASSEMBLIES) {
                    fragmentBuffer.keys.firstOrNull()?.let { fragmentBuffer.remove(it) }
                }
                return try {
                    val decompressed = zlibDecompress(full.toByteArray())
                    TransportInstruction.parseFrom(decompressed)
                } catch (_: Exception) {
                    continue
                }
            }
        }
    }

    /**
     * Recreate the UDP socket to recover from network changes (IP roaming).
     * The old socket may be bound to a defunct interface; a fresh socket
     * from the same [socketProvider] inherits the same transport choice
     * (raw UDP for direct sessions, tunneled UDP for tunneled sessions —
     * see #164).
     *
     * Called from the send loop. Create the replacement FIRST, then swap. The
     * old socket is RETIRED, not closed: the receive loop is normally blocked
     * in `socket.receive()` on it, and closing it under that call makes the
     * read fail with `SocketException("Socket closed")` (EBADF on Android) —
     * the one-shot "Receive error" line the #421 reporter log showed after
     * every rebind. A retired socket stays open so the in-flight receive
     * times out normally; [closeRetiredSockets] reclaims it at the next
     * [receiveInstruction] entry, when the receive side is provably no longer
     * using it, and in [close].
     *
     * If `create()` throws — the tunnel is still flapping, or the interface
     * change isn't complete mid-roam ([sh.haven.mosh.network.UdpSocketProvider]
     * for a tunneled session raises `IOException` here) — keep the current
     * socket instead of installing a closed one, and never let the exception
     * escape: the old code closed-then-created, so a throwing create left the
     * field pointing at a closed socket and unwound into the send loop, killing
     * it. The receive loop then hot-spun on the closed socket ("Socket is
     * closed") and the session was stranded one-way-dead with no reconnect
     * (#421). Swallowing the failure here means the next stall cycle retries;
     * when connectivity returns, create() succeeds and the swap recovers the
     * session.
     *
     * Concurrent sends during the swap are held on [socketLock] so a send
     * never fires a packet into a socket the receive thread has just
     * released. Under normal operation the lock is uncontended.
     */
    fun rebindSocket() {
        synchronized(socketLock) {
            val fresh = try {
                socketProvider.create()
            } catch (_: Exception) {
                return
            }
            retiredSockets.add(socket)
            socket = fresh
        }
    }

    /**
     * Close sockets retired by [rebindSocket]. Called from [receiveInstruction]
     * entry and [close] — points where the receive loop is not inside
     * `socket.receive()`, so no in-flight read can lose its fd. Guarded by
     * [socketLock] against a rebind racing between the sweep and the next
     * field read.
     */
    private fun closeRetiredSockets() {
        synchronized(socketLock) {
            while (retiredSockets.isNotEmpty()) {
                val retired = retiredSockets.removeAt(retiredSockets.size - 1)
                try { retired.close() } catch (_: Exception) {}
            }
        }
    }

    override fun close() {
        socket.close()
        closeRetiredSockets()
        deflater.end()
        inflater.end()
    }

    private fun zlibCompress(data: ByteArray): ByteArray {
        deflater.reset()
        deflater.setInput(data)
        deflater.finish()
        val out = ByteArrayOutputStream(data.size)
        while (!deflater.finished()) {
            val n = deflater.deflate(deflateBuf)
            out.write(deflateBuf, 0, n)
        }
        return out.toByteArray()
    }

    private fun zlibDecompress(data: ByteArray): ByteArray {
        inflater.reset()
        inflater.setInput(data)
        val out = ByteArrayOutputStream(data.size * 2)
        while (!inflater.finished()) {
            val n = inflater.inflate(inflateBuf)
            if (n == 0 && inflater.needsInput()) break
            out.write(inflateBuf, 0, n)
        }
        return out.toByteArray()
    }

    companion object {
        const val FRAG_HEADER_LEN = 10
        const val TIMESTAMP_LEN = 4
        // MTU 1280 - IP(40) - UDP(8) - nonce(8) - tag(16) - timestamp(4) - frag_hdr(10) = 1194
        const val MAX_FRAG_PAYLOAD = 1194
        const val RECV_BUF_SIZE = 2048
        const val MAX_PENDING_ASSEMBLIES = 16
    }
}
