package sh.haven.mosh

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import sh.haven.mosh.crypto.MoshCrypto
import sh.haven.mosh.network.MoshConnection
import sh.haven.mosh.network.UdpReceivedPacket
import sh.haven.mosh.network.UdpSocketAdapter
import sh.haven.mosh.network.UdpSocketProvider
import java.util.Base64
import java.util.concurrent.CountDownLatch

/**
 * Regression tests for the socket rebind used to recover a stalled Mosh
 * session after IP roaming (#421). The bug: the old rebind closed the current
 * socket *before* calling the provider's `create()`; when `create()` threw
 * (tunnel flapped, or the interface change wasn't complete mid-roam), the
 * connection was left with a closed socket installed and the exception unwound
 * into the send loop — stranding the session one-way-dead with no reconnect.
 */
class RebindSocketTest {

    private fun crypto() = MoshCrypto(Base64.getEncoder().encodeToString(ByteArray(16)))

    private class RecordingAdapter : UdpSocketAdapter {
        var sends = 0
        var closed = false
        override fun send(data: ByteArray, host: String, port: Int) { sends++ }
        override fun receive(buf: ByteArray, timeoutMs: Int): UdpReceivedPacket? = null
        override fun close() { closed = true }
    }

    /** The #421 bug: a failing `create()` must not throw or close the old socket. */
    @Test
    fun `failed rebind keeps the old socket and does not throw`() {
        val a = RecordingAdapter()
        val b = RecordingAdapter()
        var call = 0
        val provider = UdpSocketProvider {
            when (call++) {
                0 -> a // installed at construction
                1 -> throw java.io.IOException("tunnel still down mid-roam")
                else -> b
            }
        }
        val conn = MoshConnection("127.0.0.1", 60001, crypto(), provider)

        // Must not throw (the old code unwound into the send loop) and must not
        // close the still-usable old socket.
        conn.rebindSocket()
        assertFalse("old socket must be retained, not closed, on a failed rebind", a.closed)

        // Once connectivity returns, the next rebind swaps cleanly.
        conn.rebindSocket()
        conn.close()
        assertTrue("old socket is closed (at close() at the latest)", a.closed)
        assertTrue("the rebound socket is the one now installed", b.closed)
    }

    /** Happy path: a successful rebind swaps to the new socket and closes the old. */
    @Test
    fun `successful rebind swaps to the new socket and closes the old`() {
        val a = RecordingAdapter()
        val b = RecordingAdapter()
        var call = 0
        val provider = UdpSocketProvider { if (call++ == 0) a else b }
        val conn = MoshConnection("127.0.0.1", 60001, crypto(), provider)

        conn.rebindSocket()
        assertFalse("new socket left open", b.closed)
        conn.close()
        assertTrue("old socket is closed (retired sockets close on close())", a.closed)
        assertTrue("close() closes the current (rebound) socket", b.closed)
    }

    /**
     * A receive in flight on the old socket when a rebind swaps must not have
     * the socket closed underneath it. That is the Android-side manifestation
     * of the one-shot "Receive error: recvfrom failed: EBADF" in the #421
     * reporter log: rebindSocket closed the old fd while an in-flight
     * `recvfrom` was still blocked on it, so that one receive always errored
     * (twice in the log, once per rebind). The receive side retries, so the
     * error was harmless but noisy — the fix is to retire the old socket and
     * close it once receiveInstruction is back in control.
     *
     * Host analogue of the OS behaviour: a receive blocked on a socket that
     * gets closed fails with SocketException("Socket closed") (EBADF on
     * Android). The adapter models exactly that.
     */
    @Test
    fun `rebind does not close the old socket under an in-flight receive`() {
        val a = LatchingAdapter()
        val b = RecordingAdapter()
        var call = 0
        val provider = UdpSocketProvider { if (call++ == 0) a else b }
        val conn = MoshConnection("127.0.0.1", 60001, crypto(), provider)

        val executor = java.util.concurrent.Executors.newSingleThreadExecutor()
        try {
            val result = executor.submit { conn.receiveInstruction(10_000) }
            assertTrue("receive never entered the old socket", a.entered.await(5, java.util.concurrent.TimeUnit.SECONDS))

            conn.rebindSocket()
            assertFalse(
                "the old socket must stay open while a receive is in flight on it",
                a.closed,
            )

            a.release.countDown()
            // No exception means the in-flight receive survived the rebind.
            result.get(5, java.util.concurrent.TimeUnit.SECONDS)

            // Retired socket is reclaimed once the receive side (or close) is
            // back in control — nothing leaks.
            conn.close()
            assertTrue("retired old socket closed", a.closed)
            assertTrue("current socket closed", b.closed)
        } finally {
            executor.shutdownNow()
        }
    }
}

/** Adapter whose receive models an OS-level receive interrupted by close. */
private class LatchingAdapter : UdpSocketAdapter {
    val entered = CountDownLatch(1)
    val release = CountDownLatch(1)
    @Volatile var closed = false
    override fun send(data: ByteArray, host: String, port: Int) {}
    override fun receive(buf: ByteArray, timeoutMs: Int): UdpReceivedPacket? {
        entered.countDown()
        release.await()
        if (closed) throw java.net.SocketException("Socket closed")
        return null
    }
    override fun close() { closed = true }
}
