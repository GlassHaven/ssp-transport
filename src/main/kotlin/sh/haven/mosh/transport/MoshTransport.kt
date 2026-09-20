package sh.haven.mosh.transport

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import com.google.protobuf.ExtensionRegistryLite
import sh.haven.mosh.MoshLogger
import sh.haven.mosh.NoOpLogger
import sh.haven.mosh.crypto.MoshCrypto
import sh.haven.mosh.network.MoshConnection
import sh.haven.mosh.proto.Hostinput
import sh.haven.mosh.proto.Transportinstruction.Instruction as TransportInstruction
import java.io.Closeable

private const val TAG = "MoshTransport"

/**
 * Pure Kotlin mosh transport implementing the State Synchronization Protocol.
 *
 * Replaces the native mosh-client binary. Handles UDP communication,
 * AES-128-OCB encryption, SSP state tracking, and protobuf framing.
 *
 * Terminal output (VT100 sequences from the server) is delivered via
 * [onOutput] and fed directly to connectbot's termlib emulator.
 */
class MoshTransport(
    private val serverIp: String,
    private val port: Int,
    key: String,
    private val onOutput: (ByteArray, Int, Int) -> Unit,
    private val onDisconnect: ((cleanExit: Boolean) -> Unit)? = null,
    private val logger: MoshLogger = NoOpLogger,
    private val initialCols: Int = 80,
    private val initialRows: Int = 24,
    /**
     * Factory for the underlying UDP socket. Defaults to a plain
     * [java.net.DatagramSocket] via [sh.haven.mosh.network.AndroidUdpAdapter],
     * matching pre-#164 behaviour. Tunneled callers (Mosh-over-WireGuard
     * or Mosh-over-Tailscale per #164) pass a provider that yields a
     * tunneled adapter so packets traverse the tunnel rather than the
     * device's default route.
     */
    private val socketProvider: sh.haven.mosh.network.UdpSocketProvider =
        sh.haven.mosh.network.UdpSocketProvider { sh.haven.mosh.network.AndroidUdpAdapter() },
    /**
     * Whether the device currently has a usable network. This is what lets the
     * transport tell "we are offline, keep waiting" (mosh's whole point — resume
     * after a tunnel, a pocket, a doze) apart from "we are online but this
     * session is never coming back", which is the only case [declareDead] acts
     * on. #92 removed an earlier silence-only death heuristic because it killed
     * live sessions after 8s offline; gating on connectivity is what stops this
     * from reintroducing that. Defaults to "assume online" so a host that does
     * not wire it still gets the #421 escape hatch.
     */
    private val networkAvailable: () -> Boolean = { true },
) : Closeable {

    private val crypto = MoshCrypto(key)
    private val userStream = UserStream()
    private val extensionRegistry = ExtensionRegistryLite.newInstance().also {
        Hostinput.registerAllExtensions(it)
    }

    // Connection created on IO thread in start() to avoid main-thread network StrictMode
    @Volatile private var connection: MoshConnection? = null

    // SSP state tracking
    private val receiveState = ReceiveState()         // guards client-side state advancement (#73)
    @Volatile private var serverAckedOurNum: Long = 0 // server's ack of our state
    @Volatile private var lastAckSent: Long = 0       // last ack we sent to server
    // #421: set when a diff is skipped because the server is diffing from a
    // state we've already passed; cleared once sendState has put our actual
    // state back on the wire. Only our ack can correct the server's base.
    @Volatile private var ackResendWanted: Boolean = false
    @Volatile private var lastSendTimeMs: Long = 0

    /** Current state number from the server; updated only when a matching-base diff is applied. */
    private val remoteStateNum: Long
        get() = receiveState.num

    // Track whether we have genuinely new data vs just retransmitting
    @Volatile private var lastSentNewNum: Long = 0
    @Volatile private var retransmitCount: Int = 0

    // Diagnostic counters
    @Volatile private var packetsSent: Long = 0
    @Volatile private var packetsReceived: Long = 0
    @Volatile private var firstOutputReceived: Boolean = false

    // Network roaming / stall detection
    @Volatile private var lastReceiveTimeMs: Long = 0
    @Volatile private var lastRebindTimeMs: Long = 0

    /**
     * Socket rebinds attempted since the last packet arrived — reset by any
     * receive. Requiring several before [DEAD_SESSION_MS] can fire means a
     * session is only declared dead after repeated recovery attempts have all
     * gone unanswered, not merely because one rebind landed badly.
     */
    @Volatile private var rebindsSinceReceive: Int = 0

    /**
     * When the remote state last actually advanced, and how many diffs we have
     * rejected since. Together these separate "receiving but stuck" (#421) from
     * "idle": an idle session records no skips.
     */
    @Volatile private var lastProgressTimeMs: Long = 0
    @Volatile private var skipsSinceProgress: Int = 0
    @Volatile private var consecutiveSendErrors: Int = 0

    // Stall age surfaced to the UI when the server has gone silent.
    // null while the connection is healthy or before the first packet
    // arrives; otherwise the seconds since the last server packet. The
    // transport never gives up on silence alone (mosh semantics — the
    // session resumes whenever connectivity returns); it ends only on an
    // announced server shutdown or an explicit [close].
    private val _stallSeconds = MutableStateFlow<Int?>(null)
    val stallSeconds: StateFlow<Int?> = _stallSeconds.asStateFlow()

    // Conflated channel: wakes the send loop immediately when input arrives
    private val inputNotify = Channel<Unit>(Channel.CONFLATED)

    @Volatile private var closed = false
    private var receiveJob: Job? = null
    private var sendJob: Job? = null

    /**
     * Start the transport: opens UDP socket on IO thread, begins receive and send loops.
     */
    fun start(scope: CoroutineScope) {
        scope.launch(Dispatchers.IO) {
            if (closed) return@launch
            try {
                connection = MoshConnection(serverIp, port, crypto, socketProvider)
                logger.d(TAG, "UDP socket connected to $serverIp:$port")
                // Start the silence clock at connect, not at first packet. The
                // stall/rebind/escalation block is gated on lastReceiveTimeMs > 0,
                // so a session that never hears back at all — server gone, port
                // blocked, wrong host after a move — used to skip it entirely: no
                // rebinds, no stall age, no escalation, just retransmits forever.
                // That is the same "stuck retrying" the user reports, in the
                // never-connected case. Device-verified with mosh-fault-rig.py:
                // the replacement session sent 50+ retransmits and 0 rebinds.
                lastReceiveTimeMs = System.currentTimeMillis()
            } catch (e: Exception) {
                logger.e(TAG, "Failed to create UDP connection", e)
                onDisconnect?.invoke(false)
                return@launch
            }
            // Send initial resize — mosh-server waits for a client state change
            // (newNum > 0) before releasing the child shell process
            userStream.pushResize(initialCols, initialRows)
            logger.d(TAG, "Queued initial resize ${initialCols}x${initialRows}")

            // Only one coroutine sends — no race on nonce counter
            receiveJob = launch { receiveLoop() }
            sendJob = launch { sendLoop() }
        }
    }

    /** Enqueue user keystrokes for delivery to the server. */
    fun sendInput(data: ByteArray) {
        if (closed) return
        val prevSize = userStream.size
        userStream.pushKeystroke(data)
        logger.d(TAG, "sendInput: ${data.size} bytes, userStream ${prevSize}→${userStream.size}")
        inputNotify.trySend(Unit)
    }

    /** Enqueue a terminal resize event. */
    fun resize(cols: Int, rows: Int) {
        if (closed) return
        userStream.pushResize(cols, rows)
        inputNotify.trySend(Unit)
    }

    override fun close() {
        if (closed) return
        closed = true
        receiveJob?.cancel()
        sendJob?.cancel()
        try { connection?.close() } catch (_: Exception) {}
        // Clear the stall countdown so the "No server contact — retrying"
        // banner can't stay frozen on screen after the transport is gone.
        // The value is only refreshed inside the (now-cancelled) send loop,
        // so without this it sticks at its last reading and reads as a
        // reconnect that never happens (#421). A genuinely stalling — but
        // still live — transport keeps updating it and still shows the banner.
        _stallSeconds.value = null
    }

    private suspend fun receiveLoop() {
        try {
            while (!closed) {
                val conn = connection ?: break
                val instruction = try {
                    conn.receiveInstruction(RECV_TIMEOUT_MS)
                } catch (_: CancellationException) {
                    throw CancellationException()
                } catch (e: Exception) {
                    if (!closed) logger.e(TAG, "Receive error: ${e.message}")
                    // Back off before retrying. receiveInstruction returns null
                    // on a normal timeout, so reaching here means a real socket
                    // error; without a pause a persistently-bad socket becomes a
                    // CPU/log hot-loop (the "Socket is closed" flood in #421),
                    // and delay() is also the loop's only suspension point, so it
                    // is what lets cooperative cancellation actually take effect.
                    delay(RECV_TIMEOUT_MS.toLong())
                    continue
                }

                if (instruction == null) continue // timeout
                lastReceiveTimeMs = System.currentTimeMillis()
                rebindsSinceReceive = 0 // contact restored — start the #421 count over
                _stallSeconds.value = null
                processInstruction(instruction)
            }
        } catch (_: CancellationException) {
            // normal shutdown
        } catch (e: Exception) {
            if (!closed) {
                logger.e(TAG, "Receive loop failed", e)
                onDisconnect?.invoke(false)
                // A fatal receive error means the transport is dead — stop the
                // send loop (which would otherwise keep retransmitting as a
                // zombie) and clear the stall banner (#421).
                close()
            }
        }
    }

    internal fun processInstruction(inst: TransportInstruction) {
        packetsReceived++

        // Explicit server shutdown: when the shell exits, mosh-server
        // announces it by sending a state numbered -1 (uint64 max) —
        // upstream Transport::start_shutdown(). This replaces the old
        // silence-based SESSION_DEAD_MS heuristic (#92), which couldn't
        // tell a dead shell from a dead network and killed live sessions
        // after 8s offline. We don't ack the shutdown state; the server
        // stops waiting for the ack after ~3s and exits anyway.
        if (inst.newNum == SHUTDOWN_STATE_NUM) {
            if (!closed) {
                logger.d(TAG, "Server announced shutdown (newNum=-1), closing")
                close()
                onDisconnect?.invoke(true)
            }
            return
        }

        // Update server's acknowledgement of our state
        if (inst.ackNum > serverAckedOurNum) {
            val oldAck = serverAckedOurNum
            serverAckedOurNum = inst.ackNum
            retransmitCount = 0 // server got our data, reset backoff
            logger.d(TAG, "Server acked our state: $oldAck → ${inst.ackNum}")
        }

        // Only apply diffs whose base matches our current state. The server's
        // diff is a VT100 rendering sequence computed from oldNum → newNum on
        // the *server's* framebuffer. Feeding those bytes to termlib when it
        // isn't at oldNum produces cumulative display corruption (the exact
        // "cursor below the prompt / freezes after a few Returns" symptom
        // reported on #73).
        //
        // receiveState.tryAdvance mirrors upstream mosh's Transport::recv()
        // semantics: on base mismatch it returns false and leaves the state
        // number alone. We must NOT lie about our state in subsequent acks
        // (the prior implementation advanced the number anyway, which made
        // the server throw away the exact states the client needed).
        if (!receiveState.tryAdvance(inst.oldNum, inst.newNum)) {
            if (inst.newNum > remoteStateNum) {
                logger.d(
                    TAG,
                    "Skipping diff: oldNum=${inst.oldNum} ≠ remoteStateNum=$remoteStateNum " +
                        "(newNum=${inst.newNum}) — waiting for retransmit with matching base",
                )
                // The server is ahead of us but building its diffs from a
                // state we have already passed, so no retransmit can ever
                // match: it has not acted on our ack of the state we're at
                // (dkoppenh's #421 log — server retransmitting base-17 diffs
                // at ~14/s while the client sat at 18 and sent nothing for
                // 4.8s). Only an ack carrying our actual state moves its
                // base, so ask the send loop for one now instead of waiting
                // out the keepalive (3s of frozen screen per storm).
                ackResendWanted = true
                inputNotify.trySend(Unit)
            }
            // Counted so a sustained run of these can be told apart from an
            // idle session by the liveness check (#421).
            skipsSinceProgress++
            return
        }

        lastProgressTimeMs = System.currentTimeMillis()
        skipsSinceProgress = 0

        // Notify the send loop so it can ack the new state promptly.
        // Without this, the send loop sleeps until its next keepalive
        // (up to 3s), during which the server keeps computing diffs from
        // the old acked state — all of which get skipped because the
        // client's base has moved on. The cascade of skips causes
        // terminal state divergence (e.g. DECCKM mode lost → arrow keys
        // fail in Mutt). See #73.
        inputNotify.trySend(Unit)

        // tryAdvance already committed the state number. Render the diff.
        if (inst.hasDiff() && !inst.diff.isEmpty) {
            if (!firstOutputReceived) {
                firstOutputReceived = true
                logger.d(TAG, "First terminal output received (newNum=${inst.newNum}, diffSize=${inst.diff.size()}, packets sent=$packetsSent received=$packetsReceived)")
            }
            try {
                val hostMsg = Hostinput.HostMessage.parseFrom(inst.diff, extensionRegistry)
                for (hi in hostMsg.instructionList) {
                    if (hi.hasExtension(Hostinput.hostbytes)) {
                        val hb = hi.getExtension(Hostinput.hostbytes)
                        val bytes = hb.hoststring.toByteArray()
                        onOutput(bytes, 0, bytes.size)
                    }
                }
            } catch (e: Exception) {
                logger.e(TAG, "Failed to decode HostMessage", e)
            }
        }
    }

    private suspend fun sendLoop() {
        try {
            // Send initial keepalive immediately
            sendState()

            while (!closed) {
                val now = System.currentTimeMillis()
                val elapsed = now - lastSendTimeMs
                val currentNum = userStream.size
                val hasNewInput = currentNum != lastSentNewNum
                val hasNewAck = remoteStateNum > lastAckSent
                val needsRetransmit = currentNum > serverAckedOurNum

                val recvAge = now - lastReceiveTimeMs
                if (lastReceiveTimeMs > 0) {
                    // Surface the stall age once we cross the display
                    // threshold so the UI can show a "no contact for N s"
                    // indicator. There is no client-side give-up: shell
                    // exit is announced explicitly by the server (see
                    // SHUTDOWN_STATE_NUM), so silence only ever means the
                    // network is away — keep retrying until it returns,
                    // like upstream mosh.
                    _stallSeconds.value = if (recvAge > STALL_DISPLAY_MS) {
                        (recvAge / 1000).toInt()
                    } else {
                        null
                    }
                    // Network stall: rebind the socket periodically for IP
                    // roaming recovery. After an interface change (Wi-Fi →
                    // LTE) the old socket may sit on a dead network; a
                    // one-shot rebind can itself land while the network is
                    // still down, so repeat every NETWORK_STALL_MS of
                    // continued silence until packets flow again.
                    if (recvAge > NETWORK_STALL_MS &&
                        now - lastRebindTimeMs >= NETWORK_STALL_MS
                    ) {
                        logger.d(TAG, "No packets for ${recvAge}ms, rebinding socket")
                        connection?.rebindSocket()
                        lastRebindTimeMs = now
                        rebindsSinceReceive++
                    }
                    // Escalation (#421): rebinding recovers a *roamed* session,
                    // but not one the server side no longer has — and then we
                    // retransmit into the void forever behind a "retrying"
                    // banner that never resolves, while the user's own manual
                    // close-and-reconnect (which starts a fresh mosh-server)
                    // works immediately. Once we have been silent this long,
                    // have re-bound the socket repeatedly, AND the device does
                    // have a network, "the network is away" no longer explains
                    // it: report the transport dead so the session layer can
                    // reconnect. The connectivity gate is deliberate — with no
                    // network this never fires, so a phone in a pocket still
                    // resumes, which is the #92 regression we must not repeat.
                    val noProgressAge = if (lastProgressTimeMs == 0L) 0L else now - lastProgressTimeMs
                    if (shouldDeclareDead(
                            recvAge,
                            rebindsSinceReceive,
                            networkAvailable(),
                            noProgressAge,
                            skipsSinceProgress,
                        )
                    ) {
                        logger.e(
                            TAG,
                            "No packets for ${recvAge}ms across $rebindsSinceReceive rebinds " +
                                "while the network is up — declaring the session dead (#421)",
                        )
                        close()
                        onDisconnect?.invoke(false)
                        return
                    }
                }

                when {
                    // New keystrokes: send promptly
                    hasNewInput && elapsed >= SEND_MIN_INTERVAL_MS -> sendState()
                    // New ack to send: send soon
                    hasNewAck && elapsed >= ACK_DELAY_MS -> sendState()
                    // #421: a skipped diff means the server is diffing from a
                    // state we've passed — only our ack can move its base, so
                    // resend it promptly instead of waiting for the next
                    // keepalive (up to 3s of frozen screen per storm).
                    ackResendWanted && elapsed >= ACK_RESEND_MS -> {
                        ackResendWanted = false
                        sendState()
                    }
                    // Retransmit unacked data: back off exponentially
                    needsRetransmit && elapsed >= retransmitInterval() -> sendState()
                    // Keepalive
                    elapsed >= KEEPALIVE_INTERVAL_MS -> sendState()
                    else -> {
                        val wait = when {
                            hasNewInput -> SEND_MIN_INTERVAL_MS - elapsed
                            hasNewAck -> ACK_DELAY_MS - elapsed
                            ackResendWanted -> ACK_RESEND_MS - elapsed
                            needsRetransmit -> retransmitInterval() - elapsed
                            // Idle: sleep until next keepalive, woken early by inputNotify
                            else -> KEEPALIVE_INTERVAL_MS - elapsed
                        }
                        withTimeoutOrNull(maxOf(5L, wait)) { inputNotify.receive() }
                    }
                }
            }
        } catch (_: CancellationException) {
            // normal shutdown
        }
    }

    /** Exponential backoff for retransmissions: 100ms, 200ms, 400ms, capped at 1000ms. */
    private fun retransmitInterval(): Long {
        val base = 100L
        val interval = base shl minOf(retransmitCount, 3) // 100, 200, 400, 800
        return minOf(interval, 1000L)
    }

    private fun sendState() {
        if (closed) return
        try {
            val currentNum = userStream.size
            val diff = userStream.diffFrom(serverAckedOurNum)
            val instruction = TransportInstruction.newBuilder()
                .setProtocolVersion(PROTOCOL_VERSION)
                .setOldNum(serverAckedOurNum)
                .setNewNum(currentNum)
                .setAckNum(remoteStateNum)
                .setThrowawayNum(serverAckedOurNum)
                .setDiff(com.google.protobuf.ByteString.copyFrom(diff))
                .build()
            connection?.sendInstruction(instruction) ?: return
            packetsSent++
            val isRetransmit = currentNum == lastSentNewNum && currentNum > serverAckedOurNum
            // Keepalives carry an empty diff, so the first two conditions hide
            // them entirely after startup. That made a reporter's #421 log
            // unreadable in the way that mattered: 90 seconds with no sendState
            // line at all, which looks exactly like a dead send loop but is
            // equally consistent with healthy keepalives going unlogged. The
            // sampled third condition makes "we were still sending" visible
            // without flooding an hour-long offline session.
            if (packetsSent <= 3L || diff.isNotEmpty() || packetsSent % KEEPALIVE_LOG_EVERY == 0L) {
                logger.d(TAG, "sendState #$packetsSent: oldNum=$serverAckedOurNum newNum=$currentNum ackNum=$remoteStateNum diffSize=${diff.size}${if (isRetransmit) " RETRANSMIT" else ""}")
            }
            lastSendTimeMs = System.currentTimeMillis()
            lastAckSent = remoteStateNum
            ackResendWanted = false

            if (currentNum == lastSentNewNum && currentNum > serverAckedOurNum) {
                retransmitCount++ // same data resent
            } else {
                retransmitCount = 0
            }
            lastSentNewNum = currentNum
            consecutiveSendErrors = 0
        } catch (e: Exception) {
            // While the network is away every keepalive/retransmit throws;
            // log the first failure and then sample, or an hour offline
            // floods logcat and the verbose buffer.
            consecutiveSendErrors++
            if (!closed && (consecutiveSendErrors == 1 || consecutiveSendErrors % 20 == 0)) {
                logger.e(TAG, "Send error (x$consecutiveSendErrors)", e)
            }
        }
    }

    companion object {
        const val PROTOCOL_VERSION = 2
        const val SEND_MIN_INTERVAL_MS = 20L
        const val ACK_DELAY_MS = 20L
        /** Floor between ack resends forced by skipped diffs (#421). */
        const val ACK_RESEND_MS = 100L
        /** Threshold after which the UI sees a non-null stall age — set to
         *  cover two missed keepalives ([KEEPALIVE_INTERVAL_MS] 3s) plus
         *  jitter so a single lost packet doesn't flicker the indicator on
         *  a healthy connection. */
        const val STALL_DISPLAY_MS = 8_000L
        /** Cadence of socket rebinds during a stall (IP roaming recovery). */
        const val NETWORK_STALL_MS = 6_000L
        /**
         * Silence after which an ONLINE device treats the session as gone
         * rather than roaming (#421). Generous on purpose: a real roam (Wi-Fi →
         * LTE, VPN flap) recovers within a rebind or two, so anything past this
         * with connectivity present is a session the server no longer has.
         * Never fires while offline — see [networkAvailable] and #92.
         */
        const val DEAD_SESSION_MS = 45_000L
        /** Rebinds that must go unanswered before [DEAD_SESSION_MS] can fire. */
        const val MIN_REBINDS_BEFORE_DEAD = 3

        /**
         * Whether a silent session should be given up on (#421). All three
         * conditions are required, and [networkAvailable] is the one that
         * matters most: without it this is the #92 heuristic that killed live
         * sessions whenever the phone went offline briefly. Pure so the policy
         * is testable without waiting out [DEAD_SESSION_MS] of real time.
         */
        fun shouldDeclareDead(
            recvAgeMs: Long,
            rebindsSinceReceive: Int,
            networkAvailable: Boolean,
            noProgressMs: Long = 0L,
            skipsSinceProgress: Int = 0,
        ): Boolean =
            networkAvailable && (
                (
                    recvAgeMs > DEAD_SESSION_MS &&
                        rebindsSinceReceive >= MIN_REBINDS_BEFORE_DEAD
                    ) ||
                    // #421 second failure mode: packets keep ARRIVING but none
                    // can be used. The server bases every diff on a state we do
                    // not have, we skip them all, and the silence-based test
                    // above never fires because the receive stream looks
                    // perfectly healthy. Observed in a reporter's log: 90
                    // seconds of nothing but skips, no recovery, no reconnect.
                    //
                    // Gated on skips rather than elapsed time alone, because an
                    // IDLE session also makes no progress — and killing those is
                    // the #92 regression. A session nobody is using produces no
                    // skips at all; only a server actively sending diffs we
                    // cannot apply does.
                    (
                        skipsSinceProgress >= MIN_SKIPS_BEFORE_DEAD &&
                            noProgressMs > NO_PROGRESS_DEAD_MS
                        )
                )
        /**
         * State number mosh-server sends to announce shutdown after the
         * shell exits (uint64 max, i.e. -1). Upstream mosh
         * Transport::start_shutdown().
         */
        const val SHUTDOWN_STATE_NUM = -1L
        const val KEEPALIVE_INTERVAL_MS = 3000L
        const val RECV_TIMEOUT_MS = 250

        /**
         * How long a session may keep receiving diffs it cannot apply before
         * it counts as dead (#421). Shorter than [DEAD_SESSION_MS] because
         * this state is unambiguous — the peer is talking and we understand
         * none of it — whereas receive-silence has innocent explanations
         * (a pocketed phone) that deserve the longer rope.
         */
        const val NO_PROGRESS_DEAD_MS = 20_000L

        /**
         * Skips required before [NO_PROGRESS_DEAD_MS] can fire. A couple of
         * skips is ordinary: a diff crossing with our ack resolves itself on
         * the next exchange. A sustained run of them does not.
         */
        const val MIN_SKIPS_BEFORE_DEAD = 3

        /**
         * Log one in this many sends even when nothing changed, so an
         * otherwise-silent keepalive stream is still visible in a bug report.
         * At [KEEPALIVE_INTERVAL_MS] that is roughly one line a minute idle.
         */
        const val KEEPALIVE_LOG_EVERY = 20L
    }
}
