package at.yawk.password.server;

import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.PriorityQueue;

/**
 * The nonces of accepted requests, each kept until its request timestamp is older than the retention by the server
 * clock, so that a nonce is only forgotten once its request would be rejected as stale anyway. This holds when the
 * clock steps back; a forward jump followed by a step back can forget nonces of requests that become fresh again.
 * Not thread safe.
 *
 * @author yawkat
 */
final class NonceMemory {
    private final int maxSize;
    private final long retentionMillis;
    private final Map<String, Long> timestamps = new HashMap<>();
    private final PriorityQueue<Map.Entry<String, Long>> byTimestamp =
            new PriorityQueue<>(Map.Entry.comparingByValue(Comparator.naturalOrder()));

    /**
     * @param maxSize Upper bound on remembered nonces. When full, the one closest to expiry is forgotten early, so its
     *                request could be replayed until it is stale.
     */
    NonceMemory(int maxSize, long retentionMillis) {
        this.maxSize = maxSize;
        this.retentionMillis = retentionMillis;
    }

    boolean contains(String nonce) {
        return timestamps.containsKey(nonce);
    }

    void add(String nonce, long timestamp, long now) {
        while (!byTimestamp.isEmpty() &&
               (now - byTimestamp.peek().getValue() > retentionMillis ||
                timestamps.size() >= maxSize)) {
            timestamps.remove(byTimestamp.poll().getKey());
        }
        timestamps.put(nonce, timestamp);
        byTimestamp.add(Map.entry(nonce, timestamp));
    }

    int size() {
        return timestamps.size();
    }
}
