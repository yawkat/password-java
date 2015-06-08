package at.yawk.password.server;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;
import lombok.SneakyThrows;
import lombok.Value;

/**
 * TODO: fix obvious memory leak
 *
 * @author yawkat
 */
class ChallengeManager {
    private static final int CHALLENGE_LENGTH = 32;

    private final SecureRandom secureRandom;
    private final Set<Entry> entries = new HashSet<>();

    @SneakyThrows(NoSuchAlgorithmException.class)
    ChallengeManager() {
        secureRandom = SecureRandom.getInstance("SHA1PRNG");
    }

    /**
     * Generate a new challenge and add it to this manager.
     */
    public synchronized byte[] generateAndAddChallenge() {
        byte[] challenge;
        do {
            challenge = new byte[CHALLENGE_LENGTH];
            secureRandom.nextBytes(challenge);
        } while (!entries.add(new Entry(challenge))); // check for (unlikely) collisions
        return challenge;
    }

    /**
     * Remove the given challenge if present.
     *
     * @return <code>true</code> if the challenge was registered in this manager and was now removed, <code>false</code>
     * otherwise.
     */
    public synchronized boolean removeChallenge(byte[] challenge) {
        return entries.remove(new Entry(challenge));
    }

    /**
     * Wrapper class for proper array equality.
     */
    @Value
    private static class Entry {
        private final byte[] value;
    }
}
