package com.example.service;

import java.security.SecureRandom;
import java.util.Base64;

public class NonceGenerator {

	private static final int NONCE_LENGTH = 16;
    private final SecureRandom secureRandom = new SecureRandom();

    public String generateNonce() {
        byte[] nonce = new byte[NONCE_LENGTH];
        secureRandom.nextBytes(nonce);
        return Base64.getEncoder().encodeToString(nonce);
    }
}
