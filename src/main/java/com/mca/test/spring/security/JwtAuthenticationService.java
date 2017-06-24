package com.mca.test.spring.security;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.validation.ValidationException;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;

public class JwtAuthenticationService {

    private static final String SEPARATOR = ".";
    private static final String SEPARATOR_SPLITTER = "\\.";
    private final Mac hmac;

    private final static ObjectMapper jsonMapper = new ObjectMapper();

    public JwtAuthenticationService(byte[] secret, String algo) {
        try {
            hmac = Mac.getInstance(algo);
            hmac.init(new SecretKeySpec(secret, algo));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("failed to initialize HMAC: " + e.getMessage(), e);
        }
    }

    public String serialize(JwtToken token) {
        byte[] tokenBytes;
        try {
            tokenBytes = jsonMapper.writeValueAsBytes(token);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
        byte[] hash = hash(tokenBytes);
        final StringBuilder sb = new StringBuilder();
        sb.append(toBase64(tokenBytes));
        sb.append(SEPARATOR);
        sb.append(toBase64(hash));
        return sb.toString();
    }

    public JwtToken deserialize(String tokenValue) {
        final String[] parts = tokenValue.split(SEPARATOR_SPLITTER);
        if (parts.length == 2 && parts[0].length() > 0 && parts[1].length() > 0) {
            final byte[] userBytes = fromBase64(parts[0]);
            final byte[] hash = fromBase64(parts[1]);

            boolean validHash = Arrays.equals(hash(userBytes), hash);
            if (validHash) {
                try {
                    return jsonMapper.readValue(userBytes, JwtToken.class);
                } catch (IOException e) {
                    throw new ValidationException("Failed to deserialize json!");
                }
            }
        }
        throw new ValidationException("Hash does not match!");
    }

    public JwtToken generateToken(String userId, String... authoritiesSet) {
        String authorities = String.join(", ", Arrays.asList(authoritiesSet));
        return new JwtToken(userId, authorities, new Date().getTime());
    }

    private String toBase64(byte[] content) {
        return DatatypeConverter.printBase64Binary(content);
    }

    private byte[] fromBase64(String content) {
        return DatatypeConverter.parseBase64Binary(content);
    }

    // synchronized to guard internal hmac object
    private synchronized byte[] hash(byte[] content) {
        return hmac.doFinal(content);
    }


    public static class JwtToken {

        private final static String USER_NAME_PROPERTY = "u";
        private final static String AUTHORITIES_PROPERTY = "a";
        private final static String CREATED_PROPERTY = "c";

        private String getName;

        private long created;

        private String authorities;

        @JsonCreator
        public JwtToken(@JsonProperty(USER_NAME_PROPERTY) String getName,
                        @JsonProperty(AUTHORITIES_PROPERTY) String authorities,
                        @JsonProperty(CREATED_PROPERTY) long createdTimestamp) {
            this.getName = getName;
            this.authorities = authorities;
            this.created = createdTimestamp;
        }

        @JsonProperty(USER_NAME_PROPERTY)
        public String getUserName() {
            return getName;
        }

        @JsonProperty(AUTHORITIES_PROPERTY)
        public String getAuthorities() {
            return authorities;
        }

        @JsonProperty(CREATED_PROPERTY)
        public long getCreated() {
            return created;
        }
    }
}
