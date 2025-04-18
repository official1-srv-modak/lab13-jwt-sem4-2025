package com.souravmodak.lab13jwt;

public enum Roles {
    SERVER_ADMIN("SERVER_ADMIN"),
    ADMIN("ADMIN"),
    USER("USER");

    private final String value;

    Roles(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
