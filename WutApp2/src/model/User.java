package model;

import security.SecureIt;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class User {

    private String username;
    private String password;
    private String hashedPassword;
    private KeyPair keyPair;
    private boolean isActive;
    private X509Certificate userCertificate;
    public boolean algSetByThisUser = false;

    public User(String username, String password, X509Certificate userCertificate) {
        this.username = username;
        this.password = password;
        this.userCertificate = userCertificate;
        this.keyPair = new KeyPair(userCertificate.getPublicKey(), SecureIt.readKey(username, ""));
    }

    public void setActive(boolean active) {
        isActive = active;
    }

    private void hashPassword() {
    }

    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public String getUsername() {
        return username;
    }

    @Override
    public String toString() {
        return "#" + username + "#" + hashedPassword + "#" + isActive;
    }
}
