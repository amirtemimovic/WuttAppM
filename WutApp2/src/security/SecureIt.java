package security;

import gui.ChatWindow;
import main.WutApp;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import util.SetUp;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class SecureIt {
    public static final String SHA512 = "SHA-512";
    public static final String SHA256 = "SHA-256";
    public static final String SHA384 = "SHA-384";
    public static final String DES = "DES";
    public static final String AES = "AES";

    public static byte[] hashAlgorithm(String message, String algorithm) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
            byte[] hashedString = messageDigest.digest(message.getBytes("UTF8"));
            return hashedString;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    public static PublicKey takeReceiversPublicKey(String receiversUsername) {
        X509Certificate receiversCert = CertificationAuthority.retrieveCertificate(receiversUsername);
        PublicKey receiversPublicKey = receiversCert.getPublicKey();
        return receiversPublicKey;
    }


    public static PrivateKey readKey(String username, String password) {
        try (PEMParser pemParser = new PEMParser(new FileReader(SetUp.fileSystemPath + File.separatorChar + "Certificates" + File.separatorChar
                + "privateKeys" + File.separatorChar + username + ".pem"))) {
            Object object = pemParser.readObject();
            PEMDecryptorProvider decryptorProvider = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
            JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter().setProvider(CertificationAuthority.wpProvider);
            KeyPair keyPair = null;
            if (object instanceof PEMEncryptedKeyPair) {
                keyPair = keyConverter.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(decryptorProvider));
                return keyPair.getPrivate();
            } else {
                keyPair = keyConverter.getKeyPair((PEMKeyPair) object);
                return keyPair.getPrivate();
            }

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public static void sendSymKey(SecretKey key, String otherUsername, String name) {
        File file = new File(SetUp.fileSystemPath + File.separatorChar + "Users" + File.separatorChar +
                otherUsername + File.separatorChar + "inbox" + File.separatorChar + name +
                WutApp.loggedUser.getUsername() + ".txt");
        PublicKey receiversPublicKey = takeReceiversPublicKey(otherUsername);
        byte[] encryptedSymKey = encryptSecretKey(key, receiversPublicKey);
        try {
            file.createNewFile();
            PrintWriter printWriter = new PrintWriter(new BufferedWriter(new FileWriter(file)));
            printWriter.printf("Symmetric Key\n");
            printWriter.println(Base64.getEncoder().encodeToString(encryptedSymKey));
            printWriter.close();
            if (!WutApp.loggedUser.algSetByThisUser) {
                ChatWindow.connection = true;
            }
        } catch (IOException ex) {
            return;
        }

        //System.out.println(gui.ChatWindow.symKey.getEncoded().toString());
    }

    public static void getSymKey(String otherUsername, String fileName) {
        try {
            File file = new File(SetUp.fileSystemPath + File.separatorChar + "Users" + File.separatorChar +
                    WutApp.loggedUser.getUsername() + File.separatorChar + "inbox" + File.separatorChar + fileName +
                    otherUsername + ".txt");
            BufferedReader bufferedReader = new BufferedReader(new FileReader(file));
            String message = "";
            bufferedReader.readLine();
            message = bufferedReader.readLine();
            bufferedReader.close();

            decryptSecretKey(Base64.getDecoder().decode(message), ChatWindow.currSymAlg);

        } catch (Exception e) {
            e.printStackTrace();
        }
        //System.out.println(gui.ChatWindow.symKey.getEncoded().toString());
    }



    public static byte[] encryptText(String textToEncrypt, String algorithm, SecretKey secretKey) {
        byte[] byteCipherText = null;
        try {
            Cipher encCipher = Cipher.getInstance(algorithm);
            encCipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byteCipherText = encCipher.doFinal(textToEncrypt.getBytes());
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return byteCipherText;
    }


    public static byte[] encryptSecretKey(SecretKey secretKey, PublicKey publicKey) {
        byte[] encryptedKey = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.PUBLIC_KEY, publicKey);
            encryptedKey = cipher.doFinal(secretKey.getEncoded());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return encryptedKey;
    }

    public static byte[] decryptSecretKey(byte[] encryptedSecretKey, String algorithm) {
        byte[] decryptedKey = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.PRIVATE_KEY, WutApp.loggedUser.getPrivateKey());
            decryptedKey = cipher.doFinal(encryptedSecretKey);
            SecretKey originalKey = new SecretKeySpec(decryptedKey, 0, decryptedKey.length, algorithm);
            ChatWindow.symKey = originalKey;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return decryptedKey;
    }

    public static String decryptText(byte[] encryptedText, String algorithm) {
        String decryptedPlainText = null;
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, ChatWindow.symKey);
            byte[] bytePlainText = cipher.doFinal(encryptedText);
            decryptedPlainText = new String(bytePlainText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return decryptedPlainText;
    }
}
