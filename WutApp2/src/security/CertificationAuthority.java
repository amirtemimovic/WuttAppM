package security;

import javafx.application.Platform;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import util.SetUp;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyPair;
import java.security.Provider;
import java.security.Security;
import java.security.cert.*;

public class CertificationAuthority {

    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    static public X509Certificate CASelfSignedCert;
    static KeyPair CAKeyPair;
    public static final Provider wpProvider = new BouncyCastleProvider();

    static {
        if (new File(SetUp.fileSystemPath + File.separatorChar + "Certificates" + File.separatorChar +
                "certificates" + File.separatorChar + "rootCA.crt").exists()) {
            CASelfSignedCert = retrieveCertificate("rootCA");
            CAKeyPair = new KeyPair(CASelfSignedCert.getPublicKey(), SecureIt.readKey("rootCA", ""));
        } else {
            System.out.println("jbg");
        }
    }


    public static X509Certificate retrieveCertificate(String username) {
        try (FileInputStream fileInput = new FileInputStream(SetUp.fileSystemPath + File.separatorChar
                + "Certificates" + File.separatorChar + "certificates" + File.separatorChar + username + ".crt")) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate userCertificate = (X509Certificate) certificateFactory.generateCertificate(fileInput);
            return userCertificate;
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public static boolean isValidCertificateDate(X509Certificate certificate) {
        try {
            certificate.checkValidity();
            return true;
        } catch (CertificateNotYetValidException e) {
            Platform.runLater(() -> {
                Alert alert = new Alert(Alert.AlertType.ERROR, "CERTIFICATE IS NOT YET VALID", ButtonType.OK);
                alert.showAndWait();
            });

            return false;
        } catch (CertificateExpiredException e) {
            Platform.runLater(() -> {
                Alert alert = new Alert(Alert.AlertType.ERROR, "CERTIFICATE IS NO LONGER VALID", ButtonType.OK);
                alert.showAndWait();
            });

            return false;
        }
    }

    public static boolean isCertificateInCRL(X509Certificate certificate) {
        File file = new File(SetUp.fileSystemPath + File.separatorChar + "Certificates" + File.separatorChar + "CRL.pem");
        if (file.exists()) {
            try (FileInputStream inputStream = new FileInputStream(file)) {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                X509CRL crl = (X509CRL) certificateFactory.generateCRL(inputStream);
                X509CRLEntry revoked = crl.getRevokedCertificate(certificate.getSerialNumber());
                if (revoked == null) {
                    return false;
                } else {
                    Platform.runLater(() -> {
                        Alert alert = new Alert(Alert.AlertType.ERROR, "CERTIFICATE HAS BEEN REVOKED BY CA!", ButtonType.OK);
                        alert.showAndWait();
                    });
                    return true;
                }
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
        return false;
    }

    public static boolean isCertificateRootValid(X509Certificate certificate) {
        try {
            certificate.verify(CAKeyPair.getPublic());
        } catch (Exception ex) {
            Platform.runLater(() -> {
                Alert alert = new Alert(Alert.AlertType.ERROR, "CERTIFICATE HAS NOT BEEN SIGNED BY GIVEN CA!", ButtonType.OK);
                alert.showAndWait();
            });

            return false;
        }
        return true;
    }

}
