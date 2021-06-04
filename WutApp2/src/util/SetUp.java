package util;

import security.SecureIt;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.Base64;

public class SetUp {

    public static final String fileSystemPath = "C:\\Users\\Amir\\Desktop\\WuttAppM";

    public static void setUpFileSystem() {
        File f = new File(fileSystemPath);
        if (!f.exists()) {
            f = new File(fileSystemPath + File.separatorChar + "Users" + File.separatorChar + "messi" + File.separatorChar + "inbox");
            f.mkdirs();
            f = new File(fileSystemPath + File.separatorChar + "Users" + File.separatorChar + "ronaldo" + File.separatorChar + "inbox");
            f.mkdirs();
            f = new File(fileSystemPath + File.pathSeparator + "Users" + File.pathSeparator + "lebron" + File.separatorChar + "inbox");
            f.mkdirs();
            f = new File(fileSystemPath + File.separatorChar + "Users" + File.separatorChar + "curry" + File.separatorChar + "inbox");
            f.mkdirs();
            f = new File(fileSystemPath + File.separatorChar + "Users" + File.separatorChar + "activeUsers");
            f.mkdirs();
            f = new File(fileSystemPath + File.separatorChar + "Certificates" + File.separatorChar + "certificates");
            f.mkdirs();
            f = new File(fileSystemPath + File.separatorChar + "Certificates" + File.separatorChar + "privateKeys");
            f.mkdirs();
            f = new File(fileSystemPath + File.separatorChar + "Passwords");
            f.mkdirs();
            f = new File(fileSystemPath + File.separatorChar + "Connection" + File.separatorChar + "HashAlgorithm");
            f.mkdirs();
            f = new File(fileSystemPath + File.separatorChar + "Connection" + File.separatorChar + "SymAlgorithm");
            f.mkdirs();
        }
        hashPasswords();

    }

    private static void hashPasswords() {
        File file = new File(fileSystemPath + File.separatorChar + "Passwords" + File.separatorChar + "pass.txt");
        try {
            PrintWriter printWriter = new PrintWriter(new BufferedWriter(new FileWriter(file)));
            String temp = Base64.getEncoder().encodeToString(SecureIt.hashAlgorithm("lapulga1987", SecureIt.SHA512));
            printWriter.printf("messi - %s\n", temp);
            temp = Base64.getEncoder().encodeToString(SecureIt.hashAlgorithm("crseven1985", SecureIt.SHA512));
            printWriter.printf("ronaldo - %s\n", temp);
            temp = Base64.getEncoder().encodeToString(SecureIt.hashAlgorithm("king1984", SecureIt.SHA512));
            printWriter.printf("lebron - %s\n", temp);
            temp = Base64.getEncoder().encodeToString(SecureIt.hashAlgorithm("chef1988", SecureIt.SHA512));
            printWriter.printf("curry - %s\n", temp);

            printWriter.close();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }


}
