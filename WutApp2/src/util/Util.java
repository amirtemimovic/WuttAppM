package util;

import gui.ChatWindow;
import model.User;
import security.SecureIt;

import java.io.File;
import java.io.IOException;
import java.nio.file.WatchEvent;
import java.util.Random;

public class Util {

    public static String getFileName(File fullName) {
        String temp1 = fullName.toString();
        //System.out.println(temp1);
        String temp2 = temp1.replace("" + File.separatorChar, "-");
        String[] parts = temp2.split("-");
        int len = parts.length;
        String result = parts[len - 1].replace(".txt", "");
        return result;
    }

    public static String getFileName(String fullName) {
        //System.out.println(temp1);
        String temp2 = fullName.replace("" + File.separatorChar, "-");
        String[] parts = temp2.split("-");
        int len = parts.length;
        String result = parts[len - 1].replace(".txt", "");
        return result;
    }

    public static String getUser(String name) {
        String[] parts = name.split("_");
        int len = parts.length;
        String result = parts[1].replace(".txt", "");
        return result;
    }

    public static <T> WatchEvent<T> cast(WatchEvent<?> event) {
        return (WatchEvent<T>) event;
    }

    public static void selectAlgorithms(User loggedUser) {
        File fileDir = new File(SetUp.fileSystemPath + File.separatorChar + "Connection" + File.separatorChar + "HashAlgorithm");
        String hashAlg = "";
        String symAlg = "";
        if (fileDir.exists()) {
            if (fileDir.list().length == 0) {
                Random random = new Random();
                int hash = random.nextInt(3);
                switch (hash) {
                    case 0:
                        hashAlg = SecureIt.SHA256;
                        break;
                    case 1:
                        hashAlg = SecureIt.SHA384;
                        break;
                    case 2:
                        hashAlg = SecureIt.SHA512;
                        break;
                }
                File temp = new File(fileDir.getAbsolutePath() + File.separatorChar + hashAlg + ".txt");
                try {
                    temp.createNewFile();
                    loggedUser.algSetByThisUser = true;
                    ChatWindow.currHashAlg = hashAlg;
                } catch (IOException e) {
                    e.printStackTrace();
                }
            } else {
                File[] files = fileDir.listFiles();
                for (int i = 0; i < files.length; i++) {
                    if (files[i].isFile()) {
                        String name = Util.getFileName(files[i]);
                        if (SecureIt.SHA512.contains(name)) {
                            ChatWindow.currHashAlg = SecureIt.SHA512;
                        } else if (SecureIt.SHA256.contains(name)) {
                            ChatWindow.currHashAlg = SecureIt.SHA256;
                        } else if (SecureIt.SHA384.contains(name)) {
                            ChatWindow.currHashAlg = SecureIt.SHA384;
                        }
                    }
                }
            }
        }

        fileDir = new File(SetUp.fileSystemPath + File.separatorChar + "Connection" + File.separatorChar + "SymAlgorithm");
        if (fileDir.exists()) {
            if (fileDir.list().length == 0) {
                Random random = new Random();
                int sym = random.nextInt(2);
                switch (sym) {
                    case 0:
                        symAlg = SecureIt.AES;
                        break;
                    case 1:
                        symAlg = SecureIt.DES;
                        break;
                }
                File temp = new File(SetUp.fileSystemPath + File.separatorChar + "Connection" + File.separatorChar +
                        "SymAlgorithm" + File.separatorChar + symAlg + ".txt");
                try {
                    temp.createNewFile();
                    loggedUser.algSetByThisUser = true;
                    ChatWindow.currSymAlg = symAlg;
                } catch (IOException e) {

                }
            } else {
                File[] files = fileDir.listFiles();
                for (int i = 0; i < files.length; i++) {
                    if (files[i].isFile()) {
                        String name = Util.getFileName(files[i]);
                        if (name.equals(SecureIt.AES)) {
                            ChatWindow.currSymAlg = name;
                        } else if (name.equals(SecureIt.DES)) {
                            ChatWindow.currSymAlg = name;
                        }
                    }
                }
            }
        }
    }

}
