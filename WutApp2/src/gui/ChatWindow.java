package gui;

import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.stage.Stage;
import main.WutApp;
import security.CertificationAuthority;
import security.SecureIt;
import security.Steganography;
import util.SetUp;
import util.Util;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class ChatWindow {
//koji se korisnik prvi prijavi, postavlja sym alg i hash alg, te zapocinje komunikaciju..
// oba korisnika moraju otvoriti odgovarajuci chat window
    public static boolean isLastMsg = false;
    public static volatile boolean isThreadRunning = false;
    private static int messageSentCounter = 0;
    public static boolean connection = false;
    private static Thread inboxThread;
    public static String currHashAlg = "";
    public static String currSymAlg = "";
    public static PublicKey receiversPublicKey;
    public static SecretKey symKey = null;
    public static List<String> messages = new ArrayList<String>();
    public static boolean convStarted = false;

    private static Stage chatWindow;
    private static BorderPane borderPane;
    private static TextArea text;

    public static void display(String username, String otherusername) {
        inboxThread = new Thread() {
            @Override
            public void run() {
                watcher(username);
            }
        };
        isThreadRunning = true;
        inboxThread.start();

        text = new TextArea();
        text.setPrefRowCount(30);
        text.setPrefColumnCount(60);
        text.setWrapText(true);
        text.setEditable(false);
        chatWindow = new Stage();
        chatWindow.setOnCloseRequest(e -> {
            if (isThreadRunning) {
                try {
                    inboxThread.interrupt();
                } catch (Exception ex) {

                }
            }
        });

        Button sendButton = new Button("SEND");
        TextField messageInput = new TextField();
        messageInput.setPrefColumnCount(40);
        /*sendButton.disableProperty().bind(Bindings.createBooleanBinding(() ->
                !("Pozdrav, zapocnimo chat".equals(messageInput.getText()) && !connection), messageInput.textProperty()
        ));*/
        sendButton.setOnAction(e -> {
            if ("Pozdrav, zapocnimo chat".equals(messageInput.getText()) && !connection) {
                KeyGenerator keyGenerator;
                SecretKey symetricKey;
                int size = 128;
                try {
                    if ("DES".equals(currSymAlg)) {
                        size = 56;
                    }
                    keyGenerator = KeyGenerator.getInstance(currSymAlg);
                    keyGenerator.init(size);
                    symetricKey = keyGenerator.generateKey();
                    if (symKey == null) {
                        symKey = symetricKey;
                    }

                    if (WutApp.loggedUser.algSetByThisUser) {
                        SecureIt.sendSymKey(symKey, otherusername, "connectionRequest_");
                        addToTextArea("ESTABLISHING CONNECTION...");

                    } else {
                        SecureIt.sendSymKey(symKey, otherusername, "accept_");
                        addToTextArea("CONNECTION ESTABLISHED.");
                    }
                    messageSentCounter++;
                } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
                    noSuchAlgorithmException.printStackTrace();
                }


            } else if ("Ovo je zadnja poruka.Ciao".equals(messageInput.getText()) && connection) {
                send(messageInput.getText(), true, otherusername, currSymAlg);
                addToTextArea("You: " + messageInput.getText());
                messageSentCounter++;
                sendButton.setDisable(true);
            } else if (messageSentCounter == 1 && connection && (messageInput.getText().length() != 0) && !isLastMsg) {
                send(messageInput.getText(), true, otherusername, currSymAlg);
                addToTextArea("You: " + messageInput.getText());
                messageSentCounter++;
            } else if ((messageInput.getText().length() != 0) && connection && !isLastMsg) {
                send(messageInput.getText(), false, otherusername, currSymAlg);
                addToTextArea("You: " + messageInput.getText());
                messageSentCounter++;
            } else if ((messageInput.getText().length() != 0) && connection && isLastMsg) {
                send(messageInput.getText(), true, otherusername, currSymAlg);
                addToTextArea("You: " + messageInput.getText());
                messageSentCounter++;
                sendButton.setDisable(true);
            }
            messageInput.clear();
        });
        HBox bottom = new HBox(8, new Label("YOU SAY: "), messageInput, sendButton);
        HBox.setHgrow(messageInput, Priority.ALWAYS);
        bottom.setPadding(new Insets(8));
        bottom.setStyle("-fx-border-color: black; -fx-border-width:2px");
        borderPane = new BorderPane(text);
        borderPane.setBottom(bottom);
        chatWindow.setTitle("CHATTING WITH " + otherusername);
        chatWindow.setScene(new Scene(borderPane));
        chatWindow.setResizable(false);
        chatWindow.show();
        //kliknem send, drugi korisnik ako prihvati, pocinje dopisivanje
    }

    public static void watcher(String username) {
        File folder = new File(SetUp.fileSystemPath + File.separatorChar + "Users" + File.separatorChar
                + username + File.separatorChar + "inbox");

        try {
            WatchService watchService = FileSystems.getDefault().newWatchService();
            Path inbox = Paths.get(SetUp.fileSystemPath + File.separatorChar + "Users" + File.separatorChar
                    + username + File.separatorChar + "inbox");
            inbox.register(watchService, StandardWatchEventKinds.ENTRY_CREATE);
            while (!Thread.currentThread().isInterrupted()) {
                WatchKey key;
                try {
                    key = watchService.take();
                } catch (InterruptedException e) {
                    return;
                }

                for (WatchEvent<?> event : key.pollEvents()) {
                    if (event.kind() == StandardWatchEventKinds.ENTRY_CREATE) {
                        WatchEvent<Path> ev = Util.cast(event);
                        Path file = ev.context();
                        String fileName = file.getFileName().toString();
                        String otherUsername = Util.getUser(fileName);
                        //System.out.println(fileName);
                        String temp = Util.getFileName(fileName);
                        //System.out.println(temp);
                        if (temp.contains("connectionRequest_")) {
                            String user = Util.getUser(temp);

                            Platform.runLater(() -> {
                                Alert alert = new Alert(Alert.AlertType.INFORMATION, "model.User " + user + " wants to chat with you.", ButtonType.OK);
                                alert.showAndWait();
                            });
                            addToTextArea("ESTABLISHING CONNECTION...");
                            SecureIt.getSymKey(user, "connectionRequest_");
                            //System.out.println("req " + Base64.getEncoder().encodeToString(symKey.getEncoded()));
                            File f = new File(SetUp.fileSystemPath + File.separatorChar + "Users" + File.separatorChar
                                    + username + File.separatorChar + "inbox" + File.separatorChar + fileName);
                            f.delete();

                        } else if (temp.contains("accept_")) {
                            String user = Util.getUser(temp);

                            //System.out.println("acc " + Base64.getEncoder().encodeToString(symKey.getEncoded()));
                            addToTextArea("CONNECTION ESTABLISHED.");
                            SecureIt.getSymKey(user, "accept_");
                            connection = true;
                            File f = new File(SetUp.fileSystemPath + File.separatorChar + "Users" + File.separatorChar
                                    + username + File.separatorChar + "inbox" + File.separatorChar + fileName);
                            f.delete();
                        } else {
                            receive(fileName, otherUsername);
                        }
                        //receive();//System.out.println(f.getAbsolutePath());

                    }
                }
                boolean valid = key.reset();
                if (!valid) {
                    break;
                }
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    public static void send(String message, boolean stego, String otherUsername, String algorithm) {
        try {
            receiversPublicKey = SecureIt.takeReceiversPublicKey(otherUsername);
            byte[] hash = SecureIt.hashAlgorithm(message, currHashAlg);
            Cipher cipher;
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, WutApp.loggedUser.getPrivateKey());
            byte[] signedHash = cipher.doFinal(hash);
            String signature = Base64.getEncoder().encodeToString(signedHash);
            byte[] cryptedMsgBytes = SecureIt.encryptText(message, algorithm, symKey);
            String cryptedMsg = Base64.getEncoder().encodeToString(cryptedMsgBytes);
            File file = new File(SetUp.fileSystemPath + File.separatorChar + "Users" + File.separatorChar + otherUsername +
                    File.separatorChar + "inbox" + File.separatorChar + messageSentCounter + "_" + WutApp.loggedUser.getUsername() + ".txt");
            if (stego) {
                String pathToStego = Steganography.encode(new File(SetUp.fileSystemPath + File.separatorChar + "stego"
                        + File.separatorChar + "tree_original.bmp"), cryptedMsg);

                file.createNewFile();
                PrintWriter printWriter = new PrintWriter(new BufferedWriter(new FileWriter(file)));
                printWriter.println("stego");
                printWriter.println(pathToStego);
                printWriter.println("########## ##########");
                printWriter.println(signature);
                printWriter.close();

            } else {

                file.createNewFile();
                PrintWriter printWriter = new PrintWriter(new BufferedWriter(new FileWriter(file)));
                printWriter.println(cryptedMsg);
                printWriter.println("########## ##########");
                printWriter.println(signature);
                printWriter.close();

            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }

    }

    private static void receive(String fileName, String otherUsername) {

        try {
            File file = new File(SetUp.fileSystemPath + File.separatorChar + "Users" + File.separatorChar + WutApp.loggedUser.getUsername() +
                    File.separatorChar + "inbox" + File.separatorChar + fileName);
            X509Certificate otherUsernameCert = CertificationAuthority.retrieveCertificate(otherUsername);
            //(fileName);
            receiversPublicKey = SecureIt.takeReceiversPublicKey(otherUsername);

            Cipher cipher = Cipher.getInstance("RSA");
            String signedHash = "";
            String message = "";
            String cryptedMessage = "";
            byte[] signedHashDecoded;
            byte[] hashDecrypted;
            String hashDecryptedString;

            BufferedReader bufferedReader = new BufferedReader(new FileReader(file));
            String firstLine = bufferedReader.readLine();
            if (firstLine.contains("stego")) {
                String stegoPath = bufferedReader.readLine();
                bufferedReader.readLine();
                File stegFile = new File(stegoPath);
                cryptedMessage = Steganography.decode(stegFile);
                message = SecureIt.decryptText(Base64.getDecoder().decode(cryptedMessage), currSymAlg);
                signedHash = bufferedReader.readLine();
                signedHashDecoded = Base64.getDecoder().decode(signedHash);
                cipher.init(Cipher.DECRYPT_MODE, receiversPublicKey);
                hashDecrypted = cipher.doFinal(signedHashDecoded);
                hashDecryptedString = new String(hashDecrypted);

            } else {
                cryptedMessage = firstLine;
                bufferedReader.readLine();
                signedHash = bufferedReader.readLine();
                message = SecureIt.decryptText(Base64.getDecoder().decode(cryptedMessage), currSymAlg);
                signedHashDecoded = Base64.getDecoder().decode(signedHash);
                cipher.init(Cipher.DECRYPT_MODE, receiversPublicKey);
                hashDecrypted = cipher.doFinal(signedHashDecoded);
                hashDecryptedString = new String(hashDecrypted);

            }
            byte[] myHash = SecureIt.hashAlgorithm(message, currHashAlg);
            String myHashString = new String(myHash, StandardCharsets.UTF_8);
            if (hashDecryptedString.equals(myHashString)) {
                addToTextArea(otherUsername + ": " + message);
                if ("Ovo je zadnja poruka.Ciao".equals(message)) {
                    isLastMsg = true;
                }
            } else {
                Platform.runLater(() -> {
                    Alert alert = new Alert(Alert.AlertType.ERROR, "CONNECTION INTERRUPTED! HASH NOT EQUAL", ButtonType.OK);
                    alert.showAndWait();

                    chatWindow.close();
                });
            }
            bufferedReader.close();
            file.delete();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public static void addToTextArea(String message) {
        Platform.runLater(() -> text.appendText(message + "\n\n"));
    }
}
