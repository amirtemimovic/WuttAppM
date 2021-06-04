package main;

import gui.ChatWindow;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import model.User;
import security.CertificationAuthority;
import security.SecureIt;
import util.SetUp;
import util.Util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.*;
import java.security.cert.X509Certificate;
import java.util.Base64;


public class WutApp extends Application {

    public static User loggedUser;
    public static boolean started = false;
    public ObservableList<String> activeUsers = FXCollections.observableArrayList();
    //public static boolean algSetByThisUser = false;
    private Thread watcherThread;
    private volatile boolean isThreadRunning = false;

    @Override
    public void start(Stage stage) throws Exception {
        SetUp.setUpFileSystem();
        stage.setTitle("LOGIN WINDOW");
        Scene loginScene;
        Button loginButton = new Button("LOGIN");
        GridPane loginGrid = new GridPane();
        loginGrid.setHgap(10);
        loginGrid.setVgap(10);
        loginGrid.setAlignment(Pos.CENTER);
        loginGrid.setPadding(new Insets(20, 20, 20, 20));

        Label nameLabel = new Label("Username");
        Label passwordLabel = new Label("Password");

        TextField nameInput = new TextField();
        nameInput.setPromptText("username");
        PasswordField passwordInput = new PasswordField();
        passwordInput.setPromptText("password");
        stage.setOnCloseRequest(e -> {
            if (started) {
                File file = new File(SetUp.fileSystemPath + File.separatorChar + "Users" + File.separatorChar
                        + "activeUsers" + File.separatorChar + nameInput.getText() + ".txt");
                file.delete();
                //System.out.println(gui.ChatWindow.currHashAlg);
                if (loggedUser.algSetByThisUser) {
                    File file1 = new File(SetUp.fileSystemPath + File.separatorChar + "Connection" + File.separatorChar
                            + "HashAlgorithm" + File.separatorChar + ChatWindow.currHashAlg + ".txt");
                    File file2 = new File(SetUp.fileSystemPath + File.separatorChar + "Connection" + File.separatorChar
                            + "SymAlgorithm" + File.separatorChar + ChatWindow.currSymAlg + ".txt");
                    try {
                        file1.delete();
                        file2.delete();
                    } catch (Exception ex) {

                    }
                }
                if (isThreadRunning) {
                    try {
                        watcherThread.interrupt();
                    } catch (Exception ex) {

                    }
                }
            }

            //System.exit(0);
        });
        loginButton.setOnAction(e -> {
            boolean res = check(nameInput.getText(), passwordInput);
            started = true;
            if (res) {
                File file = new File(SetUp.fileSystemPath + File.separatorChar + "Users" + File.separatorChar
                        + "activeUsers" + File.separatorChar + nameInput.getText() + ".txt");
                X509Certificate userCertificate = CertificationAuthority.retrieveCertificate(nameInput.getText());
                if (CertificationAuthority.isValidCertificateDate(userCertificate) && CertificationAuthority.isCertificateRootValid(userCertificate)
                        && !(CertificationAuthority.isCertificateInCRL(userCertificate))) {
                    loggedUser = new User(nameInput.getText(), passwordInput.getText(), userCertificate);
                    try {
                        file.createNewFile();
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                    display(stage, activeUsers);
                } else {
                    stage.close();
                }
            }
        });


        loginGrid.add(nameLabel, 0, 0);
        loginGrid.add(nameInput, 1, 0);
        loginGrid.add(passwordLabel, 0, 1);
        loginGrid.add(passwordInput, 1, 1);
        loginGrid.add(loginButton, 1, 4);

        loginScene = new Scene(loginGrid);
        stage.setScene(loginScene);
        stage.setMinHeight(250);
        stage.setMinWidth(350);
        stage.show();
    }


    private boolean check(String username, PasswordField password) {
        File file = new File(SetUp.fileSystemPath + File.separatorChar + "Users" + File.separatorChar + username);
        if (!file.exists()) {
            Alert alert = new Alert(Alert.AlertType.ERROR, "WRONG USERNAME! Please try again.", ButtonType.OK);
            alert.showAndWait();
            return false;
        } else {
            String s = Base64.getEncoder().encodeToString(SecureIt.hashAlgorithm(password.getText(), SecureIt.SHA512));
            file = new File(SetUp.fileSystemPath + File.separatorChar + "Passwords" + File.separatorChar + "pass.txt");
            try {
                BufferedReader bufferedReader = new BufferedReader(new FileReader(file));
                String line;
                while ((line = bufferedReader.readLine()) != null) {
                    String[] parts = line.split(" - ");
                    if (username.equals(parts[0])) {
                        if (s.equals(parts[1])) {
                            return true;
                        }
                    }

                }
                bufferedReader.close();
                Alert alert = new Alert(Alert.AlertType.INFORMATION, "WRONG USERNAME or PASSWORD! Please, try again.", ButtonType.OK);
                alert.showAndWait();
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
        return false;
    }


    private void display(Stage stage, ObservableList<String> activeUsers) {
        ListView activeView = new ListView();
        activeView.setItems(activeUsers);
        Util.selectAlgorithms(loggedUser);
        stage.setTitle("ACTIVE USERS");
        Button chatButton = new Button("Chat");
        VBox layout = new VBox(10);
        layout.setPadding(new Insets(20, 20, 20, 20));

        Scene usersScene = new Scene(layout);
        watcherThread = new Thread() {
            @Override
            public void run() {
                watch();
            }
        };
        isThreadRunning = true;
        watcherThread.start();


        activeView.getSelectionModel().setSelectionMode(SelectionMode.SINGLE);
        chatButton.setOnAction(e -> {
            if (!activeView.getSelectionModel().isEmpty()) {
                String otherUsername = (String) activeView.getSelectionModel().getSelectedItem();
                ChatWindow.display(loggedUser.getUsername(), otherUsername);
            }
        });
        layout.getChildren().addAll(activeView, chatButton);
        stage.setScene(usersScene);
        stage.show();

    }

    public void watch() {
        File folder = new File(SetUp.fileSystemPath + File.separatorChar + "Users" + File.separatorChar + "activeUsers");
        File[] listOfFiles = folder.listFiles();
        for (int i = 0; i < listOfFiles.length; i++) {
            if (listOfFiles[i].isFile()) {
                //System.out.println(listOfFiles[i]);
                String name = Util.getFileName(listOfFiles[i]);
                if (!loggedUser.getUsername().equals(name)) {
                    activeUsers.add(name);
                }
            }
        }
        try {
            WatchService watcher = FileSystems.getDefault().newWatchService();
            Path logDir = Paths.get(SetUp.fileSystemPath + File.separatorChar + "Users" + File.separatorChar + "activeUsers");
            logDir.register(watcher, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_DELETE);
            while (!Thread.currentThread().isInterrupted()) {
                WatchKey key;
                try {
                    key = watcher.take();
                } catch (InterruptedException ex) {
                    return;
                }

                for (WatchEvent<?> event : key.pollEvents()) {
                    if (event.kind() == StandardWatchEventKinds.ENTRY_CREATE) {
                        WatchEvent<Path> ev = Util.cast(event);
                        Path file = ev.context();
                        String temp1 = file.getFileName().toString();
                        String temp2 = temp1.replace("" + File.separatorChar, "-");
                        String[] parts = temp2.split("-");
                        int length = parts.length;
                        String name = parts[length - 1].replace(".txt", "");
                        if ((!activeUsers.contains(name)) && (!loggedUser.getUsername().equals(name))) {
                            Platform.runLater(() -> {
                                activeUsers.add(name);
                            });

                        }
                    } else if (event.kind() == StandardWatchEventKinds.ENTRY_DELETE) {
                        WatchEvent<Path> ev = Util.cast(event);
                        Path file = ev.context();
                        String temp1 = file.getFileName().toString();
                        String temp2 = temp1.replace("" + File.separatorChar, "-");
                        String[] parts = temp2.split("-");
                        int length = parts.length;
                        final String fileName = parts[length - 1].replace(".txt", "");
                        Platform.runLater(() -> {
                            activeUsers.removeIf(s -> s.equals(fileName));
                        });
                    }
                }
                boolean valid = key.reset();
                if (!valid) {
                    break;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public static void main(String[] args) {
        launch(args);
    }


}
