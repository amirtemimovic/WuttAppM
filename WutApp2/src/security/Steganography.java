package security;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

public class Steganography {
    public static String encode(File file, String message) {
        int position = locate(file);
        int readByte = 0;
        File stegFile = new File(file.getAbsolutePath().substring(0, file.getAbsolutePath().length() - 4) + "_stego.bmp");
        try {
            Files.copy(file.toPath(), stegFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException ex) {
            ex.printStackTrace();
        }

        try (RandomAccessFile stream = new RandomAccessFile(stegFile, "rw")) {
            stream.seek(position);
            for (int i = 0; i < 32; i++) {
                readByte = stream.read();
                stream.seek(position);
                stream.write(readByte & 0b11111110);
                position++;
            }

            message += (char) 0;
            int messageByte;
            int messageBit;
            int newByte;

            for (char e : message.toCharArray()) {
                messageByte = (int) e;
                for (int i = 0; i < 8; i++) {
                    readByte = stream.read();
                    messageBit = (messageByte >> i) & 1;
                    newByte = (readByte & 0b11111110) | messageBit;
                    stream.seek(position);
                    stream.write(newByte);
                    position++;
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
        return stegFile.getPath();
    }

    public static String decode(File file) {
        int start = locate(file);
        try (FileInputStream inputStream = new FileInputStream(file)) {
            inputStream.skip(start);
            for (int i = 0; i < 32; i++) {
                if ((inputStream.read() & 1) != 0) {
                    return "PICTURE HAS NOT BEEN ENCODED!";
                }
            }

            String result = "";
            int character;
            while (true) {
                character = 0;
                for (int i = 0; i < 8; i++) {
                    character = character | ((inputStream.read() & 1) << i);
                }
                if (character == 0) {
                    break;
                }
                result += (char) character;
            }
            return result;
        } catch (Exception ex) {
            return "IOException: " + ex.getMessage();
        }
    }

    public static int charsAvailable(File file) {
        return (int) (file.length() - locate(file) + 32) / 8;
    }

    public static int locate(File file) {
        try (FileInputStream inputStream = new FileInputStream(file)) {
            inputStream.skip(10);
            int location = 0;
            for (int i = 0; i < 4; i++) {
                location = location | (inputStream.read() << (4 * i));
            }
            return location;
        } catch (Exception ex) {
            ex.printStackTrace();
            return -1;
        }
    }
}
