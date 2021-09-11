package dev.phonis.blober;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

public class Main {

    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        if (args.length < 2) {
            System.out.println("Usage: (mode) (file) (password)");
            System.exit(-1);
        }

        if (args[0].equals("toBlob")) {
            File file = new File(args[1]);
            File out = new File("out.blob");
            FileOutputStream fileOut = new FileOutputStream(out);
            Cipher encryptCipher = Main.generateCipher(args[2], fileOut);
            DataOutputStream dos = new DataOutputStream(
                new GZIPOutputStream(
                    new CipherOutputStream(
                        fileOut,
                        encryptCipher
                    )
                )
            );

            Main.blobFile(file, dos);
            dos.flush();
            dos.close();
        } else if (args[0].equals("fromBlob")) {
            File file = new File(args[1]);
            FileInputStream fileIn = new FileInputStream(file);
            Cipher decryptCipher = Main.getCipherFromFile(args[2], fileIn);
            DataInputStream dis = new DataInputStream(
                new GZIPInputStream(
                    new CipherInputStream(
                        fileIn,
                        decryptCipher
                    )
                )
            );

            Main.constructBlob(dis, file.getParentFile());
            dis.close();
        } else {
            System.out.println("Valid modes: toBlob, fromBlob");
            System.exit(-1);
        }
    }

    private static Cipher getCipherFromSaltAndIV(String password, byte[] salt, byte[] iv, int mode) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException {
        assert salt.length == 16;

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKey secretKey = new SecretKeySpec(
            factory.generateSecret(spec).getEncoded(),
            "AES"
        );
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");

        cipher.init(mode, secretKey, ivSpec);

        return cipher;
    }

    private static Cipher getCipherFromFile(String password, FileInputStream fileIn) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        return Main.getCipherFromSaltAndIV(password, fileIn.readNBytes(16), fileIn.readNBytes(16), Cipher.DECRYPT_MODE);
    }

    private static Cipher generateCipher(String password, FileOutputStream fileOut) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IOException, InvalidAlgorithmParameterException {
        SecureRandom sr = SecureRandom.getInstanceStrong();
        byte[] salt = new byte[16];
        byte[] iv = new byte[16];

        sr.nextBytes(salt);
        sr.nextBytes(iv);

        fileOut.write(salt);
        fileOut.write(iv);

        return Main.getCipherFromSaltAndIV(password, salt, iv, Cipher.ENCRYPT_MODE);
    }

    private static void blobFile(File toBlob, DataOutputStream dos) throws IOException {
        if (toBlob.isDirectory()) {
            File[] files = toBlob.listFiles();

            Main.writeDirHeader(dos, toBlob.getName(), files == null ? 0 : files.length);

            if (files == null) return;

            for (File file : files) {
                Main.blobFile(file, dos);
            }
        } else {
            Main.writeFileHeader(dos, toBlob.getName(), toBlob.length());
            Main.writeFile(dos, toBlob);
        }
    }

    private static void writeDirHeader(DataOutputStream dos, String name, int length) throws IOException {
        dos.writeBoolean(true);
        dos.writeUTF(name);
        dos.writeInt(length);
    }

    private static void writeFileHeader(DataOutputStream dos, String name, long length) throws IOException {
        dos.writeBoolean(false);
        dos.writeUTF(name);
        dos.writeLong(length);
    }

    private static void writeFile(DataOutputStream dos, File toBlob) throws IOException {
        FileInputStream fileIn = new FileInputStream(toBlob);
        byte[] buffer = new byte[4096];
        int bytesRead;

        while ((bytesRead = fileIn.read(buffer)) >= 0) {
            dos.write(buffer, 0, bytesRead);
        }

        fileIn.close();
    }

    private static void readFile(DataInputStream dis, File currentDirectory, String name) throws IOException {
        long fileLength = dis.readLong();
        File newFile = new File(currentDirectory, name);
        FileOutputStream fileOut = new FileOutputStream(newFile);
        byte[] buffer = new byte[1024];
        long bytesLeft = fileLength;

        while (bytesLeft > 0) {
            long toRead = Math.min(bytesLeft, buffer.length);
            int numRead = dis.read(buffer, 0, (int) toRead);

            fileOut.write(buffer, 0, numRead);

            bytesLeft -= numRead;
        }

        fileOut.flush();
        fileOut.close();
    }

    private static void constructBlob(DataInputStream dis, File currentDirectory) throws IOException {
        boolean isDir = dis.readBoolean();
        String name = dis.readUTF();

        if (isDir) {
            int numFiles = dis.readInt();
            File newDir = new File(currentDirectory, name);

            if (newDir.mkdir()) System.out.println("Creating directory: " + name);

            for (int i = 0; i < numFiles; i++) {
                Main.constructBlob(dis, newDir);
            }
        } else {
            System.out.println("Creating file: " + name);
            Main.readFile(dis, currentDirectory, name);
        }
    }

}
