package dev.phonis.blober;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.*;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

public class Main {

    private record PriorityRunnable(Runnable runnable, long priority) implements Runnable, Comparable<PriorityRunnable> {

        private static final Comparator<PriorityRunnable> priorityRunnableComparator = Comparator.comparingLong(
            PriorityRunnable::priority
        ).reversed();

        @Override
        public void run() {
            this.runnable.run();
        }

        @Override
        public int compareTo(PriorityRunnable o) {
            return PriorityRunnable.priorityRunnableComparator.compare(this, o);
        }

    }

    private static final char pathSeparator = System.getProperty("file.separator").charAt(0);
    private static SecureRandom secureRandom;
    private static final BlockingQueue<File> fileOutQueue = new LinkedBlockingQueue<>();
    private static final int nThreads = Runtime.getRuntime().availableProcessors();
    private static final ExecutorService threadPool = Executors.newFixedThreadPool(Main.nThreads);

    static {
        try {
            Main.secureRandom = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            System.exit(-1);
        }
    }

    public static void main(String[] args) throws IOException, InterruptedException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, ExecutionException {
        if (args.length < 3) {
            System.out.println("Usage: (mode) (file) (password)");
            System.exit(-1);
        }

        if (args[0].equals("toBlob")) {
            Main.generateBlobFromFileWithPassword(args[1], args[2]);
        } else if (args[0].equals("fromBlob")) {
            Main.constructFileFromBlobWithPassword(args[1], args[2]);
        } else {
            System.out.println("Valid modes: toBlob, fromBlob");
            System.exit(-1);
        }
    }

    private static void constructFileFromBlobWithPassword(String fileName, final String password) throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, ExecutionException, InterruptedException {
        final File file = new File(fileName).getAbsoluteFile();
        Path filePath = file.toPath().toRealPath();
        final Path parentDirectory = filePath.getParent();
        InputStream blobIn = new FileInputStream(file);
        DataInputStream dis = new DataInputStream(blobIn);
        long directoryStructureLength = dis.readLong();
        long currentFilePos = 8; // start at 8 since long is 8 bytes
        InputStream decryptedAndDecompressed = Main.decryptAndDecompressInputStream(dis, password);
        dis = new DataInputStream(decryptedAndDecompressed);
        boolean isDirectory = dis.readBoolean();
        DirectoryStructure directoryStructure = isDirectory ? DirectoryStructure.readFromDataInputStream(dis) : null;
        int numFiles = isDirectory ? directoryStructure.getNumFiles() : 1;
        currentFilePos += directoryStructureLength;

        dis.close();

        if (isDirectory) {
            System.out.println("Creating directories...");
            directoryStructure.makeDirs(parentDirectory);
            System.out.println("Created directories.");
        }

        System.out.println("Unblobbing " + numFiles + " file" + (numFiles == 1 ? "" : "s") + "...");
        System.out.flush();

        List<PriorityRunnable> tasks = new ArrayList<>();
        List<Future<?>> fileFutures = new ArrayList<>();
        blobIn = new FileInputStream(file);
        dis = new DataInputStream(blobIn);
        long currentFileLength;

        dis.skipNBytes(currentFilePos);

        for (int i = 0; i < numFiles; i++) {
            currentFileLength = dis.readLong();
            currentFilePos += 8;
            final long filePosCopy = currentFilePos;

            tasks.add(
                new PriorityRunnable(
                    () -> Main.decryptAndDecompressFile(parentDirectory, file, filePosCopy, password),
                    currentFileLength
                )
            );

            dis.skipNBytes(currentFileLength);
            currentFilePos += currentFileLength;
        }

        dis.close();
        Collections.sort(tasks);
        tasks.forEach(task -> fileFutures.add(Main.threadPool.submit(task)));

        for (Future<?> future : fileFutures) {
            future.get();
        }

        Main.threadPool.shutdown();
    }

    private static void generateBlobFromFileWithPassword(String fileName, String password) throws IOException, InterruptedException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        File file = new File(fileName).getAbsoluteFile();
        Path filePath = file.toPath().toRealPath();
        Path parentDirectory = filePath.getParent();
        File tempDirectoryStructure = Files.createTempFile("blober", "temp").toFile();
        List<PriorityRunnable> tasks = new ArrayList<>();

        System.out.println("Generating tasks...");

        DirectoryStructure directoryStructure = Main.generateBlobRecursively(tasks, parentDirectory, file, password);

        System.out.println("Sorting tasks...");
        Collections.sort(tasks);
        System.out.println("Scheduling tasks...");
        tasks.forEach(Main.threadPool::submit);

        boolean isDirectory = directoryStructure != null;
        int numFiles = isDirectory ? directoryStructure.getNumFiles() : 1;

        System.out.println("Blobbing " + numFiles + " file" + (numFiles == 1 ? "" : "s") + "...");
        System.out.flush();

        int currentFile = 0;
        OutputStream blobOut = new FileOutputStream(filePath.resolveSibling("out.blob").toFile());
        OutputStream tempDirectoryStructureOut = new FileOutputStream(tempDirectoryStructure);
        OutputStream encryptedAndCompressed = Main.encryptAndCompressOutputStream(tempDirectoryStructureOut, password);
        DataOutputStream dos = new DataOutputStream(encryptedAndCompressed);

        dos.writeBoolean(isDirectory);

        if (isDirectory) DirectoryStructure.writeToDataOutputStream(directoryStructure, dos);

        encryptedAndCompressed.close();

        dos = new DataOutputStream(blobOut); // switch to non-compressed/encrypted

        dos.writeLong(tempDirectoryStructure.length());
        Main.writeFile(dos, tempDirectoryStructure);

        if (!tempDirectoryStructure.delete())
            System.out.println("Could not delete temporary file: " + tempDirectoryStructure.getName());

        while (currentFile < numFiles) {
            File toWrite = Main.fileOutQueue.take();

            dos.writeLong(toWrite.length());
            Main.writeFile(dos, toWrite);

            if (!toWrite.delete()) System.out.println("Could not delete temporary file: " + toWrite.getName());

            currentFile++;
        }

        dos.close();
        Main.threadPool.shutdown();
    }

    private static DirectoryStructure generateBlobRecursively(List<PriorityRunnable> tasks, final Path parentDirectory, final File file, final String password) {
        DirectoryStructure directoryStructure;

        if (file.isDirectory()) {
            directoryStructure = new DirectoryStructure(file.getName());
            File[] files = file.listFiles();

            if (files == null) return directoryStructure;

            for (File subFile : files) {
                DirectoryStructure subFileDirectoryStructure = Main.generateBlobRecursively(tasks, parentDirectory, subFile, password);

                if (subFileDirectoryStructure != null)
                    directoryStructure.addSubFile(subFileDirectoryStructure);
                else
                    directoryStructure.incrementFileCount();
            }
        } else {
            directoryStructure = null;

            tasks.add(new PriorityRunnable(() -> Main.encryptAndCompressFile(parentDirectory, file, password), file.length()));
        }

        return directoryStructure;
    }

    private static void decryptAndDecompressFile(Path parentDirectory, File file, long filePos, String password) {
        boolean failed = false;

        try (InputStream fileIn = new FileInputStream(file)) {
            fileIn.skipNBytes(filePos);

            DataInputStream dis = new DataInputStream(
                Main.decryptAndDecompressInputStream(fileIn, password)
            );
            String relativeFileName = dis.readUTF();
            File outFile = parentDirectory.resolve(relativeFileName).toFile();

            Main.readFile(dis, outFile);
            dis.close();
            System.out.println("Created file: " + relativeFileName);
        } catch (IOException | InvalidAlgorithmParameterException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException e) {
            failed = true;
        }

        if (failed) System.exit(-1);
    }

    private static void encryptAndCompressFile(Path parentDirectory, File file, String password) {
        File outFile;
        boolean failed = false;

        try {
            outFile = Files.createTempFile("blober", "temp").toFile();
        } catch (IOException e) {
            System.exit(-1);

            return;
        }

        try (OutputStream fileOut = new FileOutputStream(outFile)) {
            DataOutputStream dos = new DataOutputStream(
                Main.encryptAndCompressOutputStream(fileOut, password)
            );
            String relativeFileName = parentDirectory.relativize(
                file.toPath()
            ).toString().replace(
                Main.pathSeparator,
                '/'
            );

            dos.writeUTF(relativeFileName);
            Main.writeFile(dos, file);
            dos.close();
            Main.fileOutQueue.put(outFile);
            System.out.println("Blobbed file: " + relativeFileName);
        } catch (IOException | InterruptedException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException ignored) {
            failed = true;
        }

        if (failed) System.exit(-1);
    }

    private static InputStream decryptAndDecompressInputStream(InputStream inputStream, String password) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        return new GZIPInputStream(
            new CipherInputStream(
                inputStream,
                Main.getCipherFromInputStream(password, inputStream)
            )
        );
    }

    private static OutputStream encryptAndCompressOutputStream(OutputStream outputStream, String password) throws InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException {
        return new GZIPOutputStream(
            new CipherOutputStream(
                outputStream,
                Main.generateCipher(password, outputStream)
            )
        );
    }

    private static Cipher getCipherFromSaltAndIV(String password, byte[] salt, byte[] iv, int mode) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException {
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

    private static Cipher getCipherFromInputStream(String password, InputStream inputStream) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        return Main.getCipherFromSaltAndIV(password, inputStream.readNBytes(16), inputStream.readNBytes(16), Cipher.DECRYPT_MODE);
    }

    private static Cipher generateCipher(String password, OutputStream out) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IOException, InvalidAlgorithmParameterException {
        byte[] salt = new byte[16];
        byte[] iv = new byte[16];

        Main.secureRandom.nextBytes(salt);
        Main.secureRandom.nextBytes(iv);
        out.write(salt);
        out.write(iv);

        return Main.getCipherFromSaltAndIV(password, salt, iv, Cipher.ENCRYPT_MODE);
    }

    private static void writeFile(OutputStream outputStream, File toWrite) throws IOException {
        try (InputStream fileIn = new FileInputStream(toWrite)) {
            byte[] buffer = new byte[1024];
            int bytesRead;

            while ((bytesRead = fileIn.read(buffer)) >= 0) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }
    }

    private static void readFile(InputStream inputStream, File newFile) throws IOException {
        try (OutputStream fileOut = new FileOutputStream(newFile)) {
            byte[] buffer = new byte[1024];
            int bytesRead;

            while ((bytesRead = inputStream.read(buffer)) >= 0) {
                fileOut.write(buffer, 0, bytesRead);
            }
        }
    }

}
