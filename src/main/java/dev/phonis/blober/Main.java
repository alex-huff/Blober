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
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.*;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/*
    TODO:
        When generating files from a blob, instead of writing encrypted/compressed data to temp files,
        send blob file pointer with runnable. This can be done quickly since skipping over data in
        files is efficient. This removes the need for hacky implementation of priority-based ExecutorService
        since we can sort the tasks on the spot, since generating them will be pretty quick.
        The length of the to-be decompressed/decrypted file does not need to be given to the runnable since
        GZIPInputStream will know when to stop because of the presence of a trailer.
        ...
        It is worth noting that doing this will make adapting Blober for use over a network more challenging since
        multiple processes are reading from the same file through multiple input streams, something that can't
        really be replicated on a SocketInputStream without first writing all data to a file or a buffer. The current
        implementation, though, would work just fine for use over a network since data received over the network
        is split up into temporary files, where it is then processed.
        ...
        Blobbing files can then be easily rewritten to not need the priority-based ExecutorService by making
        FileRunnable comparable, and sorting a list of them after recursing over the file/directory given.
        ...
        Now that generating files from a blob will produce runnables that are not tied to a specific file,
        FileRunnable cannot be used for sorting these tasks. A more generic PriorityRunnable may suit both
        blobbing/un-blobbing well and can replace FileRunnable.
        ...
        Something like this?

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
 */

public class Main {

    private static final char pathSeparator = System.getProperty("file.separator").charAt(0);
    private static SecureRandom secureRandom;
    private static final BlockingQueue<File> fileOutQueue = new LinkedBlockingQueue<>();
    private static final int nThreads = Runtime.getRuntime().availableProcessors();
    private static final ExecutorService threadPool = new ThreadPoolExecutor(
        Main.nThreads,
        Main.nThreads,
        0L,
        TimeUnit.MILLISECONDS,
        new PriorityBlockingQueue<>(
            1,
            Comparator.comparingLong(
                runnable -> {
                    if (runnable instanceof PriorityFuture<?> priorityFuture) return priorityFuture.getPriority();

                    return Long.MAX_VALUE;
                }
            ).reversed()
        )
    ) {

        @Override
        protected <T> RunnableFuture<T> newTaskFor(Runnable runnable, T ignored) {
            RunnableFuture<T> runnableFuture = super.newTaskFor(runnable, ignored);

            if (runnable instanceof FileRunnable fileRunnable)
                return new PriorityFuture<>(
                    runnableFuture,
                    fileRunnable.getToProcess().length()
                );

            return runnableFuture;
        }

    };

    private record PriorityFuture<T>(RunnableFuture<T> delegate, long priority) implements RunnableFuture<T> {

        public long getPriority() {
            return priority;
        }

        public boolean cancel(boolean mayInterruptIfRunning) {
            return delegate.cancel(mayInterruptIfRunning);
        }

        public boolean isCancelled() {
            return delegate.isCancelled();
        }

        public boolean isDone() {
            return delegate.isDone();
        }

        public T get() throws InterruptedException, ExecutionException {
            return delegate.get();
        }

        public T get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException {
            return delegate.get();
        }

        public void run() {
            delegate.run();
        }

    }

    private record FileRunnable(File toProcess, Runnable toRun) implements Runnable {

        public File getToProcess() {
            return this.toProcess;
        }

        @Override
        public void run() {
            this.toRun.run();
        }

    }

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
        File file = new File(fileName).getAbsoluteFile();
        Path filePath = file.toPath().toRealPath();
        final Path parentDirectory = filePath.getParent();
        File tempDirectoryStructure = Files.createTempFile("blober", "temp").toFile();
        InputStream blobIn = new FileInputStream(file);

        Main.readFile(new DataInputStream(blobIn), tempDirectoryStructure);

        InputStream tempDirectoryStructureIn = new FileInputStream(tempDirectoryStructure);
        InputStream decryptedAndDecompressed = Main.decryptAndDecompressInputStream(tempDirectoryStructureIn, password);
        DataInputStream dis = new DataInputStream(decryptedAndDecompressed);
        boolean isDirectory = dis.readBoolean();
        DirectoryStructure directoryStructure = isDirectory ? DirectoryStructure.readFromDataInputStream(dis) : null;

        decryptedAndDecompressed.close();

        if (!tempDirectoryStructure.delete())
            System.out.println("Could not delete temporary file: " + tempDirectoryStructure.getName());

        int numFiles = isDirectory ? directoryStructure.getNumFiles() : 1;
        dis = new DataInputStream(blobIn); // switch to non-decompressed/decrypted
        List<Future<?>> fileFutures = new ArrayList<>();

        if (isDirectory) {
            System.out.println("Creating directories...");
            directoryStructure.makeDirs(parentDirectory);
            System.out.println("Created directories.");
        }

        System.out.println("Unblobbing " + numFiles + " file" + (numFiles == 1 ? "" : "s") + ".");
        System.out.flush();

        for (int i = 0; i < numFiles; i++) {
            final File tempFile = Files.createTempFile("blober", "temp").toFile();

            Main.readFile(dis, tempFile);
            fileFutures.add(
                Main.threadPool.submit(
                    new FileRunnable(tempFile, () -> Main.decryptAndDecompressFile(parentDirectory, tempFile, password))
                )
            );
        }

        dis.close();

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
        DirectoryStructure directoryStructure = Main.generateBlobRecursively(parentDirectory, file, password);
        boolean isDirectory = directoryStructure != null;
        int numFiles = isDirectory ? directoryStructure.getNumFiles() : 1;

        System.out.println("Blobbing " + numFiles + " file" + (numFiles == 1 ? "" : "s") + ".");
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
        Main.writeFileNoLength(dos, tempDirectoryStructure);

        if (!tempDirectoryStructure.delete())
            System.out.println("Could not delete temporary file: " + tempDirectoryStructure.getName());

        while (currentFile < numFiles) {
            File toWrite = Main.fileOutQueue.take();

            dos.writeLong(toWrite.length());
            Main.writeFileNoLength(dos, toWrite);

            if (!toWrite.delete()) System.out.println("Could not delete temporary file: " + toWrite.getName());

            currentFile++;
        }

        dos.close();
        Main.threadPool.shutdown();
    }

    private static DirectoryStructure generateBlobRecursively(final Path parentDirectory, final File file, final String password) {
        DirectoryStructure directoryStructure;

        if (file.isDirectory()) {
            directoryStructure = new DirectoryStructure(file.getName());
            File[] files = file.listFiles();

            if (files == null) return directoryStructure;

            for (File subFile : files) {
                DirectoryStructure subFileDirectoryStructure = Main.generateBlobRecursively(parentDirectory, subFile, password);

                if (subFileDirectoryStructure != null)
                    directoryStructure.addSubFile(subFileDirectoryStructure);
                else
                    directoryStructure.incrementFileCount();
            }
        } else {
            directoryStructure = null;

            Main.threadPool.submit(
                new FileRunnable(file, () -> Main.encryptAndCompressFile(parentDirectory, file, password))
            );
        }

        return directoryStructure;
    }

    private static void decryptAndDecompressFile(Path parentDirectory, File file, String password) {
        boolean failed = false;

        try (InputStream fileIn = new FileInputStream(file)) {
            DataInputStream dis = new DataInputStream(
                Main.decryptAndDecompressInputStream(fileIn, password)
            );
            String relativeFileName = dis.readUTF();
            File outFile = parentDirectory.resolve(relativeFileName).toFile();

            Main.readFileNoLength(dis, outFile);
            dis.close();
            System.out.println("Created file: " + relativeFileName);

            if (!file.delete()) System.out.println("Could not delete temporary file: " + file.getName());
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
            Main.writeFileNoLength(dos, file);
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

    private static void writeFileNoLength(OutputStream outputStream, File toWrite) throws IOException {
        try (InputStream fileIn = new FileInputStream(toWrite)) {
            byte[] buffer = new byte[1024];
            int bytesRead;

            while ((bytesRead = fileIn.read(buffer)) >= 0) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }
    }

    private static void readFile(DataInputStream dis, File newFile) throws IOException {
        long fileLength = dis.readLong();

        try (OutputStream fileOut = new FileOutputStream(newFile)) {
            byte[] buffer = new byte[1024];
            long bytesLeft = fileLength;

            while (bytesLeft > 0) {
                long toRead = Math.min(bytesLeft, buffer.length);
                int numRead = dis.read(buffer, 0, (int) toRead);

                fileOut.write(buffer, 0, numRead);

                bytesLeft -= numRead;
            }
        }
    }

    private static void readFileNoLength(InputStream inputStream, File newFile) throws IOException {
        try (OutputStream fileOut = new FileOutputStream(newFile)) {
            byte[] buffer = new byte[1024];
            int bytesRead;

            while ((bytesRead = inputStream.read(buffer)) >= 0) {
                fileOut.write(buffer, 0, bytesRead);
            }
        }
    }

}
