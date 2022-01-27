package dev.phonis.blober;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.LinkedList;
import java.util.List;

public class DirectoryStructure {

    private final String directoryName;
    private final List<DirectoryStructure> subDirectories = new LinkedList<>();
    private int numFiles = 0;

    public DirectoryStructure(String directoryName) {
        this.directoryName = directoryName;
    }

    public void addSubFile(DirectoryStructure subDirectory) {
        if (subDirectory != null) {
            this.subDirectories.add(subDirectory);
            
            this.numFiles += subDirectory.numFiles;
        }
    }

    public void incrementFileCount() {
        this.numFiles++;
    }

    public int getNumFiles() {
        return this.numFiles;
    }

    public void makeDirs(Path parentPath) {
        this.makeDirs(parentPath.toFile());
    }

    private void makeDirs(File currentDirectory) {
        File newDir = new File(currentDirectory, this.directoryName);

        if (newDir.mkdir()) System.out.println("Creating directory: " + newDir.getName());

        for (DirectoryStructure subDirectory : this.subDirectories) {
            subDirectory.makeDirs(newDir);
        }
    }

    public static void writeToDataOutputStream(DirectoryStructure directoryStructure, DataOutputStream dos) throws IOException {
        dos.writeUTF(directoryStructure.directoryName);
        dos.writeInt(directoryStructure.numFiles);
        dos.writeInt(directoryStructure.subDirectories.size());

        for (DirectoryStructure subDirectory : directoryStructure.subDirectories) {
            DirectoryStructure.writeToDataOutputStream(subDirectory, dos);
        }
    }

    public static DirectoryStructure readFromDataInputStream(DataInputStream dis) throws IOException {
        String name = dis.readUTF();
        int numFiles = dis.readInt();
        int numSubDirectories = dis.readInt();
        DirectoryStructure directoryStructure = new DirectoryStructure(name);

        for (int i = 0; i < numSubDirectories; i++) {
            directoryStructure.addSubFile(DirectoryStructure.readFromDataInputStream(dis));
        }

        directoryStructure.numFiles = numFiles;

        return directoryStructure;
    }

}
