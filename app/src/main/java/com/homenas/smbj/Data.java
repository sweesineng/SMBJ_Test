package com.homenas.smbj;

import android.arch.persistence.room.Entity;
import android.arch.persistence.room.PrimaryKey;

@Entity(tableName = "Data")
public class Data {
    @PrimaryKey(autoGenerate = true)
    private int id;
    private String fileName;
    private String pathName;

    public Data() {

    }

    public Data(String fileName, String pathName) {
        this.fileName = fileName;
        this.pathName = pathName;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public String getPathName() {
        return pathName;
    }

    public void setPathName(String pathName) {
        this.pathName = pathName;
    }
}
