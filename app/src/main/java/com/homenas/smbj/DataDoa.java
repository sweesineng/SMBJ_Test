package com.homenas.smbj;

import android.arch.persistence.room.Dao;
import android.arch.persistence.room.Delete;
import android.arch.persistence.room.Insert;
import android.arch.persistence.room.Query;

import java.util.List;

@Dao
public interface DataDoa {
    @Insert
    void insertData(Data... data);

    @Query("SELECT * FROM Data")
    List<Data> ListAllData();

    @Query("SELECT id FROM Data ORDER BY id DESC LIMIT 1")
    int LastId();

    @Delete
    void deleteData(Data data);
}
