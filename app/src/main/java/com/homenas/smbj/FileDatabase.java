package com.homenas.smbj;

import android.arch.persistence.room.Database;
import android.arch.persistence.room.RoomDatabase;

@Database(entities = {Data.class}, version = 1, exportSchema = false)
public abstract class FileDatabase extends RoomDatabase{
    public abstract DataDoa datadoa();
}
