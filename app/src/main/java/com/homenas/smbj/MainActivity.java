package com.homenas.smbj;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.storage.StorageManager;
import android.os.storage.StorageVolume;
import android.provider.DocumentsContract;
import android.support.v4.provider.DocumentFile;
import android.support.v7.app.AppCompatActivity;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class MainActivity extends AppCompatActivity {
    private int PERMISSIONS_REQUEST_CODE = 0;
    public static DocumentFile ExtStorage;
    public static String id;
    public static Uri uri;
    private static List<DocumentFile> mList = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        getExtStorage();
    }

    public void getExtStorage() {
        StorageManager mStorageManager = this.getSystemService(StorageManager.class);
        if (mStorageManager != null) {
            List<StorageVolume> storageVolumes = mStorageManager.getStorageVolumes();
            for (final StorageVolume volume : storageVolumes) {
                if(!volume.isPrimary()){
                    Intent intent = volume.createAccessIntent(null);
                    startActivityForResult(intent, PERMISSIONS_REQUEST_CODE);
                }
            }
        }
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == PERMISSIONS_REQUEST_CODE && resultCode == Activity.RESULT_OK) {
            if (data.getData() != null) {
                this.getContentResolver().takePersistableUriPermission(data.getData(), Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
                uri = data.getData();
                ExtStorage = DocumentFile.fromTreeUri(this, uri);
                id = DocumentsContract.getTreeDocumentId(uri);
                if (ExtStorage.exists() && ExtStorage != null) {
                    mList.addAll(Arrays.asList(ExtStorage.listFiles()));
                    new SmbBackup(getApplicationContext(), mList).execute();
                }
            }
        }
    }

    private static String TestCheckSum(InputStream is) throws NoSuchAlgorithmException, IOException {
        MessageDigest md = MessageDigest.getInstance("SHA1");
        byte[] dataBytes = new byte[1024];
        int nread = 0;
        while ((nread = is.read(dataBytes)) != -1) {
            md.update(dataBytes, 0, nread);
        };
        byte[] mdbytes = md.digest();
        StringBuffer sb = new StringBuffer("");
        for (int i = 0; i < mdbytes.length; i++) {
            sb.append(Integer.toString((mdbytes[i] & 0xff) + 0x100, 16).substring(1));
        }
        return sb.toString();
    }
}
