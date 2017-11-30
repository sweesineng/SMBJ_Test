package com.homenas.smbj;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.storage.StorageManager;
import android.os.storage.StorageVolume;
import android.support.v4.provider.DocumentFile;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.io.InputStreamByteChunkProvider;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.rapid7.client.dcerpc.mssrvs.ServerService;
import com.rapid7.client.dcerpc.mssrvs.messages.NetShareInfo0;
import com.rapid7.client.dcerpc.transport.RPCTransport;
import com.rapid7.client.dcerpc.transport.SMBTransportFactories;

import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.ref.WeakReference;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

public class MainActivity extends AppCompatActivity {
    private static final SmbConfig cfg = SmbConfig.builder().
            withMultiProtocolNegotiate(true).
            withSecurityProvider(new BCSecurityProvider()).
            build();
    private static SMBClient client = new SMBClient(cfg);
    private static String mBackupFolder = "smb_test";
    private static String ShareName = null;
    private int PERMISSIONS_REQUEST_CODE = 0;
    private static DocumentFile ExtStorage;
    private static List<DocumentFile> mList = new ArrayList<>();
    private static DiskShare share;

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
            if(data.getData() != null) {
                this.getContentResolver().takePersistableUriPermission(data.getData(),Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
                ExtStorage = DocumentFile.fromTreeUri(this,data.getData());
                if(ExtStorage.exists() && ExtStorage != null) {
                    Filewalker fw = new Filewalker();
                    fw.walk(ExtStorage);
                }
                new ConnectSmb(getApplicationContext()).execute();
            }
        }
    }

    protected static class ConnectSmb extends AsyncTask {
        private WeakReference<Context> contextRef;

        private ConnectSmb(Context context){
            contextRef = new WeakReference<>(context);
        }
        @Override
        protected Object doInBackground(Object... arg0) {
            try {
                Connection connection = client.connect("136.198.98.114");
                if(connection.isConnected()) {
                    // Get Max Rear & Write size
                    int MaxReadSize = connection.getNegotiatedProtocol().getMaxReadSize();
                    int MaxWriteSize = connection.getNegotiatedProtocol().getMaxWriteSize();
                    Log.i("SMBJ", "MaxReadSize: " + MaxReadSize + " MaxWriteSize: " + MaxWriteSize);
                    // Set username and password to empty for anonymous login
                    Session session = connection.authenticate(new AuthenticationContext("engss","Sinsweeeng".toCharArray(),"jes"));
                    if(session.getConnection().isConnected()){
                        Log.i("SMBJ","Session established");
                        // List all share on computer using smbj-rpc
                        final RPCTransport transport = SMBTransportFactories.SRVSVC.getTransport(session);
                        final ServerService serverService = new ServerService(transport);
                        final List<NetShareInfo0> shares = serverService.getShares();
                        for(final NetShareInfo0 share : shares) {
                            if(!share.getName().endsWith("$")) {
                                Log.i("SMBJ", "Share: " + share.getName());
                                ShareName = share.getName();
                            }
                        }

                        // Access specific share folder
                        share = (DiskShare) session.connectShare(ShareName);
                        for(FileIdBothDirectoryInformation f : share.list("","*")) {
                        }
                        // Create folder if does not exists
                        if(!share.folderExists(mBackupFolder)) {
                            share.mkdir(mBackupFolder);
                        }
                        // Start timer
                        long start = System.nanoTime();
                        for(DocumentFile f : mList) {
                            if(f.isDirectory()) {
                                String path = mBackupFolder + File.separator + StringUtils.substringAfterLast(f.getUri().getPath(),"document/").replace(":", File.separator);
                                String[] folders = StringUtils.split(path,"/");
                                String mPath = "";
                                for (String folder : folders) {
                                    mPath = mPath + folder;
                                    if (!share.folderExists(mPath)) {
                                        Log.i("Flist", "F create: " + mPath);
                                        share.mkdir(mPath);
                                    }
                                    mPath = mPath + "\\";
                                }
                            }
                            if(f.isFile()){
                                String path = (mBackupFolder + File.separator + StringUtils.substringAfterLast(f.getUri().getPath(),"document/").replace(":", File.separator)).replace(File.separator,"\\");
                                Log.i("Flist", "path: " + path);
                                if(!share.fileExists(path)) {
                                    com.hierynomus.smbj.share.File smbFile = share.openFile(
                                            path,
                                            EnumSet.of(AccessMask.GENERIC_WRITE, AccessMask.GENERIC_READ),
                                            EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                                            EnumSet.of(SMB2ShareAccess.FILE_SHARE_WRITE),
                                            SMB2CreateDisposition.FILE_OVERWRITE_IF,
                                            null);
                                    try {
                                        InputStream is = contextRef.get().getContentResolver().openInputStream(f.getUri());
                                        smbFile.write(new InputStreamByteChunkProvider(is));
                                        smbFile.close();
                                        Log.i("Flist","F create: " + path);
                                    } catch (FileNotFoundException e) {
                                        e.printStackTrace();
                                    }
                                }else{
//                                    long size=0;
//                                    Cursor cursor = contextRef.get().getContentResolver().query(f.getUri(), null, null, null);
//                                    cursor.moveToFirst();
//                                    size = cursor.getLong(cursor.getColumnIndex(OpenableColumns.SIZE));
//                                    String src = null;
//                                    String dest = null;
//                                    Log.i("Flist", "path: " + path);
//                                    try {
//                                        src = TestCheckSum(contextRef.get().getContentResolver().openInputStream(f.getUri()));
//                                    } catch (NoSuchAlgorithmException e) {
//                                        e.printStackTrace();
//                                    }
//                                    Log.i("Flist", " src: " + src + " dest: " + dest);
                                }
                            }
//                            share.close();
                        }
                        // End timer
                        double end = (double)(System.nanoTime()-start)/1000000000.0;
                        Log.i("Flist","File Successfully Copied.. " + Double.toString(end) + "s");
                        // copy back to local
                        DocumentFile newFolder = ExtStorage.createDirectory("Ess/test");
                        DocumentFile newfile = newFolder.createFile("application/octet-stream","test.mp4");
                        long start1 = System.nanoTime();
                        try {
                            OutputStream os = contextRef.get().getContentResolver().openOutputStream(newfile.getUri());
//                            DocumentFile src = DocumentFile.fromSingleUri(contextRef.get(), Uri.parse("content://com.android.externalstorage.documents/tree/0C01-3409%3A/document/0C01-3409%3Atest%2FVID_20171128_021643.mp4"));
//                            InputStream is = contextRef.get().getContentResolver().openInputStream(src.getUri());
                            InputStream is = share.openFile("smb_test\\0C01-3409\\test\\VID_20171128_021643.mp4", EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null).getInputStream();
                            int read;
                            byte[] buffer = new byte[1024];
                            while ((read = is.read(buffer)) != -1) {
                                os.write(buffer, 0, read);
                            }
                        } catch (FileNotFoundException e) {
                            e.printStackTrace();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                        double end1 = (double)(System.nanoTime()-start1)/1000000000.0;
                        Log.i("Flist","File Successfully Copied.. " + Double.toString(end1) + "s");
                    }
//                    session.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            return null;
        }
    }

    private class Filewalker {
        private void walk(DocumentFile root) {
            for (DocumentFile f : root.listFiles()) {
                if (f.isDirectory()) {
//                    Log.i("SMBJ", "D: " + f.getUri());
                    mList.add(f);
                    walk(f);
                }
                else {
                    Log.i("SMBJ", "F: " + f.getUri());
                    mList.add(f);
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
