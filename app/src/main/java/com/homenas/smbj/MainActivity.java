package com.homenas.smbj;

import android.app.Activity;
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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

public class MainActivity extends AppCompatActivity {
    private final SmbConfig cfg = SmbConfig.builder().
            withMultiProtocolNegotiate(true).
            withSecurityProvider(new BCSecurityProvider()).
            build();
    private SMBClient client = new SMBClient(cfg);
    private String mBackupFolder = "smb_test";
    private String ShareName = null;
    private int PERMISSIONS_REQUEST_CODE = 0;
    private DocumentFile ExtStorage;
    private List<DocumentFile> mList = new ArrayList<>();
    private DiskShare share;

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
                new ConnectSmb().execute();
            }
        }
    }

    private class ConnectSmb extends AsyncTask {
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

                        for(DocumentFile f : mList) {
//                            Log.i("Flist", "Uri: " + f.getUri().getPath());
                            if(f.isDirectory()) {
                                String path = mBackupFolder + "/" + StringUtils.substringAfterLast(f.getUri().getPath(),"document/").replace(":","/");
                                String[] folders = StringUtils.split(path,"/");
                                String mPath = "";
                                for(int i = 0; i < folders.length; i++) {
                                    mPath = mPath + folders[i];
                                    if(!share.folderExists(mPath)) {
                                        Log.i("Flist" , "Folder create: " + mPath);
                                        share.mkdir(mPath);
                                    }
                                    mPath = mPath + "\\";
                                }
                            }
                            if(f.isFile()){
                                String path = mBackupFolder + "/" + StringUtils.substringAfterLast(f.getUri().getPath(),"document/").replace(":","/");
                                com.hierynomus.smbj.share.File smbFile = share.openFile(path.replace("/","\\"), EnumSet.of(AccessMask.GENERIC_WRITE, AccessMask.GENERIC_READ), EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL), EnumSet.of(SMB2ShareAccess.FILE_SHARE_WRITE), SMB2CreateDisposition.FILE_OVERWRITE_IF, null);
                                try {
                                    InputStream is = getContentResolver().openInputStream(f.getUri());
                                    long start = System.nanoTime();
                                    smbFile.write(new InputStreamByteChunkProvider(is));
                                    Log.i("Flist","File Successfully Copied.. " + (System.nanoTime()-start) + "s");
                                    smbFile.close();
                                } catch (FileNotFoundException e) {
                                    e.printStackTrace();
                                }
                            }
                        }
                        // Copy List of file
//                        for(String f : mList) {
//                            if(isDir(f) && !share.folderExists(mBackupFolder+"\\"+getName(f))){
//                                share.mkdir(mBackupFolder+"\\"+getName(f));
//                            }else{
////                            copyTo(share, f, mBackupFolder);
//                            }
//                        }
                        // Open test folder inside share folder
//                        com.hierynomus.smbj.share.Directory test = share.openDirectory(mBackupFolder, EnumSet.of(AccessMask.GENERIC_READ),null, SMB2ShareAccess.ALL, FILE_OPEN,null);
//                        for(FileIdBothDirectoryInformation f : test.list()) {
//                            Log.i("SMBJ", "Dir: " + f.getFileName());
//                        }
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            return null;
        }
    }

    public class Filewalker {
        public void walk(DocumentFile root) {
            for (DocumentFile f : root.listFiles()) {
                if (f.isDirectory()) {
                    Log.i("SMBJ", "D: " + f.getUri());
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
}
