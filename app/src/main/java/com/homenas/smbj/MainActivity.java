package com.homenas.smbj;

import android.app.Activity;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.storage.StorageManager;
import android.os.storage.StorageVolume;
import android.provider.OpenableColumns;
import android.support.v4.provider.DocumentFile;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import com.hierynomus.msdtyp.AccessMask;
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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

import static com.hierynomus.mssmb2.SMB2CreateDisposition.FILE_OPEN;

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
    private List<String> mList = new ArrayList<>();

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
                    for(DocumentFile f : ExtStorage.listFiles()){
                        if(f.isFile()) {
                            mList.add(f.getUri().toString());
                        }
                    }
                }
                new ConnectSmb().execute();
            }
        }
    }

    private class ConnectSmb extends AsyncTask {
        @Override
        protected Object doInBackground(Object... arg0) {
            try {
//                Connection connection = client.connect("192.168.174.135");
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
                        DiskShare share = (DiskShare) session.connectShare(ShareName);
                        for(FileIdBothDirectoryInformation f : share.list("","*")) {
                            Log.i("SMBJ", "list: " + f.getFileName());
                        }
                        // Create folder if does not exists
                        if(!share.folderExists(mBackupFolder)) {
                            share.mkdir(mBackupFolder);
                        }
                        // Copy List of file
                        for(String f : mList) {
                            Log.i("SMBJ", "Print: " + f);
                            Log.i("SMBJ", "Name: " + getName(f));
                            copyTo(share, f, mBackupFolder);
                        }
                        // Open test folder inside share folder
                        com.hierynomus.smbj.share.Directory test = share.openDirectory(mBackupFolder, EnumSet.of(AccessMask.GENERIC_READ),null, SMB2ShareAccess.ALL, FILE_OPEN,null);
                        for(FileIdBothDirectoryInformation f : test.list()) {
                            Log.i("SMBJ", "Dir: " + f.getFileName());
                        }
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            return null;
        }
    }

    private void copyTo(DiskShare mshare, String source, String destination) {
        String sName = destination + "\\" + getName(source);
        com.hierynomus.smbj.share.File smbFile = mshare.openFile(sName, EnumSet.of(AccessMask.GENERIC_WRITE, AccessMask.GENERIC_READ), null, null, SMB2CreateDisposition.FILE_OVERWRITE_IF, null);
        try {
            InputStream is = getContentResolver().openInputStream(Uri.parse(source));
            long start = System.nanoTime();
            smbFile.write(new InputStreamByteChunkProvider(is));
            Log.i("SMBJ","File Successfully Copied.. " + (System.nanoTime()-start) + "s");
            smbFile.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    private String transformPath(String path) {
        return path.replace("/", "\\");
    }

    private String getName(String path) {
        String name = null;
        Cursor cursor = getContentResolver().query(Uri.parse(path),null,null,null,null);
        try {
            if (cursor != null && cursor.moveToFirst()) {
                name = cursor.getString(cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME));
            }
        } finally {
            cursor.close();
        }
        return name;
    }
}
