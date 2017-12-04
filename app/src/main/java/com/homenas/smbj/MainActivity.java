package com.homenas.smbj;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.storage.StorageManager;
import android.os.storage.StorageVolume;
import android.provider.DocumentsContract;
import android.support.v4.provider.DocumentFile;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.rapid7.client.dcerpc.mssrvs.ServerService;
import com.rapid7.client.dcerpc.mssrvs.messages.NetShareInfo0;
import com.rapid7.client.dcerpc.transport.RPCTransport;
import com.rapid7.client.dcerpc.transport.SMBTransportFactories;

import java.io.IOException;
import java.io.InputStream;
import java.lang.ref.WeakReference;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
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
    public static DocumentFile ExtStorage;
    public static String id;
    public static Uri uri;
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
                uri = data.getData();
                ExtStorage = DocumentFile.fromTreeUri(this, uri);
                id = DocumentsContract.getTreeDocumentId(uri);
                if(ExtStorage.exists() && ExtStorage != null) {
                    Filewalker fw = new Filewalker();
                    fw.walk(ExtStorage);
                }
//                new ConnectSmb(getApplicationContext()).execute();
                new SmbBackup(getApplicationContext(),mList).execute();
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
//                Connection connection = client.connect("136.198.98.114");
                Connection connection = client.connect("136.198.98.91");
                if(connection.isConnected()) {
                    // Get Max Rear & Write size
                    int MaxReadSize = connection.getNegotiatedProtocol().getMaxReadSize();
                    int MaxWriteSize = connection.getNegotiatedProtocol().getMaxWriteSize();
                    Log.i("SMBJ", "MaxReadSize: " + MaxReadSize + " MaxWriteSize: " + MaxWriteSize);
                    // Set username and password to empty for anonymous login
//                    Session session = connection.authenticate(new AuthenticationContext("engss","Sinsweeeng".toCharArray(),"jes"));
                    Session session = connection.authenticate(new AuthenticationContext("staff","ok".toCharArray(),"jes"));
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
                    }
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
