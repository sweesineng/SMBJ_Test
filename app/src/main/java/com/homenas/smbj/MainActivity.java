package com.homenas.smbj;

import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.util.List;

public class MainActivity extends AppCompatActivity {
    private final SmbConfig cfg = SmbConfig.builder().
            withMultiProtocolNegotiate(true).
            withSecurityProvider(new BCSecurityProvider()).
            build();
    private SMBClient client = new SMBClient(cfg);
    private String ShareName = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        new ConnectSmb().execute();
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
                        if(!share.folderExists("smb_test")) {
                            share.mkdir("smb_test");
                            for(FileIdBothDirectoryInformation f : share.list("","*")) {
                                Log.i("SMBJ", "list: " + f.getFileName());
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

//    public static void copyFile(File source, File destination) throws IOException {
//        byte[] buffer = new byte[<some buffer size>];
//        try(InputStream in = source.getInputStream()) {
//            try(OutputStream out = destination.getOutputStream()) {
//                int bytesRead;
//                while((bytesRead = in.read(buffer)) != -1) {
//                    out.write(buffer, 0, bytesRead);
//                }
//            }
//        }
//    }

    // Fastest way to copy file... http://crunchify.com/java-tips-what-is-the-fastest-way-to-copy-file-in-java/
    public static void fileCopy(File source, File destination) throws IOException {
        FileChannel inChannel = new FileInputStream(source).getChannel();
        FileChannel outChannel = new FileOutputStream(destination).getChannel();
        try {
            int maxCount = (64 * 1024 * 1024) - (32 * 1024);
            long size = inChannel.size();
            long position = 0;
            while ( position < size ) {
                position += inChannel.transferTo( position, maxCount, outChannel );
            }
            System.out.println("File Successfully Copied..");
        }finally{
            if ( inChannel != null ) {
                inChannel.close();
            }
            if ( outChannel != null ) {
                outChannel.close();
            }
        }
    }
}
