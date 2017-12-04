package com.homenas.smbj;

import android.content.Context;
import android.net.Uri;
import android.os.AsyncTask;
import android.provider.DocumentsContract;
import android.support.v4.provider.DocumentFile;
import android.util.Log;
import android.webkit.MimeTypeMap;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.protocol.transport.TransportException;
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
import org.apache.commons.lang3.time.StopWatch;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

public class SmbBackup extends AsyncTask<Void, Void, Void>{
    private final String TAG = getClass().getSimpleName();
    private WeakReference<Context> contextRef;
    private static List<DocumentFile> mList = new ArrayList<>();
    private static DiskShare mShare;
    private boolean LOG = true;
    private static String ShareName = null;
    private static final SmbConfig cfg = SmbConfig.builder().
            withMultiProtocolNegotiate(true).
            withSecurityProvider(new BCSecurityProvider()).
            build();


    public SmbBackup(Context context, List<DocumentFile> list){
        contextRef = new WeakReference<>(context);
        mList = list;
    }

    @Override
    protected Void doInBackground(Void... voids) {
        try {
            SMBClient client = new SMBClient(cfg);
            Connection connection = client.connect("136.198.98.114");
            if(connection.isConnected()) {
                Session session = connection.authenticate(new AuthenticationContext("engss","Sinsweeeng".toCharArray(),"jes"));
                if(session.getConnection().isConnected()){
                    if(LOG) Log.i(TAG,"Session established");
                    // List all share on computer using smbj-rpc
                    final RPCTransport transport = SMBTransportFactories.SRVSVC.getTransport(session);
                    final ServerService serverService = new ServerService(transport);
                    final List<NetShareInfo0> shares = serverService.getShares();
                    for(final NetShareInfo0 share : shares) {
                        if(!share.getName().endsWith("$")) {
                            ShareName = share.getName();
                            if(LOG) Log.i(TAG, "Share: " + ShareName);
                            mShare = (DiskShare) session.connectShare(ShareName);
                            // List content inside the share folder
                            for(FileIdBothDirectoryInformation f : mShare.list("","*")) {
                                if(LOG) Log.i(TAG, "Remote: " + f.getFileName() + " (" + f.getAllocationSize() + ")");
                            }
                            // Create Backup Folder
                            String mBackup = "Smb_Backup";
                            mkSmbDir(mShare, mBackup);
                            // Start copy file from list
                            if(mList != null) {
                                for (DocumentFile src : mList) {
                                    copy2Smb(mShare, src, mBackup);
                                }
                            }
                        }
                    }
                }
//                copy2Local(mShare,"Smb_Backup\\0C01-3409\\test\\VID_20171128_021643.mp4", MainActivity.ExtStorage,"return_test/test");
                session.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private void mkSmbDir(DiskShare share, String folder){
        String mPath = "";
        if(share != null && !folder.equals("")) {
            if(folder.contains("/") || folder.contains("\\")) {
                String[] folders = {};
                if(folder.contains("/")) {
                    folders = StringUtils.split(folder,"/");
                }
                if(folder.contains("\\")) {
                    folders = StringUtils.split(folder,"\\");
                }
                if(folders.length != 0) {
                    for (String f : folders) {
                        mPath = mPath + f;
                        if(!share.folderExists(mPath)) {
                            share.mkdir(mPath);
                            if(LOG) Log.i(TAG, "F create: " + mPath);
                        }
                        mPath = mPath + "\\";
                    }
                }
            }else{
                if(!share.folderExists(folder)) {
                    mPath = folder;
                    share.mkdir(mPath);
                    if(LOG) Log.i(TAG, "F create: " + mPath);
                }
            }

        }
    }

    private void copy2Smb(DiskShare share, DocumentFile file, String dest) {
        StopWatch stopWatch = new StopWatch();
        if(share != null && file != null) {
            String path = dest + File.separator + StringUtils.substringAfterLast(file.getUri().getPath(),"document/").replace(":", File.separator);
            if(file.isDirectory()) {
                mkSmbDir(mShare,path);
            }else{
                if(file.isFile()) {
                    path = path.replace(File.separator,"\\");
                    if(!share.fileExists(path)) {
                        com.hierynomus.smbj.share.File smbFile = share.openFile(
                                path,
                                EnumSet.of(AccessMask.GENERIC_WRITE, AccessMask.GENERIC_READ),
                                EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                                EnumSet.of(SMB2ShareAccess.FILE_SHARE_WRITE),
                                SMB2CreateDisposition.FILE_OVERWRITE_IF,
                                null);
                        try {
                            InputStream is = contextRef.get().getContentResolver().openInputStream(file.getUri());
                            stopWatch.start();
                            smbFile.write(new InputStreamByteChunkProvider(is));
                            smbFile.close();
                            stopWatch.stop();
                            if(LOG) Log.i(TAG, "File: " + file.getName() + " completed: " + stopWatch.getTime() + "ms");
                            stopWatch.reset();
                        } catch (FileNotFoundException e) {
                            e.printStackTrace();
                        }
                    }else{
                        if(file.length() != getSmbSize(mShare,path)) {
                            if(LOG) Log.i(TAG, "Compare: " + file.getName() + " remote: " + path);
                            if(LOG) Log.i(TAG, "Compare: " + file.length() + " remote: " + getSmbSize(mShare,path));
                            com.hierynomus.smbj.share.File smbFile = share.openFile(
                                    path,
                                    EnumSet.of(AccessMask.GENERIC_WRITE, AccessMask.GENERIC_READ),
                                    EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                                    EnumSet.of(SMB2ShareAccess.FILE_SHARE_WRITE),
                                    SMB2CreateDisposition.FILE_OVERWRITE_IF,
                                    null);
                            try {
                                InputStream is = contextRef.get().getContentResolver().openInputStream(file.getUri());
                                stopWatch.start();
                                smbFile.write(new InputStreamByteChunkProvider(is));
                                smbFile.close();
                                stopWatch.stop();
                                if(LOG) Log.i(TAG, "File: " + file.getName() + " completed: " + stopWatch.getTime() + "ms");
                                stopWatch.reset();
                            } catch (FileNotFoundException e) {
                                e.printStackTrace();
                            }
                        }else{
                            if(LOG) Log.i(TAG, "Local : Remote in sync (" + file.length() + ":"+ getSmbSize(mShare,path) + ")");
                        }
                    }
                }
            }
        }
    }

    private void copy2Local(DiskShare share, String source, DocumentFile root, String target) {
        com.hierynomus.smbj.share.File src = share.openFile(source, EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null);
        Uri childrenUri = DocumentsContract.buildDocumentUriUsingTree(MainActivity.uri,MainActivity.id + target);
        DocumentFile childfile = DocumentFile.fromSingleUri(contextRef.get(),childrenUri);
        if(childfile != null && childfile.exists()) {
            Log.i(TAG, "Folder exist");
        }else{
            Log.i(TAG, "Folder not exist");
            DocumentFile newFolder = root.createDirectory(target);
        }
//        try {
//            DocumentFile newfile = newFolder.createFile(getSmbMimeType(source),getSmbName(source));
//            OutputStream os = contextRef.get().getContentResolver().openOutputStream(newfile.getUri());
//            InputStream is = src.getInputStream();
//            int read;
//            byte[] buffer = new byte[1024];
//            while ((read = is.read(buffer)) != -1) {
//                os.write(buffer, 0, read);
//            }
//        } catch (FileNotFoundException e) {
//            e.printStackTrace();
//        } catch (IOException e) {
//            e.printStackTrace();        }
    }

    private long getSmbSize(DiskShare share, String path) {
        long size = 0;
        try {
            size = share.openFile(path, EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null).getFileInformation().getStandardInformation().getEndOfFile();
        } catch (TransportException e) {
            e.printStackTrace();
        }
        return size;
    }

    private String getSmbName(String path) {
        String name;
        if(path.contains("/") || path.contains("\\")){
            if(path.contains("/")) {
                name = StringUtils.substringAfterLast(path, "/");
            }else{
                name = StringUtils.substringAfterLast(path, "\\");
            }
        }else{
            name = path;
        }
        return name;
    }

    private String getSmbMimeType(String path) {
        String extension = MimeTypeMap.getFileExtensionFromUrl(getSmbName(path));
        String mimeType = MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension);
        return mimeType;
    }
}
