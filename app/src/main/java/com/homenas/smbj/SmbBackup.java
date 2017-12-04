package com.homenas.smbj;

import android.content.Context;
import android.os.AsyncTask;
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
import java.io.OutputStream;
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
                            String shareName = share.getName();
                            if(LOG) Log.i(TAG, "Share: " + shareName);
                            mShare = (DiskShare) session.connectShare(shareName);
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
//                                    copy2Smb(mShare, src, mBackup);
                                    new SyncAll().walk(mShare, src, mBackup);
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

    private class SyncAll {
        private void walk(DiskShare share, DocumentFile files, String dest) {
            if(files.isDirectory()) {
                String path = dest + File.separator + StringUtils.substringAfterLast(files.getUri().getPath(),"document/").replace(":", File.separator);
                mkSmbDir(share, path);
                if(files.listFiles().length > 0){
                    for(DocumentFile f : files.listFiles()) {
                        walk(share, f, dest);
                    }
                }
            }else{
                if(files.isFile()) {
                    String path = dest + File.separator + StringUtils.substringAfterLast(files.getUri().getPath(),"document/").replace(":", File.separator);
                    path = path.replace(File.separator, "\\");
                    if(!share.fileExists(path)) {
                        write2Smb(share, files, path);
                    }else{
                        if(files.length() != getSmbSize(mShare,path)) {
                            write2Smb(share, files, path);
                        }else{
                            if(LOG) Log.i(TAG, "Local : Remote in sync (" + files.length() + ":"+ getSmbSize(mShare,path) + ")");
                        }
                    }
                }
            }
        }
        private void write2Smb(DiskShare share, DocumentFile file, String path) {
            StopWatch stopWatch = new StopWatch();
            path = path.replace(File.separator,"\\");
            com.hierynomus.smbj.share.File smbFile = share.openFile(
                    path,
                    EnumSet.of(AccessMask.GENERIC_WRITE, AccessMask.GENERIC_READ),
                    EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                    EnumSet.of(SMB2ShareAccess.FILE_SHARE_WRITE),
                    SMB2CreateDisposition.FILE_OVERWRITE_IF,
                    null);
            try {
                stopWatch.start();
                InputStream is = contextRef.get().getContentResolver().openInputStream(file.getUri());
                smbFile.write(new InputStreamByteChunkProvider(is));
                stopWatch.stop();
                smbFile.close();
                if(LOG) Log.i(TAG, "File " + file.getName() + " create in " + stopWatch.getTime() + "ms");
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
        }
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
                            if(LOG) Log.i(TAG, "Folder create: " + mPath);
                        }
                        mPath = mPath + "\\";
                    }
                }
            }else{
                if(!share.folderExists(folder)) {
                    mPath = folder;
                    share.mkdir(mPath);
                    if(LOG) Log.i(TAG, "Folder create: " + mPath);
                }
            }

        }
    }

    private void copy2Local(DiskShare share, String source, DocumentFile root, String target) {
        com.hierynomus.smbj.share.File src = share.openFile(source, EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null);
        String[] folders;
        DocumentFile newFolder = root;
        if(target.contains("/")) {
            folders = StringUtils.split(target, "/");
        }else{
            folders = new String[]{target};
        }
        for(String folder: folders) {
            if(newFolder.findFile(folder) == null) {
                newFolder = newFolder.createDirectory(folder);
            }else{
                newFolder = newFolder.findFile(folder);
            }
        }
        if(newFolder.findFile(getSmbName(source)) != null) {
            try {
                DocumentFile newFile = newFolder.createFile(getSmbMimeType(source),getSmbName(source));
                OutputStream os = contextRef.get().getContentResolver().openOutputStream(newFile.getUri());
                InputStream is = src.getInputStream();
                int read;
                byte[] buffer = new byte[1024];
                while ((read = is.read(buffer)) != -1) {
                    if (os != null) {
                        os.write(buffer, 0, read);
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
//        Uri childrenUri = DocumentsContract.buildDocumentUriUsingTree(MainActivity.uri,MainActivity.id + target);
//        DocumentFile childfile = DocumentFile.fromSingleUri(contextRef.get(),childrenUri);
//        if(childfile != null && childfile.exists()) {
//            Log.i(TAG, "Folder exist");
//        }else{
//            Log.i(TAG, "Folder not exist");
//            DocumentFile newFolder = root.createDirectory(target);
//        }
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
        return MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension);
    }
}
