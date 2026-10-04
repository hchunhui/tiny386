package org.yourorg.tiny386;

import android.database.Cursor;
import android.database.MatrixCursor;
import android.os.CancellationSignal;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract.Document;
import android.provider.DocumentsContract.Root;
import android.provider.DocumentsProvider;
import android.webkit.MimeTypeMap;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

public class MyStorageProvider extends DocumentsProvider {
    private final String[] rootCols = {
            Root.COLUMN_ROOT_ID, Root.COLUMN_FLAGS, Root.COLUMN_ICON, Root.COLUMN_TITLE, Root.COLUMN_DOCUMENT_ID
    };
    private final String[] docCols = {
            Document.COLUMN_DOCUMENT_ID, Document.COLUMN_MIME_TYPE, Document.COLUMN_DISPLAY_NAME,
            Document.COLUMN_LAST_MODIFIED, Document.COLUMN_FLAGS, Document.COLUMN_SIZE
    };

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public Cursor queryRoots(String[] projection) {
        MatrixCursor cursor = new MatrixCursor(projection != null ? projection : rootCols);

        File baseDir = getContext().getExternalFilesDir(null);
        if (baseDir == null) return cursor;

        String appName = getContext().getApplicationInfo().loadLabel(getContext().getPackageManager()).toString();
        int appIcon = getContext().getApplicationInfo().icon;

        cursor.newRow()
                .add(Root.COLUMN_ROOT_ID, "root_app_data")
                .add(Root.COLUMN_DOCUMENT_ID, baseDir.getAbsolutePath())
                .add(Root.COLUMN_TITLE, appName)
                .add(Root.COLUMN_ICON, appIcon)
                .add(Root.COLUMN_FLAGS, Root.FLAG_SUPPORTS_CREATE);

        return cursor;
    }

    @Override
    public Cursor queryDocument(String documentId, String[] projection) throws FileNotFoundException {
        MatrixCursor cursor = new MatrixCursor(projection != null ? projection : docCols);
        File file = new File(documentId);
        if (file.exists()) {
            appendFileRow(cursor, file);
        }
        return cursor;
    }

    @Override
    public Cursor queryChildDocuments(String parentDocumentId, String[] projection, String sortOrder) throws FileNotFoundException {
        MatrixCursor cursor = new MatrixCursor(projection != null ? projection : docCols);
        File parent = new File(parentDocumentId);
        File[] files = parent.listFiles();
        if (files != null) {
            for (File file : files) {
                appendFileRow(cursor, file);
            }
        }
        return cursor;
    }

    @Override
    public ParcelFileDescriptor openDocument(String documentId, String mode, CancellationSignal signal) throws FileNotFoundException {
        File file = new File(documentId);
        int accessMode = ParcelFileDescriptor.parseMode(mode != null ? mode : "r");
        return ParcelFileDescriptor.open(file, accessMode);
    }

    @Override
    public String createDocument(String parentDocumentId, String mimeType, String displayName) throws FileNotFoundException {
        File parent = new File(parentDocumentId);
        File newFile = new File(parent, displayName != null ? displayName : "Untitled");

        try {
            if (Document.MIME_TYPE_DIR.equals(mimeType)) {
                newFile.mkdir();
            } else {
                newFile.createNewFile();
            }
        } catch (IOException e) {
            throw new FileNotFoundException("Failed to create document: " + e.getMessage());
        }
        return newFile.getAbsolutePath();
    }

    @Override
    public void deleteDocument(String documentId) throws FileNotFoundException {
        File file = new File(documentId);
        if (!file.delete()) {
            throw new FileNotFoundException("Failed to delete file: " + file.getPath());
        }
    }

    private void appendFileRow(MatrixCursor cursor, File file) {
        boolean isDir = file.isDirectory();

        String mime;
        if (isDir) {
            mime = Document.MIME_TYPE_DIR;
        } else {
            String ext = MimeTypeMap.getFileExtensionFromUrl(file.getAbsolutePath());
            mime = MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext.toLowerCase());
            if (mime == null) mime = "application/octet-stream";
        }

        int flags;
        if (isDir) {
            flags = Document.FLAG_DIR_SUPPORTS_CREATE | Document.FLAG_SUPPORTS_DELETE;
        } else {
            flags = Document.FLAG_SUPPORTS_WRITE | Document.FLAG_SUPPORTS_DELETE;
        }

        cursor.newRow()
                .add(Document.COLUMN_DOCUMENT_ID, file.getAbsolutePath())
                .add(Document.COLUMN_DISPLAY_NAME, file.getName())
                .add(Document.COLUMN_MIME_TYPE, mime)
                .add(Document.COLUMN_LAST_MODIFIED, file.lastModified())
                .add(Document.COLUMN_SIZE, file.length())
                .add(Document.COLUMN_FLAGS, flags);
    }
}
