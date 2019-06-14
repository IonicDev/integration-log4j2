package com.ionic.sdk.addon.tomcat.servlet;

import javax.servlet.ServletOutputStream;
import javax.servlet.WriteListener;
import java.io.IOException;
import java.io.OutputStream;

public class IonicServletOutputStream extends ServletOutputStream {

    private final OutputStream os;

    public IonicServletOutputStream(OutputStream outputStream) {
        super();
        os = outputStream;
    }

    @Override
    public boolean isReady() {
        return false;
    }

    @Override
    public void setWriteListener(WriteListener writeListener) {

    }

    @Override
    public void write(byte b[]) throws IOException {
        os.write(b);
    }

    @Override
    public void write(byte b[], int off, int len) throws IOException {
        os.write(b, off, len);
    }

    @Override
    public void write(int b) throws IOException {
        os.write(b);
    }
}
