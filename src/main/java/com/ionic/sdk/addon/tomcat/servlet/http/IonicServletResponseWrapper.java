package com.ionic.sdk.addon.tomcat.servlet.http;

import com.ionic.sdk.addon.tomcat.servlet.IonicServletOutputStream;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class IonicServletResponseWrapper extends HttpServletResponseWrapper {

    private final ByteArrayOutputStream os;
    private final IonicServletOutputStream ios;

    public byte[] getBytes() {
        return os.toByteArray();
    }

    public IonicServletResponseWrapper(HttpServletResponse response) {
        super(response);
        os = new ByteArrayOutputStream();
        ios = new IonicServletOutputStream(os);
    }

    public void close() throws IOException {
        os.close();
    }

    @Override
    public void flushBuffer() throws IOException {
        os.flush();
    }

    @Override
    public ServletOutputStream getOutputStream() {
        return ios;
    }
}
