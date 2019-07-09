/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache license, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the license for the specific language governing permissions and
 * limitations under the license.
 */
package com.ionic.sdk.addon.log4j2.core.appender;

import com.ionic.sdk.agent.Agent;
import com.ionic.sdk.agent.cipher.file.data.FileCipher;
import com.ionic.sdk.agent.cipher.file.data.FileCryptoEncryptAttributes;
import com.ionic.sdk.agent.cipher.file.family.generic.output.GenericOutput;
import com.ionic.sdk.error.IonicException;
import com.ionic.sdk.error.SdkData;
import com.ionic.sdk.error.SdkError;
import org.apache.logging.log4j.core.Filter;
import org.apache.logging.log4j.core.Layout;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.appender.AppenderLoggingException;
import org.apache.logging.log4j.core.appender.OutputStreamManager;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.config.plugins.PluginBuilderAttribute;
import org.apache.logging.log4j.core.util.Constants;
import org.apache.logging.log4j.status.StatusLogger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;

/**
 * Appends log events as bytes to a byte output stream. The stream encoding is defined in the layout.
 *
 * @param <M> The kind of {@link OutputStreamManager} under management
 */
public abstract class IonicAbstractOutputStreamAppender<M extends OutputStreamManager> extends AbstractAppender {

    /**
     * Subclasses can extend this abstract Builder.
     *
     * @param <B> The type to build.
     */
    public abstract static class Builder<B extends Builder<B>> extends AbstractAppender.Builder<B> {

        @PluginBuilderAttribute
        private boolean bufferedIo = true;

        @PluginBuilderAttribute
        private int bufferSize = Constants.ENCODER_BYTE_BUFFER_SIZE;

        @PluginBuilderAttribute
        private boolean immediateFlush = true;

        public int getBufferSize() {
            return bufferSize;
        }

        public boolean isBufferedIo() {
            return bufferedIo;
        }

        public boolean isImmediateFlush() {
            return immediateFlush;
        }

        public B withImmediateFlush(final boolean immediateFlush) {
            this.immediateFlush = immediateFlush;
            return asBuilder();
        }

        public B withBufferedIo(final boolean bufferedIo) {
            this.bufferedIo = bufferedIo;
            return asBuilder();
        }

        public B withBufferSize(final int bufferSize) {
            this.bufferSize = bufferSize;
            return asBuilder();
        }

    }

    /**
     * Immediate flush means that the underlying writer or output stream will be flushed at the end of each append
     * operation. Immediate flush is slower but ensures that each append request is actually written. If
     * <code>immediateFlush</code> is set to {@code false}, then there is a good chance that the last few logs events
     * are not actually written to persistent media if and when the application crashes.
     */
    private final boolean immediateFlush;

    private final M manager;

    /**
     * Ionic, derived from source at:
     *  https://github.com/apache/logging-log4j2/blob/61f125b8b879d1a0852b24358da7424baeb20c31/log4j-core/src/main/java/org/apache/logging/log4j/core/appender/AbstractOutputStreamAppender.java
     */

    /**
     * Ionic state.
     *
     * Cache of data to be written to underlying log4j appender.  This object is supplied to the {@link GenericOutput}
     * constructor.  The cache is written to and emptied in the context of the write call.
     */
    private ByteArrayOutputStream bos;

    /**
     * Ionic state.
     *
     * Ionic GenericFileCipher internal class.  As log content is received by this Appender, the content is piped into
     * GenericOutput, where it is encrypted.  The encrypted content is then passed along to be written to the
     * filesystem.
     *
     * GenericOutput is reset when the underlying file is rotated.  This results in the fetch of a new AES key (each
     * file is encrypted by exactly one key).
     */
    private GenericOutput genericOutput = null;

    /**
     * On rollover of {@link OutputStreamManager} backing file, Ionic file cipher state is reset (causing the
     * encryption key to be rotated).
     *
     * @param agent Ionic key services implementation
     * @throws IonicException on failure to initialize Ionic file cipher state
     * @throws IOException    on failure to write to the stream
     */
    protected void setGenericOutput(final Agent agent) throws IonicException, IOException {
        // initialize GenericOutput to receive data to be encrypted
        this.bos = new ByteArrayOutputStream();
        this.genericOutput = new GenericOutput(bos, 1024 * 1024, agent);
        // select file format version 1.3 (allowing for variable length data writes)
        final FileCryptoEncryptAttributes encryptAttributes =
                new FileCryptoEncryptAttributes(FileCipher.Generic.V13.LABEL);
        // initialize call causes an Ionic platform key create operation
        this.genericOutput.init(encryptAttributes);
        // flush the Ionic generic file header to disk
        final byte[] genericHeader = bos.toByteArray();
        manager.writeBytes(genericHeader, 0, genericHeader.length);
        this.bos.reset();
    }

    /**
     * Instantiates a WriterAppender and set the output destination to a new {@link java.io.OutputStreamWriter}
     * initialized with <code>os</code> as its {@link java.io.OutputStream}.
     *
     * @param name The name of the Appender.
     * @param layout The layout to format the message.
     * @param manager The OutputStreamManager.
     * @deprecated Use {@link #IonicAbstractOutputStreamAppender(String, Layout, Filter, boolean, boolean, Property[], OutputStreamManager)}
     */
    @Deprecated
    protected IonicAbstractOutputStreamAppender(final String name, final Layout<? extends Serializable> layout,
                                                final Filter filter, final boolean ignoreExceptions, final boolean immediateFlush, final M manager) {
        super(name, filter, layout, ignoreExceptions, Property.EMPTY_ARRAY);
        this.manager = manager;
        this.immediateFlush = immediateFlush;
    }

    /**
     * Instantiates a WriterAppender and set the output destination to a new {@link java.io.OutputStreamWriter}
     * initialized with <code>os</code> as its {@link java.io.OutputStream}.
     *
     * @param name The name of the Appender.
     * @param layout The layout to format the message.
     * @param properties optional properties
     * @param manager The OutputStreamManager.
     */
    protected IonicAbstractOutputStreamAppender(final String name, final Layout<? extends Serializable> layout,
                                                final Filter filter, final boolean ignoreExceptions, final boolean immediateFlush,
                                                final Property[] properties, final M manager) {
        super(name, filter, layout, ignoreExceptions, properties);
        this.manager = manager;
        this.immediateFlush = immediateFlush;
    }

    /**
     * Gets the immediate flush setting.
     *
     * @return immediate flush.
     */
    public boolean getImmediateFlush() {
        return immediateFlush;
    }

    /**
     * Gets the manager.
     *
     * @return the manager.
     */
    public M getManager() {
        return manager;
    }

    @Override
    public void start() {
        if (getLayout() == null) {
            LOGGER.error("No layout set for the appender named [" + getName() + "].");
        }
        if (manager == null) {
            LOGGER.error("No OutputStreamManager set for the appender named [" + getName() + "].");
        }
        super.start();
    }

    @Override
    public boolean stop(final long timeout, final TimeUnit timeUnit) {
        return stop(timeout, timeUnit, true);
    }

    @Override
    protected boolean stop(final long timeout, final TimeUnit timeUnit, final boolean changeLifeCycleState) {
        boolean stopped = super.stop(timeout, timeUnit, changeLifeCycleState);
        stopped &= manager.stop(timeout, timeUnit);
        if (changeLifeCycleState) {
            setStopped();
        }
        LOGGER.debug("Appender {} stopped with status {}", getName(), stopped);
        return stopped;
    }

    /**
     * Actual writing occurs here.
     * <p>
     * Most subclasses of <code>AbstractOutputStreamAppender</code> will need to override this method.
     * </p>
     *
     * @param event The LogEvent.
     */
    @Override
    public void append(final LogEvent event) {
        try {
            tryAppend(event);
        } catch (final AppenderLoggingException ex) {
            error("Unable to write to stream " + manager.getName() + " for appender " + getName(), event, ex);
            throw ex;
        }
    }

    private void tryAppend(final LogEvent event) {
        if (Constants.ENABLE_DIRECT_ENCODERS) {
            directEncodeEvent(event);
        } else {
            writeByteArrayToManager(event);
        }
    }

    protected void directEncodeEvent(final LogEvent event) {
        getLayout().encode(event, manager);
        if (this.immediateFlush || event.isEndOfBatch()) {
            manager.flush();
        }
    }

    protected void writeByteArrayToManager(final LogEvent event) {
        final byte[] bytes = getLayout().toByteArray(event);
        if (bytes != null && bytes.length > 0) {
            writeByteArrayToManagerIonic(bytes);
        }
    }

    /**
     * Manipulate Ionic file cipher internals to write a ciphertext block to the output file.
     *
     * @param bytes the plaintext data to be persisted
     */
    private void writeByteArrayToManagerIonic(final byte[] bytes) {
        try {
            SdkData.checkTrue(genericOutput != null, SdkError.ISAGENT_NOINIT);
            // prepare plaintext for Ionic API call
            final ByteBuffer bufferPlainText = genericOutput.getPlainText();
            bufferPlainText.clear();
            bufferPlainText.put(bytes);
            bufferPlainText.limit(bufferPlainText.position());
            bufferPlainText.position(0);
            // encrypt the data block (the encrypted text is written to the provided ByteArrayOutputStream)
            genericOutput.write(bufferPlainText);
            // write the ciphertext to the underlying log4j output stream
            final byte[] bytesIonic = bos.toByteArray();
            manager.writeBytes(bytesIonic, 0, bytesIonic.length);
            manager.flush();
            bos.reset();
        } catch (IOException e) {
            StatusLogger.getLogger().error("IOException", e);
        } catch (IonicException e) {
            StatusLogger.getLogger().error("IonicException", e);
        }
    }
}
