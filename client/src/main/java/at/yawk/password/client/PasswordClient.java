package at.yawk.password.client;

import at.yawk.password.Encoding;
import at.yawk.password.LocalStorageProvider;
import at.yawk.password.SignedBlobCodec;
import at.yawk.password.model.DecryptedBlob;
import at.yawk.password.model.EncryptedBlob;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.util.AttributeKey;
import io.netty.util.concurrent.Promise;
import java.net.InetSocketAddress;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.annotation.Nullable;
import lombok.Setter;

/**
 * @author yawkat
 */
public class PasswordClient {
    private static final AttributeKey<Promise<DecryptedBlob>> DECRYPT_FUTURE_ATTRIBUTE =
            AttributeKey.newInstance("decrypt_future");
    static final Object SIGNAL_NO_ENTRY = new Object();

    private LocalStorageProvider localStorageProvider = LocalStorageProvider.NOOP;
    @Setter private ObjectMapper objectMapper;
    private Bootstrap readBootstrap;
    private Bootstrap writeBootstrap;
    private KeyPair rsaKeyPair;
    @Setter private byte[] password;

    public void setRemote(String host, int port) {
        setRemote(new InetSocketAddress(host, port));
    }

    public void setRemote(InetSocketAddress address) {
        readBootstrap = new Bootstrap();
        readBootstrap.channel(NioSocketChannel.class);
        readBootstrap.group(new NioEventLoopGroup());
        readBootstrap.remoteAddress(address);
        writeBootstrap = readBootstrap.clone();

        readBootstrap.handler(new ReadChannelInitializer());
        writeBootstrap.handler(new WriteChannelInitializer());
    }

    public synchronized <T> ClientValue<T> load(Class<T> type) throws Exception {
        if (objectMapper == null) {
            objectMapper = new ObjectMapper();
        }

        @Nullable T value = null;
        Exception exception = null;
        boolean fromLocalStorage = false;
        try {
            value = loadRemote(type);
        } catch (Exception e) {
            exception = e;
        }
        if (value == null) {
            // either the remote errored or it doesn't have a blob yet

            byte[] local = localStorageProvider.load();
            if (exception != null) {
                if (local == null) {
                    // we have no local blob to use and the remote errored
                    throw exception;
                }
                // the remote errored but we can fall back on a local copy
                exception.printStackTrace();
            }
            if (local != null) {
                EncryptedBlob encryptedBlob = new EncryptedBlob();
                encryptedBlob.read(Unpooled.wrappedBuffer(local));
                value = loadKeyPairAndMap(type, Decrypter.decrypt(objectMapper, local, encryptedBlob));
            }
            fromLocalStorage = true;
        }
        return new ClientValue<>(value, fromLocalStorage);
    }

    @Nullable
    private <T> T loadRemote(Class<T> type) throws Exception {
        ChannelFuture channelFuture = readBootstrap.connect();
        channelFuture.addListener(new ChannelFutureListener() {
            @Override
            public void operationComplete(ChannelFuture future) throws Exception {
                future.channel().attr(DECRYPT_FUTURE_ATTRIBUTE).set(
                        future.channel().eventLoop().newPromise()
                );
            }
        });
        channelFuture.sync();
        Channel chan = channelFuture.channel();
        DecryptedBlob decrypted = chan.attr(DECRYPT_FUTURE_ATTRIBUTE).get().sync().get();
        if (decrypted != null) {
            saveToStorage(decrypted);
        }
        return loadKeyPairAndMap(type, decrypted);
    }

    private void saveToStorage(DecryptedBlob decrypted) throws Exception {
        EncryptedBlob encrypted = Encrypter.encrypt(objectMapper, password, decrypted);
        ByteBuf buf = Unpooled.buffer();
        encrypted.write(buf);
        localStorageProvider.save(Encoding.toByteArray(buf));
    }

    /**
     * Load the key pair from the given decrypted blob and return the blob data as the given type.
     */
    @Nullable
    private <T> T loadKeyPairAndMap(Class<T> type, DecryptedBlob decrypted) throws Exception {
        if (decrypted == null) {
            return null;
        }
        byte[] priEnc = Base64.getDecoder().decode(decrypted.getRsa().getPrivateKey());
        byte[] pubEnc = Base64.getDecoder().decode(decrypted.getRsa().getPublicKey());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        rsaKeyPair = new KeyPair(
                keyFactory.generatePublic(new X509EncodedKeySpec(pubEnc)),
                keyFactory.generatePrivate(new PKCS8EncodedKeySpec(priEnc))
        );

        return objectMapper.reader()
                .forType(type)
                .readValue(decrypted.getData());
    }

    public void save(Object data) throws Exception {
        if (rsaKeyPair == null) {
            rsaKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        }

        DecryptedBlob decryptedBlob = new DecryptedBlob();
        decryptedBlob.getRsa().setPrivateKey(
                Base64.getEncoder().encodeToString(rsaKeyPair.getPrivate().getEncoded()));
        decryptedBlob.getRsa().setPublicKey(
                Base64.getEncoder().encodeToString(rsaKeyPair.getPublic().getEncoded()));
    }

    public void close() {
        try {
            readBootstrap.group().close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            writeBootstrap.group().close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private class WriteChannelInitializer extends ChannelInitializer<Channel> {
        @Override
        protected void initChannel(Channel ch) throws Exception {
            ch.pipeline()
                    .addLast(new HttpClientCodec())
                    .addLast(new SignedBlobCodec())
                    .addLast(new Signer(rsaKeyPair))
                    .addLast(new Encrypter(objectMapper, password))
                    .addLast(new SimpleChannelInboundHandler<HttpResponse>() {
                        @Override
                        protected void messageReceived(ChannelHandlerContext ctx, HttpResponse msg) throws Exception {
                            if (msg.status().code() != 200) {
                                throw new Exception("Http status " + msg.status().code());
                            }
                        }
                    });
        }
    }

    private class ReadChannelInitializer extends ChannelInitializer<Channel> {
        @Override
        protected void initChannel(Channel ch) throws Exception {
            ch.pipeline()
                    .addLast(new HttpClientCodec())
                    .addLast(new StatusCodeReader())
                    .addLast(new EncryptedBlobCodec())
                    .addLast(new Decrypter(objectMapper, password))
                    .addLast(new SimpleChannelInboundHandler<Object>() {
                        @Override
                        protected void messageReceived(ChannelHandlerContext ctx, Object msg) throws Exception {
                            ctx.channel().attr(DECRYPT_FUTURE_ATTRIBUTE)
                                    .get().setSuccess(msg == SIGNAL_NO_ENTRY ? null : (DecryptedBlob) msg);
                        }

                        @Override
                        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
                            ctx.close();
                            ctx.channel().attr(DECRYPT_FUTURE_ATTRIBUTE)
                                    .get().setFailure(cause);
                        }
                    });
        }

    }

}
