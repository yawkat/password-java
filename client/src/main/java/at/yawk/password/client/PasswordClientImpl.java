package at.yawk.password.client;

import at.yawk.password.*;
import at.yawk.password.model.DecryptedBlob;
import at.yawk.password.model.EncryptedBlob;
import at.yawk.password.model.PasswordBlob;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.util.concurrent.Promise;
import java.net.InetSocketAddress;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.annotation.Nullable;

/**
 * @author yawkat
 */
class PasswordClientImpl implements PasswordClient {
    private LocalStorageProvider localStorageProvider = LocalStorageProvider.NOOP;
    private ObjectMapper objectMapper;
    private Bootstrap bootstrap;
    private KeyPair rsaKeyPair;
    private byte[] password;

    @Override
    public void setObjectMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void setPassword(byte[] password) {
        this.password = password;
    }

    @Override
    public void setRemote(InetSocketAddress address) {
        bootstrap = new Bootstrap();
        bootstrap.channel(NioSocketChannel.class);
        bootstrap.group(new NioEventLoopGroup());
        bootstrap.remoteAddress(address);
        bootstrap.handler(new ChannelInitializer<Channel>() {
            @Override
            protected void initChannel(Channel ch) throws Exception {
                ch.pipeline().addLast(new HttpClientCodec());
            }
        });
    }

    @Override
    public synchronized ClientValue<PasswordBlob> load() throws Exception {
        if (objectMapper == null) {
            objectMapper = new ObjectMapper();
        }

        @Nullable PasswordBlob value = null;
        Exception exception = null;
        boolean fromLocalStorage = false;
        try {
            value = loadRemote();
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
                value = loadKeyPairAndMap(Decrypter.decrypt(objectMapper, local, encryptedBlob));
            }
            fromLocalStorage = true;
        }
        return new ClientValue<>(value, fromLocalStorage);
    }

    @Nullable
    private PasswordBlob loadRemote() throws Exception {
        Channel ch = bootstrap.connect().sync().channel();
        // value is nullable
        Promise<DecryptedBlob> decryptedBlobPromise = ch.eventLoop().newPromise();
        ch.pipeline()
                .addLast(new HttpByteCodec())
                .addLast(new EncryptedBlobCodec())
                .addLast(new Decrypter(objectMapper, password))
                .addLast(new SimpleChannelInboundHandler<Object>() {
                    @Override
                    protected void messageReceived(ChannelHandlerContext ctx, Object msg) throws Exception {
                        if (msg instanceof HttpResponse) {
                            HttpResponseStatus status = ((HttpResponse) msg).status();
                            switch (status.code()) {
                            case 200:
                                break;
                            case 404:
                                decryptedBlobPromise.setSuccess(null);
                                ctx.close();
                                break;
                            default:
                                decryptedBlobPromise.setFailure(new Exception("Invalid status: " + status));
                                ctx.close();
                                break;
                            }
                        } else if (msg instanceof DecryptedBlob) {
                            decryptedBlobPromise.setSuccess((DecryptedBlob) msg);
                        }
                    }

                    @Override
                    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
                        decryptedBlobPromise.setFailure(cause);
                        ctx.close();
                    }
                });
        ch.write(new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/"))
                .addListener(ExceptionForwardingFutureListener.create(ch));
        ch.flush();
        DecryptedBlob decrypted = decryptedBlobPromise.get();
        if (decrypted != null) {
            saveToStorage(decrypted);
        }
        return loadKeyPairAndMap(decrypted);
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
    private PasswordBlob loadKeyPairAndMap(DecryptedBlob decrypted) throws Exception {
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

        return decrypted.getData();
    }

    @Override
    public void save(PasswordBlob data) throws Exception {
        if (rsaKeyPair == null) {
            rsaKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        }

        DecryptedBlob decryptedBlob = new DecryptedBlob();
        decryptedBlob.getRsa().setPrivateKey(
                Base64.getEncoder().encodeToString(rsaKeyPair.getPrivate().getEncoded()));
        decryptedBlob.getRsa().setPublicKey(
                Base64.getEncoder().encodeToString(rsaKeyPair.getPublic().getEncoded()));
        decryptedBlob.setData(data);

        Channel ch = bootstrap.connect().sync().channel();
        Promise<Void> completionPromise = ch.eventLoop().newPromise();
        ch.pipeline()
                .addLast(new HttpByteCodec())
                .addLast(new SignedBlobCodec())
                .addLast(new Signer(rsaKeyPair))
                .addLast(new Encrypter(objectMapper, password))
                .addLast(new SimpleChannelInboundHandler<HttpResponse>() {
                    @Override
                    protected void messageReceived(ChannelHandlerContext ctx, HttpResponse msg) throws Exception {
                        if (msg.status().code() == 200) {
                            completionPromise.setSuccess(null);
                        } else {
                            completionPromise.setFailure(new Exception("Http status " + msg.status().code()));
                        }
                        ctx.close();
                    }
                });
        DefaultHttpRequest request = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, "/");
        request.headers().set("Transfer-Encoding", "Chunked");
        ch.write(request)
                .addListener(ExceptionForwardingFutureListener.create(ch));
        ch.write(decryptedBlob)
                .addListener(ExceptionForwardingFutureListener.create(ch));
        ch.write(new DefaultLastHttpContent())
                .addListener(ExceptionForwardingFutureListener.create(ch));
        ch.flush();
        completionPromise.sync();
    }

    @Override
    public void close() throws Exception {
        bootstrap.group().close();
    }
}
