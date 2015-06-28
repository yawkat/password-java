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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import javax.annotation.Nullable;
import javax.xml.bind.DatatypeConverter;
import lombok.extern.slf4j.Slf4j;

/**
 * @author yawkat
 */
@Slf4j
class PasswordClientImpl implements PasswordClient {
    private LocalStorageProvider localStorageProvider;
    private ObjectMapper objectMapper;
    private Bootstrap bootstrap;
    private KeyPair rsaKeyPair;
    private byte[] password;
    private String host;

    @Override
    public void setLocalStorageProvider(LocalStorageProvider localStorageProvider) {
        this.localStorageProvider = localStorageProvider;
    }

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
        host = address.getHostString();
    }

    @Override
    public synchronized ClientValue<PasswordBlob> load() throws Exception {
        log.info("Loading password blob");
        if (objectMapper == null) {
            objectMapper = new ObjectMapper();
        }

        @Nullable PasswordBlob value = null;
        Exception exception = null;
        boolean fromLocalStorage = false;
        try {
            value = loadRemote();
            log.info("Loaded password data from remote");
        } catch (Exception e) {
            log.warn("Failed to load password blob from remote", e);
            exception = e;
        }
        if (value == null) {
            // either the remote errored or it doesn't have a blob yet

            value = tryLoadLocal();
            if (exception != null) {
                if (value == null) {
                    // no local data, might as well throw the remote one
                    throw exception;
                } else {
                    // don't swallow
                    log.info("Loaded password data from local instead");
                }
            }
            fromLocalStorage = true;
        }
        return new ClientValue<>(value, fromLocalStorage);
    }

    @Nullable
    private PasswordBlob tryLoadLocal() throws Exception {
        byte[] local = localStorageProvider.load();
        if (local != null) {
            EncryptedBlob encryptedBlob = new EncryptedBlob();
            encryptedBlob.read(Unpooled.wrappedBuffer(local));
            return loadKeyPairAndMap(Decrypter.decrypt(objectMapper, password, encryptedBlob));
        } else {
            return null;
        }
    }

    private byte[] loadChallenge() throws Exception {
        Channel ch = bootstrap.connect().sync().channel();
        Promise<byte[]> challengePromise = ch.eventLoop().newPromise();
        ch.pipeline().addLast(new SimpleChannelInboundHandler<HttpObject>() {
            ByteBuf buf = Unpooled.buffer();

            @Override
            protected void messageReceived(ChannelHandlerContext ctx, HttpObject msg) throws Exception {
                if (msg instanceof HttpResponse) {
                    if (((HttpResponse) msg).status().code() != 200) {
                        challengePromise.setFailure(new Exception("Status " + ((HttpResponse) msg).status()));
                        ctx.close();
                        return;
                    }
                }
                if (msg instanceof HttpContent) {
                    ByteBuf content = ((HttpContent) msg).content();
                    content.readBytes(buf, content.readableBytes());
                }
                if (msg instanceof LastHttpContent) {
                    challengePromise.setSuccess(Arrays.copyOf(buf.array(), buf.readableBytes()));
                    ctx.close();
                }
            }
        });
        DefaultFullHttpRequest request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/challenge");
        request.headers().add("Host", host);
        ExceptionForwardingFutureListener.write(ch, request);
        ch.flush();
        return challengePromise.sync().get();
    }

    @Nullable
    private PasswordBlob loadRemote() throws Exception {
        if (rsaKeyPair == null) {
            // try loading the key pair from local
            tryLoadLocal();
        }

        byte[] challenge;
        byte[] challengeSignature;
        if (rsaKeyPair != null) {
            challenge = loadChallenge();
            challengeSignature = Signer.sign(rsaKeyPair.getPrivate(), challenge);
        } else {
            challenge = challengeSignature = null;
            log.info("Could not find key pair in local, let's hope the remote doesn't have a key pair yet");
        }

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
                                decryptedBlobPromise.setFailure(new Exception("Status: " + status));
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
        DefaultFullHttpRequest request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/db");
        request.headers().add("Host", host);
        if (challenge != null && challengeSignature != null) {
            // add auth header
            request.headers().add("Authorization",
                                  "Signature " + DatatypeConverter.printHexBinary(challenge) +
                                  " " + DatatypeConverter.printHexBinary(challengeSignature));
        }
        ch.write(request).addListener(ExceptionForwardingFutureListener.create(ch));
        ch.flush();
        DecryptedBlob decrypted = decryptedBlobPromise.sync().get();
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
        rsaKeyPair = decrypted.getRsa().toKeyPair();

        return decrypted.getData();
    }

    @Override
    public void save(PasswordBlob data) throws Exception {
        log.info("Saving password blob");
        if (objectMapper == null) {
            objectMapper = new ObjectMapper();
        }

        if (rsaKeyPair == null) {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(4096);
            rsaKeyPair = gen.generateKeyPair();
        }

        DecryptedBlob decryptedBlob = new DecryptedBlob();
        decryptedBlob.setRsa(DecryptedBlob.RsaKeyPair.ofKeyPair(rsaKeyPair));
        decryptedBlob.setData(data);

        saveToStorage(decryptedBlob);

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
        DefaultHttpRequest request = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, "/db");
        request.headers().add("Host", host);
        request.headers().set("Transfer-Encoding", "Chunked");
        ch.write(request)
                .addListener(ExceptionForwardingFutureListener.create(ch));
        ch.write(decryptedBlob)
                .addListener(ExceptionForwardingFutureListener.create(ch));
        ch.write(new DefaultLastHttpContent())
                .addListener(ExceptionForwardingFutureListener.create(ch));
        ch.flush();
        completionPromise.sync();
        log.info("Password blob saved");
    }

    @Override
    public void close() throws Exception {
        bootstrap.group().close();
    }
}
