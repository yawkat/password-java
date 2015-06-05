package at.yawk.password.server;

import at.yawk.password.Encoding;
import at.yawk.password.LocalStorageProvider;
import at.yawk.password.SignedBlobCodec;
import at.yawk.password.model.SignedBlob;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.*;
import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.Optional;

/**
 * @author yawkat
 */
public class PasswordServer implements Closeable {
    private final LocalStorageProvider storageProvider;
    private final ServerBootstrap bootstrap;

    private Optional<SignedBlob> data;

    {
        bootstrap = new ServerBootstrap();
        bootstrap.channel(NioServerSocketChannel.class);
        bootstrap.group(new NioEventLoopGroup(), new NioEventLoopGroup());
        bootstrap.childHandler(new ChannelInitializer<Channel>() {
            @Override
            protected void initChannel(Channel ch) throws Exception {
                ch.pipeline()
                        .addLast(new HttpServerCodec())
                        .addLast(new SignedBlobCodec())
                        .addLast(new SignatureVerifier())
                        .addLast(new DataReceiver())
                        .addLast(new RequestHandler());
            }
        });
    }

    public PasswordServer(LocalStorageProvider storageProvider) {
        this.storageProvider = storageProvider;
    }

    public void bind(int port) {
        bind(new InetSocketAddress("0.0.0.0", port));
    }

    public void bind(InetSocketAddress address) {
        bootstrap.bind(address);
    }

    private synchronized void verifyAndSetData(SignedBlob blob) throws Exception {
        Optional<SignedBlob> oldData = getData();
        if (oldData.isPresent()) {
            if (!Arrays.equals(oldData.get().getKey(), blob.getKey())) {
                throw new Exception("Signature mismatch");
            }
        }
        ByteBuf buf = Unpooled.buffer();
        blob.write(buf);
        storageProvider.save(Encoding.toByteArray(buf));
        data = Optional.of(blob);
    }

    private synchronized Optional<SignedBlob> getData() throws IOException {
        if (data != null) {
            return data;
        }
        byte[] raw = storageProvider.load();
        if (raw == null) {
            data = Optional.empty();
            return data;
        }
        SignedBlob blob = new SignedBlob();
        blob.read(Unpooled.wrappedBuffer(raw));
        data = Optional.of(blob);
        return data;
    }

    @Override
    public void close() {
        try {
            bootstrap.group().close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            bootstrap.childGroup().close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private class RequestHandler extends SimpleChannelInboundHandler<HttpRequest> {
        @Override
        protected void messageReceived(ChannelHandlerContext ctx, HttpRequest msg)
                throws Exception {
            if (msg.method().equals(HttpMethod.GET)) {
                Optional<SignedBlob> data = getData();
                if (data.isPresent()) {
                    DefaultFullHttpResponse response = new DefaultFullHttpResponse(
                            msg.protocolVersion(), HttpResponseStatus.OK);
                    data.get().write(response.content());
                    ctx.channel().write(response);
                } else {
                    ctx.channel().write(new DefaultFullHttpResponse(
                            msg.protocolVersion(), HttpResponseStatus.NOT_FOUND));
                }
            }
        }
    }

    private class DataReceiver extends SimpleChannelInboundHandler<SignedBlob> {
        @Override
        protected void messageReceived(ChannelHandlerContext ctx, SignedBlob msg) throws Exception {
            verifyAndSetData(msg);
        }
    }
}
