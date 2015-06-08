package at.yawk.password.server;

import at.yawk.password.Encoding;
import at.yawk.password.ExceptionForwardingFutureListener;
import at.yawk.password.LocalStorageProvider;
import at.yawk.password.model.SignedBlob;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.Optional;

/**
 * @author yawkat
 */
class PasswordServerImpl implements PasswordServer {
    private final ServerBootstrap bootstrap;

    private LocalStorageProvider storageProvider;
    private Optional<SignedBlob> data;

    final ChallengeManager challengeManager = new ChallengeManager();

    {
        bootstrap = new ServerBootstrap();
        bootstrap.channel(NioServerSocketChannel.class);
        bootstrap.group(new NioEventLoopGroup(), new NioEventLoopGroup());
        bootstrap.childHandler(new ChannelInitializer<Channel>() {
            @Override
            protected void initChannel(Channel ch) throws Exception {
                ch.pipeline()
                        .addLast(new HttpServerCodec())
                        .addLast(new Dispatcher())
                        .addLast(new Cleaner());
            }
        });
    }

    @Override
    public void setStorageProvider(LocalStorageProvider storageProvider) {
        this.storageProvider = storageProvider;
    }

    @Override
    public void bind(InetSocketAddress address) {
        bootstrap.bind(address);
    }

    synchronized void verifyAndSetData(SignedBlob blob) throws Exception {
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

    synchronized Optional<SignedBlob> getData() throws IOException {
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
    public void close() throws Exception {
        bootstrap.group().close();
        bootstrap.childGroup().close();
    }

    private class Cleaner extends ChannelHandlerAdapter {
        boolean eof = false;

        @Override
        public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
            ctx.write(msg, promise);
            if (msg instanceof LastHttpContent) {
                eof = true;
            }
        }

        @Override
        public void flush(ChannelHandlerContext ctx) throws Exception {
            ctx.flush();
            if (eof) {
                ChannelPipeline pipeline = ctx.pipeline();
                // clear out the pipeline until this handler
                while (pipeline.last() != this) {
                    pipeline.removeLast();
                }
                eof = false;
            }
        }
    }

    private class Dispatcher extends SimpleChannelInboundHandler<HttpRequest> {
        @Override
        protected void messageReceived(ChannelHandlerContext ctx, HttpRequest msg)
                throws Exception {
            if (msg.uri().equals("/db")) {
                if (msg.method().equals(HttpMethod.GET)) {
                    ctx.pipeline().addLast(new GetBlobRequestHandler(PasswordServerImpl.this));
                    ctx.fireChannelRead(msg);
                    return;
                }
                if (msg.method().equals(HttpMethod.POST)) {
                    ctx.pipeline().addLast(new SetBlobRequestHandler(PasswordServerImpl.this));
                    ctx.fireChannelRead(msg);
                    return;
                }
            } else if (msg.uri().equals("/challenge")) {
                if (msg.method().equals(HttpMethod.GET)) {
                    ctx.pipeline().addLast(new GetChallengeRequestHandler(PasswordServerImpl.this));
                    ctx.fireChannelRead(msg);
                    return;
                }
            }

            ctx.channel().write(new DefaultFullHttpResponse(msg.protocolVersion(), HttpResponseStatus.NOT_FOUND))
                    .addListener(ExceptionForwardingFutureListener.create(ctx));
            ctx.channel().flush();
            ctx.channel().disconnect();
        }
    }
}
