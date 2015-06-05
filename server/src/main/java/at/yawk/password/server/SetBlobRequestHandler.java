package at.yawk.password.server;

import at.yawk.password.ExceptionForwardingFutureListener;
import at.yawk.password.HttpByteCodec;
import at.yawk.password.SignedBlobCodec;
import at.yawk.password.model.SignedBlob;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerAppender;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.*;
import lombok.RequiredArgsConstructor;

/**
 * @author yawkat
 */
@RequiredArgsConstructor
class SetBlobRequestHandler extends ChannelHandlerAppender {
    private final PasswordServerImpl server;

    private HttpVersion protocolVersion;
    private boolean readComplete = false;

    {
        add(new HttpByteCodec());
        add(new SignedBlobCodec());
        add(new SignatureVerifier());
        add(new SimpleChannelInboundHandler<Object>() {
            @Override
            protected void messageReceived(ChannelHandlerContext ctx, Object msg) throws Exception {
                Channel ch = ctx.channel();

                if (msg instanceof HttpRequest) {
                    protocolVersion = ((HttpRequest) msg).protocolVersion();
                }
                if (msg instanceof SignedBlob) {
                    readComplete = true;
                    try {
                        server.verifyAndSetData((SignedBlob) msg);
                        ExceptionForwardingFutureListener.write(
                                ch, new DefaultFullHttpResponse(protocolVersion, HttpResponseStatus.OK));
                    } catch (Exception e) {
                        ExceptionForwardingFutureListener.write(ch, new DefaultFullHttpResponse(
                                protocolVersion, HttpResponseStatus.INTERNAL_SERVER_ERROR));
                    }
                    ch.flush();
                }
                if (msg instanceof LastHttpContent) {
                    if (!readComplete) {
                        ExceptionForwardingFutureListener.write(
                                ch, new DefaultFullHttpResponse(protocolVersion, HttpResponseStatus.BAD_REQUEST));
                        ch.flush();
                    }
                }
            }
        });
    }
}
