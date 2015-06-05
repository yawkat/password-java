package at.yawk.password.server;

import at.yawk.password.ExceptionForwardingFutureListener;
import at.yawk.password.HttpByteCodec;
import at.yawk.password.SignedBlobCodec;
import at.yawk.password.model.SignedBlob;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerAppender;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.*;
import java.util.Optional;
import lombok.RequiredArgsConstructor;

/**
 * @author yawkat
 */
@RequiredArgsConstructor
class GetBlobRequestHandler extends ChannelHandlerAppender {
    private final PasswordServerImpl server;
    private HttpVersion protocolVersion;

    {
        add(new HttpByteCodec());
        add(new SimpleChannelInboundHandler<HttpObject>() {
            @Override
            protected void messageReceived(ChannelHandlerContext ctx, HttpObject msg) throws Exception {
                if (msg instanceof HttpRequest) {
                    protocolVersion = ((HttpRequest) msg).protocolVersion();
                }
                if (msg instanceof LastHttpContent) {
                    Channel ch = ctx.channel();

                    // write response
                    Optional<SignedBlob> data = server.getData();
                    if (data.isPresent()) {
                        DefaultHttpResponse response = new DefaultHttpResponse(protocolVersion, HttpResponseStatus.OK);
                        response.headers().add("Transfer-Encoding", "Chunked");
                        ExceptionForwardingFutureListener.write(
                                ch, response);
                        // we just write the encrypted blob directly without using the codec and such
                        ExceptionForwardingFutureListener.write(
                                ch, Unpooled.wrappedBuffer(data.get().getBody()));
                    } else {
                        ExceptionForwardingFutureListener.write(
                                ch, new DefaultFullHttpResponse(protocolVersion, HttpResponseStatus.NOT_FOUND));
                    }
                    ch.flush();
                }
            }
        });
    }
}
