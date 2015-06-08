package at.yawk.password.server;

import at.yawk.password.ExceptionForwardingFutureListener;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.*;
import lombok.RequiredArgsConstructor;

/**
 * @author yawkat
 */
@RequiredArgsConstructor
class GetChallengeRequestHandler extends SimpleChannelInboundHandler<HttpObject> {
    private final PasswordServerImpl server;
    private HttpVersion protocolVersion;

    @Override
    protected void messageReceived(ChannelHandlerContext ctx, HttpObject msg) throws Exception {
        if (msg instanceof HttpRequest) {
            protocolVersion = ((HttpRequest) msg).protocolVersion();
        }
        if (msg instanceof LastHttpContent) {
            byte[] challenge = server.challengeManager.generateAndAddChallenge();
            DefaultFullHttpResponse response = new DefaultFullHttpResponse(
                    protocolVersion, HttpResponseStatus.OK, Unpooled.wrappedBuffer(challenge));
            response.headers().add("Content-Length", String.valueOf(challenge.length));
            ExceptionForwardingFutureListener.write(ctx.channel(), response);
            ctx.channel().flush();
        }
    }
}
