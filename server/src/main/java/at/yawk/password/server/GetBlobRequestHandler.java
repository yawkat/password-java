package at.yawk.password.server;

import at.yawk.password.ExceptionForwardingFutureListener;
import at.yawk.password.model.SignedBlob;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerAppender;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.*;
import java.security.GeneralSecurityException;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.bind.DatatypeConverter;
import lombok.RequiredArgsConstructor;

/**
 * @author yawkat
 */
@RequiredArgsConstructor
class GetBlobRequestHandler extends ChannelHandlerAppender {
    private static final Pattern AUTHORIZATION_HEADER_PATTERN = Pattern.compile("Signature ([0-9a-f]+) ([0-9a-f]+)",
                                                                                Pattern.CASE_INSENSITIVE);

    private final PasswordServerImpl server;
    private HttpVersion protocolVersion;

    {
        add(new SimpleChannelInboundHandler<HttpObject>() {
            boolean authorized = false;

            @Override
            protected void messageReceived(ChannelHandlerContext ctx, HttpObject msg) throws Exception {
                if (msg instanceof HttpRequest) {
                    HttpRequest req = (HttpRequest) msg;
                    protocolVersion = req.protocolVersion();
                    Optional<SignedBlob> data = server.getData();
                    if (data.isPresent()) { // only require auth if we have data already
                        if (!checkAuthorization(req, data.get())) {
                            sendError(ctx.channel(), HttpResponseStatus.FORBIDDEN);
                            return;
                        }
                    }
                    authorized = true;
                }
                if (msg instanceof LastHttpContent) {
                    if (!authorized) {
                        throw new AssertionError();
                    }
                    authorized = false;

                    Channel ch = ctx.channel();

                    // write response
                    Optional<SignedBlob> data = server.getData();
                    if (data.isPresent()) {
                        // we just write the encrypted blob directly without using the codec and such
                        byte[] body = data.get().getBody();
                        DefaultHttpResponse response = new DefaultFullHttpResponse(
                                protocolVersion, HttpResponseStatus.OK, Unpooled.wrappedBuffer(body));
                        response.headers().add("Content-Length", String.valueOf(body.length));
                        ExceptionForwardingFutureListener.write(ch, response);
                        ch.flush();
                    } else {
                        sendError(ch, HttpResponseStatus.NOT_FOUND);
                    }
                }
            }

            private boolean checkAuthorization(HttpRequest req, SignedBlob signedBlob)
                    throws GeneralSecurityException {
                CharSequence authorizationHeader = req.headers().get("Authorization");
                if (authorizationHeader == null) {
                    return false;
                }
                Matcher matcher = AUTHORIZATION_HEADER_PATTERN.matcher(authorizationHeader);
                if (!matcher.matches()) {
                    return false;
                }
                byte[] challenge = DatatypeConverter.parseHexBinary(matcher.group(1));
                byte[] signature = DatatypeConverter.parseHexBinary(matcher.group(2));

                if (!server.challengeManager.removeChallenge(challenge)) {
                    return false;
                }

                return SignatureVerifier.verify(signedBlob.getKey(), challenge, signature);
            }

            private void sendError(Channel ch, HttpResponseStatus status) {
                ExceptionForwardingFutureListener.write(ch, new DefaultFullHttpResponse(protocolVersion, status));
                ch.flush();
            }
        });
    }
}
