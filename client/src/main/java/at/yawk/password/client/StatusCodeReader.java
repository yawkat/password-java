package at.yawk.password.client;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageDecoder;
import io.netty.handler.codec.http.HttpResponse;
import java.util.List;

/**
 * @author yawkat
 */
class StatusCodeReader extends MessageToMessageDecoder<HttpResponse> {
    @Override
    protected void decode(ChannelHandlerContext ctx, HttpResponse msg, List<Object> out)
            throws Exception {
        switch (msg.status().code()) {
        case 200:
            break;
        case 404:
            out.add(PasswordClient.SIGNAL_NO_ENTRY);
            break;
        default:
            throw new Exception("Invalid status: " + msg.status());
        }
    }
}
