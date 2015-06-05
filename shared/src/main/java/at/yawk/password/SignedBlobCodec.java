package at.yawk.password;

import at.yawk.password.model.SignedBlob;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageCodec;
import java.util.List;

/**
 * @author yawkat
 */
public class SignedBlobCodec extends ByteToMessageCodec<SignedBlob> {
    @Override
    protected void encode(ChannelHandlerContext ctx, SignedBlob msg, ByteBuf out) throws Exception {
        msg.write(out);
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out)
            throws Exception {
        SignedBlob signedBlob = new SignedBlob();
        if (signedBlob.read(in)) {
            out.add(signedBlob);
        }
    }
}
