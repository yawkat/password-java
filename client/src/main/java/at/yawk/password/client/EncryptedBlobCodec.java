package at.yawk.password.client;

import at.yawk.password.model.EncryptedBlob;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageCodec;
import java.util.List;

/**
 * @author yawkat
 */
class EncryptedBlobCodec extends ByteToMessageCodec<EncryptedBlob> {
    @Override
    protected void encode(ChannelHandlerContext ctx, EncryptedBlob msg, ByteBuf out) throws Exception {
        msg.write(out);
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out)
            throws Exception {
        EncryptedBlob encryptedBlob = new EncryptedBlob();
        if (encryptedBlob.read(in)) {
            out.add(encryptedBlob);
        }
    }
}
