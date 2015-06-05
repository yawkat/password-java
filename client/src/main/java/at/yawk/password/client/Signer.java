package at.yawk.password.client;

import at.yawk.password.Encoding;
import at.yawk.password.model.EncryptedBlob;
import at.yawk.password.model.SignedBlob;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageEncoder;
import java.security.KeyPair;
import java.security.Signature;
import java.util.List;
import lombok.RequiredArgsConstructor;

/**
 * @author yawkat
 */
@RequiredArgsConstructor
class Signer extends MessageToMessageEncoder<EncryptedBlob> {
    private final KeyPair keyPair;

    @Override
    protected void encode(ChannelHandlerContext ctx, EncryptedBlob msg, List<Object> out) throws Exception {
        System.out.println("Signing " + msg);

        ByteBuf bodyBuf = Unpooled.buffer();
        msg.write(bodyBuf);
        byte[] body = Encoding.toByteArray(bodyBuf);

        Signature signature = Signature.getInstance("SHA512withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(body);

        SignedBlob signedBlob = new SignedBlob();
        signedBlob.setKey(keyPair.getPublic().getEncoded()); // we assume this always returns DER
        signedBlob.setSignature(signature.sign());
        signedBlob.setBody(body);
        out.add(signedBlob);
    }
}
