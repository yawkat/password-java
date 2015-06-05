package at.yawk.password.server;

import at.yawk.password.model.SignedBlob;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author yawkat
 */
class SignatureVerifier extends SimpleChannelInboundHandler<SignedBlob> {
    @Override
    protected void messageReceived(ChannelHandlerContext ctx, SignedBlob msg) throws Exception {
        System.out.println("Verify " + msg);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(msg.getKey());
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);
        Signature signature = Signature.getInstance("SHA512withRSA");
        signature.initVerify(publicKey);
        signature.update(msg.getBody());
        if (!signature.verify(msg.getSignature())) {
            throw new Exception("Invalid signature");
        }
        ctx.fireChannelRead(msg);
    }
}
