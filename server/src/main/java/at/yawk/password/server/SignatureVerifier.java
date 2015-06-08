package at.yawk.password.server;

import at.yawk.password.model.SignedBlob;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import java.security.GeneralSecurityException;
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
        if (!verify(msg.getKey(), msg.getBody(), msg.getSignature())) {
            throw new Exception("Invalid signature");
        }
        ctx.fireChannelRead(msg);
    }

    static boolean verify(byte[] key, byte[] data, byte[] signature) throws GeneralSecurityException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);
        Signature verifier = Signature.getInstance("SHA512withRSA");
        verifier.initVerify(publicKey);
        verifier.update(data);
        return verifier.verify(signature);
    }
}
