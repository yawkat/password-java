package at.yawk.password;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerAdapter;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.http.DefaultHttpContent;
import io.netty.handler.codec.http.HttpContent;

/**
 * @author yawkat
 */
public class HttpByteCodec extends ChannelHandlerAdapter {
    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        if (msg instanceof ByteBuf) {
            System.out.println("Sending " + ((ByteBuf) msg).toString(HexCharset.getInstance()));
            ctx.write(new DefaultHttpContent((ByteBuf) msg), promise);
        } else {
            ctx.write(msg, promise);
        }
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (msg instanceof HttpContent && ((HttpContent) msg).content().isReadable()) {
            // we re-fire http content too for headers and such
            ctx.write(((HttpContent) msg).retain());
            System.out.println("Received " + ((HttpContent) msg).content().toString(HexCharset.getInstance()));
            ctx.fireChannelRead(((HttpContent) msg).content());
        } else {
            ctx.fireChannelRead(msg);
        }
    }
}
