package at.yawk.password;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.GenericFutureListener;

/**
 * @author yawkat
 */
public abstract class ExceptionForwardingFutureListener implements GenericFutureListener<Future<Void>> {
    public static ExceptionForwardingFutureListener create(ChannelHandlerContext ctx) {
        return new ExceptionForwardingFutureListener() {
            @Override
            protected void fire(Throwable exception) {
                ctx.fireExceptionCaught(exception);
            }
        };
    }

    public static ExceptionForwardingFutureListener create(Channel ch) {
        return new ExceptionForwardingFutureListener() {
            @Override
            protected void fire(Throwable exception) {
                ch.pipeline().fireExceptionCaught(exception);
            }
        };
    }

    public static void write(Channel channel, Object obj) {
        channel.write(obj).addListener(create(channel));
    }

    private ExceptionForwardingFutureListener() {}

    @Override
    public void operationComplete(Future<Void> future) throws Exception {
        if (!future.isSuccess()) {
            fire(future.cause());
        }
    }

    protected abstract void fire(Throwable exception);
}
