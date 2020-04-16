package com.nccgroup.loggerplusplus.util;

import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

public class NamedThreadFactory implements ThreadFactory {

    private final String name;
    private final AtomicInteger atomicInteger;

    public NamedThreadFactory(String name){
        this.name = name;
        this.atomicInteger = new AtomicInteger(0);
    }

    @Override
    public Thread newThread(Runnable r) {
        return new Thread(r, String.format("%s-Thread-%d", this.name, this.atomicInteger.incrementAndGet()));
    }
}
