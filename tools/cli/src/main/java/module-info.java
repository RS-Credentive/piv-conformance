module gov.gsa.pivconformance.tools.cli {
    requires gov.gsa.pivconformance.cardlib;
    requires gov.gsa.pivconformance.conformancelib;

    requires java.smartcardio;
    requires java.sql;
    requires org.slf4j;
    requires org.apache.commons.codec;
    requires org.bouncycastle.pkix;
    requires org.bouncycastle.provider;
    requires org.junit.platform.commons;
    requires org.junit.platform.engine;
    requires org.junit.platform.launcher;
    requires ch.qos.logback.classic;
    requires ch.qos.logback.core;
}
