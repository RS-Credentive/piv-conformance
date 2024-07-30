module gov.gsa.pivconformance.cardlib {
    exports gov.gsa.pivconformance.cardlib.card.client;
    exports gov.gsa.pivconformance.cardlib.tlv;
    exports gov.gsa.pivconformance.cardlib.tools;
    exports gov.gsa.pivconformance.cardlib.utils;
    exports org.apache.commons.cli;

    requires org.apache.commons.codec;
    requires org.slf4j;
    requires java.smartcardio;
    requires org.bouncycastle.pkix;
    requires org.bouncycastle.provider;
    requires java.sql;
}