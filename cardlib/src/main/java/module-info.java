module gov.gsa.pivconformance.cardlib {
    exports gov.gsa.pivconformance.cardlib.card.client;
    exports gov.gsa.pivconformance.cardlib.tlv;
    exports gov.gsa.pivconformance.cardlib.tools;
    exports gov.gsa.pivconformance.cardlib.utils;

    requires org.apache.commons.codec;
    requires org.apache.commons.cli;
    requires org.slf4j;
    requires java.smartcardio;
    requires org.bouncycastle.pkix;
    requires org.bouncycastle.provider;
    requires java.sql;
}