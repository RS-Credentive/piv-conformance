module gov.gsa.pivconformance.cardlib {
    exports gov.gsa.pivconformance.cardlib.card.client;
    exports gov.gsa.pivconformance.cardlib.tlv;
    exports gov.gsa.pivconformance.cardlib.tools;
    exports gov.gsa.pivconformance.cardlib.utils;

    requires org.apache.commons.codec;
    requires commons.cli;
    requires org.slf4j;
    requires transitive java.smartcardio;
    requires transitive org.bouncycastle.pkix;
    requires transitive org.bouncycastle.provider;
    requires java.sql;
}