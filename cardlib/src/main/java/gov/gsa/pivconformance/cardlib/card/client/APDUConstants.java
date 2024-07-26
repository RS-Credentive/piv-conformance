package gov.gsa.pivconformance.cardlib.card.client;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

// TODO: REMOVE
// import org.slf4j.Logger;
// import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.HashMap;
import java.lang.reflect.Field;

/**
 * Helper class that contains helper variables and functions for APDU generation
 *
 */
public class APDUConstants {
        // TODO: REMOVE
        // private static final Logger s_logger =
        // LoggerFactory.getLogger(APDUConstants.class);

        // public static final String DEFAULTHASHALG = "SHA-256";
        public static final byte COMMAND = 0x00;
        public static final byte COMMAND_CC = 0x10;
        public static final byte SELECT = (byte) 0xa4;
        public static final byte GENERATE = (byte) 0x47;
        public static final byte GENERAL_AUTHENTICATE = (byte) 0x87;
        public static final byte GET = (byte) 0xcb;
        public static final byte VERIFY = 0x20;
        public static final byte SM = (byte) 0x87;
        public static final byte INS_DB = (byte) 0xDB;
        public static final byte P1_3F = 0x3F;
        public static final byte P2_FF = (byte) 0xFF;
        public static final byte[] PIV_APPID = { (byte) 0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01,
                        0x00 };

        public static final byte[] DATA = { 0x53 };

        public static final int SUCCESSFUL_EXEC = 0x9000;

        public static final int CIPHER_SUITE_1 = 0x27;
        public static final int CIPHER_SUITE_2 = 0x2E;

        public static final byte PIV_SECURE_MESSAGING_KEY = 0x04;
        public static final byte PIV_AUTHENTICATION_KEY = (byte) 0x9A;
        public static final byte PIV_CARD_APPLICATION_ADMINISTRATION_KEY = (byte) 0x9B;
        public static final byte DIGITAL_SIGNATURE_KEY = (byte) 0x9C;
        public static final byte KEY_MANAGEMENT_KEY = (byte) 0x9D;
        public static final byte KEY_AUTHENTICATION_KEY = (byte) 0x9D;
        public static final byte RETIRED_KEY_MANAGEMENT_KEY = (byte) 0x82;

        public static final byte CRYPTO_MECHANISM_RSA = 0x07;
        public static final byte CRYPTO_MECHANISM_ECC_P286 = 0x11;
        public static final byte CRYPTO_MECHANISM_ECC_P384 = 0x14;

        public static final byte CONTROL_REFERENCE_TEMPLATE_TAG = (byte) 0xAC;

        public static final int APP_NOT_FOUND = 0x6A82;
        public static final int SECURITY_STATUS_NOT_SATISFIED = 0x6982;
        public static final int INCORREECT_PARAMETER = 0x6A80;
        public static final int FUNCTION_NOT_SUPPORTED = 0x6A81;
        public static final int INCORREECT_PARAMETER_P2 = 0x6A86;

        public static final String CARD_CAPABILITY_CONTAINER_OID = "2.16.840.1.101.3.7.1.219.0";
        public static final byte[] CARD_CAPABILITY_CONTAINER_TAG = { 0x5F, (byte) 0xC1, 0x07 };
        public static final int CARD_CAPABILITY_CONTAINER_ID = 0xDB00;
        public static final String CARD_CAPABILITY_CONTAINER_NAME = "Card Capability Container";

        public static final String CARD_HOLDER_UNIQUE_IDENTIFIER_OID = "2.16.840.1.101.3.7.2.48.0";
        public static final byte[] CARD_HOLDER_UNIQUE_IDENTIFIER_TAG = { 0x5F, (byte) 0xC1, 0x02 };
        public static final int CARD_HOLDER_UNIQUE_IDENTIFIER_ID = 0x3000;
        public static final String CARD_HOLDER_UNIQUE_IDENTIFIER_NAME = "Card Holder Unique Identifier";

        public static final String X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID = "2.16.840.1.101.3.7.2.1.1";
        public static final byte[] X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_TAG = { 0x5F, (byte) 0xC1, 0x05 };
        public static final int X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_ID = 0x0101;
        public static final String X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_NAME = "X.509 Certificate for PIV Authentication";

        public static final String CARDHOLDER_FINGERPRINTS_OID = "2.16.840.1.101.3.7.2.96.16";
        public static final byte[] CARDHOLDER_FINGERPRINTS_TAG = { 0x5F, (byte) 0xC1, 0x03 };
        public static final int CARDHOLDER_FINGERPRINTS_ID = 0x6010;
        public static final String CARDHOLDER_FINGERPRINTS_NAME = "Cardholder Fingerprints";

        public static final String SECURITY_OBJECT_OID = "2.16.840.1.101.3.7.2.144.0";
        public static final byte[] SECURITY_OBJECT_TAG = { 0x5F, (byte) 0xC1, 0x06 };
        public static final int SECURITY_OBJECT_ID = 0x9000;
        public static final String SECURITY_OBJECT_NAME = "Security Object";

        public static final String CARDHOLDER_FACIAL_IMAGE_OID = "2.16.840.1.101.3.7.2.96.48";
        public static final byte[] CARDHOLDER_FACIAL_IMAGE_TAG = { 0x5F, (byte) 0xC1, 0x08 };
        public static final int CARDHOLDER_FACIAL_IMAGE_ID = 0x6030;
        public static final String CARDHOLDER_FACIAL_IMAGE_NAME = "Cardholder Facial Image";

        public static final String X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID = "2.16.840.1.101.3.7.2.5.0";
        public static final byte[] X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_TAG = { 0x5F, (byte) 0xC1, 0x01 };
        public static final int X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_ID = 0x0500;
        public static final String X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_NAME = "X.509 Certificate for Card Authentication";

        public static final String X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID = "2.16.840.1.101.3.7.2.1.0";
        public static final byte[] X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_TAG = { 0x5F, (byte) 0xC1, 0x0A };
        public static final int X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_ID = 0x0100;
        public static final String X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_NAME = "X.509 Certificate for Digital Signature";

        public static final String X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID = "2.16.840.1.101.3.7.2.1.2";
        public static final byte[] X509_CERTIFICATE_FOR_KEY_MANAGEMENT_TAG = { 0x5F, (byte) 0xC1, 0x0B };
        public static final int X509_CERTIFICATE_FOR_KEY_MANAGEMENT_ID = 0x0102;
        public static final String X509_CERTIFICATE_FOR_KEY_MANAGEMENT_NAME = "X.509 Certificate for Key Management";

        public static final String PRINTED_INFORMATION_OID = "2.16.840.1.101.3.7.2.48.1";
        public static final byte[] PRINTED_INFORMATION_TAG = { 0x5F, (byte) 0xC1, 0x09 };
        public static final int PRINTED_INFORMATION_ID = 0x3001;
        public static final String PRINTED_INFORMATION_NAME = "Printed Information";

        public static final String DISCOVERY_OBJECT_OID = "2.16.840.1.101.3.7.2.96.80";
        public static final byte[] DISCOVERY_OBJECT_TAG = { 0x7E };
        public static final int DISCOVERY_OBJECT_ID = 0x6050;
        public static final String DISCOVERY_OBJECT_NAME = "Discovery Object";

        public static final String KEY_HISTORY_OBJECT_OID = "2.16.840.1.101.3.7.2.96.96";
        public static final byte[] KEY_HISTORY_OBJECT_TAG = { 0x5F, (byte) 0xC1, 0x0C };
        public static final int KEY_HISTORY_OBJECT_ID = 0x6060;
        public static final String KEY_HISTORY_OBJECT_NAME = "Key History Object";

        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_1_OID = "2.16.840.1.101.3.7.2.16.1";
        public static final byte[] RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_1_TAG = { 0x5F, (byte) 0xC1, 0x0D };
        public static final int RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_1_ID = 0x1001;
        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_1_NAME = "Retired X.509 Certificate for Key Management 1";

        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_2_OID = "2.16.840.1.101.3.7.2.16.2";
        public static final byte[] RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_2_TAG = { 0x5F, (byte) 0xC1, 0x0E };
        public static final int RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_2_ID = 0x1002;
        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_2_NAME = "Retired X.509 Certificate for Key Management 2";

        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_3_OID = "2.16.840.1.101.3.7.2.16.3";
        public static final byte[] RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_3_TAG = { 0x5F, (byte) 0xC1, 0x0F };
        public static final int RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_3_ID = 0x1003;
        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_3_NAME = "Retired X.509 Certificate for Key Management 3";

        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_4_OID = "2.16.840.1.101.3.7.2.16.4";
        public static final byte[] RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_4_TAG = { 0x5F, (byte) 0xC1, 0x10 };
        public static final int RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_4_ID = 0x1004;
        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_4_NAME = "Retired X.509 Certificate for Key Management 4";

        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_5_OID = "2.16.850.1.101.3.7.2.16.5";
        public static final byte[] RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_5_TAG = { 0x5F, (byte) 0xC1, 0x11 };
        public static final int RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_5_ID = 0x1005;
        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_5_NAME = "Retired X.509 Certificate for Key Management 5";

        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_6_OID = "2.16.860.1.101.3.7.2.16.6";
        public static final byte[] RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_6_TAG = { 0x5F, (byte) 0xC1, 0x12 };
        public static final int RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_6_ID = 0x1006;
        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_6_NAME = "Retired X.509 Certificate for Key Management 6";

        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_7_OID = "2.16.870.1.101.3.7.2.16.7";
        public static final byte[] RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_7_TAG = { 0x5F, (byte) 0xC1, 0x13 };
        public static final int RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_7_ID = 0x1007;
        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_7_NAME = "Retired X.509 Certificate for Key Management 7";

        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_8_OID = "2.16.880.1.101.3.7.2.16.8";
        public static final byte[] RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_8_TAG = { 0x5F, (byte) 0xC1, 0x14 };
        public static final int RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_8_ID = 0x1008;
        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_8_NAME = "Retired X.509 Certificate for Key Management 8";

        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_9_OID = "2.16.890.1.101.3.7.2.16.9";
        public static final byte[] RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_9_TAG = { 0x5F, (byte) 0xC1, 0x15 };
        public static final int RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_9_ID = 0x1009;
        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_9_NAME = "Retired X.509 Certificate for Key Management 9";

        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_10_OID = "2.16.8100.1.101.3.7.2.16.10";
        public static final byte[] RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_10_TAG = { 0x5F, (byte) 0xC1, 0x16 };
        public static final int RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_10_ID = 0x10010;
        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_10_NAME = "Retired X.509 Certificate for Key Management 10";

        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_11_OID = "2.16.840.1.101.3.7.2.16.11";
        public static final byte[] RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_11_TAG = { 0x5F, (byte) 0xC1, 0x17 };
        public static final int RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_11_ID = 0x1011;
        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_11_NAME = "Retired X.509 Certificate for Key Management 11";

        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_12_OID = "2.16.840.1.101.3.7.2.16.12";
        public static final byte[] RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_12_TAG = { 0x5F, (byte) 0xC1, 0x18 };
        public static final int RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_12_ID = 0x1012;
        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_12_NAME = "Retired X.509 Certificate for Key Management 12";

        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_13_OID = "2.16.840.1.101.3.7.2.16.13";
        public static final byte[] RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_13_TAG = { 0x5F, (byte) 0xC1, 0x13 };
        public static final int RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_13_ID = 0x1013;
        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_13_NAME = "Retired X.509 Certificate for Key Management 13";

        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_14_OID = "2.16.840.1.101.3.7.2.16.14";
        public static final byte[] RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_14_TAG = { 0x5F, (byte) 0xC1, 0x1a };
        public static final int RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_14_ID = 0x1014;
        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_14_NAME = "Retired X.509 Certificate for Key Management 14";

        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_15_OID = "2.16.850.1.101.3.7.2.16.15";
        public static final byte[] RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_15_TAG = { 0x5F, (byte) 0xC1, 0x15 };
        public static final int RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_15_ID = 0x1015;
        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_15_NAME = "Retired X.509 Certificate for Key Management 15";

        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_16_OID = "2.16.860.1.101.3.7.2.16.16";
        public static final byte[] RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_16_TAG = { 0x5F, (byte) 0xC1, 0x1c };
        public static final int RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_16_ID = 0x1016;
        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_16_NAME = "Retired X.509 Certificate for Key Management 16";

        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_17_OID = "2.16.870.1.101.3.7.2.16.17";
        public static final byte[] RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_17_TAG = { 0x5F, (byte) 0xC1, 0x1d };
        public static final int RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_17_ID = 0x1017;
        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_17_NAME = "Retired X.509 Certificate for Key Management 17";

        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_18_OID = "2.16.880.1.101.3.7.2.16.18";
        public static final byte[] RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_18_TAG = { 0x5F, (byte) 0xC1, 0x1e };
        public static final int RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_18_ID = 0x1018;
        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_18_NAME = "Retired X.509 Certificate for Key Management 18";

        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_19_OID = "2.16.890.1.101.3.7.2.16.19";
        public static final byte[] RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_19_TAG = { 0x5F, (byte) 0xC1, 0x1f };
        public static final int RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_19_ID = 0x1019;
        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_19_NAME = "Retired X.509 Certificate for Key Management 19";

        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_20_OID = "2.16.8100.1.101.3.7.2.16.20";
        public static final byte[] RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_20_TAG = { 0x5F, (byte) 0xC1, 0x20 };
        public static final int RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_20_ID = 0x10110;
        public static final String RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_20_NAME = "Retired X.509 Certificate for Key Management 20";

        public static final String CARDHOLDER_IRIS_IMAGES_OID = "2.16.840.1.101.3.7.2.16.21";
        public static final byte[] CARDHOLDER_IRIS_IMAGES_TAG = { 0x5F, (byte) 0xC1, 0x21 };
        public static final int CARDHOLDER_IRIS_IMAGES_ID = 0x1015;
        public static final String CARDHOLDER_IRIS_IMAGES_NAME = "Cardholder Iris Images";

        public static final String BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_OID = "2.16.840.1.101.3.7.2.16.22";
        public static final byte[] BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_TAG = { 0x7F, 0x61 };
        public static final int BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_ID = 0x1016;
        public static final String BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_NAME = "Biometric Information Templates Group Template";

        public static final String SECURE_MESSAGING_CERTIFICATE_SIGNER_OID = "2.16.840.1.101.3.7.2.16.23";
        public static final byte[] SECURE_MESSAGING_CERTIFICATE_SIGNER_TAG = { 0x5F, (byte) 0xC1, 0x22 };
        public static final int SECURE_MESSAGING_CERTIFICATE_SIGNER_ID = 0x1017;
        public static final String SECURE_MESSAGING_CERTIFICATE_SIGNER_NAME = "Secure Messaging Certificate Signer";

        public static final String PAIRING_CODE_REFERENCE_DATA_CONTAINER_OID = "2.16.840.1.101.3.7.2.16.24";
        public static final byte[] PAIRING_CODE_REFERENCE_DATA_CONTAINER_TAG = { 0x5F, (byte) 0xC1, 0x23 };
        public static final int PAIRING_CODE_REFERENCE_DATA_CONTAINER_ID = 0x1018;
        public static final String PAIRING_CODE_REFERENCE_DATA_CONTAINER_NAME = "Pairing Code Reference Data Container";

        // Key reference IDs
        public static final int PIV_SECURE_MESSAGING_KEY_ID = 0x04;
        public static final int PIV_AUTHENTICATION_KEY_ID = 0x9A;
        public static final int PIV_CARD_APPLICATION_ADMINISTRATION_KEY_ID = 0x9B;
        public static final int DIGITAL_SIGNATURE_KEY_ID = 0x9C;
        public static final int KEY_MANAGEMENT_KEY_ID = 0x9D;
        public static final int CARD_AUTHENTICATION_KEY_ID = 0x9E;
        public static final int RETIRED_KEY_MANAGEMENT_KEY_ID_1 = 0x82;
        public static final int RETIRED_KEY_MANAGEMENT_KEY_ID_2 = 0x83;
        public static final int RETIRED_KEY_MANAGEMENT_KEY_ID_3 = 0x84;
        public static final int RETIRED_KEY_MANAGEMENT_KEY_ID_4 = 0x85;
        public static final int RETIRED_KEY_MANAGEMENT_KEY_ID_5 = 0x86;
        public static final int RETIRED_KEY_MANAGEMENT_KEY_ID_6 = 0x87;
        public static final int RETIRED_KEY_MANAGEMENT_KEY_ID_7 = 0x88;
        public static final int RETIRED_KEY_MANAGEMENT_KEY_ID_8 = 0x89;
        public static final int RETIRED_KEY_MANAGEMENT_KEY_ID_9 = 0x8A;
        public static final int RETIRED_KEY_MANAGEMENT_KEY_ID_10 = 0x8B;
        public static final int RETIRED_KEY_MANAGEMENT_KEY_ID_11 = 0x8C;
        public static final int RETIRED_KEY_MANAGEMENT_KEY_ID_12 = 0x8D;
        public static final int RETIRED_KEY_MANAGEMENT_KEY_ID_13 = 0x8E;
        public static final int RETIRED_KEY_MANAGEMENT_KEY_ID_14 = 0x8F;
        public static final int RETIRED_KEY_MANAGEMENT_KEY_ID_15 = 0x90;
        public static final int RETIRED_KEY_MANAGEMENT_KEY_ID_16 = 0x91;
        public static final int RETIRED_KEY_MANAGEMENT_KEY_ID_17 = 0x92;
        public static final int RETIRED_KEY_MANAGEMENT_KEY_ID_18 = 0x93;
        public static final int RETIRED_KEY_MANAGEMENT_KEY_ID_19 = 0x94;
        public static final int RETIRED_KEY_MANAGEMENT_KEY_ID_20 = 0x95;

        public static final HashMap<String, String> containerOidToNameMap = new HashMap<String, String>() {
                private static final long serialVersionUID = 1L;
                {
                        put("2.16.840.1.101.3.7.1.219.0", "CARD_CAPABILITY_CONTAINER_OID");
                        put("2.16.840.1.101.3.7.2.48.0", "CARD_HOLDER_UNIQUE_IDENTIFIER_OID");
                        put("2.16.840.1.101.3.7.2.1.1", "X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID");
                        put("2.16.840.1.101.3.7.2.96.16", "CARDHOLDER_FINGERPRINTS_OID");
                        put("2.16.840.1.101.3.7.2.144.0", "SECURITY_OBJECT_OID");
                        put("2.16.840.1.101.3.7.2.96.48", "CARDHOLDER_FACIAL_IMAGE_OID");
                        put("2.16.840.1.101.3.7.2.5.0", "X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID");
                        put("2.16.840.1.101.3.7.2.1.0", "X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID");
                        put("2.16.840.1.101.3.7.2.1.2", "X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID");
                        put("2.16.840.1.101.3.7.2.48.1", "PRINTED_INFORMATION_OID");
                        put("2.16.840.1.101.3.7.2.96.80", "DISCOVERY_OBJECT_OID");
                        put("2.16.840.1.101.3.7.2.96.96", "KEY_HISTORY_OBJECT_OID");
                        put("2.16.840.1.101.3.7.2.16.1", "RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_1_OID");
                        put("2.16.840.1.101.3.7.2.16.2", "RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_2_OID");
                        put("2.16.840.1.101.3.7.2.16.3", "RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_3_OID");
                        put("2.16.840.1.101.3.7.2.16.4", "RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_4_OID");
                        put("2.16.850.1.101.3.7.2.16.5", "RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_5_OID");
                        put("2.16.860.1.101.3.7.2.16.6", "RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_6_OID");
                        put("2.16.870.1.101.3.7.2.16.7", "RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_7_OID");
                        put("2.16.880.1.101.3.7.2.16.8", "RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_8_OID");
                        put("2.16.890.1.101.3.7.2.16.9", "RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_9_OID");
                        put("2.16.8100.1.101.3.7.2.16.10", "RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_10_OID");
                        put("2.16.840.1.101.3.7.2.16.11", "RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_11_OID");
                        put("2.16.840.1.101.3.7.2.16.12", "RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_12_OID");
                        put("2.16.840.1.101.3.7.2.16.13", "RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_13_OID");
                        put("2.16.840.1.101.3.7.2.16.14", "RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_14_OID");
                        put("2.16.850.1.101.3.7.2.16.15", "RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_15_OID");
                        put("2.16.860.1.101.3.7.2.16.16", "RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_16_OID");
                        put("2.16.870.1.101.3.7.2.16.17", "RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_17_OID");
                        put("2.16.880.1.101.3.7.2.16.18", "RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_18_OID");
                        put("2.16.890.1.101.3.7.2.16.19", "RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_19_OID");
                        put("2.16.8100.1.101.3.7.2.16.20", "RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_20_OID");
                        put("2.16.840.1.101.3.7.2.16.21", "CARDHOLDER_IRIS_IMAGES_OID");
                        put("2.16.840.1.101.3.7.2.16.22", "BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_OID");
                        put("2.16.840.1.101.3.7.2.16.23", "SECURE_MESSAGING_CERTIFICATE_SIGNER_OID");
                        put("2.16.840.1.101.3.7.2.16.24", "PAIRING_CODE_REFERENCE_DATA_CONTAINER_OID");
                }
        };

        public static final HashMap<String, String> containerNameToOidMap = new HashMap<String, String>() {
                private static final long serialVersionUID = 1L;
                {
                        put("CARD_CAPABILITY_CONTAINER_OID", "2.16.840.1.101.3.7.1.219.0");
                        put("CARD_HOLDER_UNIQUE_IDENTIFIER_OID", "2.16.840.1.101.3.7.2.48.0");
                        put("X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID", "2.16.840.1.101.3.7.2.1.1");
                        put("CARDHOLDER_FINGERPRINTS_OID", "2.16.840.1.101.3.7.2.96.16");
                        put("SECURITY_OBJECT_OID", "2.16.840.1.101.3.7.2.144.0");
                        put("CARDHOLDER_FACIAL_IMAGE_OID", "2.16.840.1.101.3.7.2.96.48");
                        put("X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID", "2.16.840.1.101.3.7.2.5.0");
                        put("X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID", "2.16.840.1.101.3.7.2.1.0");
                        put("X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID", "2.16.840.1.101.3.7.2.1.2");
                        put("PRINTED_INFORMATION_OID", "2.16.840.1.101.3.7.2.48.1");
                        put("DISCOVERY_OBJECT_OID", "2.16.840.1.101.3.7.2.96.80");
                        put("KEY_HISTORY_OBJECT_OID", "2.16.840.1.101.3.7.2.96.96");
                        put("RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_1_OID", "2.16.840.1.101.3.7.2.16.1");
                        put("RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_2_OID", "2.16.840.1.101.3.7.2.16.2");
                        put("RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_3_OID", "2.16.840.1.101.3.7.2.16.3");
                        put("RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_4_OID", "2.16.840.1.101.3.7.2.16.4");
                        put("RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_5_OID", "2.16.850.1.101.3.7.2.16.5");
                        put("RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_6_OID", "2.16.860.1.101.3.7.2.16.6");
                        put("RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_7_OID", "2.16.870.1.101.3.7.2.16.7");
                        put("RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_8_OID", "2.16.880.1.101.3.7.2.16.8");
                        put("RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_9_OID", "2.16.890.1.101.3.7.2.16.9");
                        put("RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_10_OID", "2.16.8100.1.101.3.7.2.16.10");
                        put("RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_11_OID", "2.16.840.1.101.3.7.2.16.11");
                        put("RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_12_OID", "2.16.840.1.101.3.7.2.16.12");
                        put("RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_13_OID", "2.16.840.1.101.3.7.2.16.13");
                        put("RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_14_OID", "2.16.840.1.101.3.7.2.16.14");
                        put("RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_15_OID", "2.16.850.1.101.3.7.2.16.15");
                        put("RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_16_OID", "2.16.860.1.101.3.7.2.16.16");
                        put("RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_17_OID", "2.16.870.1.101.3.7.2.16.17");
                        put("RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_18_OID", "2.16.880.1.101.3.7.2.16.18");
                        put("RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_19_OID", "2.16.890.1.101.3.7.2.16.19");
                        put("RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_20_OID", "2.16.8100.1.101.3.7.2.16.20");
                        put("CARDHOLDER_IRIS_IMAGES_OID", "2.16.840.1.101.3.7.2.16.21");
                        put("BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_OID", "2.16.840.1.101.3.7.2.16.22");
                        put("SECURE_MESSAGING_CERTIFICATE_SIGNER_OID", "2.16.840.1.101.3.7.2.16.23");
                        put("PAIRING_CODE_REFERENCE_DATA_CONTAINER_OID", "2.16.840.1.101.3.7.2.16.24");
                }
        };

        /**
         *
         * Helper function that returns a list of all mandatory containers.
         *
         * @return Array of String values containing OIDs for all mandatory containers
         */
        public static final String[] MandatoryContainers() {
                final String[] rv = { CARD_CAPABILITY_CONTAINER_OID, CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                                X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, CARDHOLDER_FINGERPRINTS_OID,
                                SECURITY_OBJECT_OID, CARDHOLDER_FACIAL_IMAGE_OID,
                                X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID };
                return rv;
        }

        public static boolean isContainerMandatory(String oid) {
                final List<String> mandatoryContainers = Arrays.asList(MandatoryContainers());
                return mandatoryContainers.contains(oid);
        }

        /**
         *
         * Helper function that returns a list of all containers protected by a PIN.
         *
         * @return Array of String values containing OIDs for all containers protected
         *         by a PIN
         */
        public static final String[] ProtectedContainers() {
                final String[] rv = { CARDHOLDER_FINGERPRINTS_OID, PRINTED_INFORMATION_OID, CARDHOLDER_FACIAL_IMAGE_OID,
                                CARDHOLDER_IRIS_IMAGES_OID, PAIRING_CODE_REFERENCE_DATA_CONTAINER_OID };
                return rv;
        }

        public static boolean isProtectedContainer(String oid) {
                final List<String> protectedContainers = Arrays.asList(ProtectedContainers());
                return protectedContainers.contains(oid);
        }

        /**
         *
         * Helper function that returns a list of all possible containers in a PIV Card
         * Application
         *
         * @return Array of String values containing OIDs for all possible containers in
         *         a PIV Card Application
         */
        public static final List<String> AllContainers() {

                ArrayList<String> rv = new ArrayList<String>();
                rv.add(CARD_CAPABILITY_CONTAINER_OID);
                rv.add(CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
                rv.add(X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID);
                rv.add(CARDHOLDER_FINGERPRINTS_OID);
                rv.add(SECURITY_OBJECT_OID);
                rv.add(CARDHOLDER_FACIAL_IMAGE_OID);
                rv.add(X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID);
                rv.add(X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID);
                rv.add(X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID);
                rv.add(PRINTED_INFORMATION_OID);
                rv.add(DISCOVERY_OBJECT_OID);
                rv.add(KEY_HISTORY_OBJECT_OID);
                rv.add(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_1_OID);
                rv.add(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_2_OID);
                rv.add(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_3_OID);
                rv.add(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_4_OID);
                rv.add(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_5_OID);
                rv.add(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_6_OID);
                rv.add(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_7_OID);
                rv.add(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_8_OID);
                rv.add(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_9_OID);
                rv.add(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_10_OID);
                rv.add(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_11_OID);
                rv.add(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_12_OID);
                rv.add(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_13_OID);
                rv.add(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_14_OID);
                rv.add(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_15_OID);
                rv.add(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_16_OID);
                rv.add(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_17_OID);
                rv.add(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_18_OID);
                rv.add(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_19_OID);
                rv.add(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_20_OID);
                rv.add(CARDHOLDER_IRIS_IMAGES_OID);
                rv.add(BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_OID);
                rv.add(SECURE_MESSAGING_CERTIFICATE_SIGNER_OID);
                rv.add(PAIRING_CODE_REFERENCE_DATA_CONTAINER_OID);

                return rv;
        }

        /**
         * HashMap for easy look of container OIDs to names
         *
         */

        /**
         *
         * HashMap for easy lookup of tag values for PIV Data Objects
         *
         */
        public static final HashMap<String, byte[]> oidMAP = new HashMap<String, byte[]>() {
                /**
                 *
                 */
                private static final long serialVersionUID = 1L;

                {
                        put(CARD_CAPABILITY_CONTAINER_OID, CARD_CAPABILITY_CONTAINER_TAG);
                        put(CARD_HOLDER_UNIQUE_IDENTIFIER_OID, CARD_HOLDER_UNIQUE_IDENTIFIER_TAG);
                        put(X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_TAG);
                        put(CARDHOLDER_FINGERPRINTS_OID, CARDHOLDER_FINGERPRINTS_TAG);
                        put(SECURITY_OBJECT_OID, SECURITY_OBJECT_TAG);
                        put(CARDHOLDER_FACIAL_IMAGE_OID, CARDHOLDER_FACIAL_IMAGE_TAG);
                        put(X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_TAG);
                        put(X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID, X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_TAG);
                        put(X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID, X509_CERTIFICATE_FOR_KEY_MANAGEMENT_TAG);
                        put(PRINTED_INFORMATION_OID, PRINTED_INFORMATION_TAG);
                        put(DISCOVERY_OBJECT_OID, DISCOVERY_OBJECT_TAG);
                        put(KEY_HISTORY_OBJECT_OID, KEY_HISTORY_OBJECT_TAG);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_1_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_1_TAG);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_2_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_2_TAG);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_3_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_3_TAG);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_4_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_4_TAG);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_5_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_5_TAG);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_6_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_6_TAG);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_7_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_7_TAG);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_8_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_8_TAG);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_9_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_9_TAG);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_10_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_10_TAG);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_11_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_11_TAG);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_12_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_12_TAG);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_13_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_13_TAG);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_14_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_14_TAG);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_15_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_15_TAG);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_16_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_16_TAG);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_17_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_17_TAG);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_18_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_18_TAG);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_19_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_19_TAG);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_20_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_20_TAG);
                        put(CARDHOLDER_IRIS_IMAGES_OID, CARDHOLDER_IRIS_IMAGES_TAG);
                        put(BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_OID,
                                        BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_TAG);
                        put(SECURE_MESSAGING_CERTIFICATE_SIGNER_OID, SECURE_MESSAGING_CERTIFICATE_SIGNER_TAG);
                        put(PAIRING_CODE_REFERENCE_DATA_CONTAINER_OID, PAIRING_CODE_REFERENCE_DATA_CONTAINER_TAG);
                }
        };

        /**
         * HashMap for lookup of container id to OID
         *
         */
        public static final HashMap<Integer, String> containerIdOidMap = new HashMap<Integer, String>() {
                /**
                 *
                 */
                private static final long serialVersionUID = 1L;

                {
                        put(new Integer(PIV_AUTHENTICATION_KEY_ID), X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID);
                        put(new Integer(DIGITAL_SIGNATURE_KEY_ID), X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID);
                        put(new Integer(KEY_MANAGEMENT_KEY_ID), X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID);
                        put(new Integer(CARD_AUTHENTICATION_KEY_ID), X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_1),
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_1_OID);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_2),
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_2_OID);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_3),
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_3_OID);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_4),
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_4_OID);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_5),
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_5_OID);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_6),
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_6_OID);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_7),
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_7_OID);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_8),
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_8_OID);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_9),
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_9_OID);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_10),
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_10_OID);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_11),
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_11_OID);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_12),
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_12_OID);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_13),
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_13_OID);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_14),
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_14_OID);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_15),
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_15_OID);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_16),
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_16_OID);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_17),
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_17_OID);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_18),
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_18_OID);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_19),
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_19_OID);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_20),
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_20_OID);
                }
        };

        /**
         * HashMap for lookup of a PIV card key reference id given a container OID
         *
         */
        public static final HashMap<String, Integer> oidToContainerIdMap = new HashMap<String, Integer>() {
                /**
                 *
                 */
                private static final long serialVersionUID = 1L;

                {
                        put(X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, new Integer(PIV_AUTHENTICATION_KEY_ID));
                        put(X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID, new Integer(DIGITAL_SIGNATURE_KEY_ID));
                        put(X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID, new Integer(KEY_MANAGEMENT_KEY_ID));
                        put(X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, new Integer(CARD_AUTHENTICATION_KEY_ID));
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_1_OID,
                                        new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_1));
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_2_OID,
                                        new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_2));
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_3_OID,
                                        new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_3));
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_4_OID,
                                        new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_4));
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_5_OID,
                                        new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_5));
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_6_OID,
                                        new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_6));
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_7_OID,
                                        new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_7));
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_8_OID,
                                        new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_8));
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_9_OID,
                                        new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_9));
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_10_OID,
                                        new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_10));
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_11_OID,
                                        new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_11));
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_12_OID,
                                        new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_12));
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_13_OID,
                                        new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_13));
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_14_OID,
                                        new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_14));
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_15_OID,
                                        new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_15));
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_16_OID,
                                        new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_16));
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_17_OID,
                                        new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_17));
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_18_OID,
                                        new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_18));
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_19_OID,
                                        new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_19));
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_20_OID,
                                        new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_20));
                }
        };

        /**
         *
         * HashMap for easy lookup of name values for PIV Data Objects
         *
         */
        public static final HashMap<String, String> oidNameMap = new HashMap<String, String>() {
                /**
                 *
                 */
                private static final long serialVersionUID = 1L;

                {
                        put(CARD_CAPABILITY_CONTAINER_OID, CARD_CAPABILITY_CONTAINER_NAME);
                        put(CARD_HOLDER_UNIQUE_IDENTIFIER_OID, CARD_HOLDER_UNIQUE_IDENTIFIER_NAME);
                        put(X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_NAME);
                        put(CARDHOLDER_FINGERPRINTS_OID, CARDHOLDER_FINGERPRINTS_NAME);
                        put(SECURITY_OBJECT_OID, SECURITY_OBJECT_NAME);
                        put(CARDHOLDER_FACIAL_IMAGE_OID, CARDHOLDER_FACIAL_IMAGE_NAME);
                        put(X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID,
                                        X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_NAME);
                        put(X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID, X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_NAME);
                        put(X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID, X509_CERTIFICATE_FOR_KEY_MANAGEMENT_NAME);
                        put(PRINTED_INFORMATION_OID, PRINTED_INFORMATION_NAME);
                        put(DISCOVERY_OBJECT_OID, DISCOVERY_OBJECT_NAME);
                        put(KEY_HISTORY_OBJECT_OID, KEY_HISTORY_OBJECT_NAME);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_1_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_1_NAME);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_2_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_2_NAME);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_3_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_3_NAME);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_4_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_4_NAME);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_5_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_5_NAME);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_6_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_6_NAME);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_7_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_7_NAME);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_8_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_8_NAME);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_9_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_9_NAME);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_10_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_10_NAME);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_11_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_11_NAME);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_12_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_12_NAME);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_13_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_13_NAME);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_14_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_14_NAME);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_15_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_15_NAME);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_16_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_16_NAME);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_17_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_17_NAME);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_18_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_18_NAME);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_19_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_19_NAME);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_20_OID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_20_NAME);
                        put(CARDHOLDER_IRIS_IMAGES_OID, CARDHOLDER_IRIS_IMAGES_NAME);
                        put(BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_OID,
                                        BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_NAME);
                        put(SECURE_MESSAGING_CERTIFICATE_SIGNER_OID, SECURE_MESSAGING_CERTIFICATE_SIGNER_NAME);
                        put(PAIRING_CODE_REFERENCE_DATA_CONTAINER_OID, PAIRING_CODE_REFERENCE_DATA_CONTAINER_NAME);
                }
        };

        public static final HashMap<Integer, ContainerPurpose> containerPurposeMap = new HashMap<Integer, ContainerPurpose>() {
                /**
                 *
                 */
                private static final long serialVersionUID = 1L;

                {
                        put(new Integer(DIGITAL_SIGNATURE_KEY_ID), ContainerPurpose.SIGNATURE);
                        put(new Integer(KEY_MANAGEMENT_KEY_ID), ContainerPurpose.ENCRYPTION);
                        put(new Integer(CARD_AUTHENTICATION_KEY_ID), ContainerPurpose.SIGNATURE);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_1), ContainerPurpose.ENCRYPTION);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_2), ContainerPurpose.ENCRYPTION);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_3), ContainerPurpose.ENCRYPTION);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_4), ContainerPurpose.ENCRYPTION);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_5), ContainerPurpose.ENCRYPTION);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_6), ContainerPurpose.ENCRYPTION);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_7), ContainerPurpose.ENCRYPTION);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_8), ContainerPurpose.ENCRYPTION);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_9), ContainerPurpose.ENCRYPTION);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_10), ContainerPurpose.ENCRYPTION);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_11), ContainerPurpose.ENCRYPTION);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_12), ContainerPurpose.ENCRYPTION);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_13), ContainerPurpose.ENCRYPTION);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_14), ContainerPurpose.ENCRYPTION);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_15), ContainerPurpose.ENCRYPTION);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_16), ContainerPurpose.ENCRYPTION);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_17), ContainerPurpose.ENCRYPTION);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_18), ContainerPurpose.ENCRYPTION);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_19), ContainerPurpose.ENCRYPTION);
                        put(new Integer(RETIRED_KEY_MANAGEMENT_KEY_ID_20), ContainerPurpose.ENCRYPTION);
                }
        };

        /**
         *
         * HashMap for easy lookup of OID values for PIV Data Objects given container ID
         * value
         *
         */
        public static final HashMap<Integer, String> idMAP = new HashMap<Integer, String>() {
                /**
                 *
                 */
                private static final long serialVersionUID = 1L;

                {
                        put(CARD_CAPABILITY_CONTAINER_ID, CARD_CAPABILITY_CONTAINER_OID);
                        put(CARD_HOLDER_UNIQUE_IDENTIFIER_ID, CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
                        put(X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_ID, X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID);
                        put(CARDHOLDER_FINGERPRINTS_ID, CARDHOLDER_FINGERPRINTS_OID);
                        put(SECURITY_OBJECT_ID, SECURITY_OBJECT_OID);
                        put(CARDHOLDER_FACIAL_IMAGE_ID, CARDHOLDER_FACIAL_IMAGE_OID);
                        put(X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_ID, X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID);
                        put(X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_ID, X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID);
                        put(X509_CERTIFICATE_FOR_KEY_MANAGEMENT_ID, X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID);
                        put(PRINTED_INFORMATION_ID, PRINTED_INFORMATION_OID);
                        put(DISCOVERY_OBJECT_ID, DISCOVERY_OBJECT_OID);
                        put(KEY_HISTORY_OBJECT_ID, KEY_HISTORY_OBJECT_OID);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_1_ID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_1_OID);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_2_ID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_2_OID);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_3_ID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_3_OID);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_4_ID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_4_OID);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_5_ID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_5_OID);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_6_ID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_6_OID);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_7_ID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_7_OID);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_8_ID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_8_OID);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_9_ID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_9_OID);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_10_ID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_10_OID);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_11_ID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_11_OID);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_12_ID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_12_OID);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_13_ID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_13_OID);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_14_ID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_14_OID);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_15_ID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_15_OID);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_16_ID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_16_OID);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_17_ID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_17_OID);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_18_ID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_18_OID);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_19_ID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_19_OID);
                        put(RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_20_ID,
                                        RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_20_OID);
                        put(CARDHOLDER_IRIS_IMAGES_ID, CARDHOLDER_IRIS_IMAGES_OID);
                        put(BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_ID,
                                        BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_OID);
                        put(SECURE_MESSAGING_CERTIFICATE_SIGNER_ID, SECURE_MESSAGING_CERTIFICATE_SIGNER_OID);
                        put(PAIRING_CODE_REFERENCE_DATA_CONTAINER_ID, PAIRING_CODE_REFERENCE_DATA_CONTAINER_OID);
                }
        };

        /**
         *
         * Helper function to get retired key management certificate oid based on a
         * number
         *
         * @param number Integer value identifying retired key management certificate
         * @return String value containing oid of the key management certificate
         */
        public static final String getKeyManagmentCertOID(int number) {

                String firstPart = "2.16.840.1.101.3.7.2.16.";
                String oid = firstPart + number;

                return oid;
        }

        public static final String getStringForFieldNamed(String fieldName) {
                String rv = null;
                Field oidField = null;
                try {
                        oidField = APDUConstants.class.getField(fieldName);
                        rv = (String) oidField.get(APDUConstants.class);

                } catch (NoSuchFieldException | SecurityException | IllegalArgumentException
                                | IllegalAccessException e1) {
                        // e1.printStackTrace();
                        return null;
                }
                return rv;
        }

        /**
         *
         * Helper function to get key management certificate name based on a number
         *
         * @param number Integer value identifying key management certificate
         * @return String value containing name of the key management certificate
         */
        public static final String getKeyManagmentCertName(int number) {

                String firstPart = "Retired X.509 Certificate for Key Management ";
                String name = firstPart + number;

                return name;
        }

        /**
         *
         * Helper function to get retired key managrment certificate tag based on a
         * number
         *
         * @param number Integer value identifying key management certificate
         * @return Byte value containing tag of the key management certificate
         */
        public static final byte[] getKeyManagmentCertTag(int number) {

                int firstPart = 0x5FC10C;
                int tag = firstPart + number;

                byte[] arr = Arrays.copyOfRange(ByteBuffer.allocate(4).putInt(tag).array(), 1, 4);

                return arr;
        }

        /**
         *
         * Helper function to get key managment certificate ID based on a number
         *
         * @param number Integer value identifying key management certificate
         * @return Byte array containing ID of the key management certificate
         */
        public static final byte[] getKeyManagmentCertID(int number) {

                int firstPart = 0x1000;
                int tag = firstPart + number;

                byte[] arr = Arrays.copyOfRange(ByteBuffer.allocate(4).putInt(tag).array(), 1, 4);

                return arr;
        }

        /**
         * Helper function to generate a file name from an OID
         *
         * @param oid the container OID
         * @return a file name consisting of the container name appended with ".dat"
         *         that should match the container's associated class name.
         */

        public static final String getFileNameForOid(String oid) {
                return oidNameMap.get(oid).replaceAll(" for ", "For").replaceAll("[ .]", "");
        }
}
