package gov.gsa.pivconformance.cardlib.test;

import gov.gsa.pivconformance.cardlib.card.client.APDUConstants;
import gov.gsa.pivconformance.cardlib.card.client.APDUUtils;
import gov.gsa.pivconformance.cardlib.card.client.CardHolderBiometricData;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObject;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObjectFactory;
import gov.gsa.pivconformance.cardlib.card.client.SignedPIVDataObject;
import gov.gsa.pivconformance.cardlib.utils.OSUtils;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BiometricDataObjectTests {
    private static String resDir = null;
    static {
        try {
            URI uri = ClassLoader.getSystemResource("").toURI();
            resDir = Paths.get(uri).toString();
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        resDir = new DODataObjectTests().getClass().getResource("").getFile();
        System.out.println("Looking in: " + resDir);
    }
    @DisplayName("Test Biometric Data Object parsing")
    @ParameterizedTest(name = "{index} => oid = {0}, file = {1}")
    @MethodSource("dataObjectTestProvider")
    void dataObjectTest(String oid, String file, TestReporter reporter) {
        assertNotNull(oid);
        assertNotNull(file);
        Path filePath = Paths.get(resDir + File.separator + file);
        System.out.println("Looking for " + filePath.getParent() + File.separator + filePath.getFileName());
        byte[] fileData = null;
        try {
            fileData = Files.readAllBytes(filePath);
        } catch (IOException e) {
            fail(e);
        }
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
        reporter.publishEntry(oid, o.getClass().getSimpleName());


        byte[] data = APDUUtils.getTLV(APDUConstants.DATA, fileData);

        o.setOID(oid);
        o.setBytes(data);
        boolean decoded = o.decode();
        assert(decoded);

        assertNotNull(((CardHolderBiometricData) o).getBiometricCreationDate());
        assertNotNull(((CardHolderBiometricData) o).getValidityPeriodFrom());
        assertNotNull(((CardHolderBiometricData) o).getValidityPeriodTo());

        assertNotSame(((CardHolderBiometricData) o).getBiometricCreationDate(), "");
        assertNotSame(((CardHolderBiometricData) o).getValidityPeriodFrom(), "");
        assertNotSame(((CardHolderBiometricData) o).getValidityPeriodTo(), "");

        assertNotNull(((SignedPIVDataObject) o).getAsymmetricSignature());

        assertTrue(((CardHolderBiometricData) o).getErrorDetectionCode());

    }

    private static Stream<Arguments> dataObjectTestProvider() {
        return Stream.of(
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/01_Golden_PIV/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/02_Golden_PIV-I/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/03_SKID_Mismatch/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/04_Tampered_CHUID/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/05_Tampered_Certificates/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/06_Tampered_PHOTO/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/07_Tampered_Fingerprints/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/08_Tampered_Security_Object/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/09_Expired_CHUID_Signer/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/10_Expired_Cert_Signer/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/11_Certs_Expire_after_CHUID/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/12_Certs_not_yet_valid/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/13_Certs_are_expired/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/14_Expired_CHUID/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/15_CHUID_FASCN_mismatch/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/16_Card_Authentication_FASCN_mismatch/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/17_PHOTO_FASCN_mismatch/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/18_Fingerprints_FASCN_mismatch/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/19_CHUID_UUID_mismatch/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/20_Card_Authent_UUID_mismatch/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/21_PHOTO_UUID_mismatch/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/22_Fingerprints_UUID_mismatch/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/23_Public_Private_Key_mismatch/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/24_Revoked_Certificates/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/25_Disco_Object_Not_Present/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/26_Disco_Object_Present_App_PIN_Only/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/27_Disco_Object_Present_App_PIN_Primary/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/28_Disco_Object_Present_Global_PIN_Primary/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/37_Golden_FIPS_201-2_PIV_PPS_F=512_D=64/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/38_Bad_Hash_in_Sec_Object/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/39_Golden_FIPS_201-2_Fed_PIV-I/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/41_Re-keyed_Card/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/42_OCSP_Expired/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/43_OCSP_revoked_w_nocheck/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/44_OCSP_revoked_wo_nocheck/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/45_OCSP_Invalid_Signature/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/47_Golden_FIPS_201-2_PIV_SAN_Order/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/48_T=0_with_Non-Zero_PPS_LEN_Value/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/49_FIPS_201-2_Facial_Image_CBEFF_Expired/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/50_FIPS_201-2_Facial_Image_CBEFF_Expires_before_CHUID/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/51_FIPS_201-2_Fingerprint_CBEFF_Expired/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/52_FIPS_201-2_Fingerprint_CBEFF_Expires_before_CHUID/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/53_FIPS_201-2_Large_Card_Auth_Cert/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/54_Golden_FIPS_201-2_NFI_PIV-I/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/55_FIPS_201-2_Missing_Security_Object/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/56_FIPS_201-2_Signer_Expires/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/01_Golden_PIV/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/02_Golden_PIV-I/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/03_SKID_Mismatch/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/04_Tampered_CHUID/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/05_Tampered_Certificates/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/06_Tampered_PHOTO/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/07_Tampered_Fingerprints/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/08_Tampered_Security_Object/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/09_Expired_CHUID_Signer/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/10_Expired_Cert_Signer/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/12_Certs_not_yet_valid/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/13_Certs_are_expired/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/14_Expired_CHUID/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/15_CHUID_FASCN_mismatch/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/16_Card_Authentication_FASCN_mismatch/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/17_PHOTO_FASCN_mismatch/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/18_Fingerprints_FASCN_mismatch/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/19_CHUID_UUID_mismatch/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/20_Card_Authent_UUID_mismatch/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/21_PHOTO_UUID_mismatch/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/22_Fingerprints_UUID_mismatch/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/23_Public_Private_Key_mismatch/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/24_Revoked_Certificates/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/25_Disco_Object_Not_Present/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/26_Disco_Object_Present_App_PIN_Only/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/27_Disco_Object_Present_App_PIN_Primary/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/28_Disco_Object_Present_Global_PIN_Primary/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/37_Golden_FIPS_201-2_PIV_PPS_F=512_D=64/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/38_Bad_Hash_in_Sec_Object/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/39_Golden_FIPS_201-2_Fed_PIV-I/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/41_Re-keyed_Card/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/42_OCSP_Expired/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/43_OCSP_revoked_w_nocheck/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/44_OCSP_revoked_wo_nocheck/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/45_OCSP_Invalid_Signature/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/47_Golden_FIPS_201-2_PIV_SAN_Order/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/48_T=0_with_Non-Zero_PPS_LEN_Value/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/49_FIPS_201-2_Facial_Image_CBEFF_Expired/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/50_FIPS_201-2_Facial_Image_CBEFF_Expires_before_CHUID/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/51_FIPS_201-2_Fingerprint_CBEFF_Expired/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/52_FIPS_201-2_Fingerprint_CBEFF_Expires_before_CHUID/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/53_FIPS_201-2_Large_Card_Auth_Cert/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/54_Golden_FIPS_201-2_NFI_PIV-I/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/55_FIPS_201-2_Missing_Security_Object/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID,
                        "gsa-icam-card-builder/cards/ICAM_Card_Objects/56_FIPS_201-2_Signer_Expires/10 - Face Object")
                );
    }
}
