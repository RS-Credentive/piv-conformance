package gov.gsa.pivconformance.card.client;

/**
 *
 * Enumeration containing PIV Client Application Programming Interface return codes
 *
 */
public enum MiddlewareStatus {
    PIV_OK,
    PIV_CONNECTION_DESCRIPTION_MALFORMED,
    PIV_CONNECTION_FAILURE,
    PIV_CONNECTION_LOCKED,
    PIV_INVALID_CARD_HANDLE,
    PIV_CARD_READER_ERROR,
    PIV_INVALID_OID,
    PIV_DATA_OBJECT_NOT_FOUND,
    PIV_SECURITY_CONDITIONS_NOT_SATISFIED,
    PIV_SM_FAILED,
    PIV_INSUFFICIENT_BUFFER,
    PIV_CARD_APPLICATION_NOT_FOUND,
    PIV_AUTHENTICATION_FAILURE,
    PIV_AUTHENTICATOR_MALFORMED,
    PIV_UNSUPPORTED_CRYPTOGRAPHIC_MECHANISM,
    PIV_INVALID_KEY_OR_KEYALG_COMBINATION,
    PIV_FUNCTION_NOT_SUPPORTED,
    PIV_INSUFFICIENT_CARD_RESOURCE
}
