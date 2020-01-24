/**
 * SOCKS5 version byte
 */
#define SOCKS_VERSION5 0x05

/**
 * Authentication methods
 */
enum {
    SOCKS_AUTH_NONE     = 0x00, // Unauthenticated access
    SOCKS_AUTH_GSSAPI   = 0x01, // GSSAPI
    SOCKS_AUTH_BASIC    = 0x02, // Username/password authentication
    SOCKS_AUTH_CHAP     = 0x03, // CHAP authentication (draft)
    SOCKS_AUTH_INVALID  = 0xFF, // Negotiations failed
};

/**
 * CHAP authentication attributes
 */
enum {
    SOCKS_CHAP_ATTR_STATUS    = 0x00, // Authentication status
    SOCKS_CHAP_ATTR_MESSAGE   = 0x01, // Text message
    SOCKS_CHAP_ATTR_USERID    = 0x02, // User ID
    SOCKS_CHAP_ATTR_CHALLENGE = 0x03, // Challenge
    SOCKS_CHAP_ATTR_RESPONSE  = 0x04, // Response
    SOCKS_CHAP_ATTR_CHARSET   = 0x05, // Text charset
    SOCKS_CHAP_ATTR_IDENT     = 0x10, // Identifier (if algo needs it)
    SOCKS_CHAP_ATTR_ALGO      = 0x11, // Algorithm list
};

/**
 * CHAP authentication algorithms
 */
enum {
    SOCKS_CHAP_ALGO_HMAC_MD5  = 0x85, // HMAC-MD5
};

/**
 * Address types
 */
enum {
    SOCKS_ADDR_IPV4     = 0x01, // IPv4 address
    SOCKS_ADDR_DOMAIN   = 0x03, // Domain name
    SOCKS_ADDR_IPV6     = 0x04, // IPv6 address
};

/**
 * Request commands
 */
enum {
    SOCKS_CMD_CONNECT   = 0x01, // Connect to destination
    SOCKS_CMD_BIND      = 0x02, // Bind reverse TCP channel
    SOCKS_CMD_ASSOCIATE = 0x03, // Associate UDP channel
};

/**
 * Reply codes
 */
enum {
    SOCKS_ERR_SUCCESS         = 0x00, // Successful execution
    SOCKS_ERR_GENERAL         = 0x01, // General error
    SOCKS_ERR_DISALLOWED      = 0x02, // Operation not allowed
    SOCKS_ERR_NET_UNREACH     = 0x03, // Network unreachable
    SOCKS_ERR_HOST_UNREACH    = 0x04, // Host unreachable
    SOCKS_ERR_CONN_REFUSED    = 0x05, // Connection refused
    SOCKS_ERR_TTL_EXPIRED     = 0x06, // TTL expired
    SOCKS_ERR_CMD_UNSUPPORTED = 0x07, // Command not supported
    SOCKS_ERR_AF_UNSUPPORTED  = 0x08, // Address family not supported
    SOCKS_ERR_ADDR_INVALID    = 0x09, // Invalid address (from draft v5.05)
};
