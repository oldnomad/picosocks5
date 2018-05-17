/*
 * NOTES ON AUTH METHODS
 *
 * - Each method consists of sub-negotiation stages.
 * - On each stage:
 *   - Client sends a challenge.
 *   - Framework calls the method-specific function.
 *     - If the function returns a negative value, authentication fails.
 *     - If the function returns a zero, authentication succeeds.
 *     - If the function returns a positive value, authentication continues.
 *     - Regardless of the function return value, if field response_length
 *       is non-zero, response is sent to client.
 *   - If authentication succeeds and field auth is non-null, it contains
 *     an opaque pointer to auth_user.
 *
 * TO ADD A NEW AUTH METHOD:
 *
 * - Declare below a callback function with signature fitting auth_callback_t.
 * - Go to auth.c and insert an element into AUTH_METHODS[] array.
 */
int auth_method_basic(const char *peername, int stage, auth_context_t *ctxt);
