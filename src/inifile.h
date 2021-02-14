/**
 * @file
 * Definitions for option parsing code.
 */

/**
 * Option parsing context.
 */
typedef struct {
    const char *filename;  ///< File name of the INI file, or NULL for command line
    int         lineno;    ///< Line number in the INI file
    char       *section;   ///< Section name, or NULL for common section
    void       *context;   ///< Caller-provided context
} ini_context_t;

/**
 * Option value type.
 */
enum {
    INI_TYPE_PLAIN   = 0,
    INI_TYPE_LIST    = 1,
    INI_TYPE_BOOLEAN = 2,
};

struct ini_option;
/**
 * Function type for option parsing callback.
 *
 * @param ctxt  option parsing context.
 * @param opt   option being parsed.
 * @param value option value, or NULL.
 * @return zero on success, or -1 on error.
 */
typedef int (*ini_param_cbk_t)(const ini_context_t *ctxt, const struct ini_option *opt, const char *value);

/**
 * Option descriptor.
 */
typedef struct ini_option {
    const char  *name;     ///< Parameter name, or NULL for end-of-list
    const char  *optname;  ///< Command line long option name, or NULL
    char         optchar;  ///< Command line short option character, or 1 for positional parameter, or zero
    int          type;     ///< Value type
    ini_param_cbk_t
                 callback; ///< Parameter callback
} ini_option_t;

/**
 * Function type for configuration section callback.
 *
 * @param ctxt option parsing context, with new section name filled in.
 * @return list of options for this section.
 */
typedef const ini_option_t *(*ini_section_cbk_t)(const ini_context_t *ctxt);

void ini_error(const ini_context_t *ctxt, const char *fmt, ...);

int ini_load(const char *filename, ini_section_cbk_t callback, void *context);
int ini_args(int argc, char **argv, ini_section_cbk_t callback, void *context);
