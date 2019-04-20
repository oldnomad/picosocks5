/**
 * Configuration data.
 */
typedef struct {
    int   nofork;         // Don't fork to background
    int   logmode;        // Logging mode (syslog and/or stderr)
    int   loglevel;       // Logging verbosity level
    uid_t drop_uid;       // UID to drop to, or -1
    gid_t drop_gid;       // GID to drop to, or -1
    char *listen_host;    // Address to listen on, or null for all
    char *listen_service; // Port to listen on, or null for default
} daemon_config_t;

extern const char *cmdline_version(void);
extern void        cmdline_process(int argc, char **argv, daemon_config_t *cfg);
