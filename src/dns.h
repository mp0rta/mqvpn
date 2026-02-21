/*
 * dns.h — DNS resolv.conf management for mqvpn client
 *
 * Backs up the original /etc/resolv.conf and writes a new one
 * with the VPN's DNS servers. Restores on cleanup.
 */
#ifndef MQVPN_DNS_H
#define MQVPN_DNS_H

#define MQVPN_DNS_MAX_SERVERS 4

typedef struct {
    char        servers[MQVPN_DNS_MAX_SERVERS][64];
    int         n_servers;
    int         active;         /* 1 if DNS is currently overridden */
    const char *resolv_path;    /* default: /etc/resolv.conf */
    const char *backup_path;    /* default: /etc/resolv.conf.mqvpn.bak */
} mqvpn_dns_t;

/* Initialize with defaults */
void mqvpn_dns_init(mqvpn_dns_t *dns);

/* Add a DNS server address. Returns 0 on success, -1 if full. */
int  mqvpn_dns_add_server(mqvpn_dns_t *dns, const char *addr);

/* Apply DNS override: backup resolv.conf, write new one. Returns 0 on success. */
int  mqvpn_dns_apply(mqvpn_dns_t *dns);

/* Restore original resolv.conf from backup. */
void mqvpn_dns_restore(mqvpn_dns_t *dns);

/* Check if a stale backup exists (e.g. from crash). */
int  mqvpn_dns_has_stale_backup(const mqvpn_dns_t *dns);

/* Restore from stale backup (startup recovery). */
void mqvpn_dns_restore_stale(mqvpn_dns_t *dns);

#endif /* MQVPN_DNS_H */
