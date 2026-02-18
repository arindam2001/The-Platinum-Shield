#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/pfil.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if_var.h>

#include <machine/atomic.h>

static volatile u_long dropped_pkts = 0;
static pfil_hook_t httpblock_pfil_hook = NULL;
static struct pfil_hook_args httpblock_pfil_args;

static int
ascii_tolower(int c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A' + 'a';
    return c;
}

static int
memmatch_nocase(const char *buf, int buflen, int pos, const char *pat, int patlen)
{
    int i;
    if (pos + patlen > buflen)
        return 0;
    for (i = 0; i < patlen; i++) {
        if (ascii_tolower((unsigned char)buf[pos + i]) !=
            ascii_tolower((unsigned char)pat[i]))
            return 0;
    }
    return 1;
}


static int
contains_blocked_host(const char *buf, int len)
{
    const char *blocked = "blocked.com";
    const int blocked_len = 10; 

    int i;

    for (i = 0; i + 5 < len; i++) {
        if (memmatch_nocase(buf, len, i, "Host:", 5)) {    
            int j = i + 5;

            while (j < len && (buf[j] == ' ' || buf[j] == '\t'))
                j++;

        
            if (memmatch_nocase(buf, len, j, blocked, blocked_len))
                return 1;
        }
    }
    return 0;
}

static pfil_return_t
httpblock_hook(pfil_packet_t pkt, struct ifnet *ifp, int flags, void *ruleset, struct inpcb *inp)
{
    struct mbuf *m;
    struct ip *ip;
    struct tcphdr *th;

    int iphlen, tcphlen, hdrlen;
    int pktlen, payload_len;
    int need, copy_len;

    char payload[512];

    (void)ruleset;
    (void)inp;

    m = pkt.mem;
    if (m == NULL)
        return PFIL_PASS;

    m = m_pullup(m, sizeof(struct ip));
    if (m == NULL)
        return PFIL_PASS;
    pkt.mem = m; 
    ip = mtod(m, struct ip *);
    if (ip->ip_v != 4)
        return PFIL_PASS;

    if (ip->ip_p != IPPROTO_TCP)
        return PFIL_PASS;

    iphlen = ip->ip_hl << 2;
    if (iphlen < (int)sizeof(struct ip))
        return PFIL_PASS;

    if (m->m_len < iphlen + (int)sizeof(struct tcphdr)) {
        m = m_pullup(m, iphlen + (int)sizeof(struct tcphdr));
        if (m == NULL)
            return PFIL_PASS;
        pkt.mem = m; 
        ip = mtod(m, struct ip *);
    }

    th = (struct tcphdr *)((caddr_t)ip + iphlen);

    if (ntohs(th->th_dport) != 80)
        return PFIL_PASS;

    tcphlen = th->th_off << 2;
    if (tcphlen < (int)sizeof(struct tcphdr))
        return PFIL_PASS;

    hdrlen = iphlen + tcphlen;

    pktlen = ntohs(ip->ip_len);
    payload_len = pktlen - hdrlen;
    if (payload_len <= 0)
        return PFIL_PASS;

    copy_len = (payload_len > (int)sizeof(payload)) ? (int)sizeof(payload) : payload_len;
    need = hdrlen + copy_len;

    if (m->m_len < need) {
        m = m_pullup(m, need);
        if (m == NULL)
            return PFIL_PASS;
        pkt.mem = m; 
        ip = mtod(m, struct ip *);
        th = (struct tcphdr *)((caddr_t)ip + (ip->ip_hl << 2));
        iphlen = ip->ip_hl << 2;
        tcphlen = th->th_off << 2;
        hdrlen = iphlen + tcphlen;
    }

    bcopy((const char *)ip + hdrlen, payload, copy_len);

    if (contains_blocked_host(payload, copy_len)) {
        u_long c = atomic_fetchadd_long(&dropped_pkts, 1) + 1;
        printf("[httpblock] DROPPED count=%lu size=%d bytes if=%s dir=%s\n",
               c, pktlen,
               (ifp != NULL) ? ifp->if_xname : "em0",
               (flags & PFIL_OUT) ? "OUT" : "IN");
        m_freem(m);
pkt.mem = NULL; 
        return PFIL_DROPPED;
    }

    return PFIL_PASS;
}

static int
httpblock_modevent(module_t mod, int event, void *data)
{
    int error = 0;

    (void)mod;
    (void)data;

    switch (event) {

    case MOD_LOAD:
        memset(&httpblock_pfil_args, 0, sizeof(httpblock_pfil_args));
        httpblock_pfil_args.pa_version = PFIL_VERSION;
        httpblock_pfil_args.pa_flags   = PFIL_IN | PFIL_OUT;  
        httpblock_pfil_args.pa_type    = PFIL_TYPE_IP4;      
        httpblock_pfil_args.pa_func    = httpblock_hook;
        httpblock_pfil_args.pa_modname = "httpblock";
        httpblock_pfil_args.pa_rulname = "default";

        httpblock_pfil_hook = pfil_add_hook(&httpblock_pfil_args);
        if (httpblock_pfil_hook == NULL) {
            printf("[httpblock] ERROR: pfil_add_hook failed\n");
            return ENOENT;
        }

        printf("[httpblock] loaded: blocking http host blocked.com\n");
        break;

    case MOD_UNLOAD:
        if (httpblock_pfil_hook != NULL) {
            pfil_remove_hook(httpblock_pfil_hook);
            httpblock_pfil_hook = NULL;
        }
        printf("[httpblock] unloaded\n");
        break;

    default:
        error = EOPNOTSUPP;
        break;
    }

    return error;
}

static moduledata_t httpblock_mod = {
    "httpblock",
    httpblock_modevent,
    NULL
};

DECLARE_MODULE(httpblock, httpblock_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_VERSION(httpblock, 1);
