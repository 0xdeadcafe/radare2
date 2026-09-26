/*
 * Linux socket types and constants for radare2
 *
 * Usage: to types/libc/socket.h
 *
 * Note: sockaddr structs vary by architecture (different padding)
 * These are for x86_64/arm64 (LP64)
 */

/* Address families */
enum linux_af {
    AF_UNSPEC = 0,
    AF_UNIX = 1,
    AF_LOCAL = 1,
    AF_INET = 2,
    AF_AX25 = 3,
    AF_IPX = 4,
    AF_APPLETALK = 5,
    AF_NETROM = 6,
    AF_BRIDGE = 7,
    AF_ATMPVC = 8,
    AF_X25 = 9,
    AF_INET6 = 10,
    AF_ROSE = 11,
    AF_DECnet = 12,
    AF_NETBEUI = 13,
    AF_SECURITY = 14,
    AF_KEY = 15,
    AF_NETLINK = 16,
    AF_ROUTE = 16,
    AF_PACKET = 17,
    AF_ASH = 18,
    AF_ECONET = 19,
    AF_ATMSVC = 20,
    AF_RDS = 21,
    AF_SNA = 22,
    AF_IRDA = 23,
    AF_PPPOX = 24,
    AF_WANPIPE = 25,
    AF_LLC = 26,
    AF_IB = 27,
    AF_MPLS = 28,
    AF_CAN = 29,
    AF_TIPC = 30,
    AF_BLUETOOTH = 31,
    AF_IUCV = 32,
    AF_RXRPC = 33,
    AF_ISDN = 34,
    AF_PHONET = 35,
    AF_IEEE802154 = 36,
    AF_CAIF = 37,
    AF_ALG = 38,
    AF_NFC = 39,
    AF_VSOCK = 40,
    AF_KCM = 41,
    AF_QIPCRTR = 42,
    AF_SMC = 43
};

/* Socket types */
enum linux_sock_type {
    SOCK_STREAM = 1,
    SOCK_DGRAM = 2,
    SOCK_RAW = 3,
    SOCK_RDM = 4,
    SOCK_SEQPACKET = 5,
    SOCK_DCCP = 6,
    SOCK_PACKET = 10,
    SOCK_NONBLOCK = 2048,
    SOCK_CLOEXEC = 524288
};

/* IP protocols */
enum linux_ipproto {
    IPPROTO_IP = 0,
    IPPROTO_ICMP = 1,
    IPPROTO_IGMP = 2,
    IPPROTO_IPIP = 4,
    IPPROTO_TCP = 6,
    IPPROTO_EGP = 8,
    IPPROTO_PUP = 12,
    IPPROTO_UDP = 17,
    IPPROTO_IDP = 22,
    IPPROTO_TP = 29,
    IPPROTO_DCCP = 33,
    IPPROTO_IPV6 = 41,
    IPPROTO_RSVP = 46,
    IPPROTO_GRE = 47,
    IPPROTO_ESP = 50,
    IPPROTO_AH = 51,
    IPPROTO_MTP = 92,
    IPPROTO_BEETPH = 94,
    IPPROTO_ENCAP = 98,
    IPPROTO_PIM = 103,
    IPPROTO_COMP = 108,
    IPPROTO_SCTP = 132,
    IPPROTO_UDPLITE = 136,
    IPPROTO_MPLS = 137,
    IPPROTO_RAW = 255
};

/* Socket options level */
enum linux_sol {
    SOL_SOCKET = 1,
    SOL_IP = 0,
    SOL_TCP = 6,
    SOL_UDP = 17,
    SOL_IPV6 = 41,
    SOL_ICMPV6 = 58,
    SOL_RAW = 255,
    SOL_PACKET = 263
};

/* Socket options (SOL_SOCKET level) */
enum linux_so_opt {
    SO_DEBUG = 1,
    SO_REUSEADDR = 2,
    SO_TYPE = 3,
    SO_ERROR = 4,
    SO_DONTROUTE = 5,
    SO_BROADCAST = 6,
    SO_SNDBUF = 7,
    SO_RCVBUF = 8,
    SO_KEEPALIVE = 9,
    SO_OOBINLINE = 10,
    SO_NO_CHECK = 11,
    SO_PRIORITY = 12,
    SO_LINGER = 13,
    SO_BSDCOMPAT = 14,
    SO_REUSEPORT = 15,
    SO_RCVLOWAT = 18,
    SO_SNDLOWAT = 19,
    SO_RCVTIMEO = 20,
    SO_SNDTIMEO = 21,
    SO_ACCEPTCONN = 30,
    SO_SNDBUFFORCE = 32,
    SO_RCVBUFFORCE = 33
};

/* MSG flags for send/recv */
enum linux_msg_flags {
    MSG_OOB = 1,
    MSG_PEEK = 2,
    MSG_DONTROUTE = 4,
    MSG_TRYHARD = 4,
    MSG_CTRUNC = 8,
    MSG_PROBE = 16,
    MSG_TRUNC = 32,
    MSG_DONTWAIT = 64,
    MSG_EOR = 128,
    MSG_WAITALL = 256,
    MSG_FIN = 512,
    MSG_SYN = 1024,
    MSG_CONFIRM = 2048,
    MSG_RST = 4096,
    MSG_ERRQUEUE = 8192,
    MSG_NOSIGNAL = 16384,
    MSG_MORE = 32768,
    MSG_WAITFORONE = 65536,
    MSG_FASTOPEN = 536870912,
    MSG_CMSG_CLOEXEC = 1073741824
};

/* Shutdown how */
enum linux_shut {
    SHUT_RD = 0,
    SHUT_WR = 1,
    SHUT_RDWR = 2
};

/* Generic socket address - 16 bytes */
struct sockaddr {
    short sa_family;
    char sa_data[14];
};

/* IPv4 socket address - 16 bytes */
struct sockaddr_in {
    short sin_family;
    short sin_port;
    int sin_addr;
    char sin_zero[8];
};

/* IPv6 socket address - 28 bytes */
struct sockaddr_in6 {
    short sin6_family;
    short sin6_port;
    int sin6_flowinfo;
    char sin6_addr[16];
    int sin6_scope_id;
};

/* Unix domain socket address - 110 bytes */
struct sockaddr_un {
    short sun_family;
    char sun_path[108];
};

/* getaddrinfo result linked list */
struct addrinfo {
    int              ai_flags;
    int              ai_family;
    int              ai_socktype;
    int              ai_protocol;
    int              ai_addrlen;
    struct sockaddr *ai_addr;
    char            *ai_canonname;
    struct addrinfo *ai_next;
};

/* struct iovec - scatter/gather I/O */
struct iovec {
    void *iov_base;
    int   iov_len;
};

/* struct msghdr - sendmsg/recvmsg */
struct msghdr {
    void    *msg_name;
    int      msg_namelen;
    struct iovec *msg_iov;
    int      msg_iovlen;
    void    *msg_control;
    int      msg_controllen;
    int      msg_flags;
};
