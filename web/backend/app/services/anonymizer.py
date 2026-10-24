"""
Reversible anonymization of sensitive identifiers before evidence goes to an LLM.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import re
import secrets
import sqlite3
from typing import Iterable, Optional

from . import case_db

KINDS = ("HOST", "IP", "DOMAIN", "URL", "EMAIL", "USER", "SID", "MAC", "TERM")
CUSTOM_KINDS = ("TERM", "HOST", "USER", "DOMAIN") # kinds an analyst can assign to a custom value

# No word boundaries: a substring-matched TERM can sit inside a word (ACMEPC01 -> TERM_<hex>PC01).
_TOKEN_RE = re.compile(r"(HOST|IP|DOMAIN|URL|EMAIL|USER|SID|MAC|TERM)_([0-9a-fA-F]{32})", re.IGNORECASE)

# Appended to the system prompt when masking: the model must copy tokens verbatim or they cannot be restored.
PROMPT_SUFFIX = (
    " IMPORTANT: sensitive identifiers in this case (hostnames, IP addresses, "
    "domains, URLs, e-mail addresses, usernames, SIDs, MAC addresses, other sensitive "
    "terms) have been replaced by opaque tokens such as HOST_<hex>, IP_<hex>, USER_<hex>, TERM_<hex>. Each "
    "token consistently stands for one real value. Refer to them verbatim and "
    "in full in your answer (never shorten, reformat or merge them) and do not "
    "try to guess what they stand for."
)

# generic values that identify nothing
_GENERIC_USERS = {
    "system", "local service", "network service", "administrator", "administrators", "admin",
    "guest", "defaultaccount", "wdagutilityaccount", "default", "default user", "public",
    "all users", "anonymous logon", "anonymous", "everyone", "trustedinstaller", "trusted installer",
    "iusr", "iis_iusrs", "window manager", "font driver host", "local", "network", "user", "users",
    "test", "service", "logon", "unknown", "n/a", "na", "-", "none", "null", "owner", "creator owner",
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy",
    "www-data", "backup", "list", "irc", "gnats", "nobody", "nogroup", "messagebus", "sshd", "syslog",
    "tss", "uuidd", "tcpdump", "landscape", "pollinate", "fwupd-refresh", "usbmux", "dnsmasq", "avahi",
    "colord", "geoclue", "pulse", "rtkit", "saned", "whoopsie", "kernoops", "cups-pk-helper",
    "speech-dispatcher", "lightdm", "gdm", "sddm", "postfix", "mysql", "postgres", "ntp", "chrony",
    "apache", "nginx", "tomcat", "docker", "polkitd", "rpc", "rpcuser", "nfsnobody", "dbus", "ftp",
    "operator", "halt", "shutdown", "adm", "unbound", "sssd", "cockpit-ws", "cockpit-wsinstance",
    "setroubleshoot", "libstoragemgmt", "clevis", "insights", "pesign", "flatpak", "qemu", "libvirt",
    "ubuntu", "ec2-user", "centos", "debian", "fedora", "vagrant", "pi", "cloud-user", "opc", "azureuser",
    "wheel", "sudo", "staff", "desktop.ini", "ntuser.dat", "all",
    # wtmp pseudo-users and common daemon accounts
    "login", "reboot", "runlevel", "system boot", "cups-browsed", "hplip", "avahi-autoipd", "nm-openvpn",
    "dhcpcd", "lxd", "snapd", "nvidia-persistenced", "gnome-initial-setup", "gnome-remote-desktop",
    "libuuid", "cups", "bind", "named", "dovecot", "exim", "clamav", "amavis", "redis", "memcache",
    "rabbitmq", "mongodb", "elasticsearch", "kibana", "logstash", "grafana", "prometheus", "zabbix",
    "nagios", "icinga", "splunk", "jenkins", "git", "haproxy", "squid", "openvpn", "wireguard", "tor",
    "pcp", "polkitd", "sshd", "tcpdump",
}
_GENERIC_USER_RE = re.compile(r"^(?:dwm-\d+|umfd-\d+|systemd-.*|_.*|\..*|s-1-\d.*|\d+)$")
# A multi-word "user" containing one of these is a vendor/product, not a
# person (Scheduled Task Author = "Microsoft Corporation", browser Profile 1).
_VENDOR_WORDS = {
    "corporation", "corp", "inc", "ltd", "llc", "gmbh", "microsoft", "google", "apple", "adobe", "oracle",
    "intel", "nvidia", "mozilla", "canonical", "hat", "foundation", "software", "systems", "technologies",
    "profile", "account", "service", "network", "windows", "default",
}
_GENERIC_HOSTS = {
    "localhost", "localhost.localdomain", "-", "n/a", "unknown", "none", "null", "computer", "host",
    "server", "workstation", "machine", "pc", "local", "broadcasthost", "ip6-localhost", "ip6-loopback",
    "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "system boot",
}
_GENERIC_HOST_LABELS = {"www", "mail", "smtp", "imap", "pop", "ftp", "sftp", "ns", "ns1", "ns2", "dns", "api", "cdn",
                        "static", "login", "web", "m", "app", "portal", "vpn", "gw", "gateway", "proxy", "ldap", "dc", "ad"}
# wtmp "host" fields for console logins (tty1, :0), kernel versions on reboot records
_GENERIC_HOST_RE = re.compile(r"^(?:tty\S*|pts/?\S*|:\d+(?:\.\d+)?|\d+\.\d+[\w.-]*)$")
_GENERIC_DOMAINS = {
    "workgroup", "nt authority", "builtin", "nt service", "window manager", "font driver host",
    "nt virtual machine", "iis apppool", "microsoftaccount", "azuread", "microsoft", "local", "localhost",
    "localdomain", "-", "n/a", "none", "null", "unknown", "mshome",
}

# Public vendor / update / CDN / certificate / package-repo domains
_ALLOWLISTED_DOMAINS = {
    "microsoft.com", "microsoftonline.com", "windows.com", "windows.net", "windowsupdate.com",
    "windowsazure.com", "azure.com", "azure.net", "azureedge.net", "azurewebsites.net", "msftconnecttest.com",
    "msftncsi.com", "msecnd.net", "trafficmanager.net", "visualstudio.com", "microsoftstore.com",
    "akamaized.net", "akamai.net", "akamaihd.net", "akadns.net", "edgekey.net", "edgesuite.net",
    "cloudfront.net", "amazonaws.com", "cloudflare.com", "cloudflare.net", "fastly.net",
    "googleapis.com", "gstatic.com", "gvt1.com", "gvt2.com", "chrome.com", "android.com",
    "mozilla.org", "mozilla.com", "mozilla.net", "firefox.com", "apple.com", "mzstatic.com",
    "ubuntu.com", "canonical.com", "launchpad.net", "snapcraft.io", "debian.org", "centos.org",
    "redhat.com", "fedoraproject.org", "almalinux.org", "rockylinux.org", "opensuse.org", "suse.com",
    "kernel.org", "gnu.org", "python.org", "pypi.org", "pythonhosted.org", "npmjs.org", "npmjs.com",
    "nodejs.org", "docker.com", "docker.io", "digicert.com", "verisign.com", "letsencrypt.org",
    "sectigo.com", "comodoca.com", "globalsign.com", "godaddy.com", "entrust.net", "symantec.com",
    "symcb.com", "symcd.com", "thawte.com", "geotrust.com", "usertrust.com", "identrust.com",
    "w3.org", "xmlsoap.org", "openxmlformats.org", "purl.org", "dublincore.org", "adobe.com", "adobe.io",
    "oracle.com", "java.com", "java.net", "sun.com", "apache.org", "eclipse.org", "jetbrains.com",
    "mcafee.com", "kaspersky.com", "kaspersky-labs.com", "sophos.com", "eset.com", "avast.com", "avg.com",
    "bitdefender.com", "trendmicro.com", "crowdstrike.com", "sentinelone.net", "symantecliveupdate.com",
    "nvidia.com", "intel.com", "amd.com", "realtek.com", "dell.com", "hp.com", "lenovo.com",
    "teamviewer.com", "anydesk.com", "7-zip.org", "notepad-plus-plus.org", "videolan.org",
    "libreoffice.org", "openoffice.org", "gimp.org", "example.com", "example.org", "example.net",
    "in-addr.arpa", "ip6.arpa",
}

_TLDS = (
    "com net org edu gov mil int info biz name pro aero coop museum jobs mobi travel tel asia xxx arpa "
    "io app dev cloud online site store tech top xyz club shop live news blog wiki link click download "
    "space website world today email solutions services systems network digital agency company group "
    "team zone tools center academy support help host hosting server software studio design media "
    "social community global international ltd llc inc one ninja guru rocks life love fun run party vip "
    "win bid trade loan date review stream racing accountant science men faith cricket work ooo best buzz "
    "icu monster pw cc tv me co su "
    "local lan internal intranet corp home private localdomain test example invalid onion i2p "
    "ac ad ae af ag ai al am ao ar at au az ba bb bd be bf bg bh bi bj bm bn bo br bs bt bw by bz ca cd "
    "cf cg ch ci ck cl cm cn cr cu cv cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk fm fo fr ga "
    "gd ge gf gg gh gi gl gm gn gp gq gr gt gu gw gy hk hn hr ht hu id ie il im in iq ir is it je jm jo "
    "jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md mg mh mk ml mm mn mo "
    "mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn "
    "pr ps pt py qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm sn so sr ss st sv sy sz tc td tg th "
    "tj tk tl tm tn to tr tt tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw zip mov key cat"
).split()
_TLD_SET = set(_TLDS)
# TLDs that double as everyday file extensions
_FILE_EXT_TLDS = {
    "so", "py", "md", "sh", "ps", "pl", "rs", "cs", "ai", "zip", "mov", "app", "in", "am", "cc", "ac", "la",
    "pm", "pf", "gs", "tt", "st", "mk", "ph", "re", "tf", "cl", "cr", "ml", "tk", "as", "key", "cat", "pro",
}

# detection regexes
_URL_RE = re.compile(r"\b(?:https?|ftps?|sftp|smb|ldaps?|wss?|rdp|ssh|vnc)://[^\s\x1f\"'<>\]\)\}\\]+", re.IGNORECASE)
_URL_HOST_RE = re.compile(r"^[a-z]+://(?:[^@/]*@)?([^/:?#]+)", re.IGNORECASE)

# UNC server names: exactly two leading backslashes (\\server\share), so an
# ordinary separator inside a path (\VOLUME{..}\Windows) never qualifies.
_UNC_RE = re.compile(r"(?<![\w\\:])\\\\(?!\\)(?=[A-Za-z0-9._-]*[A-Za-z0-9])([A-Za-z0-9._-]+)(?=\\)")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IPV6_RE = re.compile(
    r"(?<![:\w])(?:"
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,7}:|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|"
    r"[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}|"
    r":(?::[0-9A-Fa-f]{1,4}){1,7}|"
    r"::(?:[Ff]{4}(?::0{1,4})?:)?(?:\d{1,3}\.){3}\d{1,3}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,4}:(?:\d{1,3}\.){3}\d{1,3}"
    r")(?![:\w])"
)
_IPV4_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\.?\d)")
_SID_RE = re.compile(r"\bS-1-(?:5-21|12-1)-\d+-\d+-\d+(?:-\d+)?\b")
_MAC_RE = re.compile(r"(?<![\w:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w:-])")
_FQDN_RE = re.compile(
    r"(?<![\w.@/\\-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(" + "|".join(sorted(_TLDS, key=len, reverse=True)) + r"))"
    r"(?![\w-]|\.[\w-])",
    re.IGNORECASE,
)
# "/home/<user>/", "/Users/<user>/", "C:\Users\<user>\"
_PROFILE_PATH_RE = re.compile(
    r"((?:/home/|/Users/|(?<![A-Za-z])[A-Za-z]:/Users/|"
    # C:\Users\, \Users\, \VOLUME{..}\USERS\ (Prefetch), \Device\HarddiskVolume2\Users\ (SRUM), \\?\C:\Users\
    r"(?:(?<![A-Za-z])[A-Za-z]:|\\+VOLUME\{[^}]*\}|\\+Device\\+HarddiskVolume\d+|\\+\?\\+[A-Za-z]:)?\\+Users\\+))"

    r"([^\s\x1f\\/\"'<>|*?;=,:]{1,64}(?: [^\s\x1f\\/\"'<>|*?;=,:]{1,64}){1,2}(?=[\\/\"'\n\r\t])"
    r"|[^\s\x1f\\/\"'<>|*?;=,:]{1,64}(?=[\\/\"'\s\x1f]|$))",
    re.IGNORECASE,
)

_USER_COLS = {
    "gecos", "fullname", "displayname", "realname", "givenname", "surname",
    "user", "users", "username", "usernames", "useraccount", "account", "accountname", "samaccountname",
    "subjectusername", "targetusername", "subjectaccountname", "targetaccountname", "owner", "fileowner",
    "loggedonuser", "logonuser", "userid", "login", "loginname", "actor", "runas", "runasuser", "author",
    "createdby", "modifiedby", "principal", "principalname", "profile", "profilename", "runasaccount",
    "serviceaccount", "callerusername", "ownername", "sidname", "accountdomainuser", "targetuser",
    "subjectuser", "mailbox", "upn", "userprincipalname",
}
_USER_COL_SUFFIXES = ("username", "user_name", "accountname", "loggedonuser", "userid", "owner")
_HOST_COLS = {
    "computer", "computername", "hostname", "host", "machinename", "machine", "workstation",
    "workstationname", "sourcecomputer", "destinationhostname", "clientname", "remotehost", "servername",
    "sourcehost", "targetserver", "targetservername", "dnshostname", "netbiosname",
    "systemname", "fqdn", "machineid", "computerfqdn", "sourcehostname", "remotehostname", "fromhost",
}
_HOST_COL_SUFFIXES = ("computername", "hostname", "machinename", "workstationname", "servername")
_DOMAIN_COLS = {
    "domain", "domainname", "subjectdomainname", "targetdomainname", "userdomain", "userdomainname",
    "logondomain", "workgroup", "dnsdomain", "dnsdomainname", "computerdomain", "accountdomain",
    "targetdomain", "subjectdomain", "realm", "domainfqdn", "addomain", "forest", "forestname",
}

_IDENT_VALUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._$-]{0,252}$")
_USER_VALUE_RE = re.compile(r"^(?=.*[A-Za-z])[A-Za-z0-9._$@ -]{2,64}$")
_SKIP_CELL_RE = re.compile(r"^[\d\s.,:/+TZ-]*$") # bare numbers, dates, timestamps


def _norm_col(name: str) -> str:
    return re.sub(r"[^a-z]", "", (name or "").lower())


def _numeric_uid(row: dict) -> Optional[int]:
    for col, val in row.items():
        if _norm_col(col) in ("uid", "userid") and isinstance(val, str) and val.isdigit():
            return int(val)
    return None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _ipv4_is_noise(value: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        return True
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved or int(ip) == 0xFFFFFFFF:
        return True
    inv = (~int(ip)) & 0xFFFFFFFF
    return (inv + 1) & inv == 0 # contiguous-ones subnet mask (255.255.255.0 ...)


def _ipv6_is_noise(value: str) -> bool:
    if not any(c.isdigit() for c in value):
        return True
    try:
        ip = ipaddress.IPv6Address(value.split("%", 1)[0])
    except ValueError:
        return True
    return ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved


def _email_plausible(addr: str) -> bool:
    """getty@tty1.service / user@1000.service are systemd units, not mail."""
    return addr.rsplit(".", 1)[-1].lower() in _TLD_SET


def _domain_allowlisted(host: str) -> bool:
    h = host.lower().rstrip(".")
    if _is_ip(h):
        return False
    parts = h.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in _ALLOWLISTED_DOMAINS:
            return True
    return False


def _generic_user(name: str) -> bool:
    n = name.strip().lower()
    return len(n) < 2 or n in _GENERIC_USERS or bool(_GENERIC_USER_RE.match(n))


def _generic_host(name: str) -> bool:
    n = name.strip().lower()
    return len(n) < 2 or n in _GENERIC_HOSTS or _is_ip(n) or bool(_GENERIC_HOST_RE.match(n))


def _generic_domain(name: str) -> bool:
    n = name.strip().lower()
    return len(n) < 2 or n in _GENERIC_DOMAINS or _is_ip(n) or _domain_allowlisted(n)


# persistence (per-case case.sqlite)

def ensure_tables(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE TABLE IF NOT EXISTS _anon_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS _anon_map ("
        " token TEXT PRIMARY KEY, kind TEXT NOT NULL, original TEXT NOT NULL, created_at TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS _anon_custom ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT NOT NULL UNIQUE COLLATE NOCASE, kind TEXT NOT NULL,"
        " substring INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, created_by TEXT)"
    )
    conn.commit()


def get_or_create_seed(conn: sqlite3.Connection) -> str:
    ensure_tables(conn)
    row = conn.execute("SELECT value FROM _anon_settings WHERE key = 'seed'").fetchone()
    if row:
        return row["value"]
    seed = secrets.token_hex(32)
    conn.execute("INSERT INTO _anon_settings (key, value) VALUES ('seed', ?)", (seed,))
    conn.commit()
    return seed


def load_mapping(case_id: str) -> list[dict]:
    conn = case_db.get_connection(case_id)
    try:
        ensure_tables(conn)
        rows = conn.execute("SELECT token, kind, original, created_at FROM _anon_map ORDER BY kind, original").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def load_seed(case_id: str) -> Optional[str]:
    conn = case_db.get_connection(case_id)
    try:
        ensure_tables(conn)
        row = conn.execute("SELECT value FROM _anon_settings WHERE key = 'seed'").fetchone()
        return row["value"] if row else None
    finally:
        conn.close()


def list_custom(case_id: str) -> list[dict]:
    conn = case_db.get_connection(case_id)
    try:
        ensure_tables(conn)
        rows = conn.execute("SELECT id, value, kind, substring, created_at, created_by FROM _anon_custom ORDER BY id").fetchall()
        return [{**dict(r), "substring": bool(r["substring"])} for r in rows]
    finally:
        conn.close()


def add_custom(case_id: str, value: str, kind: str, substring: bool, created_by: str) -> dict:
    """Analyst-defined sensitive value."""
    value = (value or "").strip()
    kind = (kind or "TERM").upper()
    if len(value) < 2:
        raise ValueError("Value must be at least 2 characters")
    if kind not in CUSTOM_KINDS:
        raise ValueError(f"Kind must be one of {', '.join(CUSTOM_KINDS)}")
    conn = case_db.get_connection(case_id)
    try:
        ensure_tables(conn)
        conn.execute(
            "INSERT OR REPLACE INTO _anon_custom (id, value, kind, substring, created_at, created_by) VALUES ("
            " (SELECT id FROM _anon_custom WHERE value = ? COLLATE NOCASE), ?, ?, ?, ?, ?)",
            (value, value, kind, int(substring), dt.datetime.utcnow().isoformat(), created_by),
        )
        conn.commit()
        row = conn.execute("SELECT id, value, kind, substring, created_at, created_by FROM _anon_custom WHERE value = ? COLLATE NOCASE", (value,)).fetchone()
        return {**dict(row), "substring": bool(row["substring"])}
    finally:
        conn.close()


def delete_custom(case_id: str, custom_id: int) -> bool:
    conn = case_db.get_connection(case_id)
    try:
        ensure_tables(conn)
        cur = conn.execute("DELETE FROM _anon_custom WHERE id = ?", (custom_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def clear_mapping(case_id: str) -> int:
    """Drops map and seed (custom values stay)."""
    conn = case_db.get_connection(case_id)
    try:
        ensure_tables(conn)
        n = conn.execute("SELECT COUNT(*) AS c FROM _anon_map").fetchone()["c"]
        conn.execute("DELETE FROM _anon_map")
        conn.execute("DELETE FROM _anon_settings WHERE key = 'seed'")
        conn.commit()
        return n
    finally:
        conn.close()


# the anonymizer

class Anonymizer:
    def __init__(self, seed: str, existing: Optional[Iterable[dict]] = None):
        self.seed = seed
        self._map: dict[str, tuple[str, str]] = {} # token -> (kind, original)
        self._new: dict[str, tuple[str, str]] = {} # not yet persisted
        self._used: dict[str, int] = {} # token -> replacements in this session
        self.known: dict[str, set[str]] = {"HOST": set(), "DOMAIN": set(), "USER": set(), "TERM": set()}
        self.known_substring: set[str] = set() # custom TERMs matched anywhere, not only as whole words
        self._preferred: dict[tuple[str, str], str] = {} # (kind, key) -> spelling to store/restore
        self._known_re: dict[str, Optional[re.Pattern]] = {}
        for e in existing or []:
            self._map[e["token"]] = (e["kind"], e["original"])
            if e["kind"] in self.known:
                self.known[e["kind"]].add(self._key(e["kind"], e["original"]))

    @classmethod
    def for_case(cls, case_id: str, machines: Iterable = ()) -> "Anonymizer":
        conn = case_db.get_connection(case_id)
        try:
            seed = get_or_create_seed(conn)
            rows = conn.execute("SELECT token, kind, original FROM _anon_map").fetchall()
        finally:
            conn.close()
        anon = cls(seed, [dict(r) for r in rows])
        for m in machines:
            for name in (getattr(m, "hostname", None), getattr(m, "label", None)):
                if name and _IDENT_VALUE_RE.match(name):
                    anon.add_known("HOST", name)
        for c in list_custom(case_id):
            anon.add_known(c["kind"], c["value"], force=True, substring=c["substring"])
        anon._pre_harvest_identity_tables(case_id)
        return anon

    # keys / tokens

    @staticmethod
    def _key(kind: str, value: str) -> str:
        v = value.strip()
        return v.lower() if kind in ("HOST", "DOMAIN", "EMAIL", "USER", "TERM") else v

    def token_for(self, kind: str, value: str) -> str:
        key = self._key(kind, value)
        digest = hashlib.md5(f"{self.seed}:{key}".encode("utf-8")).hexdigest()
        token = f"{kind}_{digest}"
        if token not in self._map:
            original = self._preferred.get((kind, key), value.strip())
            self._map[token] = (kind, original)
            self._new[token] = (kind, original)
        self._used[token] = self._used.get(token, 0) + 1
        return token

    def add_known(self, kind: str, value: str, preferred: bool = True, force: bool = False, substring: bool = False) -> None:
        if not value:
            return
        v = value.strip().rstrip(".")
        if force:
            if kind not in self.known:
                return
            v = value.strip()
            if kind == "TERM" and substring:
                self.known_substring.add(self._key(kind, v))
                self._known_re.pop("TERM_SUB", None)
                self._preferred.setdefault((kind, self._key(kind, v)), v)
                return
        elif kind == "HOST":
            if _generic_host(v) or not _IDENT_VALUE_RE.match(v) or _domain_allowlisted(v):
                return
            if v.endswith("$"):
                v = v[:-1]
            if "." in v: # FQDN: short name as host, the rest as domain
                short, _, dom = v.partition(".")
                self.add_known("DOMAIN", dom, preferred)
                if short.lower() in _GENERIC_HOST_LABELS:
                    pass # "www.acme.com": keep the whole name, "www" alone masks nothing useful
                else:
                    v = short
                if _generic_host(v):
                    return
        elif kind == "DOMAIN":
            if _generic_domain(v) or not _IDENT_VALUE_RE.match(v):
                return
        elif kind == "USER":
            if v.endswith("$"):
                self.add_known("HOST", v[:-1])
                return
            if "\\" in v: # DOMAIN\user
                dom, _, v = v.rpartition("\\")
                self.add_known("DOMAIN", dom.lstrip("\\"), preferred)
            if "@" in v: # UPN: the e-mail regex takes care of it
                return
            v = v.strip(", ")
            words = v.lower().split()
            if _generic_user(v) or not _USER_VALUE_RE.match(v) or len(words) > 3:
                return
            if len(words) > 1 and any(w.strip(".,") in _VENDOR_WORDS for w in words):
                return
        else:
            return
        key = self._key(kind, v)
        if preferred:
            self._preferred.setdefault((kind, key), v)
        if key not in self.known[kind]:
            self.known[kind].add(key)
            self._known_re.pop(kind, None)

    def _compiled_known(self, kind: str) -> Optional[re.Pattern]:
        if kind in self._known_re:
            return self._known_re[kind]
        names = sorted(self.known_substring if kind == "TERM_SUB" else self.known[kind], key=len, reverse=True)
        if not names:
            self._known_re[kind] = None
            return None
        alt = "|".join(re.escape(n) for n in names)
        if kind == "TERM_SUB":
            pat = re.compile(rf"(?:{alt})", re.IGNORECASE)
        elif kind == "TERM":
            pat = re.compile(rf"(?<!\w)(?:{alt})(?!\w)", re.IGNORECASE)
        elif kind == "HOST":
            # also the FQDN forms
            pat = re.compile(rf"(?<![\w.@-])(?:{alt})(?:\.[A-Za-z0-9-]+)*(?![\w-])", re.IGNORECASE)
        elif kind == "DOMAIN":
            pat = re.compile(rf"(?<![\w.@/-])(?:{alt})(?![\w.-])", re.IGNORECASE)
        else:
            pat = re.compile(rf"(?<![\w@.-])(?:{alt})(?![\w-])", re.IGNORECASE)
        self._known_re[kind] = pat
        return pat

    # harvesting

    def harvest_rows(self, rows: list[dict]) -> None:
        """Identifiers from user/host/domain-named columns, plus profile-path
        usernames anywhere in the row values."""
        texts = []
        for r in rows:
            uid = _numeric_uid(r)
            for col, val in r.items():
                if not isinstance(val, str) or not val:
                    continue
                texts.append(val)
                if len(val) > 256:
                    continue
                cn = _norm_col(col)
                if cn in _USER_COLS or cn.endswith(_USER_COL_SUFFIXES):
                    if uid is None or not (0 < uid < 1000): # Unix system accounts identify nobody
                        self.add_known("USER", val)
                elif cn in _HOST_COLS or cn.endswith(_HOST_COL_SUFFIXES):
                    self.add_known("HOST", val)
                elif cn in _DOMAIN_COLS:
                    self.add_known("DOMAIN", val)
        if texts:
            self.harvest_text(self._CELL_SEP.join(texts))

    def harvest_text(self, text: str) -> None:
        """Profile-path usernames anywhere in free text / serialized rows."""
        for m in _PROFILE_PATH_RE.finditer(text):
            self.add_known("USER", m.group(2), preferred=False)

    def _pre_harvest_identity_tables(self, case_id: str) -> None:
        """Account/login tables name every user of a host, including ones
        that only ever show up inside command lines elsewhere."""
        try:
            conn = case_db.get_connection(case_id)
        except Exception:
            return
        try:
            case_db.ensure_meta_table(conn)
            metas = conn.execute("SELECT table_name, table_label FROM _artifact_meta").fetchall()
            for meta in metas:
                label = (meta["table_label"] or "").lower()
                if not any(h in label for h in ("accounts", "passwd", "logins", "lastlog", "wtmp", "users")):
                    continue
                try:
                    rows = conn.execute(f"SELECT * FROM {case_db.safe_ident(meta['table_name'])} LIMIT 5000").fetchall()
                except Exception:
                    continue
                self.harvest_rows([dict(r) for r in rows])
        except Exception:
            pass
        finally:
            conn.close()

    # anonymizing

    def anonymize_text(self, text: Optional[str]) -> Optional[str]:
        if not text or (_SKIP_CELL_RE.match(text) and not _IPV4_RE.search(text)):
            return text
        self.harvest_text(text)
        out = text

        def _url(m: re.Match) -> str:
            url = m.group(0)
            trail = ""
            while url and url[-1] in ".,;:!?":
                trail = url[-1] + trail
                url = url[:-1]
            hm = _URL_HOST_RE.match(url)
            host = hm.group(1) if hm else ""
            if host and _domain_allowlisted(host):
                return m.group(0)
            return self.token_for("URL", url) + trail
        out = _URL_RE.sub(_url, out)

        def _unc(m: re.Match) -> str:
            server = m.group(1)
            if _generic_host(server) or _is_ip(server):
                return m.group(0)
            prefix = m.group(0)[: len(m.group(0)) - len(server)]
            return prefix + self.token_for("HOST", server)
        out = _UNC_RE.sub(_unc, out)

        out = _EMAIL_RE.sub(lambda m: self.token_for("EMAIL", m.group(0)) if _email_plausible(m.group(0)) else m.group(0), out)
        out = _IPV6_RE.sub(lambda m: m.group(0) if _ipv6_is_noise(m.group(0)) else self.token_for("IP", m.group(0)), out)
        out = _IPV4_RE.sub(lambda m: m.group(0) if _ipv4_is_noise(m.group(0)) else self.token_for("IP", m.group(0)), out)
        out = _SID_RE.sub(lambda m: self.token_for("SID", m.group(0)), out)

        def _mac(m: re.Match) -> str:
            raw = m.group(0)
            if re.fullmatch(r"(?:00[:-]){5}00|(?:[Ff]{2}[:-]){5}[Ff]{2}", raw):
                return raw
            return self.token_for("MAC", raw)
        out = _MAC_RE.sub(_mac, out)

        # Analyst-defined terms outrank the heuristics.
        for kind in ("TERM", "TERM_SUB"):
            term_re = self._compiled_known(kind)
            if term_re:
                out = term_re.sub(lambda m: self.token_for("TERM", m.group(0)), out)

        # Profile paths before the host dictionary
        out = _PROFILE_PATH_RE.sub(
            lambda m: m.group(1) + (m.group(2) if _generic_user(m.group(2)) else self.token_for("USER", m.group(2))), out
        )

        host_re = self._compiled_known("HOST")
        if host_re:
            out = host_re.sub(lambda m: self.token_for("HOST", m.group(0)), out)

        def _fqdn(m: re.Match) -> str:
            name, tld = m.group(1), m.group(2).lower()
            if tld in _FILE_EXT_TLDS or _domain_allowlisted(name):
                return m.group(0)
            labels = name.split(".")
            if all(l.isdigit() for l in labels[:-1]):
                return m.group(0)
            return self.token_for("DOMAIN", name)
        out = _FQDN_RE.sub(_fqdn, out)

        dom_re = self._compiled_known("DOMAIN")
        if dom_re:
            out = dom_re.sub(lambda m: self.token_for("DOMAIN", m.group(0)), out)
        user_re = self._compiled_known("USER")
        if user_re:
            out = user_re.sub(lambda m: self.token_for("USER", m.group(0)), out)
        return out

    _CELL_SEP = "\x1f"

    def anonymize_rows(self, rows: list[dict]) -> list[dict]:
        cells = [(i, k) for i, r in enumerate(rows) for k, v in r.items() if isinstance(v, str) and v]
        if not cells:
            return rows
        values = [rows[i][k] for i, k in cells]
        if any(self._CELL_SEP in v for v in values):
            masked = [self.anonymize_text(v) for v in values]
        else:
            masked = self.anonymize_text(self._CELL_SEP.join(values)).split(self._CELL_SEP)
            if len(masked) != len(values):
                masked = [self.anonymize_text(v) for v in values]
        out = [dict(r) for r in rows]
        for (i, k), v in zip(cells, masked):
            out[i][k] = v
        return out

    # restoring

    def restore_text(self, text: Optional[str]) -> tuple[Optional[str], int]:
        if not text:
            return text, 0
        unrestored = 0

        def _sub(m: re.Match) -> str:
            nonlocal unrestored
            token = f"{m.group(1).upper()}_{m.group(2).lower()}"
            hit = self._map.get(token)
            if hit:
                return hit[1]
            unrestored += 1
            return m.group(0)
        return _TOKEN_RE.sub(_sub, text), unrestored

    # persistence / stats

    def persist(self, case_id: str) -> int:
        if not self._new:
            return 0
        conn = case_db.get_connection(case_id)
        try:
            ensure_tables(conn)
            now = dt.datetime.utcnow().isoformat()
            conn.executemany(
                "INSERT OR IGNORE INTO _anon_map (token, kind, original, created_at) VALUES (?, ?, ?, ?)",
                [(t, k, o, now) for t, (k, o) in self._new.items()],
            )
            conn.commit()
            n = len(self._new)
            self._new.clear()
            return n
        finally:
            conn.close()

    def used_entries(self) -> list[dict]:
        """What this request masks: one row per distinct value, most frequent first."""
        rows = [
            {"token": t, "kind": self._map[t][0], "original": self._map[t][1], "occurrences": n, "new": t in self._new}
            for t, n in self._used.items()
        ]
        rows.sort(key=lambda r: (-r["occurrences"], r["kind"], r["original"].lower()))
        return rows

    def stats(self, unrestored: int = 0) -> dict:
        by_kind: dict[str, int] = {}
        for token in self._used:
            kind = self._map[token][0]
            by_kind[kind] = by_kind.get(kind, 0) + 1
        return {
            "values_masked": len(self._used),
            "replacements": sum(self._used.values()),
            "by_kind": by_kind,
            "unrestored_tokens": unrestored,
            "map_size": len(self._map),
        }
