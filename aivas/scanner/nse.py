QUICK_SCRIPTS = "banner,ssh-auth-methods,http-title"

FULL_SCRIPTS = (
    "banner,ssh-auth-methods,http-title,"
    "http-shellshock,http-vuln-cve2017-5638,"
    "smb-vuln-ms17-010,smb-vuln-cve2009-3103,"
    "ftp-vsftpd-backdoor,ftp-proftpd-backdoor"
)

UDP_SCRIPTS = "snmp-info,nbstat"


def scripts_for_level(level: int) -> str:
    if level == 1:
        return QUICK_SCRIPTS
    return FULL_SCRIPTS
