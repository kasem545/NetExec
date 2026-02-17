from nxc.helpers.args import DisplayDefaultsNotNone


def proto_args(parser, parents):
    all_parser = parser.add_parser(
        "all",
        help="run authentication against all protocols (ftp, ssh, wmi, smb, mssql, rpc, rdp, vnc, ldap, winrm, nfs)",
        parents=parents,
        formatter_class=DisplayDefaultsNotNone,
    )
    all_parser.add_argument("--port", type=int, default=0, help="Unused (each protocol uses its own default port)")
    all_parser.add_argument("-H", "--hash", metavar="HASH", dest="hash", nargs="+", default=[], help="NTLM hash(es) or file(s) containing NTLM hashes (used for protocols that support NTLM)")
    all_parser.add_argument("--local-auth", action="store_true", help="authenticate locally to each target (for protocols that support it)")

    dgroup = all_parser.add_mutually_exclusive_group()
    dgroup.add_argument("-d", "--domain", metavar="DOMAIN", dest="domain", type=str, default=None, help="domain to authenticate to (for domain-based protocols: smb, mssql, rpc, rdp, ldap, winrm, wmi)")

    all_parser.add_argument(
        "--protocols",
        metavar="PROTO_LIST",
        default=None,
        help="comma-separated list of protocols to run (default: all). Available: ftp,ssh,wmi,smb,mssql,rpc,rdp,vnc,ldap,winrm,nfs",
    )

    return parser
