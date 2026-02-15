def proto_args(parser, parents):
    rpc_parser = parser.add_parser("rpc", help="own stuff using MSRPC", conflict_handler="resolve", parents=parents)
    rpc_parser.add_argument("-H", "--hash", metavar="HASH", dest="hash", nargs="+", default=[], help="NTLM hash(es) or file(s) containing NTLM hashes")
    rpc_parser.add_argument("--port", type=int, default=135, help="RPC port (default: 135)")
    rpc_parser.add_argument("--rpc-timeout", help="RPC connection timeout", type=int, default=2)

    dgroup = rpc_parser.add_mutually_exclusive_group()
    dgroup.add_argument("-d", metavar="DOMAIN", dest="domain", default=None, type=str, help="Domain to authenticate to")
    dgroup.add_argument("--local-auth", action="store_true", help="Authenticate locally to each target")

    info_group = rpc_parser.add_argument_group("Server/Domain Information")
    info_group.add_argument("--server-info", action="store_true", help="Server info")
    info_group.add_argument("--enum-domains", action="store_true", help="Enumerate domains with SIDs")
    info_group.add_argument("--enum-trusts", action="store_true", help="Enumerate trusted domains")
    info_group.add_argument("--domain-info", action="store_true", help="Domain info")
    info_group.add_argument("--pass-pol", action="store_true", help="Password policy")

    user_group = rpc_parser.add_argument_group("User Enumeration")
    user_group.add_argument("--users", action="store_true", help="Enumerate users with detailed information (RID, username, password info, description)")
    user_group.add_argument("--rid-brute", nargs="?", type=int, const=4000, metavar="MAX_RID", help="RID cycling enumeration")
    user_group.add_argument("--user", metavar="RID_OR_NAME", type=str, help="Query user by RID or name")
    user_group.add_argument("--user-groups", metavar="RID_OR_NAME", type=str, help="Get groups for user")
    user_group.add_argument("--user-pass-pol", metavar="RID", type=str, help="User password info")
    user_group.add_argument("--lookup-names", metavar="NAMES", type=str, help="Lookup names")

    group_group = rpc_parser.add_argument_group("Group Enumeration")
    group_group.add_argument("--groups", action="store_true", help="Enumerate domain groups")
    group_group.add_argument("--group", metavar="RID_OR_NAME", type=str, help="Query group by RID or name")
    group_group.add_argument("--local-groups", action="store_true", help="Enumerate alias groups")

    share_group = rpc_parser.add_argument_group("Share Enumeration")
    share_group.add_argument("--shares", action="store_true", help="Enumerate shares")
    share_group.add_argument("--sessions", action="store_true", help="Enumerate sessions")
    share_group.add_argument("--connections", action="store_true", help="Enumerate connections")

    lsa_group = rpc_parser.add_argument_group("LSA Operations")
    lsa_group.add_argument("--lookup-name", metavar="NAME", type=str, help="Lookup name to SID")
    lsa_group.add_argument("--lsa-enum-privileges", action="store_true", help="Enumerate privileges")
    lsa_group.add_argument("--lsa-enum-account-rights", metavar="SID", type=str, help="Account rights")
    lsa_group.add_argument("--lsa-create-account", metavar="SID", type=str, help="Create LSA account")
    lsa_group.add_argument("--lsa-query-security", action="store_true", help="Query LSA security object")

    sid_group = rpc_parser.add_argument_group("SID/SAM Operations")
    sid_group.add_argument("--sid-lookup", metavar="SID", type=str, help="Lookup SID to name")
    sid_group.add_argument("--sam-lookup", nargs=2, metavar=("domain|builtin", "NAMES"), help="SAM lookup names")

    mgmt_group = rpc_parser.add_argument_group("User/Group Management")
    mgmt_group.add_argument("--create-user", metavar="USER:PASS", type=str, help="Create user")
    mgmt_group.add_argument("--delete-user", metavar="USER", type=str, help="Delete user")
    mgmt_group.add_argument("--enable-user", metavar="USER", type=str, help="Enable user account")
    mgmt_group.add_argument("--disable-user", metavar="USER", type=str, help="Disable user account")
    mgmt_group.add_argument("--set-user-info", nargs=3, metavar=("USER", "CLASS", "VALUE"), help="Set user info. Classes: fullname, description, comment, homedir, homedrive, script, profile, workstations, control, expires, primary-group, parameters, name (newuser:newfullname), logonhours (all/none/hex), preferences (country:codepage)")
    mgmt_group.add_argument("--create-group", metavar="GROUP", type=str, help="Create group")
    mgmt_group.add_argument("--delete-group", metavar="GROUP", type=str, help="Delete group")
    mgmt_group.add_argument("--add-to-group", metavar="USER:GROUP", type=str, help="Add user to group")
    mgmt_group.add_argument("--remove-from-group", metavar="USER:GROUP", type=str, help="Remove user from group")

    return parser
