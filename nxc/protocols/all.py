import contextlib
import copy
from concurrent.futures import ThreadPoolExecutor, as_completed
from os.path import join as path_join

from nxc.connection import connection
from nxc.database import create_db_engine
from nxc.logger import nxc_logger, NXCAdapter
from nxc.loaders.protocolloader import ProtocolLoader
from nxc.config import nxc_workspace
from nxc.paths import WORKSPACE_DIR

ALL_PROTOCOLS = ["ftp", "ssh", "wmi", "smb", "mssql", "rpc", "rdp", "vnc", "ldap", "winrm", "nfs"]

PROTOCOL_PORTS = {
    "ftp": 21,
    "ssh": 22,
    "wmi": 135,
    "smb": 445,
    "mssql": 1433,
    "rpc": 135,
    "rdp": 3389,
    "vnc": 5900,
    "ldap": 389,
    "winrm": ["5985", "5986"],
    "nfs": 111,
}

DOMAIN_PROTOCOLS = {"smb", "mssql", "rpc", "rdp", "ldap", "winrm", "wmi"}

PROTOCOL_EXTRA_DEFAULTS = {
    "smb": {
        "hash": [],
        "local_auth": False,
        "share": "C$",
        "smb_server_port": 445,
        "no_smbv1": False,
        "no_admin_check": False,
        "gen_relay_list": None,
        "smb_timeout": 2,
        "laps": None,
        "generate_hosts_file": None,
        "generate_krb5_file": None,
        "generate_tgt": None,
        "sam": None,
        "lsa": None,
        "ntds": None,
        "dpapi": None,
        "sccm": None,
        "mkfile": None,
        "pvk": None,
        "list_snapshots": None,
        "shares": None,
        "exclude_shares": None,
        "dir": None,
        "interfaces": False,
        "no_write_check": False,
        "filter_shares": None,
        "disks": False,
        "users": None,
        "users_export": None,
        "groups": None,
        "local_groups": None,
        "computers": None,
        "pass_pol": False,
        "rid_brute": None,
        "smb_sessions": False,
        "reg_sessions": None,
        "loggedon_users": None,
        "loggedon_users_filter": None,
        "qwinsta": None,
        "tasklist": None,
        "taskkill": None,
        "wmi_query": None,
        "wmi_namespace": "root\\cimv2",
        "spider": None,
        "spider_folder": ".",
        "content": False,
        "exclude_dirs": "",
        "depth": None,
        "only_files": False,
        "silent": False,
        "pattern": None,
        "regex": None,
        "put_file": None,
        "get_file": None,
        "append_host": False,
        "exec_method": "wmiexec",
        "dcom_timeout": 5,
        "get_output_tries": 100,
        "codec": "utf-8",
        "no_output": False,
        "execute": None,
        "ps_execute": None,
        "obfs": False,
        "amsi_bypass": None,
        "clear_obfscripts": False,
        "force_ps32": False,
        "no_encode": False,
        "delegate": None,
        "delegate_spn": None,
        "generate_st": None,
        "no_s4u2proxy": None,
        "userntds": None,
    },
    "ssh": {
        "key_file": None,
        "ssh_timeout": 15,
        "sudo_check": False,
        "sudo_check_method": "sudo-stdin",
        "get_output_tries": 5,
        "put_file": None,
        "get_file": None,
        "codec": "utf-8",
        "no_output": False,
        "execute": None,
    },
    "ftp": {
        "ls": None,
        "get": None,
        "put": None,
    },
    "wmi": {
        "hash": [],
        "local_auth": False,
        "rpc_timeout": 2,
        "list_snapshots": None,
        "wmi_query": None,
        "wmi_namespace": "root\\cimv2",
        "no_output": False,
        "execute": None,
        "execute_psh": None,
        "exec_method": "wmiexec",
        "exec_timeout": 2,
        "codec": "utf-8",
    },
    "mssql": {
        "hash": [],
        "local_auth": False,
        "mssql_timeout": 5,
        "query": None,
        "database": None,
        "sam": None,
        "lsa": None,
        "no_output": False,
        "execute": None,
        "ps_execute": None,
        "force_ps32": False,
        "obfs": False,
        "amsi_bypass": None,
        "clear_obfscripts": False,
        "no_encode": False,
        "put_file": None,
        "get_file": None,
        "rid_brute": None,
    },
    "rpc": {
        "hash": [],
        "local_auth": False,
        "rpc_timeout": 2,
        "server_info": False,
        "enum_domains": False,
        "enum_trusts": False,
        "domain_info": False,
        "pass_pol": False,
        "users": False,
        "rid_brute": None,
        "user": None,
        "user_groups": None,
        "lookup_names": None,
        "groups": False,
        "group": None,
        "local_groups": False,
        "sessions": False,
        "connections": False,
        "lookup_name": None,
        "lsa_enum_privileges": False,
        "lsa_enum_account_rights": None,
        "lsa_create_account": None,
        "lsa_query_security": False,
        "sid_lookup": None,
        "sam_lookup": None,
        "create_user": None,
        "delete_user": None,
        "enable_user": None,
        "disable_user": None,
        "set_user_info": None,
        "create_group": None,
        "delete_group": None,
        "add_to_group": None,
        "remove_from_group": None,
    },
    "rdp": {
        "hash": [],
        "local_auth": False,
        "rdp_timeout": 5,
        "nla_screenshot": False,
        "screenshot": False,
        "screentime": 10,
        "res": "1024x768",
        "execute": None,
        "ps_execute": None,
        "cmd_delay": 5,
        "clipboard_delay": 30,
        "no_output": False,
    },
    "vnc": {
        "vnc_sleep": 5,
        "screenshot": False,
        "screentime": 5,
    },
    "ldap": {
        "hash": [],
        "local_auth": False,
        "simple_bind": False,
        "asreproast": None,
        "kerberoasting": None,
        "kerberoast_account": None,
        "no_preauth_targets": None,
        "base_dn": None,
        "query": None,
        "find_delegation": False,
        "trusted_for_delegation": False,
        "password_not_required": False,
        "admin_count": False,
        "users": None,
        "users_export": None,
        "groups": None,
        "computers": False,
        "dc_list": False,
        "get_sid": False,
        "active_users": None,
        "pso": False,
        "pass_pol": False,
        "gmsa": False,
        "gmsa_convert_id": None,
        "gmsa_decrypt_lsa": None,
        "bloodhound": False,
        "collection": "Default",
    },
    "winrm": {
        "hash": [],
        "local_auth": False,
        "check_proto": ["http", "https"],
        "laps": None,
        "http_timeout": 10,
        "dump_method": "cmd",
        "sam": False,
        "lsa": False,
        "dpapi": False,
        "codec": "utf-8",
        "no_output": False,
        "execute": None,
        "ps_execute": None,
    },
    "nfs": {
        "nfs_timeout": 5,
        "share": None,
        "shares": False,
        "enum_shares": None,
        "ls": None,
        "get_file": None,
        "put_file": None,
    },
}


class all(connection):
    def __init__(self, args, db, target):
        self.protocol = "ALL"
        self.p_loader = ProtocolLoader()
        self.available_protocols = self.p_loader.get_protocols()
        super().__init__(args, db, target)

    def proto_logger(self):
        self.logger = NXCAdapter(
            extra={
                "protocol": "ALL",
                "host": self.host,
                "port": self.port,
                "hostname": self.hostname,
            }
        )

    def create_conn_obj(self):
        return True

    def enum_host_info(self):
        pass

    def print_host_info(self):
        protocols_to_run = self._get_protocols_to_run()
        self.logger.display(f"Running authentication across {len(protocols_to_run)} protocol(s): {', '.join(protocols_to_run).upper()}")

    def proto_flow(self):
        self.proto_logger()
        self.print_host_info()
        self._run_all_protocols()

    def _get_protocols_to_run(self):
        protocols_arg = getattr(self.args, "protocols", None)
        if protocols_arg:
            return [p.strip() for p in protocols_arg.split(",") if p.strip() in ALL_PROTOCOLS]
        return list(ALL_PROTOCOLS)

    def _build_sub_args(self, protocol_name):
        sub_args = copy.copy(self.args)
        sub_args.protocol = protocol_name
        sub_args.module = None
        sub_args.list_modules = None
        sub_args.show_module_options = False

        port = PROTOCOL_PORTS.get(protocol_name)
        if port is not None:
            sub_args.port = port

        if protocol_name not in DOMAIN_PROTOCOLS and "domain" in sub_args.__dict__:
            del sub_args.__dict__["domain"]

        for key, value in PROTOCOL_EXTRA_DEFAULTS.get(protocol_name, {}).items():
            if key not in sub_args.__dict__:
                setattr(sub_args, key, value)

        return sub_args

    def _load_sub_db(self, protocol_name):
        proto_info = self.available_protocols.get(protocol_name)
        if not proto_info or "dbpath" not in proto_info:
            return None
        try:
            db_path = path_join(WORKSPACE_DIR, nxc_workspace, f"{protocol_name}.db")
            db_engine = create_db_engine(db_path)
            db_cls = self.p_loader.load_protocol(proto_info["dbpath"]).database
            return db_cls(db_engine)
        except Exception as e:
            nxc_logger.debug(f"Could not load {protocol_name} database: {e}")
            return None

    def _run_protocol(self, protocol_name):
        if protocol_name not in self.available_protocols:
            nxc_logger.debug(f"Protocol {protocol_name} not available, skipping")
            return
        try:
            sub_db = self._load_sub_db(protocol_name)
            if sub_db is None:
                nxc_logger.debug(f"No database for {protocol_name}, skipping")
                return
            sub_args = self._build_sub_args(protocol_name)
            proto_info = self.available_protocols[protocol_name]
            proto_cls = getattr(self.p_loader.load_protocol(proto_info["path"]), protocol_name)
            proto_cls(sub_args, sub_db, self.hostname)
        except Exception as e:
            nxc_logger.debug(f"Error running {protocol_name} against {self.hostname}: {e}")

    def _run_all_protocols(self):
        targets = self._get_protocols_to_run()
        with ThreadPoolExecutor(max_workers=len(targets)) as executor:
            futures = {executor.submit(self._run_protocol, proto): proto for proto in targets}
            for future in as_completed(futures):
                with contextlib.suppress(Exception):
                    future.result()
