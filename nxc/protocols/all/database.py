from sqlalchemy import Column, Integer, String, PrimaryKeyConstraint, select
from sqlalchemy.dialects.sqlite import Insert
from sqlalchemy.orm import declarative_base

from nxc.database import BaseDB
from nxc.logger import nxc_logger

Base = declarative_base()


class database(BaseDB):
    def __init__(self, db_engine):
        self.HostsTable = None
        super().__init__(db_engine)

    class Host(Base):
        __tablename__ = "hosts"
        id = Column(Integer)
        host = Column(String)

        __table_args__ = (PrimaryKeyConstraint("id"),)

    @staticmethod
    def db_schema(db_conn):
        Base.metadata.create_all(db_conn)

    def reflect_tables(self):
        self.HostsTable = self.reflect_table(self.Host)

    def get_credentials(self, filter_term=None):
        return []

    def is_credential_valid(self, cred_id):
        return False

    def get_hosts(self, filter_term=None):
        q = select(self.HostsTable)
        results = self.db_execute(q).all()
        nxc_logger.debug(f"ALL get_hosts() - results: {results}")
        return results

    def add_host(self, host):
        hosts = []
        q = select(self.HostsTable).filter(self.HostsTable.c.host == host)
        results = self.db_execute(q).all()
        if not results:
            hosts = [{"host": host}]
            q = Insert(self.HostsTable)
            update_columns = {col.name: col for col in q.excluded if col.name not in "id"}
            q = q.on_conflict_do_update(index_elements=self.HostsTable.primary_key, set_=update_columns)
            self.db_execute(q, hosts)
