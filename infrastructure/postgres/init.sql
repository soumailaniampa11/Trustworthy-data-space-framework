-- One database and one role per service: a service cannot read another's state.
-- Development passwords; they must match DATABASE_URL in docker-compose.yml.
CREATE ROLE authority     LOGIN PASSWORD 'authority';
CREATE ROLE catalog       LOGIN PASSWORD 'catalog';
CREATE ROLE transparency  LOGIN PASSWORD 'transparency';
CREATE ROLE connector_a   LOGIN PASSWORD 'connector_a';
CREATE ROLE connector_b   LOGIN PASSWORD 'connector_b';
CREATE ROLE connector_c   LOGIN PASSWORD 'connector_c';

CREATE DATABASE authority    OWNER authority;
CREATE DATABASE catalog      OWNER catalog;
CREATE DATABASE transparency OWNER transparency;
CREATE DATABASE connector_a  OWNER connector_a;
CREATE DATABASE connector_b  OWNER connector_b;
CREATE DATABASE connector_c  OWNER connector_c;

REVOKE CONNECT ON DATABASE authority, catalog, transparency, connector_a, connector_b, connector_c FROM PUBLIC;
