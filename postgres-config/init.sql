-- Create the application user if it doesn't exist (it won't because we start as postgres)
CREATE USER "puzed-app" WITH LOGIN SUPERUSER PASSWORD 'password'; -- Added SUPERUSER and PASSWORD
-- Grant permissions (simplistic for dev)
ALTER USER "puzed-app" CREATEDB;
GRANT ALL PRIVILEGES ON DATABASE puzed TO "puzed-app";

-- Setup Logging Table
CREATE EXTENSION IF NOT EXISTS file_fdw;

CREATE SERVER pglog FOREIGN DATA WRAPPER file_fdw;

CREATE FOREIGN TABLE postgres_log (
  log_time timestamp(3) with time zone,
  user_name text,
  database_name text,
  process_id integer,
  connection_from text,
  session_id text,
  session_line_num bigint,
  command_tag text,
  session_start_time timestamp with time zone,
  virtual_transaction_id text,
  transaction_id bigint,
  error_severity text,
  sql_state_code text,
  message text,
  detail text,
  hint text,
  internal_query text,
  internal_query_pos integer,
  context text,
  query text,
  query_pos integer,
  location text,
  application_name text,
  backend_type text,
  leader_pid integer,
  query_id bigint
) SERVER pglog
OPTIONS ( program 'grep "," /var/log/postgresql/postgresql.csv', format 'csv' );

GRANT SELECT ON postgres_log TO "puzed-app";
