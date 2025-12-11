# pgcertmin

A PostgreSQL security min-lab environment focusing on SSL configuration and Client Certificate Authentication.

## Features

- **PostgreSQL 16** running in Docker.
- **SSL Enabled**: Server configured with SSL.
- **Client Certificate Authentication**: Enforced verification for client connections.
- **Management UI**: A web interface to manage databases, users, and certificates.
- **Logging**: Detailed logging of connections and disconnections.

## Getting Started

### Prerequisites

- Docker & Docker Compose
- Node.js (v20+)

### Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/markwylde/pgcertmin.git
    cd pgcertmin
    ```

2.  Install dependencies:
    ```bash
    npm install
    ```

3.  Start the application and database:
    ```bash
    docker-compose up -d
    npm run dev
    ```

4.  Access the UI at `http://localhost:3000`.

## Architecture

- `docker-compose.yml`: Defines the PostgreSQL service configuration.
- `local-certs/`: Stores generated SSL certificates.
- `src/`: Backend Node.js application (Express).
- `public/`: Frontend assets.
- `postgres-config/`: PostgreSQL configuration files (init.sql, pg_hba.conf).
