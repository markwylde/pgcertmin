const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

const CA_CERT_PATH = process.env.CA_CERT_PATH || '/data/certs/postgres-clients/ca.crt';
const CA_KEY_PATH = process.env.CA_KEY_PATH || '/data/certs/postgres-clients/ca.key'; // Only needed for signing
const CLIENT_CERTS_DIR = process.env.CLIENT_CERTS_DIR || '/data/certs/postgres-clients/';

// Ensure dir exists (mocking for dev if needed, but assuming it exists on prod)
if (!fs.existsSync(CLIENT_CERTS_DIR)) {
    // console.warn(`Client certs dir ${CLIENT_CERTS_DIR} likely missing in dev.`);
}

const CertManager = {
    getCaCert: async () => {
        try {
            return await fs.promises.readFile(CA_CERT_PATH, 'utf8');
        } catch (e) {
            console.error('Error reading CA cert:', e);
            return null;
        }
    },

    listCerts: async () => {
        try {
            // This is a naive implementation: listing .crt files in the dir
            const files = await fs.promises.readdir(CLIENT_CERTS_DIR);
            const certs = files.filter(f => f.endsWith('.crt') && f !== 'ca.crt').map(f => {
                const name = f.replace('.crt', '');
                const stats = fs.statSync(path.join(CLIENT_CERTS_DIR, f));
                return {
                    name: name,
                    created: stats.birthtime, // or mtime
                    // We could parse the cert to get expiry but that's expensive for a list
                };
            });
            return certs;
        } catch (e) {
            console.error('Error listing certs:', e);
            return [];
        }
    },

    createCert: async (name) => {
        const safeName = name.replace(/[^a-z0-9-_]/gi, '');
        if (!safeName) throw new Error("Invalid name");

        const keyPath = path.join(CLIENT_CERTS_DIR, `${safeName}.key`);
        const csrPath = path.join(CLIENT_CERTS_DIR, `${safeName}.csr`);
        const crtPath = path.join(CLIENT_CERTS_DIR, `${safeName}.crt`);

        try {
            // 1. Generate Key
            await execPromise(`openssl genrsa -out ${keyPath} 2048`);
            
            // 2. Generate CSR
            // Subject needs to be correct. CN usually matches the DB user if mapping is 1:1, or verification logic.
            // Prompt says: "postgresql://puzed-app@...".
            // Standard mapping: CN = db_user.
            // I'll make CN = name.
            await execPromise(`openssl req -new -key ${keyPath} -out ${csrPath} -subj "/CN=${safeName}"`);

            // 3. Sign CSR with CA
            // valid for 365 days
            await execPromise(`openssl x509 -req -in ${csrPath} -CA ${CA_CERT_PATH} -CAkey ${CA_KEY_PATH} -CAcreateserial -out ${crtPath} -days 365 -sha256`);

            // Cleanup CSR
            try { await fs.promises.unlink(csrPath); } catch (e) {}

            return { success: true };
        } catch (e) {
            console.error('Error creating cert:', e);
            throw e;
        }
    },
    
    getPaths: (name) => {
        const safeName = name.replace(/[^a-z0-9-_]/gi, '');
         return {
            cert: path.join(CLIENT_CERTS_DIR, `${safeName}.crt`),
            key: path.join(CLIENT_CERTS_DIR, `${safeName}.key`)
        };
    }
};

module.exports = CertManager;
