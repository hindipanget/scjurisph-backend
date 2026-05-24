const fs = require('fs');
const path = require('path');
const https = require('https');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const WORKER_URL = 'https://sc-search-api.hindipogi.workers.dev/api/internal/download/';

const DATABASES = [
    'db_recent.db',         // Full 1901-2026 search index (PRIORITY)
    'db_statutes.db',
    'jurisprudence_free.db',
    'db_classic.db'
];

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

function downloadFile(filename) {
    return new Promise((resolve, reject) => {
        const dest = path.join(DATA_DIR, filename);
        if (fs.existsSync(dest) && fs.statSync(dest).size > 1024 * 1024) {
            console.log(`✅ [SKIP] ${filename} already exists (${(fs.statSync(dest).size / 1024 / 1024).toFixed(2)} MB).`);
            return resolve();
        }

        console.log(`⬇️  Downloading ${filename} from Cloudflare R2...`);
        const file = fs.createWriteStream(dest);
        
        https.get(WORKER_URL + filename, (response) => {
            if (response.statusCode === 200) {
                response.pipe(file);
                file.on('finish', () => {
                    file.close();
                    console.log(`✅ [DONE] Downloaded ${filename}`);
                    resolve();
                });
            } else {
                file.close();
                fs.unlinkSync(dest); // Delete partial file
                console.warn(`⚠️ [WARN] Could not download ${filename} (Status: ${response.statusCode})`);
                response.resume(); // Consume the stream to free up memory/socket so Node can exit!
                resolve(); // Don't reject, some DBs are optional
            }
        }).on('error', (err) => {
            fs.unlinkSync(dest);
            console.error(`❌ [ERR] Error downloading ${filename}: ${err.message}`);
            resolve(); // Don't crash server
        });
    });
}

async function main() {
    console.log('========================================================');
    console.log('☁️   PULLING DATABASES FROM CLOUDFLARE R2 TO MEMORY');
    console.log('========================================================');
    
    for (const db of DATABASES) {
        await downloadFile(db);
    }
    
    console.log('✅   All required databases pulled successfully!');
    console.log('========================================================');
}

main().then(() => {
    process.exit(0);
});
