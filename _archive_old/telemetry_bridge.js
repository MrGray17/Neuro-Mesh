const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const Tail = require('tail').Tail;
const { exec } = require('child_process'); // ARCHITECTURAL ADDITION: For spawning C++ binaries

const app = express();
const server = http.createServer(app);

// CORS for React Dashboard
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});

// Allow Express to parse JSON bodies and handle CORS
app.use(express.json());
app.use(require('cors')());

const TELEMETRY_FILE = '../neuro_mesh/web/mesh_status.json';

io.on('connection', (socket) => {
    console.log('[BRIDGE] React Dashboard Connected.');
});

// ============================================================
// NEW: SOC COMMAND & CONTROL API
// ============================================================
app.post('/api/inject-threat', (req, res) => {
    console.log("[BRIDGE] Threat Injection Command Received from Dashboard.");
    
    // Execute the C++ simulator asynchronously
    exec('./simulate_threat', { cwd: '../neuro_mesh' }, (error, stdout, stderr) => {
        if (error) {
            console.error(`[ERROR] Simulator execution failed: ${error.message}`);
            return res.status(500).json({ error: "Failed to spawn threat simulator" });
        }
        console.log(`[SIMULATOR] ${stdout}`);
    });

    // Return immediate 200 OK so the React UI doesn't hang waiting for the C++ mesh to finish
    res.status(200).json({ status: "THREAT_INJECTED", message: "Mesh consensus initiated." });
});

// ============================================================
// TELEMETRY TAIL (Existing)
// ============================================================
try {
    const tail = new Tail(TELEMETRY_FILE);
    tail.on("line", function(data) {
        try {
            const event = JSON.parse(data);
            io.emit('mesh_event', event); 
        } catch (e) {}
    });
} catch (error) {
    console.error("[FATAL] Could not tail telemetry file.");
}

server.listen(4000, () => {
    console.log('[BRIDGE] WebSocket & Command Server listening on port 4000');
});
