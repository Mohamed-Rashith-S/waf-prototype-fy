// A. IMPORT MODULES
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors'); 

const app = express();
const PORT = process.env.PORT || 3000; 

// B. MIDDLEWARE
app.use(cors()); 
app.use(bodyParser.json()); 

// --- C. SERVER STATE (In-Memory Database) ---
// This keeps track of data as long as the server is running.
let serverStats = {
    totalRequests: 0,
    blockedRequests: 0,
    sqlCount: 0,
    xssCount: 0,
    rceCount: 0,
    systemStatus: 'OPERATIONAL'
};

// Store the last 50 logs for the dashboard
let requestLogs = [];

// --- D. SECURITY LOGIC (WAF ENGINE) ---
function wafCheck(input) {
    const lowerInput = input.toLowerCase();
    
    // 1. SQL Injection (High Severity)
    const sqliPatterns = ['select *', 'union select', 'drop table', ' or 1=1', '--', 'insert into', 'update users'];
    for (const pattern of sqliPatterns) {
        if (lowerInput.includes(pattern)) {
            return { blocked: true, type: 'SQLi', severity: 'HIGH', reason: 'SQL Injection Signature' };
        }
    }

    // 2. XSS (Medium Severity)
    const xssPatterns = ['<script', 'javascript:', 'onerror=', 'onload=', 'alert(', 'document.cookie'];
    for (const pattern of xssPatterns) {
        if (lowerInput.includes(pattern)) {
            return { blocked: true, type: 'XSS', severity: 'MEDIUM', reason: 'Cross-Site Scripting Pattern' };
        }
    }

    // 3. RCE & Path Traversal (Critical Severity)
    const rcePatterns = ['; ls', '&&', '|', 'sudo', 'cmd.exe', '../', '..\\', '/etc/passwd', 'whoami'];
    for (const pattern of rcePatterns) {
        if (lowerInput.includes(pattern)) {
            return { blocked: true, type: 'RCE', severity: 'CRITICAL', reason: 'Remote Command Execution' };
        }
    }

    return { blocked: false, type: 'Clean', severity: 'LOW', reason: 'Valid Request' }; 
}

// --- E. API ROUTES ---

// 1. TRAFFIC ANALYSIS ROUTE
app.post('/api/check', (req, res) => {
    const userInput = req.body.userInput || '';
    
    // Simulate Client IP for realism
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '192.168.1.' + Math.floor(Math.random() * 255);

    serverStats.totalRequests++;

    const result = wafCheck(userInput);

    // Create Log Entry
    const logEntry = {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        ip: clientIp,
        payload: userInput,
        action: result.blocked ? 'BLOCKED' : 'ALLOWED',
        type: result.type,
        severity: result.severity
    };

    // Update History
    requestLogs.unshift(logEntry); 
    if (requestLogs.length > 50) requestLogs.pop(); // Keep log size manageable

    if (result.blocked) {
        serverStats.blockedRequests++;
        if (result.type === 'SQLi') serverStats.sqlCount++;
        if (result.type === 'XSS') serverStats.xssCount++;
        if (result.type === 'RCE') serverStats.rceCount++;

        // Change system status dynamically based on threat level
        if(serverStats.blockedRequests > 10) serverStats.systemStatus = 'ELEVATED THREAT';

        console.log(`[BLOCKED] IP: ${clientIp} | Type: ${result.type}`);
        
        return res.status(403).json({ 
            status: 'blocked', 
            message: result.reason,
            log: logEntry
        });
    }

    console.log(`[ALLOWED] IP: ${clientIp} | Clean Traffic`);
    
    res.json({ 
        status: 'safe', 
        message: 'Request Allowed',
        log: logEntry
    });
});

// 2. DASHBOARD DATA ROUTE (The Frontend calls this to update charts)
app.get('/api/stats', (req, res) => {
    res.json({
        stats: serverStats,
        logs: requestLogs
    });
});

// 3. RESET ROUTE (Optional: to clear stats for a fresh demo)
app.post('/api/reset', (req, res) => {
    serverStats = { totalRequests: 0, blockedRequests: 0, sqlCount: 0, xssCount: 0, rceCount: 0, systemStatus: 'OPERATIONAL' };
    requestLogs = [];
    res.json({ message: 'System Reset' });
});

app.get('/', (req, res) => {
    res.send('WAF Enterprise Backend is Online v2.0');
});

// F. START SERVER
app.listen(PORT, () => {
    console.log(`>>> WAF Server running on port ${PORT}`);
});
