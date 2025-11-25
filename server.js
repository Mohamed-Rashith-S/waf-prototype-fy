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
    // Checks for keywords like UNION, SELECT, OR 1=1
    if (lowerInput.match(/(select\s\*|union\s+select|drop\s+table|or\s+1=1|--|\binsert\b|\bupdate\b)/)) {
        return { blocked: true, type: 'SQLi', severity: 'HIGH', reason: 'SQL Injection Signature' };
    }

    // 2. XSS (Medium Severity)
    // Checks for script tags, event handlers, and javascript: protocols
    if (lowerInput.match(/(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)/)) {
        return { blocked: true, type: 'XSS', severity: 'MEDIUM', reason: 'Cross-Site Scripting Pattern' };
    }

    // 3. RCE & Path Traversal (Critical Severity)
    // Checks for command chaining, directory traversal, and system files
    if (lowerInput.match(/(;\s*ls|&&\s*|\|\s*|sudo\s|cmd\.exe|\.\.\/|\.\.\\|\/etc\/passwd|whoami)/)) {
        return { blocked: true, type: 'RCE', severity: 'CRITICAL', reason: 'Remote Command Execution' };
    }

    return { blocked: false, type: 'Clean', severity: 'LOW', reason: 'Valid Request' }; 
}

// --- E. API ROUTES ---

// 1. TRAFFIC ANALYSIS ROUTE (The WAF Guard)
app.post('/api/check', (req, res) => {
    const userInput = req.body.userInput || '';
    
    // Simulate Client IP (since Render creates a proxy, real IP might be hidden)
    const clientIp = req.headers['x-forwarded-for'] || '192.168.1.' + Math.floor(Math.random() * 255);

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

    // Update History (Keep only last 50 logs)
    requestLogs.unshift(logEntry); 
    if (requestLogs.length > 50) requestLogs.pop(); 

    if (result.blocked) {
        serverStats.blockedRequests++;
        if (result.type === 'SQLi') serverStats.sqlCount++;
        if (result.type === 'XSS') serverStats.xssCount++;
        if (result.type === 'RCE') serverStats.rceCount++;

        // Change system status dynamically based on threat level
        if(serverStats.blockedRequests > 5) serverStats.systemStatus = 'ELEVATED THREAT';

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

// 3. RESET ROUTE (To clear stats for a fresh demo)
app.post('/api/reset', (req, res) => {
    serverStats = { totalRequests: 0, blockedRequests: 0, sqlCount: 0, xssCount: 0, rceCount: 0, systemStatus: 'OPERATIONAL' };
    requestLogs = [];
    res.json({ message: 'System Reset' });
});

app.get('/', (req, res) => {
    res.send('WAF Enterprise Backend is Online v3.0');
});

// F. START SERVER
app.listen(PORT, () => {
    console.log(`>>> WAF Server running on port ${PORT}`);
});
