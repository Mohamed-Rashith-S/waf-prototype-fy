const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
// Serves the HTML file from the 'public' folder
app.use(express.static(path.join(__dirname, 'public'))); 

// --- DATABASE (In-Memory) ---
let stats = {
    total: 0,
    blocked: 0,
    sql: 0,
    xss: 0,
    rce: 0
};
let logs = [];

// --- WAF ENGINE LOGIC ---
function analyzePacket(input) {
    if (!input) return { blocked: false, type: 'Empty', severity: 'LOW' };
    
    const s = input.toLowerCase();
    
    // SQL Injection Patterns
    if (s.match(/(select|union|insert|update|drop|--|' or 1=1|1=1)/)) 
        return { blocked: true, type: 'SQL Injection', severity: 'HIGH' };
    
    // XSS Patterns
    if (s.match(/(<script|javascript:|onerror=|onload=|alert\()/)) 
        return { blocked: true, type: 'XSS', severity: 'MEDIUM' };

    // RCE (Command Injection) Patterns
    if (s.match(/(; ls|&&|\||sudo|cmd.exe|\/etc\/passwd|cat |ping )/)) 
        return { blocked: true, type: 'Remote Code Exec', severity: 'CRITICAL' };

    return { blocked: false, type: 'Valid Request', severity: 'LOW' };
}

// --- API ROUTES ---

// 1. Check Payload
app.post('/api/check', (req, res) => {
    const payload = req.body.userInput || '';
    // specific logic to catch localhost or real IP
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
    
    stats.total++;
    
    const result = analyzePacket(payload);
    
    const logEntry = {
        id: Date.now(),
        time: new Date().toISOString(),
        ip: ip.replace('::ffff:', ''), // Clean up IPv6 prefix if present
        payload: payload,
        ...result
    };

    logs.unshift(logEntry);
    if(logs.length > 50) logs.pop(); // Keep only last 50 logs

    if(result.blocked) {
        stats.blocked++;
        if(result.type.includes('SQL')) stats.sql++;
        if(result.type.includes('XSS')) stats.xss++;
        if(result.type.includes('Code')) stats.rce++;
        
        return res.status(200).json({ status: 'blocked', log: logEntry });
    }

    res.json({ status: 'allowed', log: logEntry });
});

// 2. Get Stats
app.get('/api/stats', (req, res) => {
    res.json({ stats, logs });
});

// 3. Reset System
app.post('/api/reset', (req, res) => {
    stats = { total: 0, blocked: 0, sql: 0, xss: 0, rce: 0 };
    logs = [];
    res.json({ success: true });
});

app.listen(PORT, () => console.log(`[AIGuard] Server running on http://localhost:${PORT}`));
