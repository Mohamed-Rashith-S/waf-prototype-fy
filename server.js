const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors'); 

const app = express();
const PORT = process.env.PORT || 3000; 

app.use(cors()); 
app.use(bodyParser.json()); 
app.use(express.static('public')); // Serve static files if needed

// --- DATABASE (In-Memory) ---
let stats = {
    total: 0,
    blocked: 0,
    sql: 0,
    xss: 0,
    rce: 0,
    status: 'ACTIVE'
};
let logs = [];

// --- WAF ENGINE ---
function analyzePacket(input) {
    const s = input.toLowerCase();
    
    // SQL Injection
    if (s.match(/(select|union|insert|update|drop|--|' or 1=1)/)) 
        return { blocked: true, type: 'SQLi', severity: 'HIGH' };
    
    // XSS
    if (s.match(/(<script|javascript:|onerror=|onload=|alert\()/)) 
        return { blocked: true, type: 'XSS', severity: 'MEDIUM' };

    // RCE (Command Injection)
    if (s.match(/(; ls|&&|\||sudo|cmd.exe|\/etc\/passwd)/)) 
        return { blocked: true, type: 'RCE', severity: 'CRITICAL' };

    return { blocked: false, type: 'Clean', severity: 'LOW' };
}

// --- API ROUTES ---

// 1. Analyze Traffic
app.post('/api/check', (req, res) => {
    const payload = req.body.userInput || '';
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '192.168.1.55';
    
    stats.total++;
    
    const result = analyzePacket(payload);
    
    const logEntry = {
        id: Date.now(),
        time: new Date().toISOString(),
        ip: ip,
        payload: payload,
        ...result
    };

    logs.unshift(logEntry);
    if(logs.length > 50) logs.pop();

    if(result.blocked) {
        stats.blocked++;
        if(result.type === 'SQLi') stats.sql++;
        if(result.type === 'XSS') stats.xss++;
        if(result.type === 'RCE') stats.rce++;
        
        return res.status(403).json({ status: 'blocked', log: logEntry });
    }

    res.json({ status: 'allowed', log: logEntry });
});

// 2. Get Stats (Polling)
app.get('/api/stats', (req, res) => {
    res.json({ stats, logs });
});

// 3. Reset System
app.post('/api/reset', (req, res) => {
    stats = { total: 0, blocked: 0, sql: 0, xss: 0, rce: 0, status: 'ACTIVE' };
    logs = [];
    res.json({ success: true });
});

app.listen(PORT, () => console.log(`WAF Server running on port ${PORT}`));
