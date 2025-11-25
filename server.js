const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors'); 

const app = express();
const PORT = process.env.PORT || 3000; 

// Allow all connections
app.use(cors()); 
app.use(bodyParser.json()); 

// --- SECURITY LOGIC ---
function wafCheck(input) {
    if (!input) return { blocked: false, type: 'SAFE', reason: 'Empty input' };
    
    const lowerInput = input.toLowerCase();
    
    // 1. SQL Injection Checks
    const sqliPatterns = ['select *', 'union select', ' or 1=1', '--', 'drop table', 'update users', 'insert into'];
    for (const pattern of sqliPatterns) {
        if (lowerInput.includes(pattern)) {
            return { blocked: true, type: 'SQL INJECTION', reason: 'Database manipulation signature detected' };
        }
    }

    // 2. XSS Checks
    const xssPatterns = ['<script', 'javascript:', 'onerror=', 'onload=', 'alert(', 'document.cookie'];
    for (const pattern of xssPatterns) {
        if (lowerInput.includes(pattern)) {
            return { blocked: true, type: 'XSS ATTACK', reason: 'Malicious script tag detected' };
        }
    }

    // 3. Command Injection Checks
    const cmdPatterns = ['; ls', '&&', '|', 'cat /etc/passwd', 'whoami', 'cmd.exe'];
    for (const pattern of cmdPatterns) {
        if (lowerInput.includes(pattern)) {
            return { blocked: true, type: 'RCE ATTACK', reason: 'System command execution detected' };
        }
    }

    return { blocked: false, type: 'SAFE', reason: 'Traffic looks clean' }; 
}

// --- API ROUTE ---
app.post('/api/check', (req, res) => {
    const userInput = req.body.userInput || '';
    const result = wafCheck(userInput);
    
    // Create a Timestamp for the server log
    const time = new Date().toISOString();

    if (result.blocked) {
        // Log with Timestamp (Helps you debug on Render)
        console.log(`[${time}] 🔴 BLOCKED: ${result.type} | Input: "${userInput}"`);
        
        return res.status(403).json({ 
            status: 'blocked', 
            type: result.type, 
            message: result.reason 
        });
    }

    console.log(`[${time}] 🟢 SAFE: Input: "${userInput}"`);
    res.json({ 
        status: 'safe', 
        type: 'SAFE',
        message: result.reason 
    });
});

// --- HEALTH CHECK ROUTE ---
// Makes the root URL look like a real API
app.get('/', (req, res) => {
    res.json({
        system: 'WAF Prototype',
        status: 'Online',
        timestamp: new Date()
    });
});

app.listen(PORT, () => console.log(`>>> WAF Server running on port ${PORT}`));
