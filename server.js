const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors'); 

const app = express();
const PORT = process.env.PORT || 3000; 

// Allow all connections so your frontend works immediately
app.use(cors()); 
app.use(bodyParser.json()); 

// --- SECURITY LOGIC ---
function wafCheck(input) {
    const lowerInput = input.toLowerCase();
    
    // 1. SQL Injection Checks
    const sqliPatterns = ['select *', 'union select', ' or 1=1', '--', 'drop table'];
    for (const pattern of sqliPatterns) {
        if (lowerInput.includes(pattern)) {
            return { blocked: true, type: 'SQL INJECTION', reason: 'Database manipulation signature detected' };
        }
    }

    // 2. XSS Checks
    const xssPatterns = ['<script', 'javascript:', 'onerror=', 'onload=', 'alert('];
    for (const pattern of xssPatterns) {
        if (lowerInput.includes(pattern)) {
            return { blocked: true, type: 'XSS ATTACK', reason: 'Malicious script tag detected' };
        }
    }

    // 3. Command Injection Checks
    const cmdPatterns = ['; ls', '&&', '|', 'cat /etc/passwd'];
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

    if (result.blocked) {
        console.log(`[BLOCKED] ${result.type}: ${userInput}`);
        return res.status(403).json({ 
            status: 'blocked', 
            type: result.type,
            message: result.reason 
        });
    }

    console.log(`[SAFE] ${userInput}`);
    res.json({ 
        status: 'safe', 
        type: 'SAFE',
        message: result.reason 
    });
});

app.get('/', (req, res) => res.send('WAF Server is Running.'));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
