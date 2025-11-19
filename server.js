// A. IMPORT NECESSARY MODULES
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors'); 

const app = express();
// Render automatically assigns a PORT. We use process.env.PORT for deployment, 
// and 3000 as a fallback for local testing.
const PORT = process.env.PORT || 3000; 

// B. ADD MIDDLEWARE
// Use CORS to allow requests from your Vercel-hosted frontend domain.
app.use(cors()); 
// Use body-parser to read JSON data sent by the frontend (the user input).
app.use(bodyParser.json()); 

// C. THE WAF CHECKER FUNCTION (The security logic)
function wafCheck(input) {
    const lowerInput = input.toLowerCase();
    
    // --- SQLi Detection Rules (Checks for common SQL keywords) ---
    const sqliPatterns = [
        'select * from', 
        'union select', 
        '--' // SQL comment often used to bypass checks
    ];

    for (const pattern of sqliPatterns) {
        if (lowerInput.includes(pattern)) {
            return { isBlocked: true, reason: 'SQL Injection Signature Detected' };
        }
    }

    // --- XSS Detection Rules (Checks for common script/HTML tags) ---
    const xssPatterns = [
        '<script', 
        'javascript:', 
        'onerror=',
        '<img>' 
    ];

    for (const pattern of xssPatterns) {
        if (lowerInput.includes(pattern)) {
            return { isBlocked: true, reason: 'Cross-Site Scripting (XSS) Tag Detected' };
        }
    }

    // If no malicious patterns are matched
    return { isBlocked: false, reason: "" }; 
}

// D. THE CORE API ROUTE
app.post('/api/check', (req, res) => {
    // Get the user input from the request body
    const userInput = req.body.userInput || '';

    // 1. Run the WAF check
    const checkResult = wafCheck(userInput);

    if (checkResult.isBlocked) {
        // 2. BLOCKED: Attack detected
        console.log(`ATTACK DETECTED: ${checkResult.reason} - Input: ${userInput}`);
        // Log to database would go here!
        return res.status(403).json({ 
            status: 'blocked', 
            message: `ACCESS DENIED by WAF. Reason: ${checkResult.reason}. This event has been logged.` 
        });
    }

    // 3. SAFE: Input passed the check
    res.json({ 
        status: 'safe', 
        message: `Input passed WAF check successfully. Processing: "${userInput}"` 
    });
});

// E. Basic route for health checks (Render needs this)
app.get('/', (req, res) => {
    res.send('WAF Backend is running.');
});

// F. START THE SERVER
app.listen(PORT, () => {
    console.log(`WAF Prototype running on port ${PORT}`);
});
