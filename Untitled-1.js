// WARNING: This code is intentionally vulnerable for demonstration purposes.
// DO NOT use this code in a production environment.

const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const port = 3000;

// --- Vulnerability 1: Insecure Cookie Handling (Missing HttpOnly, Secure, SameSite) ---
// Snyk Code would flag missing HttpOnly, Secure, and SameSite attributes
app.use(cookieParser());
app.use((req, res, next) => {
  if (!req.cookies.session_id) {
    // Setting a session cookie without HttpOnly, Secure, or SameSite=Strict/Lax
    res.cookie('session_id', Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15), {
      maxAge: 3600000 // 1 hour
    });
  }
  next();
});

// --- Vulnerability 2: Insecure Body Parser (Potential for Prototype Pollution) ---
// Older versions of body-parser, especially with extended: true, can be vulnerable
// to prototype pollution. While newer versions might have mitigations, Snyk might
// flag this usage pattern as a general risk.
app.use(bodyParser.urlencoded({ extended: true })); // Vulnerable if not properly secured/updated
app.use(bodyParser.json());

// --- Vulnerability 3: CSRF Vulnerability (Missing CSRF token protection on POST) ---
// This is the core CSRF vulnerability. No CSRF token check is performed.
app.post('/transfer', (req, res) => {
  const { amount, toAccount } = req.body;
  const userId = req.cookies.session_id; // Simulating session identification via insecure cookie

  if (!userId) {
    return res.status(401).send('Unauthorized: No session found.');
  }

  if (amount && toAccount) {
    // --- Vulnerability 4: Basic SQL Injection (Missing prepared statements/parameterization) ---
    // Snyk Code would flag this for potential SQL Injection
    // This is a common pattern for SQL injection
    const unsafeQuery = `UPDATE accounts SET balance = balance - ${amount} WHERE user_id = '${userId}'; UPDATE accounts SET balance = balance + ${amount} WHERE account_number = '${toAccount}'`;
    console.log("Executing UNSAFE SQL Query:", unsafeQuery);
    // In a real app, this would execute against a database
    // Assume it 'succeeds' for demonstration
    res.status(200).send(`Transferred $${amount} to account ${toAccount} from user ${userId}. (SQL Injection possible!)`);
  } else {
    res.status(400).send('Amount and recipient account are required.');
  }
});

// --- Vulnerability 5: Server-side XSS / Unsafe HTML rendering (Reflected XSS) ---
// Snyk Code might flag this for XSS due to direct user input rendering
app.get('/search', (req, res) => {
  const query = req.query.q || ' ';
  // Directly injecting user input without sanitization or encoding
  res.send(`<h1>Search Results for: ${query}</h1><p>No results found for your query.</p>`);
});

// --- Vulnerability 6: Path Traversal / Directory Traversal ---
// Snyk Code would flag this for potential Path Traversal
app.get('/download', (req, res) => {
  const filePath = req.query.file; // User controls part of the path
  if (filePath) {
    // No validation or sanitization on filePath
    const absolutePath = path.join(__dirname, 'downloads', filePath);
    console.log("Attempting to send file from:", absolutePath);
    // This would send the file, allowing access to arbitrary files if vulnerable
    res.sendFile(absolutePath);
  } else {
    res.status(400).send('File parameter is required.');
  }
});

// Serve a basic HTML form for CSRF demonstration
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Vulnerable App</title>
        <style>
            body { font-family: sans-serif; padding: 20px; }
            form { margin-bottom: 20px; padding: 15px; border: 1px solid #ccc; border-radius: 5px; }
            label, input { display: block; margin-bottom: 10px; }
            input[type="submit"] { background-color: #f44336; color: white; padding: 10px 15px; border: none; cursor: pointer; }
        </style>
    </head>
    <body>
        <h1>Vulnerable Banking App Demo</h1>

        <h2>Current User Session</h2>
        <p>Your (insecure) session ID: <span id="sessionId"></span></p>

        <h2>Transfer Funds (CSRF Vulnerability)</h2>
        <p>This form can be tricked into making requests from other sites.</p>
        <form action="/transfer" method="POST">
            <label for="amount">Amount:</label>
            <input type="number" id="amount" name="amount" value="100" required>

            <label for="toAccount">To Account:</label>
            <input type="text" id="toAccount" name="toAccount" value="12345" required>

            <input type="submit" value="Transfer Funds">
        </form>

        <h2>Search (Reflected XSS Vulnerability)</h2>
        <form action="/search" method="GET">
            <label for="q">Search Query:</label>
            <input type="text" id="q" name="q" placeholder="Enter search term" required>
            <input type="submit" value="Search">
        </form>

        <h2>Download File (Path Traversal Vulnerability)</h2>
        <form action="/download" method="GET">
            <label for="file">File to Download (e.g., config.js, ../../etc/passwd):</label>
            <input type="text" id="file" name="file" value="myreport.txt" required>
            <input type="submit" value="Download">
        </form>

        <script>
            document.getElementById('sessionId').textContent = document.cookie.split('; ').find(row => row.startsWith('session_id=')).split('=')[1];
            // --- XSS in client-side (less critical for Snyk SAST, but good demo) ---
            // Example of an XSS payload for the search endpoint: <img src=x onerror=alert(document.domain)>
            // Example of a path traversal payload: ../../etc/passwd
        </script>
    </body>
    </html>
  `);
});

// Create a dummy 'downloads' directory for path traversal demo
const fs = require('fs');
const downloadsDir = path.join(__dirname, 'downloads');
if (!fs.existsSync(downloadsDir)) {
  fs.mkdirSync(downloadsDir);
  fs.writeFileSync(path.join(downloadsDir, 'myreport.txt'), 'This is a sample report file.');
  fs.writeFileSync(path.join(downloadsDir, 'config.js'), 'module.exports = { secret: "mysecretkey" };');
}


app.listen(port, () => {
  console.log(`Vulnerable Express app listening at http://localhost:${port}`);
  console.log('Access the app in your browser: http://localhost:3000');
  console.log('---');
  console.log('To test CSRF (after visiting the app first):');
  console.log('  Create a malicious page on a different domain with a form like this (e.g., attacker.com/malicious.html):');
  console.log('  <form action="http://localhost:3000/transfer" method="POST">');
  console.log('      <input type="hidden" name="amount" value="1000">');
  console.log('      <input type="hidden" name="toAccount" value="67890">');
  console.log('      <input type="submit" value="Click me!">');
  console.log('  </form>');
  console.log('  If the user is logged into http://localhost:3000 and clicks "Click me!" on attacker.com, the transfer will happen.');
  console.log('---');
  console.log('To test XSS: Navigate to http://localhost:3000/search?q=%3Cscript%3Ealert(%27XSS%20Attack%27)%3C/script%3E');
  console.log('---');
  console.log('To test Path Traversal: Navigate to http://localhost:3000/download?file=../../app.js (or ../../downloads/config.js)');
});