const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const sqlite3 = require('sqlite3').verbose();
const querystring = require('querystring');
const bcrypt = require('bcrypt');
const cookie = require('cookie');
const formidable = require('formidable');
const WebSocket = require('ws');

const db = new sqlite3.Database(path.join(__dirname, 'users.db'));

db.serialize(() => {
    db.run("PRAGMA busy_timeout = 30000"); // Set busy timeout to 30 seconds

    // Create the users table with the correct schema if it doesn't exist
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, email TEXT UNIQUE, profile_image TEXT DEFAULT 'default_pfp.png')", (err) => {
        if (err) {
            console.error("Table creation failed:", err.message);
        } else {
            console.log("Table 'users' created or already exists.");
        }

        // Add the bio column if it doesn't exist
        db.run("ALTER TABLE users ADD COLUMN bio TEXT", (err) => {
            if (err && err.message.includes("duplicate column name")) {
                console.log("Column 'bio' already exists.");
            } else if (err) {
                console.error("Failed to add 'bio' column:", err.message);
            } else {
                console.log("Column 'bio' added successfully.");
            }

            // Debugging: Check if the email column exists
            db.all("PRAGMA table_info(users)", (err, rows) => {
                if (err) {
                    console.error("Failed to retrieve table info:", err.message);
                } else {
                    console.log("Table info:");
                    rows.forEach(row => {
                        console.log(row);
                    });
                }
            });
        });
    });
});

const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;
    const cookies = cookie.parse(req.headers.cookie || '');

    if (pathname === '/register' && req.method === 'POST') {
        console.log("Received registration request");
        const form = new formidable.IncomingForm();
        form.uploadDir = path.join(__dirname, 'images'); // Set upload directory
        form.keepExtensions = true; // Keep file extensions

        form.parse(req, (err, fields, files) => {
            if (err) {
                console.error("Form parsing failed:", err.message);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ message: 'Registration failed' }));
                return;
            }
            console.log("Form parsed successfully");
            console.log("Fields:", fields);
            console.log("Files:", files);

            const username = fields.username;
            const password = fields.password;
            const email = fields.email;
            console.log("Received registration data:", { username, password, email });

            if (!username || !password || !email) {
                console.error("Username, password, or email missing");
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ message: 'Username, password, or email missing' }));
                return;
            }

            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                console.error("Invalid email format");
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ message: 'Invalid email format' }));
                return;
            }

            bcrypt.hash(password, 10, (err, hash) => {
                if (err) {
                    console.error("Hashing failed:", err.message);
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ message: 'Registration failed' }));
                    return;
                }
                console.log("Password hashed successfully:", hash);

                const file = files['profile-image'];
                const profileImagePath = file ? `${username}.png` : 'default_pfp.png';

                if (file) {
                    const oldPath = file.filepath;
                    const newPath = path.join(__dirname, 'images', profileImagePath);
                    fs.rename(oldPath, newPath, (err) => {
                        if (err) {
                            console.error("Image rename failed:", err.message);
                            res.writeHead(500, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ message: 'Registration failed' }));
                            return;
                        }
                        console.log("Profile image saved successfully");
                    });
                }

                db.run("INSERT INTO users (username, password, email, profile_image) VALUES (?, ?, ?, ?)", [username, hash, email, profileImagePath], (err) => {
                    if (err) {
                        if (err.code === 'SQLITE_CONSTRAINT') {
                            console.error("Registration failed: Username or email already exists");
                            res.writeHead(409, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ message: 'Username or email already exists' }));
                        } else {
                            console.error("Registration failed:", err.message);
                            res.writeHead(500, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ message: 'Registration failed' }));
                        }
                    } else {
                        console.log("User registered:", username);
                        res.writeHead(200, {
                            'Content-Type': 'application/json',
                            'Set-Cookie': cookie.serialize('username', username, {
                                httpOnly: true,
                                maxAge: 60 * 60 * 24 * 7 // 1 week
                            })
                        });
                        res.end(JSON.stringify({ message: 'registration_success', username }));

                        // Notify all connected clients about the new registration
                        notifyClientsAboutUpdate();
                    }
                });
            });
        });
    } else if (pathname === '/login' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });
        req.on('end', () => {
            const { username, password } = querystring.parse(body);
            console.log("Received login data:", { username, password });
            db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
                if (err || !row) {
                    console.error("Login Failed:", err ? err.message : "User Not Found");
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ message: 'Username or Password Not Found' }));
                } else {
                    console.log("User found:", row);
                    bcrypt.compare(password, row.password, (err, result) => {
                        if (result) {
                            console.log("User Logged In:", username);
                            res.writeHead(200, {
                                'Content-Type': 'application/json',
                                'Set-Cookie': cookie.serialize('username', username, {
                                    httpOnly: true,
                                    maxAge: 60 * 60 * 24 * 7 // 1 week
                                })
                            });
                            res.end(JSON.stringify({ message: 'login_success', username }));
                        } else {
                            console.error("Login failed: Incorrect password");
                            res.writeHead(401, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ message: 'Username or Password Not Found' }));
                        }
                    });
                }
            });
        });
    } else if (pathname === '/logout' && req.method === 'POST') {
        res.writeHead(200, {
            'Content-Type': 'application/json',
            'Set-Cookie': cookie.serialize('username', '', {
                httpOnly: true,
                maxAge: 0 // Expire the cookie
            })
        });
        res.end(JSON.stringify({ message: 'logout_success' }));
        // Clear bio data on logout
        broadcastUpdate('bio_cleared', { username: cookies.username });
    } else if (pathname === '/check-login' && req.method === 'GET') {
        if (cookies.username) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ loggedIn: true, username: cookies.username }));
        } else {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ loggedIn: false }));
        }
    } else if (pathname === '/upload-profile-image' && req.method === 'POST') {
        const form = new formidable.IncomingForm();
        form.uploadDir = path.join(__dirname, 'images'); // Set upload directory
        form.keepExtensions = true; // Keep file extensions

        form.parse(req, (err, fields, files) => {
            if (err) {
                console.error("Image upload failed:", err.message);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ message: 'upload_failed' }));
                return;
            }
            console.log("Files received:", files); // Log the files object
            const file = files['profile-image'];
            if (!file) {
                console.error("No file uploaded");
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ message: 'No file uploaded' }));
                return;
            }
            const oldPath = file.filepath; // Get the temporary file path
            console.log("Old path:", oldPath); // Log the old path

            const cookies = cookie.parse(req.headers.cookie || '');
            const username = cookies.username;
            if (!username) {
                console.error("Username not found in cookies");
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ message: 'Username not found' }));
                return;
            }

            const newPath = path.join(__dirname, 'images', `${username}.png`);
            fs.rename(oldPath, newPath, (err) => {
                if (err) {
                    console.error("Image rename failed:", err.message);
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ message: 'upload_failed' }));
                    return;
                }
                db.run("UPDATE users SET profile_image = ? WHERE username = ?", [`${username}.png`, username], (err) => {
                    if (err) {
                        console.error("Database update failed:", err.message);
                        res.writeHead(500, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ message: 'upload_failed' }));
                        return;
                    }
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ message: 'upload_success', username }));

                    // Notify all connected clients about the profile image update
                    wss.clients.forEach(client => {
                        if (client.readyState === WebSocket.OPEN) {
                            client.send(JSON.stringify({ type: 'profile_image_updated', username }));
                        }
                    });
                });
            });
        });
    } else if (pathname === '/profile-picture' && req.method === 'GET') {
        const username = parsedUrl.query.username;
        console.log("Retrieving profile picture for username:", username);
        db.get("SELECT profile_image FROM users WHERE username = ?", [username], (err, row) => {
            if (err || !row) {
                console.error("Profile picture retrieval failed:", err ? err.message : "User Not Found");
                res.writeHead(404);
                res.end();
                return;
            }
            const imagePath = path.join(__dirname, 'images', row.profile_image);
            fs.readFile(imagePath, (err, data) => {
                if (err) {
                    console.error("Image read failed:", err.message);
                    if (row.profile_image === 'default_pfp.png') {
                        fs.readFile(path.join(__dirname, 'images', 'default_pfp.png'), (err, data) => {
                            if (err) {
                                console.error("Default image read failed:", err.message);
                                res.writeHead(404);
                                res.end();
                                return;
                            }
                            res.writeHead(200, { 'Content-Type': 'image/png' });
                            res.end(data);
                        });
                    } else {
                        res.writeHead(404);
                        res.end();
                    }
                    return;
                }
                res.writeHead(200, { 'Content-Type': 'image/png' });
                res.end(data);
            });
        });
    } else if (pathname === '/update-bio' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });
        req.on('end', () => {
            const { bio } = querystring.parse(body);
            const cookies = cookie.parse(req.headers.cookie || '');
            const username = cookies.username;
            console.log("Received bio update request:", { username, bio }); // Debugging statement
            if (!username) {
                console.error("Username not found in cookies");
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ message: 'Username not found' }));
                return;
            }
            db.run("UPDATE users SET bio = ? WHERE username = ?", [bio, username], (err) => {
                if (err) {
                    console.error("Bio update failed:", err.message); // Debugging statement
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ message: 'Bio update failed' }));
                    return;
                }
                console.log("Bio updated successfully for user:", username); // Debugging statement
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ message: 'Bio updated successfully' }));
            });
        });
    } else if (pathname === '/profile-data' && req.method === 'GET') {
        const username = parsedUrl.query.username;
        console.log("Retrieving profile data for username:", username); // Debugging statement
        db.get("SELECT bio FROM users WHERE username = ?", [username], (err, row) => {
            if (err || !row) {
                console.error("Profile data retrieval failed for user:", username, err ? err.message : "User Not Found");
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ message: 'Profile data not found' }));
                return;
            }
            console.log("Profile data retrieved successfully for user:", username, row); // Debugging statement
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(row));
        });
    } else {
        let filePath = path.join(__dirname, pathname === '/' ? 'index.html' : pathname);
        let extname = path.extname(filePath);
        let contentType = 'text/html';

        switch (extname) {
            case '.js':
                contentType = 'text/javascript';
                break;
            case '.css':
                contentType = 'text/css';
                break;
            case '.json':
                contentType = 'application/json';
                break;
            case '.png':
                contentType = 'image/png';
                break;
            case '.jpg':
                contentType = 'image/jpg';
                break;
        }

        fs.readFile(filePath, (err, content) => {
            if (err) {
                if (err.code == 'ENOENT') {
                    fs.readFile(path.join(__dirname, '404.html'), (err, content) => {
                        res.writeHead(200, { 'Content-Type': 'text/html' });
                        res.end(content, 'utf8');
                    });
                } else {
                    res.writeHead(500);
                    res.end(`Server Error: ${err.code}`);
                }
            } else {
                res.writeHead(200, { 'Content-Type': contentType });
                res.end(content, 'utf8');
            }
        });
    }
});

const wss = new WebSocket.Server({ server });

wss.on('connection', ws => {
    console.log('Client connected');
    ws.on('message', message => {
        console.log('Received:', message);
    });
    ws.on('close', () => {
        console.log('Client disconnected');
    });
});

function broadcastUpdate(type, data) {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({ type, ...data }));
        }
    });
}

// Example usage: Call this function whenever you update the database
function notifyClientsAboutUpdate() {
    broadcastUpdate('database_update', { message: 'Database has been updated' });
}

process.on('SIGINT', () => {
    db.close((err) => {
        if (err) {
            console.error(err.message);
        }
        console.log('Closed the database connection.');
        process.exit(0);
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
