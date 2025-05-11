const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const { body } = require('express-validator');
const { validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(bodyParser.json());
app.use(cors());

const jwtSecret = 'your_jwt_secret';

// In-memory SQLite DB setup
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, firstname TEXT, lastname TEXT, email TEXT)");
    db.run("CREATE TABLE groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, userIds TEXT, roleIds TEXT)");
    db.run(`CREATE TABLE roles (id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT, groupIds TEXT)`);
    db.run("CREATE TABLE IF NOT EXISTS permissions (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, roleIds TEXT DEFAULT '[]')");
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

function validate(req, res, next) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    next();
}

const validateUser = [
  body('username').isString().notEmpty(),
  body('password').isString().notEmpty(),
  body('firstname').optional().isString(),
  body('lastname').optional().isString(),
  body('email').optional().isEmail(),
];

const validateUserUpdate = [
  body('username').optional().isString(),
  body('password').optional().isString(),
  body('firstname').optional().isString(),
  body('lastname').optional().isString(),
  body('email').optional().isEmail(),
];

const validateGroup = [body('name').isString().notEmpty()];
const validateRole = [body('name').isString().notEmpty()];
const validatePermission = [body('name').isString().notEmpty()];
const validateUserIds = [body('userIds').isArray()];
const validateGroupIds = [body('groupIds').isArray()];
const validateRoleIds = [body('roleIds').isArray()];

// AUTH
app.post('/api/register', validateUser, validate, (req, res) => {
    const { username, password, firstname, lastname, email } = req.body;
    db.run(
      "INSERT INTO users (username, password, firstname, lastname, email) VALUES (?, ?, ?, ?, ?)",
      [username, password, firstname, lastname, email],
      function(err) {
        if (err) return res.status(400).send('User exists');
        res.status(201).json({ id: this.lastID, username, firstname, lastname, email });
      }
    );
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ? AND password = ?", [username, password], (err, user) => {
        if (err || !user) return res.sendStatus(403);
        const token = jwt.sign({ id: user.id, username: user.username }, jwtSecret);
        res.json({ token });
    });
});

// USERS
app.get('/api/users', authenticateToken, (req, res) => {
    db.all("SELECT id, username, password, firstname, lastname, email FROM users", [], (err, rows) => {
        if (err) return res.sendStatus(500);
        res.json(rows);
    });
});

app.post('/api/users', authenticateToken, validateUser, validate, (req, res) => {
    const { username, password, firstname, lastname, email } = req.body;
    db.run("INSERT INTO users (username, password, firstname, lastname, email) VALUES (?, ?, ?, ?, ?)", [username, password, firstname, lastname, email], function(err) {
        if (err) return res.status(400).send('User exists');
        res.status(201).json({ id: this.lastID, username, firstname, lastname, email });
    });
});

app.put('/api/users/:id', authenticateToken, validateUserUpdate, validate, (req, res) => {
    const { firstname, lastname, email, username, password } = req.body;
    db.run("UPDATE users SET firstname = ?, lastname = ?, email = ?, username = ?, password = ? WHERE id = ?", [firstname, lastname, email, username, password, req.params.id], function(err) {
        if (err || this.changes === 0) return res.sendStatus(404);
        res.json({ id: parseInt(req.params.id), firstname, lastname, email, username, password });
    });
});

app.delete('/api/users/:id', authenticateToken, (req, res) => {
    db.run("DELETE FROM users WHERE id = ?", [req.params.id], function(err) {
        if (err || this.changes === 0) return res.sendStatus(404);
        res.sendStatus(204);
    });
});

// GROUPS
app.get('/api/groups', authenticateToken, (req, res) => {
    db.all("SELECT * FROM groups", [], (err, rows) => {
        if (err) return res.sendStatus(500);
        res.json(rows.map(g => ({ ...g, userIds: JSON.parse(g.userIds || '[]'), roleIds: JSON.parse(g.roleIds || '[]') })));
    });
});

app.post('/api/groups', authenticateToken, validateGroup, validate, (req, res) => {
    const { name } = req.body;
    db.run("INSERT INTO groups (name, userIds, roleIds) VALUES (?, ?, ?)", [name, JSON.stringify([]), JSON.stringify([])], function(err) {
        if (err) return res.sendStatus(500);
        res.status(201).json({ id: this.lastID, name, userIds: [], roleIds: [] });
    });
});

app.put('/api/groups/:id', authenticateToken, validateGroup, validate, (req, res) => {
    const { name } = req.body;
    db.run("UPDATE groups SET name = ? WHERE id = ?", [name, req.params.id], function(err) {
        if (err || this.changes === 0) return res.sendStatus(404);
        res.json({ id: req.params.id, name });
    });
});

app.delete('/api/groups/:id', authenticateToken, (req, res) => {
    db.run("DELETE FROM groups WHERE id = ?", [req.params.id], function(err) {
        if (err || this.changes === 0) return res.sendStatus(404);
        res.sendStatus(204);
    });
});

app.get('/api/groups/:groupId/users', authenticateToken, (req, res) => {
    const groupId = req.params.groupId;
    db.get("SELECT * FROM groups WHERE id = ?", [groupId], (err, group) => {
        if (err || !group) return res.sendStatus(404);
        const userIds = JSON.parse(group.userIds || '[]');
        if (userIds.length === 0) return res.json([]);
        const placeholders = userIds.map(() => '?').join(',');
        db.all(`SELECT id, username, email FROM users WHERE id IN (${placeholders})`, userIds, (err, users) => {
            if (err) return res.sendStatus(500);
            res.json(users);
        });
    });
});

app.post('/api/groups/:groupId/users', authenticateToken, validateUserIds, validate, (req, res) => {
    const { userIds } = req.body;
    db.get("SELECT * FROM groups WHERE id = ?", [req.params.groupId], (err, group) => {
        if (err || !group) return res.sendStatus(404);
        db.run("UPDATE groups SET userIds = ? WHERE id = ?", [JSON.stringify(userIds), req.params.groupId], function(err) {
            if (err) return res.sendStatus(500);
            res.json({ id: group.id, name: group.name, userIds, roleIds: JSON.parse(group.roleIds || '[]') });
        });
    });
});

// ROLES
app.get('/api/roles', authenticateToken, (req, res) => {
    db.all("SELECT * FROM roles", [], (err, rows) => {
        if (err) return res.sendStatus(500);
        res.json(rows);
    });
});

app.post('/api/roles', authenticateToken, validateRole, validate, (req, res) => {
    const { name } = req.body;
    db.run("INSERT INTO roles (name) VALUES (?)", [name], function(err) {
        if (err) return res.sendStatus(500);
        res.status(201).json({ id: this.lastID, name });
    });
});

app.put('/api/roles/:id', authenticateToken, validateRole, validate, (req, res) => {
    const { name } = req.body;
    db.run("UPDATE roles SET name = ? WHERE id = ?", [name, req.params.id], function(err) {
        if (err || this.changes === 0) return res.sendStatus(404);
        res.json({ id: req.params.id, name });
    });
});

app.delete('/api/roles/:id', authenticateToken, (req, res) => {
    db.run("DELETE FROM roles WHERE id = ?", [req.params.id], function(err) {
        if (err || this.changes === 0) return res.sendStatus(404);
        res.sendStatus(204);
    });
});

app.post('/api/groups/:groupId/roles', authenticateToken, validateRoleIds, validate, (req, res) => {
    const { roleIds } = req.body;
    db.get("SELECT * FROM groups WHERE id = ?", [req.params.groupId], (err, group) => {
        if (err || !group) return res.sendStatus(404);
        db.run("UPDATE groups SET roleIds = ? WHERE id = ?", [JSON.stringify(roleIds), req.params.groupId], function(err) {
            if (err) return res.sendStatus(500);
            res.json({ id: group.id, name: group.name, userIds: JSON.parse(group.userIds || '[]'), roleIds });
        });
    });
});

app.put('/api/roles/:roleId/groups', authenticateToken, validateGroupIds, validate, (req, res) => {
    const { groupIds } = req.body;
    db.get("SELECT * FROM roles WHERE id = ?", [req.params.roleId], (err, role) => {
        if (err || !role) return res.sendStatus(404);
        db.run("UPDATE roles SET groupIds = ? WHERE id = ?", [JSON.stringify(groupIds), req.params.roleId], function(err) {
            if (err) return res.sendStatus(500);
            res.json({ id: role.id, name: role.name, groupIds });
        });
    });
});

// PERMISSIONS
app.get('/api/permissions', authenticateToken, (req, res) => {
    db.all("SELECT * FROM permissions", [], (err, rows) => {
        if (err) return res.sendStatus(500);
        res.json(rows);
    });
});

app.post('/api/permissions', authenticateToken, validatePermission, validate, (req, res) => {
    const { name } = req.body;
    db.run("INSERT INTO permissions (name, roleIds) VALUES (?, ?)", [name, JSON.stringify([])], function(err) {
        if (err) return res.sendStatus(500);
        res.status(201).json({ id: this.lastID, name, roleIds: [] });
    });
});

app.put('/api/permissions/:permissionId', authenticateToken, validatePermission, validate, (req, res) => {
    const { name } = req.body;
    db.get("SELECT * FROM permissions WHERE id = ?", [req.params.permissionId], (err, permission) => {
        if (err || !permission) return res.sendStatus(404);
        db.run("UPDATE permissions SET name = ? WHERE id = ?", [name, req.params.permissionId], function(err) {
            if (err) return res.sendStatus(500);
            res.json({ id: permission.id, name, roleIds: JSON.parse(permission.roleIds || '[]') });
        });
    });
});

app.delete('/api/permissions/:permissionId', authenticateToken, (req, res) => {
    db.run("DELETE FROM permissions WHERE id = ?", [req.params.permissionId], function(err) {
        if (err) return res.sendStatus(500);
        res.sendStatus(204);
    });
});

app.put('/api/permissions/:permissionId/roles', authenticateToken, validateRoleIds, validate, (req, res) => {
    const { roleIds } = req.body;
    db.get("SELECT * FROM permissions WHERE id = ?", [req.params.permissionId], (err, permission) => {
        if (err || !permission) return res.sendStatus(404);
        db.run("UPDATE permissions SET roleIds = ? WHERE id = ?", [JSON.stringify(roleIds), req.params.permissionId], function(err) {
            if (err) return res.sendStatus(500);
            res.json({ id: permission.id, name: permission.name, roleIds });
        });
    });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
