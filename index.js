const https = require('https');
const fs = require('fs');
const express = require('express');
const app = express();
const axios = require('axios');
const mongoose = require('mongoose');
const User = require('./models/userModule');
const argon2 = require("argon2");
const jwt = require('jsonwebtoken');
const JWT_SECRET = 'secret';
const JWT_EXPIRATION_MS = 1000 * 60 * 60 * 24 * 7; // 7 days

app.use(express.static('public'));
app.use(express.json());

mongoose.connect('mongodb://localhost:27017/mongo', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log('Connected to DB');
}).catch((err) => {
    console.log(err);
});

const server = https.createServer({
    key: fs.readFileSync(__dirname + '/cert/key.pem'),
    cert: fs.readFileSync(__dirname + '/cert/cert.pem')
}, app);

server.listen(3000, () => {
    console.log('Server is running on port 3000');
});

// [POST] /api/auth/login
app.post('/api/auth/login', async (req, res) => {
    const {
        email,
        password
    } = req.body;
    const user = await
    User.findOne({
        email
    }).select('-__v').lean();

    if (!user) {
        return res.status(400).json({
            status: 'error',
            error: 'Invalid email/password'
        });
    }
    if (await argon2.verify(user.password, password)) {
        const token = jwt.sign({
            id: user._id,
            email: user.email
        }, JWT_SECRET, {
            expiresIn: JWT_EXPIRATION_MS
        });

        return res.status(200).json({
            data: token,
            user: user
        });
    }
    res.status(400).json({
        status: 'error',
        error: 'Invalid email/password'
    });
});

// [POST] /api/auth/register
app.post('/api/auth/register', async (req, res) => {

    const {
        firstname,
        lastname,
        email,
        password,
        confirmPassword,
        phone,
        dateOfBirth
    } = req.body;

    try {
        const user = await User.findOne({
            email
        }).select('-__v').lean();
        if (user) {
            return res.status(400).json({
                status: 'error',
                error: 'Username already in use'
            });
        }
        if (password !== confirmPassword) {
            return res.status(400).json({
                status: 'error',
                error: 'Passwords do not match'
            });
        }

        const hashedPassword = await argon2.hash(password);

        const newUser = new User({
            firstname,
            lastname,
            email,
            phone,
            password: hashedPassword,
            dateOfBirth
        });

        await newUser.save();

        res.status(201).json({
            status: 'success',
            data: newUser
        });
    } catch (error) {
        return res.status(400).json({
            error: error.message
        });
    }

});


// [GET] /api/user/profile

app.get('/api/user/profile', async function (req, res) {
    try {
        const jwtstatus = checkJWT(req.headers.authorization);
        if (jwtstatus.status) {
            const user = await User.findOne({
                email: jwtstatus.decoded.email
            }).select('-password');
            res.status(200).json(user);
        } else {
            res.status(401).json({
                message: "Unauthorized"
            });
        }
    } catch (error) {
        res.status(500).json(error);
    }
});


// [PUT] /api/user/edit
app.put('/api/user/edit', async function (req, res) {
    try {
        const jwtstatus = checkJWT(req.headers.authorization);
        if (jwtstatus.status) {
            const user = await User.findOne({
                email: jwtstatus.decoded.email
            }).select('-password -__v -dateCreated -dateUpdated');
            if (user) {
                user.firstname = req.body.firstname;
                user.lastname = req.body.lastname;
                user.phone = req.body.phone;
                user.dateOfBirth = req.body.dateOfBirth;
                user.save();
                res.status(201).json(user);
            } else {
                res.status(404).json({
                    message: "User not found"
                });
            }
        } else {
            res.status(401).json({
                message: "Unauthorized"
            });
        }
    } catch (error) {
        res.status(500).json(error);
    }
});


// [PUT] /api/user/edit-password
app.put('/api/user/edit-password', async function (req, res) {
    try {
        const jwtstatus = checkJWT(req.headers.authorization);
        if (jwtstatus.status) {
            const user = await User.findOne({
                email: jwtstatus.decoded.email
            }).select('-__v -dateCreated -dateUpdated');
            if (user) {
                if (await argon2.verify(user.password, req.body.oldPassword)) {
                    user.password = await argon2.hash(req.body.newPassword);
                    user.save();
                    res.status(201).json(user);
                } else {
                    res.status(400).json({
                        message: "Old password is incorrect"
                    });
                }
            } else {
                res.status(404).json({
                    message: "User not found"
                });
            }
        } else {
            res.status(401).json({
                message: "Unauthorized"
            });
        }
    } catch (error) {
        res.status(500).json(error);
    }
});

// [PUT] /api/user/edit-phone

app.put('/api/user/edit-phone', async function (req, res) {
    try {
        const jwtstatus = checkJWT(req.headers.authorization);
        if (jwtstatus.status) {
            const user = await User.findOne({
                email: jwtstatus.decoded.email
            }).select('-__v -password -dateCreated -dateUpdated');
            if (user) {
                user.phone = req.body.phone;
                user.save();
                res.status(201).json(user);
            } else {
                res.status(404).json({
                    message: "User not found"
                });
            }
        } else {
            res.status(401).json({
                message: "Unauthorized"
            });
        }
    } catch (error) {
        res.status(500).json(error);
    }
});

// [PUT] /api/user/edit-email

app.put('/api/user/edit-email', async function (req, res) {
    try {
        const jwtstatus = checkJWT(req.headers.authorization);
        if (jwtstatus.status) {
            const user = await User.findOne({
                email: jwtstatus.decoded.email

            }).select('-__v -password -dateCreated -dateUpdated');
            if (user) {
                user.email = req.body.email;
                user.save();
                res.status(201).json(user);
            } else {
                res.status(404).json({
                    message: "User not found"
                });
            }
        } else {
            res.status(401).json({
                message: "Unauthorized"
            });
        }
    } catch (error) {
        res.status(500).json(error);
    }
});

// [DELETE] /api/user/delete

app.delete('/api/user/delete', async function (req, res) {
    try {
        const jwtstatus = checkJWT(req.headers.authorization);
        if (jwtstatus.status) {
            const user = await User.findOne({
                email: jwtstatus.decoded.email
            }).select('-__v -password -dateCreated -dateUpdated');
            if (user) {
                user.remove();
                res.status(200).json({
                    message: "User deleted"
                });
            } else {
                res.status(404).json({
                    message: "User not found"
                });
            }
        } else {
            res.status(401).json({
                message: "Unauthorized"
            });
        }
    } catch (error) {
        res.status(500).json(error);
    }
});

// [POST] /api/auth/logout

app.post('/api/auth/logout', async function (req, res) {
    try {
        const jwtstatus = checkJWT(req.headers.authorization);
        if (jwtstatus.status) {
            const user = await User.findOne({
                email: jwtstatus.decoded.email
            });
            if (user) {
                jwt.sign({
                    email: user.email
                }, JWT_SECRET, {
                    expiresIn: '1s'
                }, (err, token) => {
                    if (err) {
                        res.status(500).json(err);
                    } else {
                        res.status(200).json({
                            message: "Logged out",
                            token: token
                        });
                    }
                });
            } else {
                res.status(401).json({
                    message: "Unauthorized"

                });
            }
        } else {
            res.status(401).json({
                message: "Unauthorized"
            });
        }
    } catch (error) {
        res.status(500).json(error);
    }
});


// Check jwt validity
function checkJWT(full_token) {
    const token = full_token.split(' ')[1];
    if (!token)
        return {
            status: false,
            message: 'Auth token is not supplied'
        };
    else {
        try {
            let decoded = jwt.verify(token, JWT_SECRET);
            return {
                status: true,
                message: 'Token verified',
                decoded: decoded,
                token: token
            };
        } catch (err) {
            return {
                status: false,
                message: 'Token is not valid',
                error: err,
                token: token
            };
        }
    }
}