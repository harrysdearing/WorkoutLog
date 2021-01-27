const router = require('express').Router();
const User = require('../database').import('../models/user');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

router.post("/register", (req, res) => {
    User.create({
            username: req.body.user.username,
            password: bcrypt.hashSync(req.body.user.password, 10),
        })
        .then((user) => {
            const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
                expiresIn: 60 * 60 * 24,
            });
            res.status(200).json(user);
        })
        .catch((err) => res.status(500).json({ error: err }));
});


router.post("/login", (req, res) => {
    User.findOne({ where: { username: req.body.user.username } })
        .then((user) => {
            if (user === null) {
                return res.status(404).json({ message: "user not found" });
            }
            bcrypt.compare(req.body.user.password, user.password, (err, matches) => {
                if (matches) {
                    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
                        expiresIn: 60 * 60 * 24,
                    });
                    return res.status(200).json({ user, token });
                } else {
                    return res.status(401).json({ message: "wrong password" });
                }
            });
        })
        .catch((error) => res.status(500).json(error));
});

module.exports = router;