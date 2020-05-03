const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const auth = require("../../middleware/auth");
const jwt = require("jsonwebtoken");
const config =require("config");
const { check, validationResult} = require("express-validator/check");

const User = require("../../models/User");

// @route   GET api/auth
// @desc    Test route
// @access  Public
router.get("/", auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select("-password");
        res.json(user)
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server Error");
    }
});

// Loging In
// @route   Post api/auth
// @desc    Authenticate User and Get Token
// @access  Public
router.post('/', 
[
check("email", "Please enter a valid email").isEmail(),
check("password", "Password is required").exists()
], 
    async (req, res) => {
    const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({errors: errors.array()});
        }
    const {email, password} = req.body;
        try {
        // See if the user exists
        let user = await User.findOne({ email });
        if (!user) {
            return res
            .status(400)
            .json({errors: [ {msg: "Invalid Credentials"}] });
        }

        const  isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res
            .status(400)
            .json({errors: [ {msg: "Invalid Credentials"}] }); // Good to have the same Error - Security
        }

        // Return JsonToken
        const payload = {
            user: {
                id: user.id
            }
        }

        jwt.sign(
            payload, 
            config.get("jwtSecret"),
            {expiresIn: 360000 },
            (err, token) => {
                if (err) throw err;
                res.json({ token });
            });

        // res.send("User Registrated"); - OLD Response from the BE
            
        } catch (err) {
            console.error(err.message);
            res.status(500).send("Server error");
        }
});

module.exports = router;