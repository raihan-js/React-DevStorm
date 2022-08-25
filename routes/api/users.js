const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const keys = require('../../config/keys');
const passport = require('passport');

//Load Input validation
const validateRegisterInput = require('../../validation/register');
const validateLoginInput = require('../../validation/login');


//Load User model
const User = require('../../models/User');



/**
 * @route GET api/users/test
 * @desc Tests users route
 * @access Public route
 */
router.get('/test', (req, res) => res.json({msg: 'Users works'}));

/**
 * @route GET api/users/register
 * @desc Register users
 * @access Public route
 */
router.post('/register', (req, res) => {

    const { errors, isValid } = validateRegisterInput(req.body);
    
    //check validation
    if (!isValid) {
        return res.status(400).json(errors);    
    }

    User.findOne({ email: req.body.email })
        .then(user => {
            if (user) {

                errors.email = 'Email already exists!';

                return res.status(400).json(errors);
            } else {

                const avatar = gravatar.url(req.body.email, {
                    s: '200', //Size
                    r: 'pg', //Rating
                    d: 'mm', //Default
                });


                const newUser = new User({
                    name: req.body.name,
                    email: req.body.email,
                    avatar,
                    password: req.body.password,
                });

                bcrypt.genSalt(10, (err, salt) => {
                    bcrypt.hash(newUser.password, salt, (err, hash) => {
                        if(err) throw err;
                        newUser.password = hash;
                        newUser
                            .save()
                            .then(user => res.json(user))
                            .catch(err => console.log(err));
                    })
                })
            }
        })
});


/**
 * @route GET api/users/login
 * @desc Returns JWT
 * @access Public route
 */
router.post('/login', (req, res) => {

    const { errors, isValid } = validateLoginInput(req.body);
    
    //check validation
    if (!isValid) {
        return res.status(400).json(errors);    
    }


    const email = req.body.email;
    const password = req.body.password;

    //Find user in DB using Model
    User.findOne({email})
        .then(user => {
            //check for user exists
            if(!user){
                errors.email = 'User does not exist!';
                return res.status(400).json(errors);
            }

            //Check password
            bcrypt.compare(password, user.password)
            .then(isMatched => {
                if(isMatched){
                    //User matched
                    const payload = {id: user.id, name: user.name, avatar: user.avatar};

                    //Sign user token
                    jwt.sign(payload, keys.secretOrKey, { expiresIn: 3600 }, (err, token) => {
                        res.json({
                            success: true,
                            token: 'Bearer ' + token,
                        });
                    });
                }
                else {
                    errors.password = 'Password incorrect!!'
                    return res.status(400).json(errors);
                }
            });
        });
});



/**
 * @route GET api/users/current
 * @desc Returns current user
 * @access Private route
 */
router.get('/current', passport.authenticate('jwt', { session: false }), (req, res) => {
   return res.json({
    id: req.user.id,
    name: req.user.name,
    email: req.user.email,
   });
});



module.exports = router;