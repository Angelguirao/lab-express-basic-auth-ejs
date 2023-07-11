const router = require("express").Router();
const User = require('../models/User.model');
const bcrypt = require('bcryptjs');
const saltRounds = 10;


/* GET Signup page */
router.get('/signup', (req, res, next) => {
  res.render('auth/signup')
})

// POST route ==> to process form data
router.post('/signup', async (req, res, next) => {
  
  // console.log("The form data: ", req.body);

  const payload = { ...req.body }

  delete payload.password

  const salt = bcrypt.genSaltSync(13)

  payload.passwordHash = bcrypt.hashSync(req.body.password, salt)
    
    try {
      const newUser = await User.create({ username: payload.username, password: payload.passwordHash})
      res.send(newUser)
    } catch (error) {
      console.log(error)
    }
  })

  /* GET Login page */
router.get('/login', (req, res, next) => {
  res.render('auth/login')
})

/* POST data to check if our user is our user */
router.post('/login', async (req, res, next) => {
  console.log(req.body)
  try {
    const currentUser = req.body
    const checkedUser = await User.findOne({ username: currentUser.username.toLowerCase() })
    if (checkedUser) {
      // User does exists
      if (bcrypt.compareSync(currentUser.password, checkedUser.passwordHash)) {
        // Password is correct
        const loggedUser = { ...checkedUser._doc }
        delete loggedUser.passwordHash
        console.log(loggedUser)
        req.session.user = loggedUser
        res.redirect('/profile')
      } else {
        // Password is incorrect
        console.log('Password is incorrect')
        res.render('auth/login', {
          errorMessage: 'Password is incorrect',
          payload: { username: currentUser.username },
        })
      }
    } else {
      // No user with this username
      console.log('No user with this username')
      res.render('auth/login', {
        errorMessage: 'No user with this username',
        payload: { username: currentUser.username },
      })
    }
  } catch (error) {
    console.log('error occured: ', error)
    res.render('auth/login', {
      errorMessage: 'There was an error on the server',
      payload: { username: currentUser.username },
    })
  }
})

  module.exports = router;
