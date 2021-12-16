const express = require('express')
const bcrypt = require('bcryptjs')
const router = express.Router()
const User = require('../users/users-model')


const { checkPasswordLength, checkUsernameExists,checkUsernameFree } = require('./auth-middleware')

// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!


/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
  router.post('/register',checkPasswordLength,checkUsernameFree,  (req, res, next) => {
   
      // 1- pull u and p from req.body
      // 2- create a hash off of the password
      // 3- we will store u and hash to the db
      const { username, password } = req.body
      const hash =  bcrypt.hashSync(password, 8) // 2^8 rounds
      User.add({ username, password:hash})
       .then(saved => {
         res.status(201).json(saved)
       })
      
    .catch (next) 
      
    
  })

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */

  router.post('/login', checkUsernameExists,  (req, res, next) => {
    
      // 1- pull u and p from req.body
      const { password } = req.body
     if(bcrypt.compareSync(password, req.user.password)){
      req.session.user = req.user
      res.json({
        message: `Welcome ${req.user.username}!`, status :200
      })
      
     }else {
      next({ message: 'invalid credentials', status: 401 })
     }     
   
  })
  
/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
  router.get('/logout', (req, res, next) => {
    
      if (req.session.user) {
        req.session.destroy(err => {
          if (err) {
            next(err)
          } else {
            
            res.json({ message: "logged out", status:200 })
          }
        })
      } else {
        res.json({ message: 'no session', status:200 })
      }
    
  })
 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router