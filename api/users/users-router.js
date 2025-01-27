// Require the `restricted` middleware from `auth-middleware.js`. You will need it here!
const express = require('express')
const router = express.Router()
const { restrict } = require('../auth/auth-middleware')
const Users = require('./users-model')
/**
  [GET] /api/users

  This endpoint is RESTRICTED: only authenticated clients
  should have access.

  response:
  status 200
  [
    {
      "user_id": 1,
      "username": "bob"
    },
    // etc
  ]

  response on non-authenticated:
  status 401
  {
    "message": "You shall not pass!"
  }
 */

  

  router.get("/", restrict, async (req, res, next) => {
   try{
     const users = await Users.find()
     if (users){ 
     res.json(users)
     } else {
       next({status: 401,  message: "You shall not pass!"})
     }
   }catch(err){
           next(err)
   }
  })
  
  module.exports = router
 

// Don't forget to add the router to the `exports` object so it can be required in other modules
