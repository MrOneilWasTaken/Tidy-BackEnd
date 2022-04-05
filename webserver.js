const {createHmac} = import('crypto')
// import { login } from './functions/login';
import Database from 'better-sqlite3';
import express from 'express';
import multer from 'multer';
import jsonwebtoken from 'jsonwebtoken';
import bcrypt from 'bcrypt'
import { login } from './functions/login.js';
const saltRounds = 10
const upload = multer()
const app = express()
const port = 3001
app.use(express.json())
app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, authorization");
  next();
})
const db = new Database('db/projectDB.sqlite');

const secretKey = '6ngQ%q^:+=M)+.p-[nTcUYx5MJDR^J!Aq+_u"BkK!%eVO9g]vJBpPBs@KndAH%Ib%k.Thg:|O<x)sfG($-k=<)YA]0olRr)V'

const ensureToken = (req,res,next) =>{
  const bearerHeader = req.headers["authorization"]
  if (typeof bearerHeader !== "undefined"){
    const bearer = bearerHeader.split(" ")
    const bearerToken = bearer[1]
    req.token = bearerToken
    next();
  }else{
    res.sendStatus(403);
  }
}

// regex api switch statement insert here at some point 
// also shove each of these endpoints into their own files, login.js, etc.

// Base API
app.get('/api', (req, res) => {
  res.json({
    text: "yay"
  })
})
// Test protected stuff
app.get('/api/protected', ensureToken, (req, res) => {
  jsonwebtoken.verify(req.token, secretKey, (err, data) => {
    if(err){
      res.sendStatus(403)
    }else{
      res.json({
        text: "this is protected",
        data: data
      })
    }
  })
})


// Needs work - front end should just send api add task when formsubmit
app.post('/api/addtask', ensureToken, upload.array(), (req, res) => {
  jsonwebtoken.verify(req.token, secretKey, (err) => {
    if(err){
      res.send({
        status: "error",
        Message: "Please provide a valid logged in token",
      })
    }else{
      const task = req.body 

      let stmt = db.prepare('INSERT INTO userstasks (userID, dayID, content, done) VALUES (?, ?, ?, ?)')
      stmt.run(task.userID, task.dayID, task.content, ((task.done) ? 1 : 0 ))

      res.send({
        status: 204,
        Message: "Tasks uploaded",
      })          
    }
  })
  
})




// Maybe done
app.get('/api/recievetasks', ensureToken, upload.array(), (req, res) => {
  jsonwebtoken.verify(req.token, secretKey, (err) => {
    if(err){
      res.sendStatus(403)
    }else{
      const {userID} = req.query
      const recievedTasks = db.prepare('SELECT * FROM userstasks WHERE userID = ?').all(userID)
      res.send({recievedTasks})
    }
  })
})

// Needs work
app.get('/api/userstasks', (req, res) => {
  const stmt = db.prepare('SELECT * FROM users').all()
  res.send({stmt})
})

// Done
app.post('/api/signup', upload.array(), (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*')

  const {password} = req.body
  const {username} = req.body

  if ((password || username) === ''){
    res.json({Message: "No username or password"}).end()

  }else{
    bcrypt.hash(password, saltRounds, (err, hash) =>{
      if(err) {
        req.sendStatus(418)
      }else{
        let stmt = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)')
        const info = stmt.run(username,hash)

        let loginstmt = db.prepare('SELECT password FROM users WHERE username = ?')
        let hashedpssword = loginstmt.get(username) 
        
        stmt = db.prepare('SELECT userID FROM users WHERE username = ?')
        const userID = stmt.get(username)
      
        bcrypt.compare(password, hashedpssword.password, (err, result) => {
          if (err){
            res.json(err)
          }else if(result == true){
            const token = jsonwebtoken.sign(result, secretKey)
            res.json({
              Status: "200",
              Message: "Account Created",
              userID: userID.userID,
              username: username,
              token: token
            })
          } 
        })
      }
    })
  }
})

// Done
app.post('/api/login', upload.array(), (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*')
  const {password} = req.body
  const {username} = req.body

  //login(username,password,db)

  if ((password || username) === ''){
    res.json({Message: "No username or password"}).end()
    console.log("WRONG");
  }else{
    let stmt = db.prepare('SELECT password FROM users WHERE username = ?')
    const hash = stmt.get(username) 

    stmt = db.prepare('SELECT userID FROM users WHERE username = ?')
    const userID = stmt.get(username)
  
    bcrypt.compare(password, hash.password, (err, result) => {
      if (err){
        res.json(err)
      }else if(result == true){
        const token = jsonwebtoken.sign(result, secretKey)
        return res.json({
          userID: userID.userID,
          username: username,
          token: token
        })
        
      }else{
        return res.json({Message: "No login"})
        
      }
    })  
  }
})

// Done
app.get('/api/users', (req, res) => {
  const userList = db.prepare('SELECT * FROM users').all()
  res.send({userList})
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})