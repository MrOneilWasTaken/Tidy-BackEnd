const {createHmac} = import('crypto')
// import { login } from './functions/login';
import Database from 'better-sqlite3';
import express from 'express';
import multer from 'multer';
import jsonwebtoken from 'jsonwebtoken';
import bcrypt from 'bcrypt'
const saltRounds = 10
const upload = multer()
const app = express()
const port = 3001
app.use(express.json())
const db = new Database('db/projectDB.sqlite');
 
const ensureToken = (req,res,next) =>{
  const bearerHeader = req.headers["authorization"]
  if (typeof bearerHeader !== undefined){
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

app.get('/api', (req, res) => {
  res.json({
    text: "my api"
  })
})

app.post('/api/login', upload.array(), (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*')

  const {password} = req.body
  const {username} = req.body

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
        const token = jsonwebtoken.sign(result, 'my_secret_key')
        res.json({
          userID: userID.userID,
          token: token
        })
      }else{
        res.json({Message: "No login"})
      }
    })  
  }
})

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
            const token = jsonwebtoken.sign(result, 'my_secret_key')
            res.json({
              Status: "200",
              Message: "Account Created",
              userID: userID.userID,
              token: token
            })
          } 
        })
      }
    })
  }
})

app.post('/api/addtask'), ensureToken, upload.array(), (req, res) => {
  jsonwebtoken.verify(req.token, 'my_secret_key', (err, data) => {
    if(err){
      res.sendStatus(403)
    }else{
      res.setHeader('Access-Control-Allow-Origin', '*')
      let stmt = db.prepare('INSERT INTO userstasks (taskID, userID, dayID, content, done) VALUES (?, ?, ?, ?, ?)')
      const info = stmt.run(req.taskID, req.userID, req.dayID, req.content, req.done)
      res.json({
        status: 204,
        Message: "Tasks uploaded",
        
      })
    }
  })
}

app.get('/api/recievetasks'), ensureToken, upload.array(), (req, res) => {
  jsonwebtoken.verify(req.token, 'my_secret_key', (err, data) => {
    if(err){
      res.sendStatus(403)
    }else{
      const stmt = db.prepare('SELECT * FROM userstasks WHERE userID = ?').get(userID)
      res.json({
        text: "this is protected",
        data: data
      })
    }
  })
}

app.get('/api/userstasks'), upload.array(), (req, res) => {

  res.send({
    stmt
  })
}

app.get('/api/protected', ensureToken, (req, res) => {
  jsonwebtoken.verify(req.token, 'my_secret_key', (err, data) => {
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

app.get('/api/users', (req, res) => {
  const stmt = db.prepare('SELECT * FROM users').all()
  
  res.send({stmt})
})

app.get('/api/userstasks', (req, res) => {
  const stmt = db.prepare('SELECT * FROM users').all()
  
  res.send({stmt})
})


app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})