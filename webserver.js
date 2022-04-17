import Database from 'better-sqlite3';
import express from 'express';
import multer from 'multer';
import jsonwebtoken from 'jsonwebtoken';
import bcrypt from 'bcrypt'
import helmet from 'helmet';
const saltRounds = 10
const upload = multer()
const app = express()
const port = 3001
app.use(express.json())
app.use(helmet())
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
    res.status(401).send({
      StatusCode: 401,
      Message: "Unauthorized Access, Please Log In"
    });
  }
}

// regex api switch statement insert here at some point 
// also shove each of these endpoints into their own files, login.js, etc.

// Base API
app.get('/api', (req, res) => {
  res.status(200).send({
    StatusCode: 200,
    Message: 'Welcome to the API, please use the /api/[ENDPOINT]/ format to access the API you want to access'
  })
})

// Task Stuff /=============================
// Update DB when user checks a task off 
app.post('/api/updatetask', ensureToken, (req,res) =>{
  jsonwebtoken.verify(req.token, secretKey, (err) => {
    if(err){
      res.status(500).send({
        StatusCode: 500,
        Message: "An error has occurred confirming token",
      })
    }else{
      const task = req.body
      const stmt = db.prepare('UPDATE userstasks SET done = ? WHERE taskID = ?')
      stmt.run((task.done) ? 1 : 0 , task.taskid)
      res.status(200).send({
        StatusCode: 200,
        Message: "Update recieved"
      })
    }
  })
})

// Add a new task to the database
app.post('/api/addtask', ensureToken,  (req, res) => {
  jsonwebtoken.verify(req.token, secretKey, (err) => {
    if(err){
      res.status(500).send({
        StatusCode: 500,
        Message: "An error has occurred confirming token",
      })
    }else{
      const task = req.body 

      let stmt = db.prepare('INSERT INTO userstasks (userID, dayID, content, done) VALUES (?, ?, ?, ?)')
      stmt.run(task.userid, task.dayid, task.content, ((task.done) ? 1 : 0 ))

      res.status(201).send({
        StatusCode: 201,
        Message: "Tasks uploaded",
      })          
    }
  })
})

// Pull through a user's details
app.get('/api/recievetasks', ensureToken,  (req, res) => {
  jsonwebtoken.verify(req.token, secretKey, (err) => {
    if(err){
      res.status(500).send({
        StatusCode: 500,
        Message: "An error has occurred confirming token",
      })
    }else{
      const {userID} = req.query
      const recievedTasks = db.prepare('SELECT * FROM userstasks WHERE userID = ?').all(userID)
      const filtered = recievedTasks.filter((task) => {
        if (task.done === 0) return true;
        return false;
      })
      res.status(200).send({
        StatusCode: 200,
        Message: "Successfully Pulled Details",
        Tasks: filtered
      })
    }
  })
})

// Stats for Profile Page
app.get('/api/userstasks', (req, res) => {
  if (req.query.userID) {
    const {userID} = req.query
    const userTasks = db.prepare('SELECT * FROM userstasks WHERE userID = ?').all(userID)
    const userDetails = db.prepare('SELECT username FROM users WHERE userID = ?').get(userID)

    const totalTaskCalc = db.prepare('SELECT COUNT(*) FROM userstasks WHERE done = 1 AND userID = ?').all(userID) 
    const totalTaskResult = totalTaskCalc[0]['COUNT(*)']
    
    res.status(200).send({
      StatusCode: 200,
      Username: userDetails.username,
      UsersTasks: userTasks,
      UsersCompletedTasks: totalTaskResult
    })
  }else{
    res.status(400).send({
      StatusCode: 400,
      Message: "Please provide a userID"
    })
  }
})

// Achievement stuff /===========================
// Check achievements for a user
app.get('/api/achievements', ensureToken,  (req, res) => {
  jsonwebtoken.verify(req.token, secretKey, (err) => {
    if(err){
      res.status(500).send({
        StatusCode: 500,
        Message: "An error has occurred confirming token",
      })
    }else{
      if (req.query.userID){
        const {userID} = req.query
        const stmt = db.prepare('SELECT achievements.achievementID, achievement_desc FROM userachievements JOIN achievements ON achievements.achievementID = userachievements.achievementID WHERE userID = ?')
        const achievements = stmt.all(userID)
        res.status(200).send({
          StatusCode: 200,
          userID: userID,
          achievements: achievements
        })
      }else{
        res.status(400).send({
          StatusCode: 400,
          Message: "Please provide a userid"
        })
      }
      
    }
  })
})

// Check if a user has reached an achievement requirement then add it to the database
app.post('/api/addachievement', ensureToken, upload.array(), (req, res) => {
  jsonwebtoken.verify(req.token, secretKey, (err) => {
    if(err){
      res.status(500).send({
        StatusCode: 500,
        Message: "An error has occurred confirming token",
      })
    }else{
      const {userID} = req.body
      
      const totalTaskCalc = db.prepare('SELECT COUNT(*) FROM userstasks WHERE done = 1 AND userID = ?').all(userID) 
      const totalTaskResult = totalTaskCalc[0]['COUNT(*)']
      
      const addAchievement = db.prepare('INSERT INTO userachievements VALUES (@achievementID, @userID)')
      const achievementCheck = db.prepare('SELECT achievementID FROM userachievements WHERE achievementID = ? AND  userID = ? ')
      const achievementCheckOne = achievementCheck.all(1, userID)
      const achievementCheckTwo = achievementCheck.all(2, userID)
      const achievementCheckThree = achievementCheck.all(3, userID)

      switch (true) {
        case totalTaskResult>=5 && totalTaskResult<10:
          if(achievementCheckOne.length === 0){
            addAchievement.run({achievementID: 1,userID: userID})
            res.status(201).send({
              StatusCode: 201,
              userid: userID,
              Message: "5 Tasks Completed Achievement added"
            })  
          }else{
            res.status(200).send({
              StatusCode: 200,
              userid: userID,
              Message: "5 Tasks Completed Achievement already added"
            })
          }
          break;

        case totalTaskResult>=10 && totalTaskResult<15:
          if(achievementCheckTwo.length === 0){
            if(achievementCheckOne.length === 0)addAchievement.run({achievementID: 1,userID: userID})
            
            addAchievement.run({achievementID: 2,userID: userID})

            res.status(201).send({
              StatusCode: 201,
              userid: userID,
              message: "10 Tasks Completed Achievement added"
            })  

          }else{
            res.status(200).send({
              StatusCode: 200,
              userid: userID,
              Message: "10 Tasks Completed Achievement already added"
            })
          }
          break;

        case totalTaskResult>=15:
          if(achievementCheckThree.length === 0){
            if(achievementCheckTwo.length === 0)addAchievement.run({achievementID: 2,userID: userID})
            if(achievementCheckOne.length === 0)addAchievement.run({achievementID: 1,userID: userID})
            
            addAchievement.run({achievementID: 3,userID: userID})

            res.status(201).send({
              StatusCode: 201,
              userid: userID,
              message: "15 Tasks Completed Achievement added"
            })
          }else{
            res.status(200).send({
              StatusCode: 200,
              userid: userID,
              Message: "15 Tasks Completed Achievement already added"
            })
          }
          break;
      
        default:
          res.status(200).send({
            StatusCode: 200,
            userid: userID,
            Message: "User does not meet any requirements for achievements"
          })
          break;
      }
    }
  })
})

// Leaderboard stuff /===========================
// Display all users in order of highest to lowest score
app.get('/api/leaderboard', ensureToken,  (req,res) => {
  jsonwebtoken.verify(req.token, secretKey, (err) => {
    if(err){
      res.status(500).send({
        StatusCode: 500,
        Message: "An error has occurred confirming token",
      })
    }else{

      const allUsersDetails = db.prepare('SELECT UserID, username FROM users').all();
      const taskResultArray = []

      allUsersDetails.forEach(user => {
        let taskCount = {}
        let userID = user.userID
        let result = db.prepare('SELECT COUNT(*) FROM userstasks WHERE done = 1 AND userID = ?').all(userID) 
        taskCount.userID = userID 
        taskCount.username = user.username
        taskCount.result = result[0]['COUNT(*)']
        taskResultArray.push(taskCount)
      });

      taskResultArray.sort((a,b) => {
        return b.result - a.result
      })
      
      res.status(200).send({
        StatusCode: 200,
        Message: "Successfully Pulled Details",
        TaskCount: taskResultArray
      })
    }
  })
})


// User Authentication /===========================
// Adds a new user's details to the database and signs in
app.post('/api/signup', upload.array(), (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*')
  if (req.body.username) {
    if (req.body.password) {
      const {password} = req.body
      const {username} = req.body
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
    }else{
      res.status(400).send({
        StatusCode: 400,
        Message: "Please provide a password"
      })
    }
  }else{
    res.status(400).send({
      StatusCode: 400,
      Message: "Please provide a username"
    })
  }
})

// Checks the details the user provides and logs in if it is correct
app.post('/api/login', upload.array(), (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*')
  if (req.body.username) {
    if (req.body.password) {
      const {password} = req.body
      const {username} = req.body
      let stmt = db.prepare('SELECT password FROM users WHERE username = ?')
      const hash = stmt.get(username) 
    
      stmt = db.prepare('SELECT userID FROM users WHERE username = ?')
      const userID = stmt.get(username)
    
      bcrypt.compare(password, hash.password, (err, result) => {
        if (err){
          res.json(err)
        }else if(result == true){
          const token = jsonwebtoken.sign(result, secretKey)
          return res.status(200).send({
            StatusCode: 200,
            userID: userID.userID,
            username: username,
            token: token
          })
        }else{
          return res.status(400).send({
            StatusCode: 400,
            Message: "No login"
          })
          
        }
      })  
    }else{
      res.status(400).send({
        StatusCode: 400,
        Message: "Please provide a password"
      })
    }
  }else{
    res.status(400).send({
      StatusCode: 400,
      Message: "Please provide a username"
    })
  }
})

// General Purpose Endpoints /===========================
// Gets a list of all the users in the database
app.get('/api/users', (req, res) => {
  const userList = db.prepare('SELECT * FROM users').all()
  res.status(200).send({
    StatusCode: 200,
    Message: "Successfully Pulled Details",
    userList : userList
  })
})

// Opens the server on port 3000
app.listen(port, () => {
  console.log(`App listening on port ${port}`)
})