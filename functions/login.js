import bcrypt from 'bcrypt'
import jsonwebtoken from 'jsonwebtoken';

export const login = (req,res) => {
  
  

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
}